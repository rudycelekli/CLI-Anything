"""Win32 API/sharing emulation; these controls are not native Windows proof."""
import ctypes
import io
import os
import sys
import types

import pytest

from cli_anything.mermaid.utils import mermaid_backend


class Function:
    def __init__(self, call): self.call = call
    def __call__(self, *args): return self.call(*args)


@pytest.fixture
def windows_handles(monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX-backed API emulation; use the native Windows lifecycle controls")
    real_open, real_close = os.open, os.close
    real_replace, real_unlink = os.replace, os.unlink
    handles = {}
    events = []
    state = {"adoption_fails": False}

    def register(path, share):
        fd = real_open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
        handle = (1 << 40) + fd  # Verify that the wrapper accepts 64-bit handles.
        handles[handle] = {"fd": fd, "path": path, "share": share, "closed": False, "delete": False}
        return handle

    def create(path, access, share, security, disposition, attributes, template):
        events.append(("create", access, share, security, disposition, attributes, template))
        try:
            return register(path, share)
        except OSError:
            return ctypes.c_void_p(-1).value

    def disposition(handle, kind, value, size):
        assert kind == 4 and size == 1
        assert ctypes.cast(value, ctypes.POINTER(ctypes.c_ubyte)).contents.value == 1
        handles[handle]["delete"] = True
        events.append(("delete_owned_handle", handle))
        return 1

    def close(handle):
        entry = handles[handle]
        if entry["delete"]:
            real_unlink(entry["path"])
        real_close(entry["fd"])
        entry["closed"] = True
        return 1

    kernel = types.SimpleNamespace(CreateFileW=Function(create), CloseHandle=Function(close),
                                  SetFileInformationByHandle=Function(disposition))

    def adopt(handle, flags):
        events.append(("adopt", handle, flags))
        if state["adoption_fails"]:
            raise OSError("CRT descriptor allocation failed")
        return handles[handle]["fd"]

    def crt_open(path, flags, mode=0o777, **kwargs):
        if ".mermaid-" in os.fspath(path):
            handle = register(path, 0)  # Ordinary CRT opens do not share deletion.
            return handles[handle]["fd"]
        return real_open(path, flags, mode, **kwargs)

    def deny_unshared_delete(path):
        for entry in handles.values():
            if not entry["closed"] and entry["path"] == path and not entry["share"] & 4:
                raise PermissionError("Windows sharing violation")

    def replace(source, destination):
        deny_unshared_delete(source)
        return real_replace(source, destination)

    def unlink(path, *args, **kwargs):
        deny_unshared_delete(path)
        return real_unlink(path, *args, **kwargs)

    def close_fd(fd):
        for entry in handles.values():
            if entry["fd"] == fd and not entry["closed"]:
                entry["closed"] = True
        return real_close(fd)

    monkeypatch.setattr(mermaid_backend.sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: kernel, raising=False)
    monkeypatch.setattr(ctypes, "WinError", lambda: OSError("CreateFileW failed"), raising=False)
    monkeypatch.setitem(sys.modules, "msvcrt", types.SimpleNamespace(open_osfhandle=adopt))
    monkeypatch.setattr(os, "O_BINARY", 0x8000, raising=False)
    monkeypatch.setattr(os, "O_NOINHERIT", 0x80, raising=False)
    monkeypatch.setattr(os, "open", crt_open)
    monkeypatch.setattr(os, "close", close_fd)
    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "unlink", unlink)
    monkeypatch.setattr(mermaid_backend.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"<svg/>"))
    return handles, events, state


@pytest.mark.parametrize("failure", [None, "write", "publish"])
def test_windows_new_output_publishes_or_cleans_while_pinned(windows_handles, monkeypatch, tmp_path, failure):
    handles, events, _ = windows_handles
    output = tmp_path / "out.svg"
    if failure == "write":
        fdopen = os.fdopen
        class ShortWriter:
            def __init__(self, file): self.file = file
            def __enter__(self): self.file.__enter__(); return self
            def __exit__(self, *args): return self.file.__exit__(*args)
            def write(self, data): self.file.write(data[:1]); return 1
        monkeypatch.setattr(os, "fdopen", lambda fd, *a, **k: ShortWriter(fdopen(fd, *a, **k)))
    elif failure == "publish":
        def fail_publish(*args): raise OSError("publication denied")
        monkeypatch.setattr(os, "replace", fail_publish)
    if failure:
        with pytest.raises(RuntimeError, match="Incomplete|publication denied"):
            mermaid_backend.render_to_file("pako:x", str(output), "svg")
        assert not output.exists()
    else:
        mermaid_backend.render_to_file("pako:x", str(output), "svg")
        assert output.read_bytes() == b"<svg/>"
    assert not list(tmp_path.glob(".mermaid-*"))
    assert all(entry["closed"] for entry in handles.values())
    assert events[0] == ("create", 0x40010000, 4, None, 1, 0x80, None)
    assert events[1][0] == "adopt"


def test_windows_descriptor_adoption_failure_deletes_owned_handle(windows_handles, tmp_path):
    handles, events, state = windows_handles
    state["adoption_fails"] = True
    with pytest.raises(OSError, match="CRT descriptor allocation failed"):
        mermaid_backend._open_staging_file(str(tmp_path / ".mermaid-stage"), 0o666)
    assert not list(tmp_path.iterdir())
    assert all(entry["closed"] for entry in handles.values())
    assert any(event[0] == "delete_owned_handle" for event in events)


def test_windows_exclusive_creation_preserves_collision(windows_handles, tmp_path):
    handles, events, _ = windows_handles
    collision = tmp_path / ".mermaid-stage"
    collision.write_bytes(b"another writer")
    with pytest.raises(OSError, match="CreateFileW failed"):
        mermaid_backend._open_staging_file(str(collision), 0o666)
    assert collision.read_bytes() == b"another writer"
    assert not handles
    assert [event[0] for event in events] == ["create"]


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Win32 sharing and deletion semantics")
@pytest.mark.parametrize("failure", [None, "write", "publish"])
def test_native_windows_new_output_handle_lifecycle(monkeypatch, tmp_path, failure):
    monkeypatch.setattr(mermaid_backend.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"<svg/>"))
    output = tmp_path / "out.svg"
    descriptors = []
    fdopen = os.fdopen

    def observe_descriptor(fd, *args, **kwargs):
        descriptors.append(fd)
        if failure == "write":
            raise OSError("injected write setup failure")
        return fdopen(fd, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", observe_descriptor)
    if failure == "publish":
        def fail_publish(*args): raise OSError("injected publication failure")
        monkeypatch.setattr(os, "replace", fail_publish)
    if failure:
        with pytest.raises(RuntimeError, match="injected"):
            mermaid_backend.render_to_file("pako:x", str(output), "svg")
        assert not output.exists()
    else:
        mermaid_backend.render_to_file("pako:x", str(output), "svg")
        assert output.read_bytes() == b"<svg/>"
    assert descriptors
    assert not list(tmp_path.glob(".mermaid-*"))
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
