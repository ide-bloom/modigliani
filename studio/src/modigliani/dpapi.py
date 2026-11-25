"""Windows DPAPI (CryptProtectData) via ctypes, so the CA key is encrypted at rest.

The Go server decrypts with the same entropy, which is why it is a fixed constant:
DPAPI binds the secret to the Windows user account, the entropy only scopes it.
"""

from __future__ import annotations

import sys

ENTROPY = b"modigliani-local-ca-v1"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DpapiUnavailableError(RuntimeError):
    pass


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _to_blob(data: bytes) -> tuple[_Blob, ctypes.Array[ctypes.c_char]]:
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _from_blob(blob: _Blob) -> bytes:
        try:
            return ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob.pbData)

    def protect(data: bytes) -> bytes:
        inp, _keep1 = _to_blob(data)
        ent, _keep2 = _to_blob(ENTROPY)
        out = _Blob()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(inp),
            "Modigliani local CA",
            ctypes.byref(ent),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out),
        )
        if not ok:
            raise ctypes.WinError()
        return _from_blob(out)

    def unprotect(data: bytes) -> bytes:
        inp, _keep1 = _to_blob(data)
        ent, _keep2 = _to_blob(ENTROPY)
        out = _Blob()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(inp),
            None,
            ctypes.byref(ent),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out),
        )
        if not ok:
            raise ctypes.WinError()
        return _from_blob(out)

    AVAILABLE = True
else:

    def protect(data: bytes) -> bytes:
        raise DpapiUnavailableError("DPAPI exists only on Windows")

    def unprotect(data: bytes) -> bytes:
        raise DpapiUnavailableError("DPAPI exists only on Windows")

    AVAILABLE = False
