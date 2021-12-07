import sys

if sys.platform == "win32":
    dllpath = r"c:\windows\system32\cryptoCertum3PKCS.dll"
else:
    import ctypes as ct
    openssl_1_1 = [
        ct.CDLL('/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1', ct.RTLD_GLOBAL),
        ct.CDLL('/usr/lib/x86_64-linux-gnu/libssl.so.1.1', ct.RTLD_GLOBAL),
    ]
    dllpath = '/devel/lib/pkcs11libs/libcryptoCertum3PKCS.so'
