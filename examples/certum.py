import sys

if sys.platform == "win32":
    dllpath = r"c:\windows\system32\cryptoCertum3PKCS.dll"
else:
    import ctypes as ct
    if 1:
        openssl_1_1 = [
            ct.CDLL('/usr/lib/x86_64-linux-gnu/libcrypto.so', ct.RTLD_GLOBAL),
            ct.CDLL('/usr/lib/x86_64-linux-gnu/libssl.so', ct.RTLD_GLOBAL),
        ]
    dllpath = '/devel/lib/pkcs11libs/libcryptoCertum3PKCS.so'
