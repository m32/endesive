from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey
from cryptography.hazmat.backends.openssl.x509 import _Certificate


class PKCS12(object):
    """
    A PKCS #12 archive.
    """

    def __init__(self):
        self._pkey = None
        self._cert = None
        self._cacerts = None
        self._friendlyname = None

    def get_certificate(self):
        """
        Get the certificate in the PKCS #12 structure.

        :return: The certificate, or :py:const:`None` if there is none.
        :rtype: :py:class:`X509` or :py:const:`None`
        """
        return self._cert

    def set_certificate(self, cert):
        """
        Set the certificate in the PKCS #12 structure.

        :param cert: The new certificate, or :py:const:`None` to unset it.
        :type cert: :py:class:`X509` or :py:const:`None`

        :return: ``None``
        """
        if not isinstance(cert, _Certificate):
            raise TypeError("cert must be an X509 instance")
        self._cert = cert

    def get_privatekey(self):
        """
        Get the private key in the PKCS #12 structure.

        :return: The private key, or :py:const:`None` if there is none.
        :rtype: :py:class:`PKey`
        """
        return self._pkey

    def set_privatekey(self, pkey):
        """
        Set the certificate portion of the PKCS #12 structure.

        :param pkey: The new private key, or :py:const:`None` to unset it.
        :type pkey: :py:class:`PKey` or :py:const:`None`

        :return: ``None``
        """
        if not isinstance(pkey, _RSAPrivateKey):
            raise TypeError("pkey must be a PKey instance")
        self._pkey = pkey

    def get_ca_certificates(self):
        """
        Get the CA certificates in the PKCS #12 structure.

        :return: A tuple with the CA certificates in the chain, or
            :py:const:`None` if there are none.
        :rtype: :py:class:`tuple` of :py:class:`X509` or :py:const:`None`
        """
        if self._cacerts is not None:
            return tuple(self._cacerts)

    def set_ca_certificates(self, cacerts):
        """
        Replace or set the CA certificates within the PKCS12 object.

        :param cacerts: The new CA certificates, or :py:const:`None` to unset
            them.
        :type cacerts: An iterable of :py:class:`X509` or :py:const:`None`

        :return: ``None``
        """
        if cacerts is None:
            self._cacerts = None
        else:
            cacerts = list(cacerts)
            for cert in cacerts:
                if not isinstance(cert, _Certificate):
                    raise TypeError(
                        "iterable must only contain X509 instances"
                    )
            self._cacerts = cacerts

    def set_friendlyname(self, name):
        """
        Set the friendly name in the PKCS #12 structure.

        :param name: The new friendly name, or :py:const:`None` to unset.
        :type name: :py:class:`bytes` or :py:const:`None`

        :return: ``None``
        """
        if name is None:
            self._friendlyname = None
        elif not isinstance(name, bytes):
            raise TypeError(
                "name must be a byte string or None (not %r)" % (name,)
            )
        self._friendlyname = name

    def get_friendlyname(self):
        """
        Get the friendly name in the PKCS# 12 structure.

        :returns: The friendly name,  or :py:const:`None` if there is none.
        :rtype: :py:class:`bytes` or :py:const:`None`
        """
        return self._friendlyname

    def export(self, passphrase=None, iter=2048, maciter=1, backend=None):
        """
        Dump a PKCS12 object as a string.

        For more information, see the :c:func:`PKCS12_create` man page.

        :param passphrase: The passphrase used to encrypt the structure. Unlike
            some other passphrase arguments, this *must* be a string, not a
            callback.
        :type passphrase: :py:data:`bytes`

        :param iter: Number of times to repeat the encryption step.
        :type iter: :py:data:`int`

        :param maciter: Number of times to repeat the MAC step.
        :type maciter: :py:data:`int`

        :return: The string representation of the PKCS #12 structure.
        :rtype:
        """

        if self._cacerts is None:
            cacerts = backend._ffi.NULL
        else:
            cacerts = backend._lib.sk_X509_new_null()
            cacerts = backend._ffi.gc(cacerts, backend._lib.sk_X509_free)
            for cert in self._cacerts:
                backend._lib.sk_X509_push(cacerts, cert._x509)

        if passphrase is None:
            passphrase = backend._ffi.NULL

        friendlyname = self._friendlyname
        if friendlyname is None:
            friendlyname = backend._ffi.NULL

        if self._pkey is None:
            pkey = backend._ffi.NULL
        else:
            pkey = self._pkey._evp_pkey

        if self._cert is None:
            cert = backend._ffi.NULL
        else:
            cert = self._cert._x509

        pkcs12 = backend._lib.PKCS12_create(
            passphrase, friendlyname, pkey, cert, cacerts,
            backend._lib.NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
            backend._lib.NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
            iter, maciter, 0)
        backend.openssl_assert(pkcs12 != backend._ffi.NULL)
        pkcs12 = backend._ffi.gc(pkcs12, backend._lib.PKCS12_free)

        bio = backend._create_mem_bio_gc()
        backend._lib.i2d_PKCS12_bio(bio, pkcs12)
        return backend._read_mem_bio(bio)


def load_pkcs12(buffer, passphrase=None, backend=None):
    """
    Load pkcs12 data from the string *buffer*. If the pkcs12 structure is
    encrypted, a *passphrase* must be included.  The MAC is always
    checked and thus required.

    See also the man page for the C function :py:func:`PKCS12_parse`.

    :param buffer: The buffer the certificate is stored in
    :param passphrase: (Optional) The password to decrypt the PKCS12 lump
    :returns: The PKCS12 object
    """

    bio = backend._bytes_to_bio(buffer)

    # Use null passphrase if passphrase is None or empty string. With PKCS#12
    # password based encryption no password and a zero length password are two
    # different things, but OpenSSL implementation will try both to figure out
    # which one works.
    if not passphrase:
        passphrase = backend._ffi.NULL

    p12 = backend._lib.d2i_PKCS12_bio(bio.bio, backend._ffi.NULL)
    backend.openssl_assert(p12 != backend._ffi.NULL)
    p12 = backend._ffi.gc(p12, backend._lib.PKCS12_free)

    pkey = backend._ffi.new("EVP_PKEY**")
    cert = backend._ffi.new("X509**")
    cacerts = backend._ffi.new("Cryptography_STACK_OF_X509**")

    parse_result = backend._lib.PKCS12_parse(p12, passphrase, pkey, cert, cacerts)
    backend.openssl_assert(parse_result == 1)

    cacerts = backend._ffi.gc(cacerts[0], backend._lib.sk_X509_free)

    # openssl 1.0.0 sometimes leaves an X509_check_private_key error in the
    # queue for no particular reason.  This error isn't interesting to anyone
    # outside this function.  It's not even interesting to us.  Get rid of it.
    backend._consume_errors()

    if pkey[0] == backend._ffi.NULL:
        pykey = None
    else:
        pykey = backend._ffi.gc(pkey[0], backend._lib.EVP_PKEY_free)

    if cert[0] == backend._ffi.NULL:
        pycert = None
        friendlyname = None
    else:
        x509 = backend._ffi.gc(cert[0], backend._lib.X509_free)
        pycert = _Certificate(backend, x509)

        friendlyname_length = backend._ffi.new("int*")
        friendlyname_buffer = backend._lib.X509_alias_get0(
            cert[0], friendlyname_length
        )
        friendlyname = backend._ffi.buffer(
            friendlyname_buffer, friendlyname_length[0]
        )[:]
        if friendlyname_buffer == backend._ffi.NULL:
            friendlyname = None

    pycacerts = []
    for i in range(backend._lib.sk_X509_num(cacerts)):
        x509 = backend._lib.sk_X509_value(cacerts, i)
        x509 = backend._ffi.gc(x509, backend._lib.X509_free)
        pycacerts.append(_Certificate(backend, x509))
    if not pycacerts:
        pycacerts = None

    pkcs12 = PKCS12()
    pkcs12.set_privatekey(pykey)
    pkcs12.set_certificate(pycert)
    pkcs12.set_ca_certificates(pycacerts)
    pkcs12.set_friendlyname(friendlyname)
    return pkcs12
