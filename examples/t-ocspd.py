#!/usr/bin/env vpython3
import os
import io
from datetime import datetime, timezone, timedelta
from http import server, HTTPStatus
import socketserver
import logging

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

logging.basicConfig(level=logging.DEBUG)

log = logging.getLogger(__name__)


class HTTPError(Exception):
    def __init__(self, status: HTTPStatus):
        self.status = status

class HTTPD(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, port):
        super().__init__(("0.0.0.0", port), Handler)


class Handler(server.SimpleHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.extensions_map.update(
            {
                ".wasm": "application/wasm",
            }
        )
        self._root_cert = self.load_cert('demo2_ca.root.crt.pem')
        self._root_key = self.load_key('demo2_ca.root.key.pem', '1234')
        self._sub_cert = self.load_cert('demo2_ca.sub.crt.pem')
        self._sub_key = self.load_key('demo2_ca.sub.key.pem', '1234')

    def xguess_type(self, path):
        return super().guess_type(path)

    def load_cert(self, fname: str) -> x509.Certificate:
        with open(os.path.join("ca", fname), "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def load_key(self, fname: str, password: str) -> rsa.RSAPrivateKey:
        with open(os.path.join("ca", fname), "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password.encode("utf-8"),
                default_backend()
            )
            return key

    def do_ERROR(self, ispost=False):
        print("*" * 20, self.requestline)
        print(self.headers)

        if ispost:
            length = int(self.headers["Content-Length"])
            data = self.rfile.read(length)
            print(data)

        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def validate(self, serial: int) -> tuple[x509.Certificate, ocsp.OCSPCertStatus, datetime|None, x509.ReasonFlags|None]:
        try:
            cert = self.load_cert(str(serial))
        except Exception as e:
            print(f"Could not retrieve certificate with serial {serial}: {e}")
            raise HTTPError(HTTPStatus.INTERNAL_SERVER_ERROR)
        now = datetime.now(tz=timezone.utc)
        if now < cert.not_valid_before_utc:
            return (cert, ocsp.OCSPCertStatus.REVOKED, cert.not_valid_before, x509.ReasonFlags.certificate_hold)
        if cert.not_valid_after_utc < now:
            return (cert, ocsp.OCSPCertStatus.REVOKED, cert.not_valid_after, x509.ReasonFlags.certificate_hold)
        return (cert, ocsp.OCSPCertStatus.GOOD, None, None)

    def _build_ocsp_response(self, req: ocsp.OCSPRequest) -> ocsp.OCSPResponse:
        serial = req.serial_number
        try:
            cert, certificate_status, revocation_time, revocation_reason = self.validate(serial)
        except Exception as e:
            print(f"Could not determine certificate status: %{e}")
            raise HTTPError(HTTPStatus.INTERNAL_SERVER_ERROR)

        issuer = self.load_cert('demo2_ca.sub.crt.pem')
        if cert.issuer != issuer.subject:
            certificate_status=ocsp.OCSPCertStatus.UNKNOWN

        # Build the response
        time = datetime.now(tz=timezone.utc)-timedelta(days=3)
        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=cert,
            issuer=issuer,
            algorithm=hashes.SHA256(),
            cert_status=certificate_status,
            this_update=time,
            next_update=time + timedelta(days=7),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason
        )
        for ext in req.extensions:
            if ext.oid == x509.OCSPNonce.oid:
                builder.add_extension(x509.OCSPNonce(ext.value.nonce), ext.critical)
            elif ext.critical:
                print(f"Could not parse unknown critical extension: {ext}")
                raise HTTPError(HTTPStatus.INTERNAL_SERVER_ERROR)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.HASH,
            self._sub_cert
        ).sign(
            self._sub_key, hashes.SHA256()
        )
        result = builder.public_bytes(serialization.Encoding.DER)
        return result

    def do_POST_ocsp(self):
        ctype = self.headers["Content-Type"]
        assert ctype == "application/ocsp-request"

        length = int(self.headers["Content-Length"])
        data = self.rfile.read(length)
        ocsprequest = ocsp.load_der_ocsp_request(data)
        ocspresponse = self._build_ocsp_response(ocsprequest)

        f = io.BytesIO(ocspresponse)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(ocspresponse)))
        self.send_header("Last-Modified", self.date_time_string())
        self.end_headers()
        self.copyfile(f, self.wfile)

    def do_POST(self):
        print("*" * 20, self.requestline)
        print(self.headers)

        try:
            if self.path == "/":
                return self.do_POST_ocsp()
            elif self.path == "/ocsp":
                return self.do_POST_ocsp()
        except:
            import traceback
            traceback.print_exc()
        self.do_ERROR()

        # Extract and print the contents of the POST
        length = int(self.headers["Content-Length"])
        data = self.rfile.read(length)
        print("*" * 10, "data")
        print(data)

    def do_GET_ocsp(self):
        f = open("ca/demo2_ca.root.crt.pem.cer", "rb")
        fs = os.fstat(f.fileno())
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "application/pkix-cert")
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        try:
            self.copyfile(f, self.wfile)
        finally:
            f.close()
        return

    def do_GET_crl(self):
        today = datetime.now(tz=timezone.utc)-timedelta(days=3)
        builder = (
            x509.CertificateRevocationListBuilder()
            .last_update(today)
            .next_update(today + timedelta(days=7))
            .issuer_name(self._root_cert.issuer)
        )
        cert_revocation_list = builder.sign(
            private_key=self._root_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        crl = cert_revocation_list.public_bytes(encoding=serialization.Encoding.PEM)
        f = io.BytesIO(crl)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "application/pkix-crl")
        self.send_header("Content-Length", str(len(crl)))
        self.send_header("Last-Modified", self.date_time_string())
        self.end_headers()
        self.copyfile(f, self.wfile)

    def do_GET(self):
        print("*" * 20, self.requestline)
        print(self.headers)

        try:
            if self.path == "/ocsp":
                return self.do_GET_ocsp()
            if self.path == "/crl":
                return self.do_GET_crl()
        except:
            import traceback
            traceback.print_exc()
        self.do_ERROR()

    def xx(self):
        # import pdb; pdb.set_trace()
        DUMMY_RESPONSE = """\
<html>
<head>
<title>Python Test</title>
</head>

<body>
Test page...success.
<script>
debugger;
</script>
</body>
</html>
"""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(DUMMY_RESPONSE))
        self.end_headers()
        self.wfile.write(DUMMY_RESPONSE)


import threading
import sys
import getopt
import ssl


def main():
    PORT = 33150

    def done():
        input("enter to stop")
        httpd.shutdown()

    print("serving at port", PORT)
    httpd = HTTPD(PORT)
    t = threading.Thread(target=done)
    t.start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    except:
        import traceback

        traceback.print_exc()


main()
