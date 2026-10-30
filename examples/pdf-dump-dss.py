import sys

from asn1crypto import ocsp
from pypdf import PdfReader

from endesive.signer import cert2asn


class Dumper:
    def __init__(self, fname):
        self.pdf = PdfReader(fname)

    def show(self):
        root = self.pdf.trailer["/Root"]
        dss = root["/DSS"]
        print(dss)
        self.showCerts(dss["/Certs"])
        self.showVRI(dss["/VRI"])
        self.showOCSPs(dss["/OCSPs"])
        self.showCRLs(dss["/CRLs"])

    def showCert(self, der):
        certasn = cert2asn(der)
        # certasn.debug()
        print(certasn.serial_number)
        print(certasn.issuer.native)
        print(certasn.subject.native)

    def showOCSP(self, der):
        data = ocsp.OCSPResponse.load(der)
        print(data.native["response_status"])
        certs = data.basic_ocsp_response.native["certs"]
        cert = certs[0]["tbs_certificate"]
        print(cert["serial_number"])
        print(cert["subject"])
        # data.debug()

    def showCerts(self, objs):
        print("*" * 20, "Certs")
        for robj in objs:
            obj = robj.get_object()
            der = obj.get_data()
            self.showCert(der)

    def showVRI(self, obj):
        print("*" * 20, "VRI")
        for k, robj in obj.items():
            print("*" * 20, k)
            vobj = robj.get_object()
            print("/TU", vobj["/TU"])
            print("*" * 10, "VRI-cert")
            for robj in vobj["/Cert"]:
                der = robj.get_object().get_data()
                self.showCert(der)
            try:
                robjs = vobj["/OCSP"]
            except KeyError:
                robjs = []
            for robj in robjs:
                print("*" * 10, "VRI-OCSP")
                der = robj.get_object().get_data()
                self.showOCSP(der)

    def showOCSPs(self, objs):
        print("*" * 20, "OCSPs")
        for robj in objs:
            obj = robj.get_object()
            der = obj.get_data()
            print("*" * 10, "OCSP")
            self.showOCSP(der)

    def showCRLs(self, objs):
        print("*" * 20, "CRLs")
        for robj in objs:
            obj = robj.get_object()
            print(obj)


def main():
    fname = "generated/pdf-signed-cms-ltv.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    cls = Dumper(fname)
    cls.show()


main()
