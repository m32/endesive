#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import requests
import hashlib
import time
from asn1crypto import cms, algos, core, keys, pem, tsp, x509, ocsp, util


def timestamp(unhashed, hashalgo, url, credentials, req_options, prehashed=None):
    if prehashed:
        hashed_value = prehashed
    else:
        hashed_value = getattr(hashlib, hashalgo)(unhashed).digest()
    tspreq = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({'algorithm': hashalgo}),
            "hashed_message": hashed_value,
            }),
        #'req_policy', ObjectIdentifier, {'optional': True}),
        "nonce": int(time.time()*1000),
        "cert_req": True,
        #'extensions': tsp.Extensions()
        })
    tspreq = tspreq.dump()
    open('t-ts-req.bin', 'wb').write(tspreq)

    tspheaders = {"Content-Type": "application/timestamp-query"}
    username = credentials.get("username", None)
    password = credentials.get("password", None)
    if username and password:
        auth_header_value = b64encode(bytes(username + ':' + password, "utf-8")).decode("ascii")
        tspheaders["Authorization"] = f"Basic {auth_header_value}"

    tspresp = requests.post(url, data=tspreq, headers=tspheaders, **req_options)
    if tspresp.headers.get('Content-Type', None) == 'application/timestamp-reply':
        open('t-ts-resp.bin','wb').write(tspresp.content)
        tspresp = tsp.TimeStampResp.load(tspresp.content)

        if tspresp['status']['status'].native == 'granted':
            attrs = [
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('signature_time_stamp_token'),
                    'values': cms.SetOfContentInfo([
                        cms.ContentInfo({
                            'content_type': cms.ContentType('signed_data'),
                            'content': tspresp["time_stamp_token"]["content"],
                            })
                        ])
                    })
                ]
            return attrs
        else:
            raise ValueError("TimeStampResponse status is not granted")
    else:
        raise ValueError("TimeStampResponse has invalid content type")



def main():
    unhashed = b'ala ma kota'
    hashalgo = 'sha256'
    #url = "http://time.certum.pl"
    url = "http://public-qlts.certum.pl/qts-17"
    #url = 'https://freetsa.org/tsr'
    credentials = {}
    req_options = {}
    prehashed = None
    attrs = timestamp(unhashed, hashalgo, url, credentials, req_options, prehashed)

main()
