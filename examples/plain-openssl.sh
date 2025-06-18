#!/bin/bash
# http://qistoph.blogspot.com/2012/01/manual-verify-pkcs7-signed-data-with.html
# https://security.stackexchange.com/questions/176329/verify-s-mime-signature-with-no-certificate-included

sign1() {
    openssl smime -sign \
-md sha256 \
-binary \
-CAfile ca/demo2_ca.sub.crt.pem \
-in $1 -out $2 -outform der \
-inkey ca/demo2_user1.key.pem -passin pass:1234 \
-signer ca/demo2_user1.crt.pem
}

sign2() {
    cat ca/demo2_user1.crt.pem ca/demo2_ca.sub.crt.pem >x-cert.tmp
    openssl smime -sign \
-md sha256 \
-binary -noattr \
-CAfile ca/demo2_ca.root.crt.pem \
-in $1 -out $2 -outform der \
-inkey ca/demo2_user1.key.pem -passin pass:1234 \
-signer x-cert.tmp
    rm x-cert.tmp
}

verify() {
    openssl smime -verify \
-CAfile ca/root.pem \
-content $1 \
-in $2 -inform der
}

if [ -z "$1" ]; then
    echo "************************** attr"
    sign1 plain-unsigned.txt plain-ssl-signed-attr.txt
    verify plain-unsigned.txt plain-ssl-signed-attr.txt
    echo "************************** noattr"
    sign2 plain-unsigned.txt plain-ssl-signed-noattr.txt
    verify plain-unsigned.txt plain-ssl-signed-noattr.txt
else
    echo "************************** verify"
    verify plain-unsigned.txt $1
fi
