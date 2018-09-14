#!/bin/bash
# http://qistoph.blogspot.com/2012/01/manual-verify-pkcs7-signed-data-with.html
# https://security.stackexchange.com/questions/176329/verify-s-mime-signature-with-no-certificate-included

sign1(){
    openssl smime -sign \
-md sha256 \
-binary \
-CAfile demo2_ca.crt.pem \
-in $1 -out $2 -outform der \
-inkey demo2_user1.key.pem \
-signer demo2_user1.crt.pem
}

sign2(){
    openssl smime -sign \
-md sha256 \
-binary -noattr \
-CAfile demo2_ca.crt.pem \
-in $1 -out $2 -outform der \
-inkey demo2_user1.key.pem \
-signer demo2_user1.crt.pem
}

verify(){
    openssl smime -verify \
-CAfile demo2_ca.crt.pem \
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
