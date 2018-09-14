#!/bin/bash

sign1() {
    openssl smime \
-sign \
-CAfile demo2_ca.crt.pem \
-signer $1 \
-inkey $2 \
-outform SMIME \
-in $3 \
-out $4
}

sign2() {
    openssl smime \
-sign \
-noattr \
-CAfile demo2_ca.crt.pem \
-signer $1 \
-inkey $2 \
-outform SMIME \
-in $3 \
-out $4
}

encrypt() {
    openssl smime \
-encrypt \
-aes256 \
-in $2 \
-out $3 \
$1
}

decrypt() {
    openssl smime \
-decrypt \
-recip $1 \
-inkey $2 \
-in $3
}

verify() {
    openssl smime \
-verify \
-CAfile demo2_ca.crt.pem \
-in $1 \
-inform SMIME
}

if [ -z "$1" ]; then
    echo "************************** attr"
    sign1 demo2_user1.crt.pem demo2_user1.key.pem smime-unsigned.txt smime-ssl-signed-attr.txt
    verify smime-ssl-signed-attr.txt
    echo "************************** noattr"
    sign2 demo2_user1.crt.pem demo2_user1.key.pem smime-unsigned.txt smime-ssl-signed-noattr.txt
    verify smime-ssl-signed-noattr.txt
    echo "************************** encrypt"
    encrypt demo2_user1.crt.pem smime-unsigned.txt smime-ssl-encrypted.txt
    decrypt demo2_user1.crt.pem demo2_user1.key.pem smime-ssl-encrypted.txt
else
    if [ -z "$2" ]; then
        echo "************************** $1"
        verify $1
    else
        decrypt demo2_user1.crt.pem demo2_user1.key.pem $1
    fi
fi
