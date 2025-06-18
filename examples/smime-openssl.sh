#!/bin/bash

sign1() {
    openssl smime -sign -CAfile ca/root.pem -signer $1 -inkey $2 -passin pass:1234 -outform SMIME -in $3 -out $4
}

sign2() {
    openssl smime -sign -noattr -CAfile ca/root.pem -signer $1 -inkey $2 -passin pass:1234 -outform SMIME -in $3 -out $4
}

encrypt() {
    openssl smime -encrypt -aes256 -in $2 -out $3 $1
}

decrypt() {
    openssl smime -decrypt -recip $1 -inkey $2 -passin pass:1234 -in $3
}

verify() {
    openssl smime -verify -CAfile ca/root.pem -in $1 -inform SMIME
}

psssign() {
    openssl cms -sign -signer $1 -inkey $2 -passin pass:1234 -in $3 -out $4 -keyopt rsa_padding_mode:pss -md sha512
}

pssverify() {
    openssl cms -verify -signer $1 -CAfile ca/root.pem -in $2 -keyopt rsa_padding_mode:pss -md sha512
}

oaepencrypt() {
    openssl cms -encrypt -recip $1 -in $2 -out $3 -keyopt rsa_padding_mode:oaep -md sha512
}

oaepdecrypt() {
    openssl cms -decrypt -recip $1 -inkey $2 -passin pass:1234 -in $3
}

detached() {
    openssl smime -sign -in $3 -signer $1 -inkey $2 -passin pass:1234 -outform der -binary -out $4
}

detachedverify() {
    openssl smime -verify -in $2 -inform der -content $1 -CAfile ca/root.pem
}

if [ -z "$1" ]; then
    echo "************************** attr"
    sign1 ca/demo2_user1.crt.pem ca/demo2_user1.key.pem smime-unsigned.txt smime-ssl-signed-attr.txt
    verify smime-ssl-signed-attr.txt
    echo "************************** noattr"
    sign2 ca/demo2_user1.crt.pem ca/demo2_user1.key.pem smime-unsigned.txt smime-ssl-signed-noattr.txt
    verify smime-ssl-signed-noattr.txt
    echo "************************** detached"
    detached ca/demo2_user1.crt.pem ca/demo2_user1.key.pem smime-unsigned.txt smime-ssl-signed-detached.p7s
    detachedverify smime-unsigned.txt smime-ssl-signed-detached.p7s
    echo "************************** encrypt"
    encrypt ca/demo2_user1.crt.pem smime-unsigned.txt smime-ssl-encrypted.txt
    decrypt ca/demo2_user1.crt.pem ca/demo2_user1.key.pem smime-ssl-encrypted.txt
    echo "************************** pss sign"
    psssign ca/demo2_user1.crt.pem ca/demo2_user1.key.pem smime-unsigned.txt smime-ssl-pss-signed.txt
    pssverify ca/demo2_user1.crt.pem smime-ssl-pss-signed.txt
    echo "************************** oaep encrypt"
    oaepencrypt ca/demo2_user1.crt.pem smime-unsigned.txt smime-ssl-oaep-encrypted.txt
    oaepdecrypt ca/demo2_user1.crt.pem ca/demo2_user1.key.pem smime-ssl-oaep-encrypted.txt
else
    if [ -z "$2" ]; then
        echo "************************** $1"
        verify $1
    else
        decrypt ca/demo2_user1.crt.pem ca/demo2_user1.key.pem $1
    fi
fi
