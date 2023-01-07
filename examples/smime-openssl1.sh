#!/bin/bash

pssverify(){
    openssl cms -verify -signer $1 -CAfile $2 -in $3
}

oaepdecrypt(){
    openssl cms -decrypt -recip $1 -inkey $2 -in $3
}

pssverify ca/demo2_user1.crt.pem ca/demo2_ca.crt.pem smime-signed-pss.txt
oaepdecrypt ca/demo2_user1.crt.pem ca/demo2_user1.key.pem smime-encrypted-oaep.txt
