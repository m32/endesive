#!/bin/bash

pssverify(){
    openssl cms -verify -signer $1 -CAfile $2 -in $3
}

pssverify demo2_user1.crt.pem demo2_ca.crt.pem smime-signed-pss.txt
