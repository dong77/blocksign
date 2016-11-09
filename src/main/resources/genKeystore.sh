#!/bin/sh

openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

openssl genrsa -out ia.key 2048
openssl req -new -key ia.key -out ia.csr

openssl x509 -req -days 365 -in ia.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out ia.crt
openssl pkcs12 -export -out ia.p12 -inkey ia.key -in ia.crt -chain -CAfile ca.crt





