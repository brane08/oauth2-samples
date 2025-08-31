#!/bin/bash
set -e

PASSWORD=changeit
DAYS=365
KEYSIZE=2048

rm -f *.key *.pem *.crt *.csr *.srl *.p12 *.jks *.cnf

echo "### 1. Generate Root CA"
openssl genrsa -out ca.key $KEYSIZE
openssl req -x509 -new -nodes -key ca.key -sha256 -days $DAYS \
  -out ca.pem -subj "/CN=MyLocalCA"

echo "### 2. Generate SAS cert"
cat > sas.cnf <<EOF
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=localhost
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF

openssl genrsa -out sas.key $KEYSIZE
openssl req -new -key sas.key -out sas.csr -config sas.cnf
openssl x509 -req -in sas.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out sas.crt -days $DAYS -sha256 -extfile sas.cnf -extensions v3_req
openssl pkcs12 -export -in sas.crt -inkey sas.key -out sas.p12 \
  -name sas -CAfile ca.pem -caname root -password pass:$PASSWORD

echo "### 3. Generate Flask SSO cert"
cat > flask.cnf <<EOF
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=localhost
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF

openssl genrsa -out flask.key $KEYSIZE
openssl req -new -key flask.key -out flask.csr -config flask.cnf
openssl x509 -req -in flask.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out flask.crt -days $DAYS -sha256 -extfile flask.cnf -extensions v3_req

echo "### 4. Generate Client cert"
cat > client.cnf <<EOF
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=localhost
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF

openssl genrsa -out client.key $KEYSIZE
openssl req -new -key client.key -out client.csr -config client.cnf
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.crt -days $DAYS -sha256 -extfile client.cnf -extensions v3_req
openssl pkcs12 -export -in client.crt -inkey client.key -out client.p12 \
  -name client -CAfile ca.pem -caname root -password pass:$PASSWORD

echo "### 5. Create Java Truststore with CA cert"
keytool -import -trustcacerts -noprompt -alias rootCA \
  -file ca.pem -keystore truststore.jks -storepass $PASSWORD

echo "✅ All certs and truststore generated in ./certs"
