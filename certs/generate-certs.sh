#!/bin/bash
set -e

PASSWORD=changeit
DAYS=365
KEYSIZE=2048
BASE_DOMAIN=example.com

rm -f *.key *.pem *.crt *.csr *.srl *.p12 *.jks *.cnf

echo "### 1. Generate Root CA"
openssl genrsa -out ca.key $KEYSIZE
openssl req -x509 -new -nodes -key ca.key -sha256 -days $DAYS \
  -out ca.pem -subj "/CN=Local Dev Root CA"

echo "### 2. Create SAN config for .example.com services"
cat > services.cnf <<EOF
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no

[req_distinguished_name]
CN=sso.${BASE_DOMAIN}

[v3_req]
subjectAltName=@alt_names
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth

[alt_names]
DNS.1=sso.${BASE_DOMAIN}
DNS.2=auth.${BASE_DOMAIN}
DNS.3=gateway.${BASE_DOMAIN}
DNS.4=localhost
IP.1=127.0.0.1
EOF

echo "### 3. Generate private key"
openssl genrsa -out services.key $KEYSIZE

echo "### 4. Generate CSR"
openssl req -new -key services.key -out services.csr -config services.cnf

echo "### 5. Sign cert with local CA"
openssl x509 -req -in services.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out services.crt -days $DAYS -sha256 \
  -extfile services.cnf -extensions v3_req

echo "### 6. Create PKCS12 keystore (Spring Boot)"
openssl pkcs12 -export \
  -in services.crt \
  -inkey services.key \
  -out services.p12 \
  -name services \
  -CAfile ca.pem \
  -caname root \
  -password pass:$PASSWORD

echo "### 7. Create Java truststore with CA"
keytool -import -trustcacerts -noprompt \
  -alias local-dev-root \
  -file ca.pem \
  -keystore truststore.jks \
  -storepass $PASSWORD

echo "### ✅ Certificates generated"
echo "  - services.crt / services.key (httpd + gateway + auth)"
echo "  - services.p12 (Spring Boot SSL)"
echo "  - truststore.jks (Spring trust)"
echo "  - ca.pem (browser + Apache trust)"
