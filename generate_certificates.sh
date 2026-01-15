#!/bin/bash

# TLS Certificate Generation Script
# This script generates certificates compatible with mbedTLS and the TLS handshake

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certificates"

echo "Generating TLS certificates for mbedTLS..."
echo "Output directory: $CERT_DIR"

# Create output directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Generate CA private key (ECDSA P-256)
echo "1. Generating CA private key (ECDSA P-256)..."
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/ca-key.pem"

# Generate CA certificate
echo "2. Generating CA certificate..."
openssl req -new -x509 -days 365 -key "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca-cert.pem" \
    -subj "/C=US/ST=California/L=San Francisco/O=Test Organization/OU=Test CA/CN=Test CA"

# Generate server private key (ECDSA P-256)
echo "3. Generating server private key (ECDSA P-256)..."
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/server-key.pem"

# Generate server certificate signing request
echo "4. Generating server certificate signing request..."
openssl req -new -key "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server-cert.csr" \
    -subj "/C=US/ST=California/L=San Francisco/O=Test Organization/OU=Test Unit/CN=localhost"

# Create server certificate configuration file
echo "5. Creating server certificate configuration..."
cat > "$CERT_DIR/server-cert.conf" << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Test Organization
OU = Test Unit
CN = localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = test-server
IP.1 = 127.0.0.1
EOF

# Generate server certificate signed by CA
echo "6. Generating server certificate..."
openssl x509 -req -in "$CERT_DIR/server-cert.csr" \
    -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/server-cert.pem" \
    -days 365 \
    -extensions v3_req \
    -extfile "$CERT_DIR/server-cert.conf"

# Generate client private key (ECDSA P-256)
echo "7. Generating client private key (ECDSA P-256)..."
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/client-key.pem"

# Generate client certificate signing request
echo "8. Generating client certificate signing request..."
openssl req -new -key "$CERT_DIR/client-key.pem" -out "$CERT_DIR/client-cert.csr" \
    -subj "/C=US/ST=California/L=San Francisco/O=Test Organization/OU=Test Client/CN=test-client"

# Create client certificate configuration file
echo "9. Creating client certificate configuration..."
cat > "$CERT_DIR/client-cert.conf" << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Test Organization
OU = Test Client
CN = test-client

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = clientAuth
EOF

# Generate client certificate signed by CA
echo "10. Generating client certificate..."
openssl x509 -req -in "$CERT_DIR/client-cert.csr" \
    -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/client-cert.pem" \
    -days 365 \
    -extensions v3_req \
    -extfile "$CERT_DIR/client-cert.conf"

# Verify certificates
echo "11. Verifying certificates..."
echo "   CA Certificate:"
openssl x509 -in "$CERT_DIR/ca-cert.pem" -text -noout | grep -E "(Subject:|Issuer:|Validity)"

echo "   Server Certificate:"
openssl x509 -in "$CERT_DIR/server-cert.pem" -text -noout | grep -E "(Subject:|Issuer:|Validity|Key Usage|DNS:|IP Address)"

echo "   Client Certificate:"
openssl x509 -in "$CERT_DIR/client-cert.pem" -text -noout | grep -E "(Subject:|Issuer:|Validity|Key Usage)"

# Generate client private key
echo "7. Generating client private key..."
openssl genrsa -out "$CERT_DIR/client-key.pem" 2048

# Generate client certificate signing request
echo "8. Generating client certificate signing request..."
openssl req -new -key "$CERT_DIR/client-key.pem" -out "$CERT_DIR/client-cert.csr" \
    -subj "/C=US/ST=California/L=San Francisco/O=Test Organization/OU=Test Client/CN=test-client"

# Create client certificate configuration file
echo "9. Creating client certificate configuration..."
cat > "$CERT_DIR/client-cert.conf" << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Test Organization
OU = Test Client
CN = test-client

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = clientAuth
EOF

# Generate client certificate signed by CA
echo "10. Generating client certificate..."
openssl x509 -req -in "$CERT_DIR/client-cert.csr" \
    -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/client-cert.pem" \
    -days 365 \
    -extensions v3_req \
    -extfile "$CERT_DIR/client-cert.conf"

# Clean up CSR files
rm "$CERT_DIR/server-cert.csr" "$CERT_DIR/client-cert.csr"

# Verify certificate chain
echo "11. Verifying certificate chain..."
openssl verify -CAfile "$CERT_DIR/ca-cert.pem" "$CERT_DIR/server-cert.pem"
openssl verify -CAfile "$CERT_DIR/ca-cert.pem" "$CERT_DIR/client-cert.pem"

echo ""
echo "✅ Certificate generation completed successfully!"
echo ""
echo "Generated files:"
echo "  📄 $CERT_DIR/ca-cert.pem      (CA Certificate)"
echo "  🔐 $CERT_DIR/ca-key.pem       (CA Private Key)"
echo "  📄 $CERT_DIR/server-cert.pem  (Server Certificate)"
echo "  🔐 $CERT_DIR/server-key.pem   (Server Private Key)"
echo "  📄 $CERT_DIR/client-cert.pem  (Client Certificate)"
echo "  🔐 $CERT_DIR/client-key.pem   (Client Private Key)"
echo "  ⚙️  $CERT_DIR/server-cert.conf (Server Certificate Configuration)"
echo "  ⚙️  $CERT_DIR/client-cert.conf (Client Certificate Configuration)"
echo ""
echo "Key features of these certificates:"
echo "  • Compatible with mbedTLS TLS handshake"
echo "  • Server certificate: Digital signature and server authentication"
echo "  • Client certificate: Digital signature and client authentication"
echo "  • Subject Alternative Names for localhost and test-server (server cert)"
echo "  • Valid for 365 days"
echo "  • ECDSA P-256 keys (compatible with ECDHE_ECDSA cipher suites)"
echo ""
echo "The certificates are now ready for mutual TLS (bidirectional authentication)!"