# MicroPKI

A minimal Public Key Infrastructure (PKI) tool for creating and managing Certificate Authorities, issuing certificates, and serving them via an HTTP repository.

## Dependencies

- **Python** ≥ 3.9
- **cryptography** ≥ 3.0

## Installation

```bash
git clone <repository-url>
cd micropki
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

## Quick Start

### 1. Initialize Database & Root CA

```bash
mkdir secrets
echo my-root-passphrase > secrets/root.pass

python -m micropki db init --db-path ./pki/micropki.db

python -m micropki ca init \
    --subject "/CN=Demo Root CA/O=MyOrg/C=US" \
    --key-type rsa --key-size 4096 \
    --passphrase-file ./secrets/root.pass \
    --out-dir ./pki --validity-days 3650
```

### 2. Issue Intermediate CA

```bash
echo my-intermediate-pass > secrets/intermediate.pass

python -m micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./secrets/root.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MyOrg" \
    --key-type rsa --key-size 4096 \
    --passphrase-file ./secrets/intermediate.pass \
    --out-dir ./pki --validity-days 1825 --pathlen 0
```

### 3. Issue Certificates

```bash
# Server certificate (SAN required)
python -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com,O=MyOrg" \
    --san dns:example.com --san dns:www.example.com --san ip:192.168.1.10 \
    --out-dir ./pki/certs

# Client certificate
python -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --out-dir ./pki/certs

# Code signing certificate
python -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --out-dir ./pki/certs
```

### 4. Query Certificates

```bash
# List all certificates
python -m micropki ca list-certs --db-path ./pki/micropki.db

# Filter by status
python -m micropki ca list-certs --status valid --format table

# Export as JSON or CSV
python -m micropki ca list-certs --format json
python -m micropki ca list-certs --format csv

# Show a specific certificate by serial
python -m micropki ca show-cert 67BA... --db-path ./pki/micropki.db
```

### 5. Start Repository Server

```bash
python -m micropki repo serve --host 0.0.0.0 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs
```

API endpoints:
```bash
# Fetch certificate by serial
curl http://localhost:8080/certificate/67BA...

# Fetch Root CA
curl http://localhost:8080/ca/root

# Fetch Intermediate CA
curl http://localhost:8080/ca/intermediate

# CRL placeholder (returns 501)
curl http://localhost:8080/crl
```

### Output Structure

```
pki/
├── private/
│   ├── ca.key.pem               # Encrypted Root CA key
│   └── intermediate.key.pem     # Encrypted Intermediate CA key
├── certs/
│   ├── ca.cert.pem              # Root CA certificate
│   ├── intermediate.cert.pem    # Intermediate CA certificate
│   ├── example.com.cert.pem     # Server certificate
│   └── example.com.key.pem      # Server key (unencrypted)
├── csrs/
│   └── intermediate.csr.pem     # Intermediate CA CSR
├── micropki.db                  # Certificate database (SQLite)
└── policy.txt                   # Certificate policy document
```

## Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
micropki/
├── micropki/
│   ├── __init__.py        # Package marker
│   ├── __main__.py        # python -m micropki entry point
│   ├── cli.py             # CLI parser (all commands)
│   ├── ca.py              # CA operations orchestration
│   ├── certificates.py    # X.509 certificate builder
│   ├── crypto_utils.py    # Key generation, PEM, DN parsing
│   ├── csr.py             # CSR generation
│   ├── templates.py       # Certificate templates & SAN handling
│   ├── database.py        # SQLite certificate database
│   ├── serial.py          # Unique serial number generator
│   ├── repository.py      # HTTP certificate repository
│   └── logger.py          # Logging setup
├── tests/
│   ├── test_crypto_utils.py   # Unit tests: keys, DN, PEM
│   ├── test_ca.py             # Sprint 1 integration tests
│   ├── test_cli.py            # CLI validation tests
│   ├── test_templates.py      # Template & SAN tests
│   ├── test_sprint2.py        # Sprint 2 integration tests
│   └── test_sprint3.py        # Sprint 3: DB, serial, HTTP tests
├── requirements.txt
├── .gitignore
└── README.md
```
