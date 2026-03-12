# MicroPKI

Minimal educational Public Key Infrastructure (Python).

## Status

- Sprint 1 — Root CA (self-signed)
- **Sprint 2** — Intermediate CA + выдача конечных сертификатов по шаблонам

## Build & Install
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```
## Usage (Sprint 1)

```PowerShell
# RSA
micropki ca init `
  --subject "/CN=My Root CA" `
  --key-type rsa `
  --key-size 4096 `
  --passphrase-file ./secrets/ca.pass `
  --out-dir ./pki `
  --validity-days 3650

# ECC
micropki ca init `
  --subject "CN=ECC Root CA,O=MicroPKI" `
  --key-type ecc `
  --key-size 384 `
  --passphrase-file ./secrets/ca.pass
```
## Usage (Sprint 2)
```PowerShell
"myIntermediatePass123" | Out-File -FilePath ./secrets/inter.pass -Encoding utf8

micropki ca issue-intermediate `
  --subject "/CN=My Intermediate CA/O=Test Org" `
  --key-type rsa `
  --key-size 3072 `
  --validity-days 1095 `
  --pathlen 0 `
  --root-passphrase-file ./secrets/ca.pass `
  --inter-passphrase-file ./secrets/inter.pass `
  --out-dir ./pki `
  --force

# Шаблон server (TLS-сервер)
micropki ca issue-cert `
  --template server `
  --subject "CN=web.example.com" `
  --san "dns:web.example.com" `
  --san "dns:www.web.example.com" `
  --san "ip:192.168.1.100" `
  --key-type rsa `
  --key-size 2048 `
  --validity-days 365 `
  --ca-passphrase-file ./secrets/ca.pass `
  --out-dir ./issued `
  --force

# Шаблон client (аутентификация клиента)
micropki ca issue-cert `
  --template client `
  --subject "CN=Jane Doe/emailAddress=jane@example.com" `
  --san "email:jane@example.com" `
  --key-type ecc `
  --out-dir ./issued `
  --ca-passphrase-file ./secrets/ca.pass `
  --force

# Шаблон code_signing (подпись кода)
micropki ca issue-cert `
  --template code_signing `
  --subject "CN=Code Signing Cert/O=Dev Team" `
  --key-type rsa `
  --key-size 3072 `
  --validity-days 730 `
  --ca-passphrase-file ./secrets/ca.pass `
  --out-dir ./issued `
  --force
```
## Intermediate CA
```PowerShell
micropki ca issue-cert `
  --template server `
  --subject "CN=api.internal.company" `
  --san "dns:api.internal.company" `
  --key-type rsa `
  --ca-key ./pki/private/intermediate.key.pem `
  --ca-cert ./pki/certs/intermediate.cert.pem `
  --ca-passphrase-file ./secrets/inter.pass `
  --out-dir ./issued `
  --force
```
## Tests
```PowerShell
# Посмотреть сертификат
openssl x509 -in ./pki/certs/ca.cert.pem -text -noout | Select-Object -First 30

# Проверить цепочку (после Sprint 3)
openssl verify -CAfile ./pki/certs/ca.cert.pem ./issued/certs/web_example_com.cert.pem
```

## Dependencies

Python 3.9+
cryptography (PKCS#8, X.509, RSA/ECC)
