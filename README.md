# MicroPKI

Minimal educational Public Key Infrastructure (Python).

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

## Dependencies

Python 3.9+
cryptography (PKCS#8, X.509, RSA/ECC)
