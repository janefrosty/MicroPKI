# MicroPKI

Minimal educational Public Key Infrastructure (Python).

## Status

- **Sprint 1** — Root CA (self-signed)
- **Sprint 2** — Intermediate CA + выдача сертификатов по шаблонам (`server`, `client`, `code_signing`)
- **Sprint 3** — SQLite база данных, уникальные serial numbers, `list-certs`, `show-cert`
- **Sprint 4** — Отзыв сертификатов (`revoke`) + генерация CRL
- **Sprint 5** — OCSP Responder
- **Sprint 6** — Работа с CSR (client gen-csr + issue-cert-from-csr)
- **Sprint 7** — Security Hardening: Audit, Policies, CT Log, Rate Limiting & Key Compromise

## Build & Install
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```
## Usage Sprint 1

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
## Usage Sprint 2
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

## Выпуск конечного сертификата Sprint 2 + 3
```PowerShell
# Серверный сертификат
micropki ca issue-cert `
  --template server `
  --subject "CN=web.example.com" `
  --san "dns:web.example.com" `
  --san "dns:www.web.example.com" `
  --san "ip:192.168.1.100" `
  --key-type rsa `
  --ca-passphrase-file ./secrets/ca.pass `
  --out-dir ./issued `
  --force

# Клиентский сертификат
micropki ca issue-cert `
  --template client `
  --subject "CN=User Jane Doe" `
  --san "email:jane@example.com" `
  --key-type ecc `
  --ca-passphrase-file ./secrets/ca.pass `
  --out-dir ./issued `
  --force
```

## Usage Sprint 3
```PowerShell
# Инициализация БД
micropki db init --out-dir ./pki

# Просмотр всех действующих сертификатов
micropki ca list-certs --out-dir ./pki

# Просмотр сертификатов из папки issued
micropki ca list-certs --out-dir ./issued

# Просмотр конкретного сертификата по serial
micropki ca show-cert 99D2E6457A4B8C5219570FB14AB291AF --out-dir ./issued
```

## Проверка
```PowerShell
# Посмотреть все сертификаты (включая отозванные и просроченные)
micropki ca list-certs --status valid --out-dir ./pki
micropki ca list-certs --status revoked --out-dir ./pki

# Красивый вывод в JSON
micropki ca list-certs --format json --out-dir ./pki
```


## Usage Sprint 4
```PowerShell
# Отозвать сертификат
micropki ca revoke `
  --serial 99D2E6457A4B8C5219570FB14AB291AF `
  --reason 1 `
  --out-dir .\issued

# Сгенерировать CRL
micropki ca generate-crl `
  --ca-passphrase-file ./secrets/ca.pass `
  --out-dir ./issued

# Посмотреть отозванные сертификаты
micropki ca list-certs --status revoked --out-dir ./issued


# Все действующие сертификаты
micropki ca list-certs --status valid --out-dir ./pki

# Все отозванные
micropki ca list-certs --status revoked --out-dir ./issued
```

## Usage Sprint 5
```PowerShell
# Выпуск OCSP Responder сертификата
PowerShellmicropki ca issue-ocsp-cert `
  --subject "/CN=OCSP Responder/O=MicroPKI" `
  --ca-passphrase-file ./secrets/ca.pass `
  --out-dir ./pki `
  --force

# Запуск OCSP Responder
PowerShellmicropki ca serve-ocsp --port 8080
```

## Usage Sprint 6
```PowerShell
#Генерация CSR
micropki client gen-csr `
  --subject "CN=myclient.example.com" `
  --san "dns:myclient.example.com" `
  --key-type rsa

#Выдача сертификата по CSR
micropki ca issue-cert-from-csr `
  --csr ./pki/certs/client.csr.pem `
  --ca-passphrase-file ./secrets/ca.pass `
  --out-cert ./pki/certs/myclient.cert.pem
```

## Пример

```PowerShell
# 1. Root CA
micropki ca init --subject "/CN=My Root CA" --key-type rsa --passphrase-file ./secrets/ca.pass --force

# 2. Генерация CSR
micropki client gen-csr --subject "CN=test.example.com" --san "dns:test.example.com"

# 3. Выдача сертификата по CSR
micropki ca issue-cert-from-csr --csr ./pki/certs/client.csr.pem --ca-passphrase-file .\secrets\ca.pass
```

## Usage Sprint 7

```Powershell
# 1. Инициализация базы данных
micropki db init --out-dir ./pki

# 2. Выпуск сертификата с проверкой политик и записью в аудит/CT‑лог
micropki ca issue-cert --template server --subject "/CN=test.example.com" --san "dns:test.example.com" --ca-passphrase-file secrets\ca.pass --out-dir ./pki --validity-days 365 --force

#3. Просмотр аудит-лога (фильтрация по операции)
micropki audit query --operation issue_cert --format table

#4. Просмотр CT-лога (симуляция Certificate Transparency)
Get-Content .\pki\audit\ct.log

#5. Отзыв сертификата с фиксацией в аудите
micropki ca revoke --serial AF58C5EBCA40DBD3066D62A73272616F --reason 1 --out-dir ./pki

#6. Генерация CRL (Certificate Revocation List)
micropki ca generate-crl --ca-passphrase-file secrets\ca.pass --out-dir ./pki

#7. Проверка целостности аудит-лога (хеш-цепочка)
micropki audit verify

#8. Компрометация ключа (отзыв + занесение в чёрный список)
# Предварительно узнаем точное имя файла сертификата
dir .\pki\certs\
# Затем выполняем компрометацию (пример)
micropki ca compromise --cert .\pki\certs\test.example.com.cert.pem --ca-passphrase-file secrets\ca.pass --out-dir ./pki --force

#9. Выпуск OCSP responder сертификата (необходим для OCSP-сервера)
micropki ca issue-ocsp-cert --subject "/CN=OCSP Responder" --ca-passphrase-file secrets\ca.pass --out-dir ./pki --force

#10. Запуск OCSP responder с ограничением частоты запросов
micropki ca serve-ocsp --port 8080 --rate-limit 2 --rate-burst 3
```


## Tests
```PowerShell
pip install pytest
python -m pytest tests/ -v
```

## Dependencies

Python 3.9+
cryptography (PKCS#8, X.509, RSA/ECC)
tabulate
