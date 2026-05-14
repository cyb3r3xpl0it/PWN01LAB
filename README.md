# WebVulnLab 🔐

Entorno de pentesting web deliberadamente vulnerable con backend Node.js y base de datos MySQL real.

## ⚠️ Advertencia

Este entorno es **intencionalmente inseguro**. Úsalo solo en tu máquina local o red privada controlada. **Nunca lo expongas a internet.**

## Requisitos

- Docker
- Docker Compose

## Iniciar el lab

```bash
docker compose up --build
```

Abre: http://localhost:8080

## Estructura

```
vulnlab/
├── docker-compose.yml
├── db/
│   └── init.sql          # Schema + datos iniciales MySQL
├── backend/
│   ├── Dockerfile
│   ├── package.json
│   └── server.js         # API Node.js con endpoints vulnerables
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    └── index.html        # UI del lab
```

## Servicios

| Servicio  | Puerto interno | Descripción                |
|-----------|---------------|----------------------------|
| frontend  | 8080 → 80     | Nginx sirviendo el lab     |
| backend   | 3000          | API Express.js             |
| db        | 3306          | MySQL 8.0                  |

## Retos incluidos (48 total)

| #  | Vulnerabilidad            | Severidad | Endpoint                          |
|----|---------------------------|-----------|-----------------------------------|
|  1 | SQL Injection             | HIGH      | POST /api/login                   |
|  2 | XSS Reflejado             | CRIT      | GET  /api/search                  |
|  3 | IDOR                      | MED       | GET  /api/user                    |
|  4 | XSS Almacenado            | CRIT      | POST /api/messages                |
|  5 | Command Injection         | HIGH      | POST /api/ping                    |
|  6 | CSRF                      | MED       | POST /api/change-email            |
|  7 | Path Traversal (LFI)      | HIGH      | GET  /api/file                    |
|  8 | SSRF                      | HIGH      | POST /api/fetch                   |
|  9 | JWT débil / alg:none      | HIGH      | POST /api/token · GET /api/admin/flag |
| 10 | Broken Access Control     | HIGH      | GET  /api/admin/users             |
| 11 | Mass Assignment           | HIGH      | PUT  /api/profile                 |
| 12 | Open Redirect             | MED       | GET  /api/redirect                |
| 13 | Prototype Pollution       | MED       | POST /api/merge                   |
| 14 | XXE                       | MED       | POST /api/xml                     |
| 15 | SSTI (EJS)                | CRIT      | POST /api/render                  |
| 16 | Insecure Deserialization  | CRIT      | POST /api/decode                  |
| 17 | File Upload RCE           | CRIT      | POST /api/upload · GET /api/exec  |
| 18 | Race Condition            | HIGH      | POST /api/coupon/redeem           |
| 19 | CORS Misconfiguration     | HIGH      | GET  /api/cors/secret             |
| 20 | Password Reset inseguro   | HIGH      | POST /api/reset-request · POST /api/reset-confirm |
| 21 | ReDoS                     | MED       | POST /api/validate-email          |
| 22 | Business Logic            | MED       | POST /api/order                   |
| 23 | CRLF Injection            | MED       | GET  /api/set-lang                |
| 24 | Clickjacking              | MED       | GET  /api/headers-check           |
| 25 | Account Enumeration       | MED       | POST /api/check-login             |
| 26 | Verb Tampering            | MED       | GET|POST /api/admin/secret-action |
| 27 | Log Injection             | MED       | POST /api/log                     |
| 28 | Host Header Injection     | HIGH      | POST /api/reset-poison            |
| 29 | Second-order SQLi         | CRIT      | POST /api/update-username · GET /api/greet |
| 30 | Blind SQLi                | HIGH      | GET  /api/user-exists             |
| 31 | Session Fixation          | HIGH      | POST /api/session/login · GET /api/session/profile |
| 32 | JWT Algorithm Confusion   | HIGH      | POST /api/rs256/token · POST /api/rs256/forge · GET /api/rs256/flag |
| 33 | 2FA Brute Force           | HIGH      | POST /api/2fa/setup · POST /api/2fa/verify |
| 34 | OAuth State Bypass        | MED       | GET  /api/oauth/authorize · GET /api/oauth/callback |
| 35 | Weak PRNG                 | HIGH      | POST /api/prng/token · GET /api/prng/samples |
| 36 | Timing Attack             | MED       | POST /api/timing/check            |
| 37 | Email Header Injection    | MED       | POST /api/contact                 |
| 38 | HTTP Parameter Pollution  | MED       | GET  /api/items                   |
| 39 | Excessive Data Exposure   | MED       | GET  /api/users/all               |
| 40 | Debug Endpoint Expuesto   | MED       | GET  /api/debug                   |
| 41 | Stack Trace Disclosure    | MED       | GET  /api/crash                   |
| 42 | Hash sin sal (MD5)        | HIGH      | GET  /api/hashes                  |
| 43 | Cookie Flags Ausentes     | MED       | POST /api/cookie-login            |
| 44 | DOM-based XSS             | CRIT      | (frontend only — innerHTML + location.hash) |
| 45 | DOM Clobbering            | MED       | (frontend only — window.config override) |
| 46 | Stored SSRF               | HIGH      | POST /api/webhook/save · POST /api/webhook/trigger |
| 47 | Zip Slip                  | HIGH      | GET  /api/zipslip/malicious · POST /api/unzip |
| 48 | SRI Ausente               | MED       | (concepto frontend — scripts CDN sin integrity) |

## Apagar

```bash
docker compose down          # conserva la BD
docker compose down -v       # borra también el volumen de MySQL
```
