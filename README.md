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

## Retos incluidos

| # | Vulnerabilidad          | Severidad | Endpoint                    |
|---|-------------------------|-----------|-----------------------------|
| 1 | SQL Injection           | HIGH      | POST /api/login             |
| 2 | XSS Reflejado           | CRIT      | GET  /api/search            |
| 3 | IDOR                    | MED       | GET  /api/user              |
| 4 | XSS Almacenado          | CRIT      | POST /api/messages          |
| 5 | Command Injection       | HIGH      | POST /api/ping              |
| 6 | CSRF                    | MED       | POST /api/change-email      |
| 7 | Path Traversal (LFI)    | HIGH      | GET  /api/file              |
| 8 | SSRF                    | HIGH      | POST /api/fetch             |
| 9 | JWT débil / alg:none    | HIGH      | POST /api/token · GET /api/admin/flag |
|10 | Broken Access Control   | HIGH      | GET  /api/admin/users       |
|11 | Mass Assignment         | HIGH      | PUT  /api/profile           |
|12 | Open Redirect           | MED       | GET  /api/redirect          |
|13 | Prototype Pollution     | MED       | POST /api/merge             |
|14 | XXE                     | MED       | POST /api/xml               |
|15 | SSTI (EJS)              | CRIT      | POST /api/render            |
|16 | Insecure Deserialization| CRIT      | POST /api/decode            |

## Apagar

```bash
docker compose down          # conserva la BD
docker compose down -v       # borra también el volumen de MySQL
```
