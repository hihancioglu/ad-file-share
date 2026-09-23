# AD File Share

AD File Share is a lightweight file sharing application built around a Flask backend and simple HTML front‑end.  
It targets environments that rely on Active Directory for authentication and aims to provide a no‑JavaScript, form‑based experience for uploading and sharing files inside an organisation.

## Features

- Authenticate users against Active Directory.
- Upload, download and share files using plain HTML forms.
- Optional public shares that notify a user's manager via Microsoft Graph.
- Packaged with Docker and Nginx for easy deployment.

## Project layout

```
.
├── backend/             # Flask application
├── nginx/               # Reverse proxy configuration
└── docker-compose.yml   # Orchestration for local use
```

## Getting started

Use Docker Compose to start the service:

```bash
docker-compose up --build
```

The application will be available at `http://localhost:8080/`.

## Configuration

The backend reads LDAP settings from environment variables. To customize how usernames are searched, set `LDAP_SEARCH_FILTER` in the environment. The string should contain a `{query}` placeholder that will be replaced with the incoming search text. By default the application uses `(&(objectClass=user)(sAMAccountName=*{query}*))`.

Set `RELEASE_UPLOADER_GROUP` to the Active Directory group whose direct or nested members may publish releases. It defaults to `release-uploader`. Release access checks use the configured LDAP service account.

### Release publishing / Nexus

Release publishers upload setup files directly to Nexus raw hosted repositories using
their logged-in AD username and a Nexus password supplied with each request. Configure
the integration with these environment variables (shown with their defaults):

```env
NEXUS_UPLOAD_BASE_URL=
NEXUS_PUBLIC_BASE_URL=https://repo.baylan.info.tr
NEXUS_REPO_PUBLIC=apps-public
NEXUS_REPO_PUBLIC_LATEST=apps-public-latest
NEXUS_REPO_INTERNAL=apps-internal
NEXUS_REPO_INTERNAL_LATEST=apps-internal-latest
NEXUS_VERIFY_TLS=true
NEXUS_CA_CERT_FILE=
NEXUS_CONNECT_TIMEOUT=10
NEXUS_READ_TIMEOUT=3600
NEXUS_CATALOG_USERNAME=release_catalog_svc
NEXUS_CATALOG_PASSWORD=
NEXUS_CATALOG_CACHE_TTL=30
```

`NEXUS_UPLOAD_BASE_URL` is the server used for authenticated PUT requests, while
`NEXUS_PUBLIC_BASE_URL` is used to construct URLs returned to clients. Set
`NEXUS_VERIFY_TLS=false` only for a trusted development environment. When TLS
verification is enabled and `NEXUS_CA_CERT_FILE` is set, that CA bundle is used.
Timeout values are in seconds.

The release catalog uses the separate Nexus service account above; user passwords
are never required for catalog reads. This account must be read-only. Grant
`nx-search-read` plus `browse` and `read` for the configured raw repositories.
Do not grant Add, Edit, or Delete privileges.

Set `MAX_UPLOAD_SIZE` to override the default 2 GB upload limit. The value can be specified in raw bytes (e.g. `2147483648`) or using `KB`, `MB`, `GB`, or `TB` suffixes (e.g. `2GB`).

For public shares requiring manager approval, the backend sends an e-mail to the user's manager through the Microsoft Graph API. Configure the following variables:

- `GRAPH_TENANT_ID`
- `GRAPH_CLIENT_ID`
- `GRAPH_CLIENT_SECRET`
- `GRAPH_SENDER` for the account used to send mail
- `WHITE_LIST` comma-separated usernames allowed to log in even if the Manager field is empty

Additional configuration options and dependencies can be found in `backend/requirements.txt`.

## Development

Install dependencies for local development:

```bash
pip install -r backend/requirements.txt
```

Run the app directly with:

```bash
python backend/main.py
```

## Desktop file box client

A simple desktop client is provided in `desktop/file_box.py`. The program
creates a personal "box" directory for each user and allows drag‑and‑drop
sharing between them.

Run it with:

```bash
python desktop/file_box.py --user alice
```

Dropping a file onto the window prompts for the recipient's username. The
file is then copied into the recipient's box where it will appear in their
own application window.

## Kullanıcı dökümantasyonu

Türkçe kullanıcı rehberi için `docs/BaylanSend_Kullanici_Talimatlari_Kullanim_Rehberi.md` dosyasına bakabilirsiniz.
