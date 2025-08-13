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

For public shares requiring manager approval, the backend sends an e-mail to the user's manager through the Microsoft Graph API. Configure the following variables:

- `GRAPH_TENANT_ID`
- `GRAPH_CLIENT_ID`
- `GRAPH_CLIENT_SECRET`
- `GRAPH_SENDER` for the account used to send mail

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
