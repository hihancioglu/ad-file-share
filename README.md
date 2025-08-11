# AD File Share

This project provides a simple file sharing service with a Flask backend and a static HTML interface. All interactions such as login, file upload, download, and sharing are handled through standard HTML forms without any JavaScript dependencies.

## Running

Use Docker Compose to start the service:

```bash
docker-compose up --build
```

The application will be available at `http://localhost:8080/`.
An OnlyOffice Document Server is also started for collaborative editing at
`http://localhost:8081/`.

## Configuration

The backend reads LDAP settings from environment variables. To customize how user
names are searched, set `LDAP_SEARCH_FILTER` in the environment. The string
should contain a `{query}` placeholder that will be replaced with the incoming
search text. By default the application uses
`(&(objectClass=user)(sAMAccountName=*{query}*))`.

For public shares requiring manager approval, the backend sends an e-mail to the
user's manager through the Microsoft Graph API. Configure the following variables:

- `GRAPH_TENANT_ID`
- `GRAPH_CLIENT_ID`
- `GRAPH_CLIENT_SECRET`
- `GRAPH_SENDER` for the account used to send mail

### OnlyOffice

The backend integrates with an OnlyOffice Document Server. To change the URLs
used for the editor or internal callbacks, set:

- `ONLYOFFICE_URL` – external URL of the Document Server (default:
  `http://localhost:8081`)
- `ONLYOFFICE_INTERNAL_URL` – URL used by the Document Server to reach the
  backend (default: `http://backend:8000`)
- `ONLYOFFICE_JWT_SECRET` – shared secret for signing OnlyOffice requests. The
  same value must be provided to the Document Server via `JWT_SECRET`.
