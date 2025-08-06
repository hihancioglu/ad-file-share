# AD File Share

This project provides a simple file sharing service with a Flask backend and a static HTML interface. All interactions such as login, file upload, download, and sharing are handled through standard HTML forms without any JavaScript dependencies.

## Running

Use Docker Compose to start the service:

```bash
docker-compose up --build
```

The application will be available at `http://localhost:8080/`.

## Configuration

The backend reads LDAP settings from environment variables. To customize how user
names are searched, set `LDAP_SEARCH_FILTER` in the environment. The string
should contain a `{query}` placeholder that will be replaced with the incoming
search text. By default the application uses
`(&(objectClass=user)(sAMAccountName=*{query}*))`.

For public shares requiring manager approval, the backend sends an e-mail to the
user's manager. Configure SMTP settings with the following variables:

- `SMTP_SERVER` and `SMTP_PORT`
- `SMTP_USER` and `SMTP_PASSWORD` if authentication is needed
- `SMTP_FROM` for the sender address (defaults to `no-reply@example.com`)
