password-self-service
=====================

These scripts are designed to let internal and external users change their Active Directory passwords. The Docker image ships with Python 3.12 and `python-ldap`.

For it to work securely _you must use SSL on the webserver and for the LDAP connection_.

It looks like this:

![password-self-service](http://i.imgur.com/H6If1.png)

Docker
------

To build and run the application inside a container for local testing:

1. Build the image:
   ```
   docker build -t ad-password-self-service .
   ```
2. Run the container, mounting any certificate files the script expects:
   ```
   docker run --rm -p 8000:8000 \
     -v /path/to/root-ca.crt:/etc/ssl/certs/root-ca.crt:ro \
     ad-password-self-service
   ```
3. Open `http://localhost:8000` in a browser.

You can override the bind address or port with the `BIND` and `PORT` environment variables:
```
docker run --rm -e PORT=8080 -p 8080:8080 ad-password-self-service
```

The LDAP-related settings in `password.py` can also be overridden at runtime using environment variables (for example `LDAP_SERVER`, `LDAP_DOMAIN`, `LDAP_SEARCH_ROOT`, `LDAP_GROUP_TO_REMOVE`, `LDAP_CERT_FILE`, `LOG_OLD_PASSWORDS`, and `REMOVE_FROM_GROUP`).

To relax certificate checks (not recommended), set `LDAP_TLS_REQUIRE_CERT` to one of `demand` (default), `allow`, `try`, or `never`. Example:
```
docker run --rm -e LDAP_TLS_REQUIRE_CERT=never ...
```

Docker Compose
--------------

This repository also includes a `compose.yaml` for repeatable local runs:

1. Replace `certs/root-ca.crt` with the public certificate that signs your domain controller’s LDAPS endpoint.
2. Update the environment values in `compose.yaml` if your directory settings differ.
3. Start the stack:
   ```
   docker compose up --build
   ```
4. Visit `http://localhost:8000`.

Configuration
-------------

Modify the configuration variables in `password.py` and provide some explanatory text in `index.html`.

You may also wish to change the password complexity requirements in `passwords.js`.
