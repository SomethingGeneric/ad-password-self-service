#!/usr/bin/env python3

import cgi
import cgitb
import logging
import os
import sys

import ldap

cgitb.enable()  # Comment out to disable web tracebacks

# Log the user's old password (useful for determining if the user is mistyping
# a randomly generated password, for example)
LOG_OLD_PASSWORDS = os.environ.get("LOG_OLD_PASSWORDS", "true").lower() in ("true", "1", "yes")

# Remove a user from a group once they've set their password
REMOVE_FROM_GROUP = os.environ.get("REMOVE_FROM_GROUP", "true").lower() in ("true", "1", "yes")

LDAP_SERVER = os.environ.get("LDAP_SERVER", "ldaps://contoso.com:636")
LDAP_DOMAIN = os.environ.get("LDAP_DOMAIN", "CONTOSO")

# Your domain's root certificate (because we're using SSL to connect to LDAP)
LDAP_CERT_FILE = os.environ.get("LDAP_CERT_FILE", "/etc/ssl/certs/root-ca.crt")

# Where to search for users in Active Directory
LDAP_SEARCH_ROOT = os.environ.get("LDAP_SEARCH_ROOT", "DC=contoso,DC=com")

# The group to remove the user from (this is a great way to enforce security
# constraints for external users who haven't changed their generated password)
LDAP_GROUP_TO_REMOVE = os.environ.get(
    "LDAP_GROUP_TO_REMOVE",
    "CN=Default Password Holder,OU=Security Groups,DC=contoso,DC=com",
)

LDAP_TLS_REQUIRE_CERT = os.environ.get("LDAP_TLS_REQUIRE_CERT", "demand").lower()


def _map_tls_requirement(value):
    mapping = {
        "never": ldap.OPT_X_TLS_NEVER,
        "allow": ldap.OPT_X_TLS_ALLOW,
        "try": ldap.OPT_X_TLS_TRY,
        "demand": ldap.OPT_X_TLS_DEMAND,
    }

    return mapping.get(value, ldap.OPT_X_TLS_DEMAND)


logging.basicConfig(
    filename="password.log",
    level=logging.INFO,
    format="%(asctime)-15s %(levelname)-5s %(ip)-15s %(apache_user)s/%(script_user)s %(message)s",
)

print("Content-Type: text/html\n")

form = cgi.FieldStorage()

if (
    "username" not in form
    or "old_password" not in form
    or "new_password" not in form
    or "new_password_verify" not in form
):
    print("Please enter all form fields.")
    sys.exit(1)

username = form.getvalue("username")
old_password = form.getvalue("old_password")
new_password = form.getvalue("new_password")
new_password_verify = form.getvalue("new_password_verify")

log_info = {
    "script_user": username,
    "apache_user": os.environ.get("REMOTE_USER", "Unknown"),
    "ip": os.environ.get("REMOTE_ADDR", "Unknown"),
}

log = logging.LoggerAdapter(logging.getLogger("password.py"), log_info)

if LOG_OLD_PASSWORDS:
    log.info("Old password: %s", old_password)

if new_password != new_password_verify:
    print("Your new passwords do not match.")
    sys.exit(1)

try:
    ldap.set_option(ldap.OPT_REFERRALS, 0)

    if LDAP_CERT_FILE:
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_CERT_FILE)

    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, _map_tls_requirement(LDAP_TLS_REQUIRE_CERT))

    conn = ldap.initialize(LDAP_SERVER)
    conn.protocol_version = ldap.VERSION3
    conn.simple_bind_s(f"{LDAP_DOMAIN}\\{username}", old_password)

    result = conn.search_s(
        LDAP_SEARCH_ROOT,
        ldap.SCOPE_SUBTREE,
        f"(sAMAccountName={username})",
        ["distinguishedName"],
    )

    if len(result) != 1:
        raise Exception("Unable to resolve user")

    dn = result[0][0]

    old_password_bytes = f'"{old_password}"'.encode("utf-16-le")
    new_password_bytes = f'"{new_password}"'.encode("utf-16-le")

    attributes = [
        (ldap.MOD_DELETE, "unicodePwd", old_password_bytes),
        (ldap.MOD_ADD, "unicodePwd", new_password_bytes),
    ]

    conn.modify_s(dn, attributes)

    log.info("Changed password successfully.")
    print("Your password was changed successfully.<br />")
except ldap.LDAPError as e:
    log.error("LDAP exception encountered.", exc_info=True)
    print(f'<abbr title="{e}">Sorry, your password was unable to be changed.</abbr><br />')
    sys.exit(1)

if REMOVE_FROM_GROUP:
    exists_in_group = 0

    try:
        exists_in_group = conn.compare_s(LDAP_GROUP_TO_REMOVE, "member", dn)
    except Exception:
        pass

    if exists_in_group:
        try:
            group_attributes = [(ldap.MOD_DELETE, "member", dn)]
            conn.modify_s(LDAP_GROUP_TO_REMOVE, group_attributes)

            log.info("Removed from '%s' group successfully.", LDAP_GROUP_TO_REMOVE)
            print("Your account permissions have been enabled.")
            conn.unbind()
        except ldap.LDAPError as e:
            log.error("LDAP exception encountered.", exc_info=True)
            print(
                f'<abbr title="{e}"><em>However, we were unable to enable your account permissions.</em></abbr>'
            )
