#!/usr/bin/env python3

import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional

import ldap

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


def _map_tls_requirement(value: str) -> int:
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


@dataclass
class PasswordChangeResult:
    """Outcome of a password change attempt."""

    success: bool
    message: str
    group_removed: bool = False


class PasswordChangeError(Exception):
    """Raised when a request is invalid before reaching LDAP."""


def change_password(
    *,
    username: str,
    old_password: str,
    new_password: str,
    new_password_verify: str,
    log_metadata: Optional[Dict[str, str]] = None,
) -> PasswordChangeResult:
    """Change a user's password in Active Directory."""

    if not all([username, old_password, new_password, new_password_verify]):
        raise PasswordChangeError("Please enter all form fields.")

    log_info = {
        "script_user": username,
        "apache_user": (log_metadata or {}).get("apache_user", "Unknown"),
        "ip": (log_metadata or {}).get("ip", "Unknown"),
    }
    log = logging.LoggerAdapter(logging.getLogger("password.py"), log_info)

    if new_password != new_password_verify:
        raise PasswordChangeError("Your new passwords do not match.")

    if LOG_OLD_PASSWORDS:
        log.info("Old password: %s", old_password)

    connection = None
    distinguished_name = None

    try:
        ldap.set_option(ldap.OPT_REFERRALS, 0)

        if LDAP_CERT_FILE:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_CERT_FILE)

        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, _map_tls_requirement(LDAP_TLS_REQUIRE_CERT))

        connection = ldap.initialize(LDAP_SERVER)
        connection.protocol_version = ldap.VERSION3
        connection.simple_bind_s(f"{LDAP_DOMAIN}\\{username}", old_password)

        result = connection.search_s(
            LDAP_SEARCH_ROOT,
            ldap.SCOPE_SUBTREE,
            f"(sAMAccountName={username})",
            ["distinguishedName"],
        )

        if len(result) != 1:
            raise ldap.LDAPError("Unable to resolve user")

        distinguished_name = result[0][0]

        old_password_bytes = f'"{old_password}"'.encode("utf-16-le")
        new_password_bytes = f'"{new_password}"'.encode("utf-16-le")

        attributes = [
            (ldap.MOD_DELETE, "unicodePwd", old_password_bytes),
            (ldap.MOD_ADD, "unicodePwd", new_password_bytes),
        ]

        connection.modify_s(distinguished_name, attributes)

        log.info("Changed password successfully.")
        message = "Your password was changed successfully.<br />"
    except ldap.LDAPError as exc:
        log.error("LDAP exception encountered.", exc_info=True)
        return PasswordChangeResult(
            success=False,
            message=f'<abbr title="{exc}">Sorry, your password was unable to be changed.</abbr><br />',
        )
    finally:
        # Keep connections tidy if we error before simple bind succeeds
        if connection is not None and distinguished_name is None:
            try:
                connection.unbind_s()
            except Exception:
                pass

    group_removed = False

    if REMOVE_FROM_GROUP and connection and distinguished_name:
        try:
            exists_in_group = connection.compare_s(LDAP_GROUP_TO_REMOVE, "member", distinguished_name)
        except Exception:
            exists_in_group = 0

        if exists_in_group:
            try:
                group_attributes = [(ldap.MOD_DELETE, "member", distinguished_name)]
                connection.modify_s(LDAP_GROUP_TO_REMOVE, group_attributes)

                log.info("Removed from '%s' group successfully.", LDAP_GROUP_TO_REMOVE)
                group_removed = True
            except ldap.LDAPError as exc:
                log.error("LDAP exception encountered.", exc_info=True)
                message += (
                    f'<abbr title="{exc}"><em>However, we were unable to enable your account permissions.</em></abbr>'
                )

    if connection is not None:
        try:
            connection.unbind_s()
        except Exception:
            pass

    if group_removed:
        message += "Your account permissions have been enabled."

    return PasswordChangeResult(success=True, message=message, group_removed=group_removed)
