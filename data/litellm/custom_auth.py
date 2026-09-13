"""Hardcoded client keys, defined in config.yaml.

LiteLLM has no built-in config option for a list of client keys -- out of the
box there is exactly one key in config (general_settings.master_key, which is
an unrestricted admin key) and everything else must be minted into Postgres via
/key/generate. This hook is the supported way to close that gap: the proxy
calls it for every request and whatever it returns IS the caller's identity.

Keys live under a `client_keys:` block in config.yaml next to this file, so
adding a client is a config edit plus a restart.

CAUTION: this hook runs BEFORE the master-key check in LiteLLM's auth chain and
short-circuits it, so it must recognise the master key itself (it does, below)
or the admin UI locks you out. It also bypasses the Postgres key table, so any
key previously created via /key/generate stops working while this is enabled.
"""

import os
import secrets

import yaml
from fastapi import HTTPException, Request

from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")


def _load_client_keys() -> dict:
    """Read the client_keys block, keyed by the secret. Re-read per request so
    a key can be revoked by editing the config without a restart."""
    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f) or {}
    entries = {}
    for entry in config.get("client_keys") or []:
        secret = entry.get("key")
        if not secret:
            continue
        # Allow the secret itself to come from the environment, so the config
        # can be committed while the value stays in .env-private.
        if secret.startswith("os.environ/"):
            secret = os.environ.get(secret.removeprefix("os.environ/"), "")
            if not secret:
                continue
        entries[secret] = entry
    return entries


def _matches(candidate: str, known: str) -> bool:
    """Constant-time compare, so a wrong key cannot be recovered by timing."""
    return secrets.compare_digest(candidate.encode(), known.encode())


async def user_api_key_auth(request: Request, api_key: str) -> UserAPIKeyAuth:
    api_key = (api_key or "").removeprefix("Bearer ").strip()

    # The master key must keep working: this hook replaces the check for it.
    master_key = os.environ.get("LITELLM_MASTER_KEY", "")
    if master_key and _matches(api_key, master_key):
        return UserAPIKeyAuth(
            api_key=api_key,
            user_role=LitellmUserRoles.PROXY_ADMIN,
            key_alias="master",
        )

    for known, entry in _load_client_keys().items():
        if _matches(api_key, known):
            return UserAPIKeyAuth(
                api_key=api_key,
                key_alias=entry.get("alias"),
                user_id=entry.get("alias"),
                models=entry.get("models") or [],
                max_budget=entry.get("max_budget"),
                rpm_limit=entry.get("rpm_limit"),
                tpm_limit=entry.get("tpm_limit"),
            )

    raise HTTPException(status_code=401, detail={"error": "Invalid API key"})
