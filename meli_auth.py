# -*- coding: utf-8 -*-
"""OAuth do Mercado Livre para uso local ou compartilhado no Render.

No Render, as credenciais ficam criptografadas no PostgreSQL e a renovação é
serializada com SELECT ... FOR UPDATE. No Windows local, o armazenamento antigo
com DPAPI continua disponível para não invalidar a autorização já existente.
"""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
ME_URL = "https://api.mercadolibre.com/users/me"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "EntrouEconomizou"
CRED_FILE = APP_DIR / "mercadolivre_credentials.dat"
PENDING_FILE = APP_DIR / "mercadolivre_pending.dat"
TOKEN_TABLE = "entrou_economizou_meli_tokens"
PENDING_TABLE = "entrou_economizou_oauth_pending"
SHARED_TOKEN_ID = "mercadolivre_shared"

_schema_lock = threading.Lock()
_schema_ready = False
_local_refresh_lock = threading.Lock()


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _database_url():
    return os.environ.get("DATABASE_URL", "").strip()


def using_database():
    return bool(_database_url())


def _blob(data):
    buf = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _protect(data, decrypt=False):
    if os.name != "nt":
        raise RuntimeError("Configure DATABASE_URL no servidor para armazenar a autorização.")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    in_blob, _buf = _blob(data)
    out_blob = DATA_BLOB()
    fn = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    if decrypt:
        ok = fn(ctypes.byref(in_blob), None, None, None, None, 1, ctypes.byref(out_blob))
    else:
        description = "EntrouEconomizou".encode("utf-16-le")
        ok = fn(ctypes.byref(in_blob), description, None, None, None, 1, ctypes.byref(out_blob))
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _save_local(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_protect(json.dumps(obj, ensure_ascii=False).encode("utf-8")))


def _load_local(path):
    if not path.exists():
        return None
    return json.loads(_protect(path.read_bytes(), decrypt=True).decode("utf-8"))


def _fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise RuntimeError("A dependência cryptography não está instalada.") from exc
    secret = os.environ.get("TOKEN_ENCRYPTION_KEY", "").strip()
    if not secret:
        raise RuntimeError("Configure TOKEN_ENCRYPTION_KEY no Render.")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def _encrypt(obj):
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _fernet().encrypt(raw).decode("ascii")


def _decrypt(value):
    try:
        return json.loads(_fernet().decrypt(value.encode("ascii")).decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("Não foi possível descriptografar o token salvo. Confira TOKEN_ENCRYPTION_KEY.") from exc


def _connect():
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("A dependência psycopg não está instalada.") from exc
    return psycopg.connect(_database_url(), connect_timeout=10)


def ensure_database_schema():
    global _schema_ready
    if not using_database() or _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        with _connect() as conn:
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {TOKEN_TABLE} (
                    token_id TEXT PRIMARY KEY,
                    encrypted_payload TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {PENDING_TABLE} (
                    state_hash TEXT PRIMARY KEY,
                    encrypted_payload TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            conn.execute(f"DELETE FROM {PENDING_TABLE} WHERE created_at < NOW() - INTERVAL '1 hour'")
        _schema_ready = True


def _state_hash(state):
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def _save_pending(state, pending):
    if not using_database():
        _save_local(PENDING_FILE, pending)
        return
    ensure_database_schema()
    with _connect() as conn:
        conn.execute(
            f"""INSERT INTO {PENDING_TABLE} (state_hash, encrypted_payload, created_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (state_hash) DO UPDATE SET
                    encrypted_payload = EXCLUDED.encrypted_payload, created_at = NOW()""",
            (_state_hash(state), _encrypt(pending)),
        )


def _load_pending(state):
    if not using_database():
        return _load_local(PENDING_FILE)
    ensure_database_schema()
    with _connect() as conn:
        row = conn.execute(
            f"SELECT encrypted_payload FROM {PENDING_TABLE} WHERE state_hash = %s",
            (_state_hash(state),),
        ).fetchone()
    return _decrypt(row[0]) if row else None


def _delete_pending(state=None):
    if not using_database():
        PENDING_FILE.unlink(missing_ok=True)
        return
    ensure_database_schema()
    with _connect() as conn:
        if state:
            conn.execute(f"DELETE FROM {PENDING_TABLE} WHERE state_hash = %s", (_state_hash(state),))
        else:
            conn.execute(f"DELETE FROM {PENDING_TABLE}")


def _save_credentials(record, conn=None):
    if not using_database():
        _save_local(CRED_FILE, record)
        return
    ensure_database_schema()
    owns_connection = conn is None
    if owns_connection:
        conn = _connect()
    try:
        conn.execute(
            f"""INSERT INTO {TOKEN_TABLE} (token_id, encrypted_payload, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (token_id) DO UPDATE SET
                    encrypted_payload = EXCLUDED.encrypted_payload, updated_at = NOW()""",
            (SHARED_TOKEN_ID, _encrypt(record)),
        )
        if owns_connection:
            conn.commit()
    finally:
        if owns_connection:
            conn.close()


def _load_credentials_db(conn=None, for_update=False):
    ensure_database_schema()
    owns_connection = conn is None
    if owns_connection:
        conn = _connect()
    try:
        suffix = " FOR UPDATE" if for_update else ""
        row = conn.execute(
            f"SELECT encrypted_payload FROM {TOKEN_TABLE} WHERE token_id = %s{suffix}",
            (SHARED_TOKEN_ID,),
        ).fetchone()
        return _decrypt(row[0]) if row else None
    finally:
        if owns_connection:
            conn.close()


def _post_form(url, data):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST", headers={
        "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "EntrouEconomizouGerador/3.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read().decode(errors="ignore"))
            message = payload.get("message") or payload.get("error_description") or payload.get("error")
        except Exception:
            message = None
        raise RuntimeError(message or f"Mercado Livre respondeu HTTP {error.code}.") from None
    except urllib.error.URLError as error:
        raise RuntimeError("Não foi possível conectar ao Mercado Livre.") from error


def _get_json(url, token):
    req = urllib.request.Request(url, headers={
        "Accept": "application/json", "Authorization": f"Bearer {token}",
        "User-Agent": "EntrouEconomizouGerador/3.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise PermissionError("Token inválido ou expirado.") from None
        raise RuntimeError(f"API respondeu HTTP {error.code}.") from None


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def configured_redirect_uri():
    explicit = os.environ.get("MELI_REDIRECT_URI", "").strip()
    if explicit:
        return explicit
    base = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    return f"{base}/oauth/callback" if base else ""


def oauth_configuration():
    redirect_uri = configured_redirect_uri()
    return {
        "configured": bool(os.environ.get("MELI_CLIENT_ID", "").strip()
                           and os.environ.get("MELI_CLIENT_SECRET", "").strip()
                           and redirect_uri),
        "redirect_uri": redirect_uri,
        "storage": "postgresql" if using_database() else "windows_local",
    }


def start_authorization(client_id="", client_secret="", redirect_uri=""):
    client_id = os.environ.get("MELI_CLIENT_ID", "").strip() or client_id.strip()
    client_secret = os.environ.get("MELI_CLIENT_SECRET", "").strip() or client_secret.strip()
    redirect_uri = configured_redirect_uri() or redirect_uri.strip()
    if not client_id or not client_secret:
        raise ValueError("Configure o Client ID e o Client Secret do Mercado Livre.")
    if not redirect_uri.startswith("https://"):
        raise ValueError("A Redirect URI precisa começar com https://.")
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    state = secrets.token_urlsafe(32)
    pending = {
        "client_id": client_id, "client_secret": client_secret, "redirect_uri": redirect_uri,
        "code_verifier": verifier, "state": state, "created_at": int(time.time()),
    }
    _save_pending(state, pending)
    return AUTH_URL + "?" + urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
    })


def complete_authorization_params(code, state):
    code, state = code.strip(), state.strip()
    if not code or not state:
        raise ValueError("O Mercado Livre não devolveu code e state.")
    pending = _load_pending(state)
    if not pending:
        raise RuntimeError("Não existe autorização pendente para este acesso.")
    if time.time() - int(pending.get("created_at", 0)) > 1800:
        _delete_pending(state)
        raise RuntimeError("A autorização expirou. Inicie novamente.")
    if not secrets.compare_digest(state, pending.get("state", "")):
        raise RuntimeError("O parâmetro state não confere. Inicie novamente.")
    token = _post_form(TOKEN_URL, {
        "grant_type": "authorization_code", "client_id": pending["client_id"],
        "client_secret": pending["client_secret"], "code": code,
        "redirect_uri": pending["redirect_uri"], "code_verifier": pending["code_verifier"],
    })
    if not token.get("access_token"):
        raise RuntimeError("A resposta não trouxe Access Token.")
    now, expires = int(time.time()), int(token.get("expires_in") or 21600)
    record = {
        "client_id": pending["client_id"], "client_secret": pending["client_secret"],
        "redirect_uri": pending["redirect_uri"], "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token", ""), "expires_at": now + expires,
        "user_id": token.get("user_id"), "updated_at": now,
    }
    _save_credentials(record)
    _delete_pending(state)
    return record


def complete_authorization(callback_url):
    parsed = urllib.parse.urlparse(callback_url.strip())
    query = urllib.parse.parse_qs(parsed.query)
    code = (query.get("code") or [""])[0]
    state = (query.get("state") or [""])[0]
    return complete_authorization_params(code, state)


def load_credentials():
    return _load_credentials_db() if using_database() else _load_local(CRED_FILE)


def _refresh_record(cred):
    if not cred.get("refresh_token"):
        raise RuntimeError("Refresh Token indisponível. Refaça a autorização.")
    client_id = os.environ.get("MELI_CLIENT_ID", "").strip() or cred.get("client_id", "")
    client_secret = os.environ.get("MELI_CLIENT_SECRET", "").strip() or cred.get("client_secret", "")
    token = _post_form(TOKEN_URL, {
        "grant_type": "refresh_token", "client_id": client_id,
        "client_secret": client_secret, "refresh_token": cred["refresh_token"],
    })
    if not token.get("access_token"):
        raise RuntimeError("A renovação não trouxe Access Token.")
    now, expires = int(time.time()), int(token.get("expires_in") or 21600)
    cred.update({
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token") or cred["refresh_token"],
        "expires_at": now + expires, "updated_at": now,
    })
    return cred


def refresh_access_token(force=False):
    if using_database():
        ensure_database_schema()
        with _connect() as conn:
            cred = _load_credentials_db(conn, for_update=True)
            if not cred:
                raise RuntimeError("Nenhuma autorização salva.")
            if not force and int(cred.get("expires_at", 0)) > int(time.time()) + 300:
                return cred
            cred = _refresh_record(cred)
            _save_credentials(cred, conn)
            return cred
    with _local_refresh_lock:
        cred = load_credentials()
        if not cred:
            raise RuntimeError("Nenhuma autorização salva.")
        if not force and int(cred.get("expires_at", 0)) > int(time.time()) + 300:
            return cred
        cred = _refresh_record(cred)
        _save_credentials(cred)
        return cred


def get_valid_access_token():
    return refresh_access_token()["access_token"]


def get_current_user():
    try:
        return _get_json(ME_URL, get_valid_access_token())
    except PermissionError:
        return _get_json(ME_URL, refresh_access_token(force=True)["access_token"])


def token_status():
    config = oauth_configuration()
    cred = load_credentials()
    if not cred:
        return {"connected": False, **config}
    return {
        "connected": True, "user_id": cred.get("user_id"),
        "seconds_remaining": int(cred.get("expires_at", 0)) - int(time.time()),
        "has_refresh_token": bool(cred.get("refresh_token")), **config,
    }


def delete_all_credentials():
    if not using_database():
        CRED_FILE.unlink(missing_ok=True)
        PENDING_FILE.unlink(missing_ok=True)
        return
    ensure_database_schema()
    with _connect() as conn:
        conn.execute(f"DELETE FROM {TOKEN_TABLE} WHERE token_id = %s", (SHARED_TOKEN_ID,))
        conn.execute(f"DELETE FROM {PENDING_TABLE}")


def delete_all_local_credentials():
    """Compatibilidade com a versão anterior do app."""
    delete_all_credentials()
