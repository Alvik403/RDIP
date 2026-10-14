import csv
import hmac
import json
import math
import os
import re
import secrets
import time
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from io import StringIO
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import jwt
import psycopg
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from jwt import PyJWKClient
from psycopg.rows import dict_row
from psycopg.types.json import Json

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_BASE = os.environ.get("PUBLIC_BASE", "https://localhost").rstrip("/")
OIDC_INTERNAL = os.environ.get("OIDC_INTERNAL", "http://keycloak:8080/auth/realms/dip").rstrip("/")
REDIRECT_URI = PUBLIC_BASE + "/oauth/callback"
CLIENT_ID = "dip-web"
MONEY = Decimal("0.01")
LATIN = re.compile(r"[A-Za-z]")

VIEWERS, EDITORS, AUDITORS, ADMINS = "DiP-Viewers", "DiP-Editors", "DiP-Auditors", "DiP-Admins"
ALL_GROUPS = {VIEWERS, EDITORS, AUDITORS, ADMINS}
EDIT_GROUPS = {EDITORS, ADMINS}
AUDIT_GROUPS = {EDITORS, AUDITORS, ADMINS}
ROLLBACK_GROUPS = {ADMINS}


def read_secret(name: str) -> str:
    for path in (Path("/run/secrets") / name, ROOT / "secrets" / name):
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    raise SystemExit(f"missing secret: {name}")


SESSION_SECRET = read_secret("session_secret")
if len(SESSION_SECRET) < 32:
    raise SystemExit("session_secret must be at least 32 characters")
DB_PASSWORD = read_secret("postgres_password")
CLIENT_SECRET = read_secret("kc_client_secret")

SCHEMA = """
CREATE TABLE IF NOT EXISTS contracts (
  id text PRIMARY KEY,
  number text NOT NULL DEFAULT '',
  date text NOT NULL DEFAULT '',
  counterparty text NOT NULL DEFAULT '',
  subject text NOT NULL DEFAULT '',
  direction text NOT NULL DEFAULT '',
  kind text NOT NULL DEFAULT '',
  amount numeric(18,2) NOT NULL DEFAULT 0,
  vat_rate numeric(5,2) NOT NULL DEFAULT 0,
  project text NOT NULL DEFAULT '',
  responsible text NOT NULL DEFAULT '',
  start_date text NOT NULL DEFAULT '',
  end_date text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'active',
  comment text NOT NULL DEFAULT '',
  review_date text NOT NULL DEFAULT '',
  registration_date text NOT NULL DEFAULT '',
  document_card text NOT NULL DEFAULT '',
  funding_source text NOT NULL DEFAULT '',
  amount_without_vat numeric(18,2) NOT NULL DEFAULT 0,
  document_kind text NOT NULL DEFAULT 'contract',
  category text NOT NULL DEFAULT 'limit',
  other_expense boolean NOT NULL DEFAULT false,
  version integer NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS specifications (
  id text PRIMARY KEY,
  contract_id text NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
  number text NOT NULL DEFAULT '',
  date text NOT NULL DEFAULT '',
  subject text NOT NULL DEFAULT '',
  amount numeric(18,2) NOT NULL DEFAULT 0,
  vat_rate numeric(5,2) NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'active',
  version integer NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS payments (
  id text PRIMARY KEY,
  contract_id text NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
  number text NOT NULL DEFAULT '',
  date text NOT NULL DEFAULT '',
  amount numeric(18,2) NOT NULL DEFAULT 0,
  type text NOT NULL DEFAULT '',
  payment_kind text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'paid',
  comment text NOT NULL DEFAULT '',
  approval_date text NOT NULL DEFAULT '',
  payment_date text NOT NULL DEFAULT '',
  document_card text NOT NULL DEFAULT '',
  responsible text NOT NULL DEFAULT '',
  cfo text NOT NULL DEFAULT '',
  bdds text NOT NULL DEFAULT '',
  approval_amount numeric(18,2) NOT NULL DEFAULT 0,
  approval_vat_rate numeric(5,2) NOT NULL DEFAULT 0,
  specification_id text NOT NULL DEFAULT '',
  approval_amount_without_vat numeric(18,2) NOT NULL DEFAULT 0,
  approval_vat_amount numeric(18,2) NOT NULL DEFAULT 0,
  document_kind text NOT NULL DEFAULT '',
  subtype text NOT NULL DEFAULT '',
  approval_end_date text NOT NULL DEFAULT '',
  posted_date text NOT NULL DEFAULT '',
  cost_type text NOT NULL DEFAULT '',
  mvz text NOT NULL DEFAULT '',
  key_counterparty text NOT NULL DEFAULT '',
  project text NOT NULL DEFAULT '',
  version integer NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS sessions (
  id text PRIMARY KEY,
  username text NOT NULL,
  groups jsonb NOT NULL,
  csrf_token text NOT NULL,
  id_token text NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  actor text NOT NULL,
  action text NOT NULL,
  entity_type text NOT NULL,
  entity_id text NOT NULL,
  label text NOT NULL,
  before_state jsonb,
  after_state jsonb
);
"""


def connect():
    return psycopg.connect(
        host=os.environ.get("DATABASE_HOST", "postgres"),
        dbname=os.environ.get("DATABASE_NAME", "dip"),
        user=os.environ.get("DATABASE_USER", "dip"),
        password=DB_PASSWORD,
        row_factory=dict_row,
    )


@contextmanager
def transaction():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def money(value) -> Decimal:
    number = parse_money(value)
    if number is None:
        raise HTTPException(400, "Укажите сумму числом")
    return number


def parse_money(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, Decimal):
        raw = value
    elif isinstance(value, int):
        raw = Decimal(value)
    elif isinstance(value, float):
        raw = Decimal(str(value))
    else:
        cleaned = str(value or "").strip().replace("\u00a0", " ").replace("\u202f", " ")
        for mark in ("₽", "руб.", "руб"):
            cleaned = cleaned.replace(mark, "")
        cleaned = cleaned.replace(" ", "")
        if not cleaned:
            return Decimal(0).quantize(MONEY)
        if cleaned.lower() in {"nan", "+nan", "-nan", "inf", "+inf", "-inf", "infinity", "+infinity", "-infinity", "snan"}:
            return None
        last_comma, last_dot = cleaned.rfind(","), cleaned.rfind(".")
        if last_comma >= 0 and last_dot >= 0:
            if last_comma > last_dot:
                cleaned = cleaned.replace(".", "").replace(",", ".")
            else:
                cleaned = cleaned.replace(",", "")
        elif last_comma >= 0:
            cleaned = cleaned.replace(",", ".")
        try:
            raw = Decimal(cleaned)
        except InvalidOperation:
            return None
    if not raw.is_finite():
        return None
    try:
        return raw.quantize(MONEY, rounding=ROUND_HALF_UP)
    except InvalidOperation:
        return None


def text(value) -> str:
    return "" if value is None else str(value)


def as_bool(value) -> bool:
    return value is True or value in ("true", "on", "1", 1)


def without_vat(amount: Decimal, rate: Decimal) -> Decimal:
    if rate == 0:
        return amount
    return (amount / (1 + rate / Decimal(100))).quantize(MONEY, rounding=ROUND_HALF_UP)


def json_money(value):
    if isinstance(value, Decimal):
        return float(value)
    return value


def sign(value: str) -> str:
    mac = hmac.new(SESSION_SECRET.encode(), value.encode(), "sha256").hexdigest()
    return f"{value}.{mac}"


def unsign(value: str) -> str | None:
    if not value or "." not in value:
        return None
    raw, mac = value.rsplit(".", 1)
    expected = hmac.new(SESSION_SECRET.encode(), raw.encode(), "sha256").hexdigest()
    if len(mac) != len(expected) or not hmac.compare_digest(mac, expected):
        return None
    return raw


def cookie_flags(response, name: str, value: str, max_age: int):
    response.set_cookie(name, value, httponly=True, secure=True, samesite="lax", max_age=max_age, path="/")


def same_token(left: str, right: str) -> bool:
    if not left or not right or len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def check_registry(number, card, responsible, comment):
    if responsible and re.search(r"\d", text(responsible)):
        raise HTTPException(400, "В ФИО не может быть цифр")
    if responsible and LATIN.search(text(responsible)):
        raise HTTPException(400, "Ввод данных в столбце Ответств. только на русском языке")
    if comment and LATIN.search(text(comment)):
        raise HTTPException(400, "Ввод данных в столбце Коммент. только на русском языке")


def audit(conn, actor: str, action: str, entity_type: str, entity_id: str, label: str, before, after):
    conn.execute(
        """INSERT INTO audit_log (actor, action, entity_type, entity_id, label, before_state, after_state)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (actor, action, entity_type, entity_id, label, Json(before), Json(after)),
    )
    print(json.dumps({
        "event": "dip.audit",
        "actor": actor,
        "action": action,
        "entityType": entity_type,
        "entityId": entity_id,
        "label": label,
        "before": before,
        "after": after,
    }, ensure_ascii=False, default=str), flush=True)


def contract_from_row(row) -> dict:
    return {
        "id": row["id"],
        "number": row["number"],
        "date": row["date"],
        "counterparty": row["counterparty"],
        "subject": row["subject"],
        "direction": row["direction"],
        "kind": row["kind"],
        "amount": json_money(row["amount"]),
        "vatRate": json_money(row["vat_rate"]),
        "project": row["project"],
        "responsible": row["responsible"],
        "startDate": row["start_date"],
        "endDate": row["end_date"],
        "status": row["status"],
        "comment": row["comment"],
        "reviewDate": row["review_date"],
        "registrationDate": row["registration_date"],
        "documentCard": row["document_card"],
        "fundingSource": row["funding_source"],
        "amountWithoutVat": json_money(row["amount_without_vat"]),
        "documentKind": row["document_kind"],
        "category": row["category"],
        "otherExpense": row["other_expense"],
        "version": row["version"],
    }


def spec_from_row(row) -> dict:
    return {
        "id": row["id"],
        "contractId": row["contract_id"],
        "number": row["number"],
        "date": row["date"],
        "subject": row["subject"],
        "amount": json_money(row["amount"]),
        "vatRate": json_money(row["vat_rate"]),
        "status": row["status"],
        "version": row["version"],
    }


def payment_from_row(row) -> dict:
    return {
        "id": row["id"],
        "contractId": row["contract_id"],
        "number": row["number"],
        "date": row["date"],
        "amount": json_money(row["amount"]),
        "type": row["type"],
        "paymentKind": row["payment_kind"],
        "status": row["status"],
        "comment": row["comment"],
        "approvalDate": row["approval_date"],
        "paymentDate": row["payment_date"],
        "documentCard": row["document_card"],
        "responsible": row["responsible"],
        "cfo": row["cfo"],
        "bdds": row["bdds"],
        "approvalAmount": json_money(row["approval_amount"]),
        "approvalVatRate": json_money(row["approval_vat_rate"]),
        "specificationId": row["specification_id"],
        "approvalAmountWithoutVat": json_money(row["approval_amount_without_vat"]),
        "approvalVatAmount": json_money(row["approval_vat_amount"]),
        "documentKind": row["document_kind"],
        "subtype": row["subtype"],
        "approvalEndDate": row["approval_end_date"],
        "postedDate": row["posted_date"],
        "costType": row["cost_type"],
        "mvz": row["mvz"],
        "keyCounterparty": row["key_counterparty"],
        "project": row["project"],
        "version": row["version"],
    }


def load_contract(conn, entity_id: str):
    row = conn.execute("SELECT * FROM contracts WHERE id = %s", (entity_id,)).fetchone()
    return contract_from_row(row) if row else None


def load_spec(conn, entity_id: str):
    row = conn.execute("SELECT * FROM specifications WHERE id = %s", (entity_id,)).fetchone()
    return spec_from_row(row) if row else None


def load_payment(conn, entity_id: str):
    row = conn.execute("SELECT * FROM payments WHERE id = %s", (entity_id,)).fetchone()
    return payment_from_row(row) if row else None


def decorate(contracts, specs, payments):
    for contract in contracts:
        amount = Decimal(str(contract["amount"]))
        spec_sum = sum(Decimal(str(item["amount"])) for item in specs if item["contractId"] == contract["id"])
        paid = sum(Decimal(str(item["amount"])) for item in payments if item["contractId"] == contract["id"] and item["status"] == "paid")
        contract["limitRemainder"] = None if contract["kind"] != "framework" else float(amount - spec_sum)
        contract["payRemainder"] = float(amount - paid)
    for spec in specs:
        paid = sum(
            Decimal(str(item["amount"]))
            for item in payments
            if item["specificationId"] == spec["id"] and item["status"] == "paid"
        )
        spec["payRemainder"] = float(Decimal(str(spec["amount"])) - paid)
    return contracts, specs, payments


def fetch_all(conn):
    contracts = [contract_from_row(row) for row in conn.execute("SELECT * FROM contracts ORDER BY number")]
    specs = [spec_from_row(row) for row in conn.execute("SELECT * FROM specifications ORDER BY number")]
    payments = [payment_from_row(row) for row in conn.execute("SELECT * FROM payments ORDER BY date DESC")]
    return decorate(contracts, specs, payments)


def normalize_contract(payload: dict, existing: dict | None) -> dict:
    check_registry(payload.get("number"), payload.get("documentCard"), payload.get("responsible"), payload.get("comment"))
    document_kind = text(payload.get("documentKind") or "contract")
    direction = text(payload.get("direction"))
    kind = text(payload.get("kind"))
    category = text(payload.get("category") or "limit")
    start_date = text(payload.get("startDate"))
    end_date = text(payload.get("endDate"))
    if document_kind in ("invoice", "none"):
        direction, kind, category, start_date, end_date = "", "", "limit", "", ""
    elif kind == "fixed" and category in ("specification", "request"):
        category = "limit"
    amount = money(payload.get("amount"))
    rate = money(payload.get("vatRate"))
    review = text(payload.get("reviewDate") or payload.get("date"))
    return {
        "id": text(payload.get("id") or (existing or {}).get("id") or "contract-" + secrets.token_hex(8)),
        "number": text(payload.get("number")).strip(),
        "date": review,
        "counterparty": text(payload.get("counterparty")),
        "subject": text(payload.get("subject")),
        "direction": direction,
        "kind": kind,
        "amount": amount,
        "vatRate": rate,
        "project": text(payload.get("project")),
        "responsible": text(payload.get("responsible")),
        "startDate": start_date,
        "endDate": end_date,
        "status": text(payload.get("status") or (existing or {}).get("status") or "active"),
        "comment": text(payload.get("comment")),
        "reviewDate": review,
        "registrationDate": text(payload.get("registrationDate") or review),
        "documentCard": text(payload.get("documentCard")).strip(),
        "fundingSource": text(payload.get("fundingSource")),
        "amountWithoutVat": without_vat(amount, rate),
        "documentKind": document_kind,
        "category": category or "limit",
        "otherExpense": direction == "expense" and as_bool(payload.get("otherExpense")),
        "version": int((existing or {}).get("version") or 1),
    }


def normalize_spec(payload: dict, existing: dict | None) -> dict:
    amount = money(payload.get("amount"))
    rate = money(payload.get("vatRate"))
    return {
        "id": text(payload.get("id") or (existing or {}).get("id") or "spec-" + secrets.token_hex(8)),
        "contractId": text(payload.get("contractId")),
        "number": text(payload.get("number")),
        "date": text(payload.get("date")),
        "subject": text(payload.get("subject")),
        "amount": amount,
        "vatRate": rate,
        "status": text(payload.get("status") or (existing or {}).get("status") or "active"),
        "version": int((existing or {}).get("version") or 1),
    }


def normalize_payment(payload: dict, existing: dict | None) -> dict:
    check_registry(payload.get("number"), payload.get("documentCard"), payload.get("responsible"), payload.get("comment"))
    amount = money(payload.get("amount"))
    approval = money(payload.get("approvalAmount") if payload.get("approvalAmount") not in (None, "") else amount)
    rate = money(payload.get("approvalVatRate"))
    net = without_vat(approval, rate)
    payment_date = text(payload.get("paymentDate") or payload.get("date") or payload.get("approvalDate"))
    approval_date = text(payload.get("approvalDate") or payment_date)
    subtype = text(payload.get("subtype"))
    return {
        "id": text(payload.get("id") or (existing or {}).get("id") or "payment-" + secrets.token_hex(8)),
        "contractId": text(payload.get("contractId")),
        "number": text(payload.get("number")).strip(),
        "date": payment_date,
        "amount": amount,
        "type": text(payload.get("type")),
        "paymentKind": text(payload.get("paymentKind")),
        "status": text(payload.get("status") or (existing or {}).get("status") or "paid"),
        "comment": text(payload.get("comment")),
        "approvalDate": approval_date,
        "paymentDate": payment_date,
        "documentCard": text(payload.get("documentCard")).strip(),
        "responsible": text(payload.get("responsible")),
        "cfo": text(payload.get("cfo")),
        "bdds": text(payload.get("bdds")),
        "approvalAmount": approval,
        "approvalVatRate": rate,
        "specificationId": "" if subtype != "specification" else text(payload.get("specificationId")),
        "approvalAmountWithoutVat": net,
        "approvalVatAmount": (approval - net).quantize(MONEY, rounding=ROUND_HALF_UP),
        "documentKind": text(payload.get("documentKind")),
        "subtype": subtype,
        "approvalEndDate": text(payload.get("approvalEndDate") or approval_date),
        "postedDate": text(payload.get("postedDate") or payment_date),
        "costType": text(payload.get("costType") or payload.get("bdds")),
        "mvz": text(payload.get("mvz") or payload.get("cfo")),
        "keyCounterparty": text(payload.get("keyCounterparty")),
        "project": text(payload.get("project")),
        "version": int((existing or {}).get("version") or 1),
    }


def public_copy(entity: dict) -> dict:
    copied = {}
    for key, value in entity.items():
        copied[key] = float(value) if isinstance(value, Decimal) else value
    return copied


CONTRACT_SQL = """
id, number, date, counterparty, subject, direction, kind, amount, vat_rate, project, responsible,
start_date, end_date, status, comment, review_date, registration_date, document_card, funding_source,
amount_without_vat, document_kind, category, other_expense, version
"""


def contract_params(entity: dict, version: int):
    return (
        entity["id"], entity["number"], entity["date"], entity["counterparty"], entity["subject"],
        entity["direction"], entity["kind"], entity["amount"], entity["vatRate"], entity["project"],
        entity["responsible"], entity["startDate"], entity["endDate"], entity["status"], entity["comment"],
        entity["reviewDate"], entity["registrationDate"], entity["documentCard"], entity["fundingSource"],
        entity["amountWithoutVat"], entity["documentKind"], entity["category"], entity["otherExpense"], version,
    )


def upsert_contract(conn, entity: dict, version: int):
    assignments = """
    number=%s, date=%s, counterparty=%s, subject=%s, direction=%s, kind=%s, amount=%s, vat_rate=%s,
    project=%s, responsible=%s, start_date=%s, end_date=%s, status=%s, comment=%s, review_date=%s,
    registration_date=%s, document_card=%s, funding_source=%s, amount_without_vat=%s, document_kind=%s,
    category=%s, other_expense=%s, version=%s
    """
    params = contract_params(entity, version)[1:] + (entity["id"],)
    conn.execute(f"UPDATE contracts SET {assignments} WHERE id = %s", params)
    if conn.execute("SELECT 1 FROM contracts WHERE id = %s", (entity["id"],)).fetchone() is None:
        conn.execute(f"INSERT INTO contracts ({CONTRACT_SQL}) VALUES ({', '.join(['%s'] * 24)})", contract_params(entity, version))


def upsert_spec(conn, entity: dict, version: int):
    if conn.execute("SELECT 1 FROM contracts WHERE id = %s", (entity["contractId"],)).fetchone() is None:
        raise HTTPException(400, "Договор не найден")
    updated = conn.execute(
        """UPDATE specifications SET contract_id=%s, number=%s, date=%s, subject=%s, amount=%s, vat_rate=%s, status=%s, version=%s
           WHERE id=%s""",
        (entity["contractId"], entity["number"], entity["date"], entity["subject"], entity["amount"], entity["vatRate"], entity["status"], version, entity["id"]),
    )
    if updated.rowcount == 0:
        conn.execute(
            """INSERT INTO specifications (id, contract_id, number, date, subject, amount, vat_rate, status, version)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (entity["id"], entity["contractId"], entity["number"], entity["date"], entity["subject"], entity["amount"], entity["vatRate"], entity["status"], version),
        )


def upsert_payment(conn, entity: dict, version: int):
    if conn.execute("SELECT 1 FROM contracts WHERE id = %s", (entity["contractId"],)).fetchone() is None:
        raise HTTPException(400, "Договор не найден")
    values = (
        entity["contractId"], entity["number"], entity["date"], entity["amount"], entity["type"], entity["paymentKind"],
        entity["status"], entity["comment"], entity["approvalDate"], entity["paymentDate"], entity["documentCard"],
        entity["responsible"], entity["cfo"], entity["bdds"], entity["approvalAmount"], entity["approvalVatRate"],
        entity["specificationId"], entity["approvalAmountWithoutVat"], entity["approvalVatAmount"], entity["documentKind"],
        entity["subtype"], entity["approvalEndDate"], entity["postedDate"], entity["costType"], entity["mvz"],
        entity["keyCounterparty"], entity["project"], version, entity["id"],
    )
    updated = conn.execute(
        """UPDATE payments SET contract_id=%s, number=%s, date=%s, amount=%s, type=%s, payment_kind=%s, status=%s,
           comment=%s, approval_date=%s, payment_date=%s, document_card=%s, responsible=%s, cfo=%s, bdds=%s,
           approval_amount=%s, approval_vat_rate=%s, specification_id=%s, approval_amount_without_vat=%s,
           approval_vat_amount=%s, document_kind=%s, subtype=%s, approval_end_date=%s, posted_date=%s, cost_type=%s,
           mvz=%s, key_counterparty=%s, project=%s, version=%s WHERE id=%s""",
        values,
    )
    if updated.rowcount == 0:
        conn.execute(
            """INSERT INTO payments (
                 id, contract_id, number, date, amount, type, payment_kind, status, comment, approval_date, payment_date,
                 document_card, responsible, cfo, bdds, approval_amount, approval_vat_rate, specification_id,
                 approval_amount_without_vat, approval_vat_amount, document_kind, subtype, approval_end_date, posted_date,
                 cost_type, mvz, key_counterparty, project, version
               ) VALUES (
                 %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
               )""",
            (entity["id"], *values[:-1]),
        )


def contract_bundle(conn, entity_id: str):
    contract = load_contract(conn, entity_id)
    if not contract:
        return None
    specs = [spec_from_row(row) for row in conn.execute("SELECT * FROM specifications WHERE contract_id = %s", (entity_id,))]
    payments = [payment_from_row(row) for row in conn.execute("SELECT * FROM payments WHERE contract_id = %s", (entity_id,))]
    return {"entity": contract, "specifications": specs, "payments": payments}


def apply_saved(conn, kind: str, entity: dict, version: int):
    entity = dict(entity)
    entity["version"] = version
    if kind == "contract":
        upsert_contract(conn, entity, version)
    elif kind == "specification":
        upsert_spec(conn, entity, version)
    else:
        upsert_payment(conn, entity, version)
    return public_copy(entity)


def seed(conn):
    if conn.execute("SELECT 1 FROM contracts LIMIT 1").fetchone():
        return
    path = ROOT / "seed" / "data.json"
    if not path.is_file():
        return
    payload = json.loads(path.read_text(encoding="utf-8"))
    for raw in payload.get("contracts") or []:
        amount = money(raw.get("amount"))
        rate = money(raw.get("vatRate"))
        review = text(raw.get("reviewDate") or raw.get("date"))
        upsert_contract(conn, {
            "id": text(raw.get("id")),
            "number": text(raw.get("number")),
            "date": text(raw.get("date") or review),
            "counterparty": text(raw.get("counterparty")),
            "subject": text(raw.get("subject")),
            "direction": text(raw.get("direction")),
            "kind": text(raw.get("kind")),
            "amount": amount,
            "vatRate": rate,
            "project": text(raw.get("project")),
            "responsible": text(raw.get("responsible")),
            "startDate": text(raw.get("startDate")),
            "endDate": text(raw.get("endDate")),
            "status": text(raw.get("status") or "active"),
            "comment": text(raw.get("comment")),
            "reviewDate": review,
            "registrationDate": text(raw.get("registrationDate") or review),
            "documentCard": text(raw.get("documentCard")),
            "fundingSource": text(raw.get("fundingSource")),
            "amountWithoutVat": money(raw["amountWithoutVat"]) if raw.get("amountWithoutVat") not in (None, "") else without_vat(amount, rate),
            "documentKind": text(raw.get("documentKind") or "contract"),
            "category": text(raw.get("category") or "limit"),
            "otherExpense": as_bool(raw.get("otherExpense")),
        }, 1)
    for raw in payload.get("specifications") or []:
        upsert_spec(conn, {
            "id": text(raw.get("id")),
            "contractId": text(raw.get("contractId")),
            "number": text(raw.get("number")),
            "date": text(raw.get("date")),
            "subject": text(raw.get("subject")),
            "amount": money(raw.get("amount")),
            "vatRate": money(raw.get("vatRate")),
            "status": text(raw.get("status") or "active"),
        }, 1)
    for raw in payload.get("payments") or []:
        amount = money(raw.get("amount"))
        approval = money(raw.get("approvalAmount") if raw.get("approvalAmount") not in (None, "") else amount)
        rate = money(raw.get("approvalVatRate"))
        net = money(raw["approvalAmountWithoutVat"]) if raw.get("approvalAmountWithoutVat") not in (None, "") else without_vat(approval, rate)
        vat_amount = money(raw["approvalVatAmount"]) if raw.get("approvalVatAmount") not in (None, "") else (approval - net)
        payment_date = text(raw.get("paymentDate") or raw.get("date"))
        upsert_payment(conn, {
            "id": text(raw.get("id")),
            "contractId": text(raw.get("contractId")),
            "number": text(raw.get("number")),
            "date": text(raw.get("date") or payment_date),
            "amount": amount,
            "type": text(raw.get("type")),
            "paymentKind": text(raw.get("paymentKind")),
            "status": text(raw.get("status") or "paid"),
            "comment": text(raw.get("comment")),
            "approvalDate": text(raw.get("approvalDate") or payment_date),
            "paymentDate": payment_date,
            "documentCard": text(raw.get("documentCard")),
            "responsible": text(raw.get("responsible")),
            "cfo": text(raw.get("cfo")),
            "bdds": text(raw.get("bdds")),
            "approvalAmount": approval,
            "approvalVatRate": rate,
            "specificationId": text(raw.get("specificationId")),
            "approvalAmountWithoutVat": net,
            "approvalVatAmount": vat_amount,
            "documentKind": text(raw.get("documentKind")),
            "subtype": text(raw.get("subtype")),
            "approvalEndDate": text(raw.get("approvalEndDate")),
            "postedDate": text(raw.get("postedDate")),
            "costType": text(raw.get("costType")),
            "mvz": text(raw.get("mvz")),
            "keyCounterparty": text(raw.get("keyCounterparty")),
            "project": text(raw.get("project")),
        }, 1)


def prepare_database():
    last_error = None
    for _ in range(30):
        try:
            with transaction() as conn:
                for statement in SCHEMA.split(";"):
                    sql = statement.strip()
                    if sql:
                        conn.execute(sql)
                seed(conn)
            return
        except Exception as exc:
            last_error = exc
            print(f"database wait: {exc}", flush=True)
            time.sleep(2)
    raise SystemExit(f"database is not ready: {last_error}")


app = FastAPI(title="DiP registry")
_jwks = None


@app.on_event("startup")
def startup():
    prepare_database()


def jwks() -> PyJWKClient:
    global _jwks
    if _jwks is None:
        _jwks = PyJWKClient(OIDC_INTERNAL + "/protocol/openid-connect/certs")
    return _jwks


def session_row(conn, request: Request):
    raw = unsign(request.cookies.get("dip_session", ""))
    if not raw:
        return None
    return conn.execute("SELECT * FROM sessions WHERE id = %s AND expires_at > now()", (raw,)).fetchone()


def open_session(request: Request, mutating: bool):
    with transaction() as conn:
        row = session_row(conn, request)
    if not row:
        raise HTTPException(401, "Требуется вход")
    if mutating and not same_token(request.headers.get("x-csrf-token", ""), row["csrf_token"]):
        raise HTTPException(403, "CSRF")
    return row


def guard(request: Request, allowed: set[str]):
    row = open_session(request, request.method in {"POST", "PUT", "PATCH", "DELETE"})
    groups = set(row["groups"] or [])
    if not groups & ALL_GROUPS:
        raise HTTPException(403, "Нет группы доступа")
    if not groups & allowed:
        raise HTTPException(403, "Недостаточно прав")
    return row


def me_payload(row) -> dict:
    groups = list(row["groups"] or [])
    present = set(groups)
    return {
        "username": row["username"],
        "groups": groups,
        "allowed": bool(present & ALL_GROUPS),
        "canEdit": bool(present & EDIT_GROUPS),
        "canAudit": bool(present & AUDIT_GROUPS),
        "canRollback": bool(present & ROLLBACK_GROUPS),
        "csrf": row["csrf_token"],
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready():
    try:
        with transaction() as conn:
            conn.execute("SELECT 1")
    except Exception:
        return JSONResponse({"status": "down"}, status_code=503)
    return {"status": "ok"}


def kc_headers(request: Request) -> dict:
    cookie = "; ".join(
        f"{name}={value}" for name, value in request.cookies.items() if name not in {"dip_session", "dip_oauth"}
    )
    headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "localhost",
        "X-Forwarded-Port": "443",
        "Accept": "text/html,application/xhtml+xml",
    }
    if cookie:
        headers["Cookie"] = cookie
    return headers


def to_internal(url: str) -> str:
    if url.startswith(PUBLIC_BASE + "/auth"):
        return "http://keycloak:8080" + url[len(PUBLIC_BASE):]
    if url.startswith("/auth"):
        return "http://keycloak:8080" + url
    return url


def public_cookie(raw: str) -> str:
    pieces = [part.strip() for part in raw.split(";")]
    kept = [pieces[0]]
    has_path = False
    for part in pieces[1:]:
        lower = part.lower()
        if lower.startswith("path="):
            kept.append("Path=/")
            has_path = True
        elif lower.startswith("domain="):
            continue
        else:
            kept.append(part)
    if not has_path:
        kept.append("Path=/")
    return "; ".join(kept)


def attach_cookies(response, raw_cookies: list[str]):
    for raw in raw_cookies:
        response.headers.append("set-cookie", public_cookie(raw))


def rewrite_login_page(html: str) -> tuple[str, str]:
    match = re.search(r'action="([^"]+)"', html)
    action = ""
    if match:
        action = match.group(1).replace("&amp;", "&")
        html = html[:match.start(1)] + "/login" + html[match.end(1):]
    return html, action


def login_page(request: Request, saved: dict) -> HTMLResponse:
    query = urlencode({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": REDIRECT_URI,
        "state": saved["state"],
        "nonce": saved["nonce"],
    })
    headers = kc_headers(request)
    cookies: list[str] = []
    url = OIDC_INTERNAL + "/protocol/openid-connect/auth?" + query
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        upstream = client.get(url, headers=headers)
        cookies.extend(upstream.headers.get_list("set-cookie"))
        for _ in range(6):
            if upstream.status_code not in {301, 302, 303, 307, 308}:
                break
            location = upstream.headers.get("location", "")
            if "/oauth/callback" in location:
                parsed = urlparse(location)
                params = parse_qs(parsed.query)
                return complete_login(saved, params.get("code", [""])[0], params.get("state", [""])[0], cookies)
            headers["Cookie"] = merge_cookie(headers.get("Cookie", ""), cookies)
            upstream = client.get(to_internal(location), headers=headers)
            cookies.extend(upstream.headers.get_list("set-cookie"))
    if upstream.status_code != 200:
        raise HTTPException(502, "Страница входа недоступна")
    html, action = rewrite_login_page(upstream.text)
    if action:
        saved["action"] = action
    response = HTMLResponse(html)
    cookie_flags(response, "dip_oauth", sign(json.dumps(saved)), 600)
    attach_cookies(response, cookies)
    return response


def merge_cookie(current: str, raw_cookies: list[str]) -> str:
    jar = {}
    for part in current.split(";"):
        if "=" in part:
            name, value = part.split("=", 1)
            jar[name.strip()] = value.strip()
    for raw in raw_cookies:
        pair = raw.split(";", 1)[0]
        if "=" in pair:
            name, value = pair.split("=", 1)
            jar[name.strip()] = value.strip()
    return "; ".join(f"{name}={value}" for name, value in jar.items())


def oauth_saved(request: Request) -> dict:
    packed = unsign(request.cookies.get("dip_oauth", ""))
    if not packed:
        raise HTTPException(401, "Сессия входа истекла")
    return json.loads(packed)


@app.get("/login")
def login(request: Request):
    saved = {"state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24), "action": ""}
    return login_page(request, saved)


@app.post("/login")
async def login_submit(request: Request):
    saved = oauth_saved(request)
    action = saved.get("action") or ""
    if not action:
        raise HTTPException(401, "Сессия входа истекла")
    payload = parse_qs((await request.body()).decode())
    headers = kc_headers(request)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    cookies: list[str] = []
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        upstream = client.post(to_internal(action), data={key: values[-1] for key, values in payload.items()}, headers=headers)
        cookies.extend(upstream.headers.get_list("set-cookie"))
        for _ in range(8):
            if upstream.status_code not in {301, 302, 303, 307, 308}:
                break
            location = upstream.headers.get("location", "")
            if "/oauth/callback" in location:
                parsed = urlparse(location)
                params = parse_qs(parsed.query)
                return complete_login(saved, params.get("code", [""])[0], params.get("state", [""])[0], cookies)
            headers["Cookie"] = merge_cookie(headers.get("Cookie", ""), cookies)
            upstream = client.get(to_internal(location), headers=headers)
            cookies.extend(upstream.headers.get_list("set-cookie"))
    if upstream.status_code != 200:
        raise HTTPException(502, "Страница входа недоступна")
    html, next_action = rewrite_login_page(upstream.text)
    if next_action:
        saved["action"] = next_action
    response = HTMLResponse(html)
    cookie_flags(response, "dip_oauth", sign(json.dumps(saved)), 600)
    attach_cookies(response, cookies)
    return response


def groups_of(payload: dict, access_token: str) -> list[str]:
    raw = payload.get("groups")
    if not raw and access_token:
        response = httpx.get(OIDC_INTERNAL + "/protocol/openid-connect/userinfo", headers={"Authorization": "Bearer " + access_token}, timeout=15)
        if response.status_code == 200:
            raw = response.json().get("groups")
    if isinstance(raw, str):
        raw = [raw]
    names = []
    for item in raw or []:
        name = str(item).strip("/").split("/")[-1]
        if name:
            names.append(name)
    return names


def complete_login(saved: dict, code: str, state: str, extra_cookies: list[str] | None = None):
    if not code or not state or state != saved.get("state"):
        raise HTTPException(401, "Состояние входа не совпало")
    token_response = httpx.post(
        OIDC_INTERNAL + "/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        timeout=20,
    )
    if token_response.status_code != 200:
        raise HTTPException(401, "Keycloak не выдал токен")
    token_body = token_response.json()
    id_token = token_body.get("id_token") or ""
    key = jwks().get_signing_key_from_jwt(id_token)
    payload = jwt.decode(id_token, key.key, algorithms=["RS256"], audience=CLIENT_ID, options={"verify_iss": False})
    issuer = payload.get("iss") or ""
    if not issuer.endswith("/realms/dip") or payload.get("nonce") != saved.get("nonce"):
        raise HTTPException(401, "Токен входа отклонён")
    username = payload.get("preferred_username") or payload.get("sub") or ""
    groups = groups_of(payload, token_body.get("access_token") or "")
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    with transaction() as conn:
        conn.execute(
            """INSERT INTO sessions (id, username, groups, csrf_token, id_token, expires_at)
               VALUES (%s, %s, %s, %s, %s, now() + interval '8 hours')""",
            (session_id, username, Json(groups), csrf_token, id_token),
        )
    response = RedirectResponse("/", status_code=302)
    cookie_flags(response, "dip_session", sign(session_id), 8 * 3600)
    response.delete_cookie("dip_oauth", path="/", secure=True, httponly=True, samesite="lax")
    attach_cookies(response, extra_cookies or [])
    return response


@app.get("/oauth/callback")
def oauth_callback(request: Request, code: str = "", state: str = ""):
    return complete_login(oauth_saved(request), code, state)


@app.get("/api/me")
def api_me(request: Request):
    with transaction() as conn:
        row = session_row(conn, request)
    if not row:
        raise HTTPException(401, "Требуется вход")
    return me_payload(row)


@app.post("/api/logout")
def api_logout(request: Request):
    row = open_session(request, True)
    with transaction() as conn:
        conn.execute("DELETE FROM sessions WHERE id = %s", (unsign(request.cookies.get("dip_session", "")),))
    if row["id_token"]:
        try:
            httpx.get(
                OIDC_INTERNAL + "/protocol/openid-connect/logout",
                params={"id_token_hint": row["id_token"], "client_id": CLIENT_ID},
                timeout=15,
            )
        except httpx.HTTPError:
            pass
    response = JSONResponse({"url": "/login"})
    response.delete_cookie("dip_session", path="/", secure=True, httponly=True, samesite="lax")
    return response


@app.get("/api/contracts")
def list_contracts(request: Request):
    guard(request, ALL_GROUPS)
    with transaction() as conn:
        contracts, _, _ = fetch_all(conn)
    return contracts


@app.get("/api/specifications")
def list_specifications(request: Request):
    guard(request, ALL_GROUPS)
    with transaction() as conn:
        _, specs, _ = fetch_all(conn)
    return specs


@app.get("/api/payments")
def list_payments(request: Request):
    guard(request, ALL_GROUPS)
    with transaction() as conn:
        _, _, payments = fetch_all(conn)
    return payments


EXPORT_HEADERS = [
    "Раздел", "Номер", "Карта документа", "Дата рассмотрения", "Дата регистрации",
    "Контрагент", "Предмет", "Сумма", "Ставка НДС", "Источник финансирования",
    "Проект", "Ответственный", "Комментарий", "Вид документа", "Направление",
    "Вид договора", "Категория", "Дата начала", "Дата окончания", "Прочие расходы",
    "Статус", "Номер договора", "Дата согласования", "Дата оплаты", "Вид платежа",
    "Подвид", "БДДС", "ЦФО", "Сумма с НДС", "Сумма оплаты", "Вид оплаты",
]
VAT_CHOICES = {Decimal(item) for item in ("0", "5", "7", "10", "20", "22")}


class RowProblem(Exception):
    def __init__(self, line: int, column: str, message: str):
        self.line = line
        self.column = column
        self.message = message

    def text(self) -> str:
        if self.column:
            return f"Строка {self.line}, столбец «{self.column}»: {self.message}"
        return f"Строка {self.line}: {self.message}"


def fold(value) -> str:
    return text(value).strip().lower().replace("ё", "е")


def mapped(value, options: dict, line: int, column: str, default: str | None):
    raw = text(value).strip()
    if not raw:
        if default is None:
            raise RowProblem(line, column, "заполните значение")
        return default
    found = options.get(fold(raw))
    if found is None:
        raise RowProblem(line, column, f"неизвестное значение «{raw}»")
    return found


def import_date(value, line: int, column: str, required: bool) -> str:
    raw = text(value).strip()
    if not raw:
        if required:
            raise RowProblem(line, column, "укажите дату")
        return ""
    candidate = raw[:10] if re.match(r"\d{4}-\d{2}-\d{2}", raw) else raw
    for pattern in ("%Y-%m-%d", "%d.%m.%Y", "%d.%m.%y"):
        try:
            return datetime.strptime(candidate, pattern).date().isoformat()
        except ValueError:
            continue
    raise RowProblem(line, column, f"дата «{raw}» не разобрана")


def import_money(value, line: int, column: str, required: bool) -> Decimal:
    if text(value).strip() == "":
        if required:
            raise RowProblem(line, column, "укажите сумму числом")
        return Decimal("0.00")
    number = parse_money(value)
    if number is None:
        raise RowProblem(line, column, "укажите сумму числом")
    return number


def import_vat(value, line: int, column: str) -> Decimal:
    raw = text(value).strip().replace("%", "").replace(" ", "")
    if not raw:
        return Decimal("20.00")
    number = parse_money(raw)
    if number is None or number not in VAT_CHOICES:
        raise RowProblem(line, column, "допустимы ставки 0, 5, 7, 10, 20 и 22")
    return number


def import_registry_fields(number, card, responsible, comment, line: int):
    try:
        check_registry(number, card, responsible, comment)
    except HTTPException as exc:
        detail = text(exc.detail)
        column = "Комментарий" if "Коммент" in detail else "Ответственный"
        raise RowProblem(line, column, detail) from exc


def csv_table(raw: str):
    body = raw.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    if not body.strip():
        raise HTTPException(400, "Файл пустой")
    first = body.split("\n", 1)[0]
    delimiter = ";" if first.count(";") >= first.count(",") else ","
    rows = list(csv.reader(StringIO(body), delimiter=delimiter))
    while rows and not any(cell.strip() for cell in rows[-1]):
        rows.pop()
    if not rows or not any(cell.strip() for cell in rows[0]):
        raise HTTPException(400, "В файле нет заголовка")
    headers = [cell.strip() for cell in rows[0]]
    missing = [name for name in EXPORT_HEADERS if name not in headers]
    if missing:
        raise HTTPException(400, "Строка 1: нет столбца «" + "», «".join(missing) + "»")
    seen = {}
    for name in headers:
        if name and name in seen:
            raise HTTPException(400, f"Строка 1: столбец «{name}» повторяется")
        if name:
            seen[name] = True
    parsed = []
    for offset, cells in enumerate(rows[1:], start=2):
        if not any(cell.strip() for cell in cells):
            continue
        record = {name: "" for name in EXPORT_HEADERS}
        for index, name in enumerate(headers):
            if name in record and index < len(cells):
                record[name] = cells[index].strip()
        parsed.append((offset, record))
    return parsed


DOCUMENT_KIND = {"договор": "contract", "счет": "invoice", "без счета, договора": "none", "contract": "contract", "invoice": "invoice", "none": "none"}
DIRECTION = {"доходный": "income", "расходный": "expense", "income": "income", "expense": "expense"}
CONTRACT_KIND = {"рамочный": "framework", "нерамочный": "fixed", "framework": "framework", "fixed": "fixed"}
CATEGORY = {"лимит": "limit", "спецификация": "specification", "заявка": "request", "доп. соглашение": "addendum", "limit": "limit", "specification": "specification", "request": "request", "addendum": "addendum"}
CONTRACT_STATUS = {"черновик": "draft", "действует": "active", "завершен": "closed", "draft": "draft", "active": "active", "closed": "closed"}
PAY_TYPE = {"поступление": "income", "оплата": "expense", "платеж": "expense", "доходный": "income", "расходный": "expense", "income": "income", "expense": "expense"}
PAY_STATUS = {"запланирован": "planned", "исполнен": "paid", "отменен": "cancelled", "planned": "planned", "paid": "paid", "cancelled": "cancelled"}
PAY_KIND = {"аванс": "advance", "постоплата": "postpay", "гу": "gu", "advance": "advance", "postpay": "postpay", "gu": "gu"}
SUBTYPE = {"спецификация": "specification", "заявка": "request", "счет": "invoice", "specification": "specification", "request": "request", "invoice": "invoice"}
YES_VALUES = {"да", "yes", "true", "1", "on"}


def display_choice(code: str, pairs: list[tuple[str, str]]) -> str:
    for value, label in pairs:
        if value == code:
            return label
    return code or ""


def csv_amount(value):
    if value in (None, ""):
        return ""
    number = parse_money(value)
    return "" if number is None else format(number, "f")


def export_csv(contracts: list, payments: list) -> str:
    buffer = StringIO()
    writer = csv.writer(buffer, delimiter=";", lineterminator="\r\n")
    writer.writerow(EXPORT_HEADERS)
    for contract in contracts:
        writer.writerow([
            "Договор", contract["number"], contract["documentCard"], contract["reviewDate"] or contract["date"],
            contract["registrationDate"], contract["counterparty"], contract["subject"], csv_amount(contract["amount"]),
            csv_amount(contract["vatRate"]), contract["fundingSource"], contract["project"], contract["responsible"],
            contract["comment"], display_choice(contract["documentKind"], [("contract", "Договор"), ("invoice", "Счёт"), ("none", "Без счета, договора")]),
            display_choice(contract["direction"], [("income", "Доходный"), ("expense", "Расходный")]),
            display_choice(contract["kind"], [("framework", "Рамочный"), ("fixed", "Нерамочный")]),
            display_choice(contract["category"], [("limit", "Лимит"), ("specification", "Спецификация"), ("request", "Заявка"), ("addendum", "Доп. соглашение")]),
            contract["startDate"], contract["endDate"], "да" if contract["otherExpense"] else "",
            display_choice(contract["status"], [("draft", "Черновик"), ("active", "Действует"), ("closed", "Завершен")]),
            "", "", "", "", "", "", "", "", "", "",
        ])
    by_id = {contract["id"]: contract for contract in contracts}
    for payment in payments:
        parent = by_id.get(payment["contractId"]) or {}
        writer.writerow([
            "Платеж", payment["number"], payment["documentCard"], "", "",
            parent.get("counterparty") or payment.get("keyCounterparty") or "", "", "",
            csv_amount(payment["approvalVatRate"]), "", payment.get("project") or "", payment["responsible"],
            payment["comment"], display_choice(payment["documentKind"], [("contract", "Договор"), ("invoice", "Счёт"), ("none", "Без счета, договора")]),
            "", "", "", "", "", "",
            display_choice(payment["status"], [("planned", "Запланирован"), ("paid", "Исполнен"), ("cancelled", "Отменен")]),
            parent.get("number") or "", payment["approvalDate"], payment["paymentDate"] or payment["date"],
            display_choice(payment["type"], [("income", "Поступление"), ("expense", "Оплата")]),
            display_choice(payment["subtype"], [("specification", "Спецификация"), ("request", "Заявка"), ("invoice", "Счёт")]),
            payment["bdds"], payment["cfo"], csv_amount(payment["approvalAmount"]), csv_amount(payment["amount"]),
            display_choice(payment["paymentKind"], [("advance", "Аванс"), ("postpay", "Постоплата"), ("gu", "ГУ"), ("stage", "ГУ")]),
        ])
    return "\ufeff" + buffer.getvalue()


def contract_from_import(record: dict, line: int) -> dict:
    number = record["Номер"].strip()
    if not number:
        raise RowProblem(line, "Номер", "укажите номер")
    card = record["Карта документа"].strip()
    responsible = record["Ответственный"].strip()
    comment = record["Комментарий"].strip()
    import_registry_fields(number, card, responsible, comment, line)
    document_kind = mapped(record["Вид документа"], DOCUMENT_KIND, line, "Вид документа", "contract")
    direction = mapped(record["Направление"], DIRECTION, line, "Направление", "" if document_kind in ("invoice", "none") else "expense")
    kind = mapped(record["Вид договора"], CONTRACT_KIND, line, "Вид договора", "" if document_kind in ("invoice", "none") else "fixed")
    category = mapped(record["Категория"], CATEGORY, line, "Категория", "limit")
    if document_kind in ("invoice", "none"):
        direction, kind, category = "", "", "limit"
    elif kind == "fixed" and category in ("specification", "request"):
        category = "limit"
    amount = import_money(record["Сумма"], line, "Сумма", True)
    rate = import_vat(record["Ставка НДС"], line, "Ставка НДС")
    review = import_date(record["Дата рассмотрения"], line, "Дата рассмотрения", True)
    start_date = import_date(record["Дата начала"], line, "Дата начала", False)
    end_date = import_date(record["Дата окончания"], line, "Дата окончания", False)
    if document_kind in ("invoice", "none"):
        start_date, end_date = "", ""
    other_raw = record["Прочие расходы"].strip()
    if other_raw and fold(other_raw) not in YES_VALUES | {"нет", "no", "false", "0"}:
        raise RowProblem(line, "Прочие расходы", "укажите «да» или оставьте пустым")
    counterparty = record["Контрагент"].strip()
    subject = record["Предмет"].strip()
    if document_kind == "contract" and not counterparty:
        raise RowProblem(line, "Контрагент", "укажите контрагента")
    if document_kind == "contract" and not subject:
        raise RowProblem(line, "Предмет", "укажите предмет")
    return {
        "id": "contract-" + secrets.token_hex(8),
        "number": number,
        "date": review,
        "counterparty": counterparty,
        "subject": subject,
        "direction": direction,
        "kind": kind,
        "amount": amount,
        "vatRate": rate,
        "project": record["Проект"].strip(),
        "responsible": responsible,
        "startDate": start_date,
        "endDate": end_date,
        "status": mapped(record["Статус"], CONTRACT_STATUS, line, "Статус", "active"),
        "comment": comment,
        "reviewDate": review,
        "registrationDate": import_date(record["Дата регистрации"], line, "Дата регистрации", False) or review,
        "documentCard": card,
        "fundingSource": record["Источник финансирования"].strip(),
        "amountWithoutVat": without_vat(amount, rate),
        "documentKind": document_kind,
        "category": category,
        "otherExpense": direction == "expense" and fold(other_raw) in YES_VALUES,
        "version": 1,
    }


def payment_from_import(record: dict, line: int, contracts_by_number: dict) -> dict:
    number = record["Номер"].strip()
    if not number:
        raise RowProblem(line, "Номер", "укажите номер")
    contract_number = record["Номер договора"].strip()
    if not contract_number:
        raise RowProblem(line, "Номер договора", "укажите номер договора")
    found = contracts_by_number.get(contract_number)
    if found is None:
        raise RowProblem(line, "Номер договора", f"договор «{contract_number}» не найден")
    if found == "":
        raise RowProblem(line, "Номер договора", f"в реестре несколько договоров «{contract_number}»")
    card = record["Карта документа"].strip()
    responsible = record["Ответственный"].strip()
    comment = record["Комментарий"].strip()
    import_registry_fields(number, card, responsible, comment, line)
    amount = import_money(record["Сумма оплаты"], line, "Сумма оплаты", True)
    approval = import_money(record["Сумма с НДС"], line, "Сумма с НДС", False)
    if text(record["Сумма с НДС"]).strip() == "":
        approval = amount
    rate = import_vat(record["Ставка НДС"], line, "Ставка НДС")
    payment_date = import_date(record["Дата оплаты"], line, "Дата оплаты", True)
    approval_date = import_date(record["Дата согласования"], line, "Дата согласования", False) or payment_date
    subtype = mapped(record["Подвид"], SUBTYPE, line, "Подвид", "invoice")
    net = without_vat(approval, rate)
    parent = found
    return {
        "id": "payment-" + secrets.token_hex(8),
        "contractId": parent["id"],
        "number": number,
        "date": payment_date,
        "amount": amount,
        "type": mapped(record["Вид платежа"], PAY_TYPE, line, "Вид платежа", "expense"),
        "paymentKind": mapped(record["Вид оплаты"], PAY_KIND, line, "Вид оплаты", "postpay"),
        "status": mapped(record["Статус"], PAY_STATUS, line, "Статус", "paid"),
        "comment": comment,
        "approvalDate": approval_date,
        "paymentDate": payment_date,
        "documentCard": card,
        "responsible": responsible,
        "cfo": record["ЦФО"].strip(),
        "bdds": record["БДДС"].strip(),
        "approvalAmount": approval,
        "approvalVatRate": rate,
        "specificationId": "",
        "approvalAmountWithoutVat": net,
        "approvalVatAmount": (approval - net).quantize(MONEY, rounding=ROUND_HALF_UP),
        "documentKind": mapped(record["Вид документа"], DOCUMENT_KIND, line, "Вид документа", "contract"),
        "subtype": subtype,
        "approvalEndDate": approval_date,
        "postedDate": payment_date,
        "costType": record["БДДС"].strip(),
        "mvz": record["ЦФО"].strip(),
        "keyCounterparty": parent.get("counterparty") or "",
        "project": record["Проект"].strip() or parent.get("project") or "",
        "version": 1,
    }


def index_contracts(contracts: list) -> dict:
    found = {}
    for contract in contracts:
        number = text(contract["number"]).strip()
        if not number:
            continue
        found[number] = "" if number in found else contract
    return found


@app.get("/api/export")
def export_registry(request: Request):
    guard(request, ALL_GROUPS)
    with transaction() as conn:
        contracts, _, payments = fetch_all(conn)
    content = export_csv(contracts, payments).encode("utf-8")
    return Response(content, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=registry.csv"})


@app.post("/api/import")
def import_registry(request: Request, payload: dict = Body()):
    actor = guard(request, EDIT_GROUPS)
    rows = csv_table(text(payload.get("text")))
    if not rows:
        return {"addedContracts": 0, "addedPayments": 0, "duplicates": [], "errors": ["В файле нет строк для загрузки"]}
    duplicates = []
    errors = []
    accepted_contracts = []
    accepted_payments = []
    with transaction() as conn:
        stored_contracts = [contract_from_row(row) for row in conn.execute("SELECT * FROM contracts")]
        stored_payments = conn.execute("SELECT contract_id, number FROM payments").fetchall()
        contracts_by_number = index_contracts(stored_contracts)
        payment_keys = {(row["contract_id"], text(row["number"]).strip()) for row in stored_payments}
        contract_lines = {}
        payment_lines = {}
        contract_rows = []
        payment_rows = []
        for line, record in rows:
            section = fold(record["Раздел"])
            if section == "договор":
                contract_rows.append((line, record))
            elif section == "платеж":
                payment_rows.append((line, record))
            else:
                errors.append(RowProblem(line, "Раздел", "укажите «Договор» или «Платеж»").text())
        for line, record in contract_rows:
            try:
                entity = contract_from_import(record, line)
            except RowProblem as problem:
                errors.append(problem.text())
                continue
            number = entity["number"]
            if number in contract_lines:
                duplicates.append(f"Строка {line}: дубль договора № {number}. Первая строка файла — {contract_lines[number]}.")
                continue
            if number in contracts_by_number:
                duplicates.append(f"Строка {line}: дубль договора № {number}. Такая запись уже есть в реестре.")
                continue
            contract_lines[number] = line
            contracts_by_number[number] = entity
            accepted_contracts.append(entity)
        for line, record in payment_rows:
            try:
                entity = payment_from_import(record, line, contracts_by_number)
            except RowProblem as problem:
                errors.append(problem.text())
                continue
            key = (entity["contractId"], entity["number"])
            marker = f"{entity['contractId']}|{entity['number']}"
            if marker in payment_lines:
                duplicates.append(f"Строка {line}: дубль платежа № {entity['number']}. Первая строка файла — {payment_lines[marker]}.")
                continue
            if key in payment_keys:
                duplicates.append(f"Строка {line}: дубль платежа № {entity['number']} по этому договору. Такая запись уже есть в реестре.")
                continue
            payment_lines[marker] = line
            payment_keys.add(key)
            accepted_payments.append(entity)
        def line_number(message: str) -> int:
            found = re.search(r"Строка (\d+)", message)
            return int(found.group(1)) if found else 0
        duplicates.sort(key=line_number)
        errors.sort(key=line_number)
        for entity in accepted_contracts:
            saved = apply_saved(conn, "contract", entity, 1)
            audit(conn, actor["username"], "Договор добавлен", "contract", saved["id"], f"№ {saved['number']} · {saved['counterparty']}", None, saved)
        for entity in accepted_payments:
            saved = apply_saved(conn, "payment", entity, 1)
            audit(conn, actor["username"], "Операция добавлена", "payment", saved["id"], f"{saved['number']} · {saved['amount']}", None, saved)
    return {
        "addedContracts": len(accepted_contracts),
        "addedPayments": len(accepted_payments),
        "duplicates": duplicates,
        "errors": errors,
    }


@app.get("/api/audit")
def list_audit(request: Request):
    guard(request, AUDIT_GROUPS)
    with transaction() as conn:
        rows = conn.execute(
            "SELECT id, ts, actor, action, entity_type, label FROM audit_log ORDER BY id DESC LIMIT 200"
        ).fetchall()
    return [{
        "id": str(row["id"]),
        "timestamp": row["ts"].isoformat(),
        "actor": row["actor"],
        "action": row["action"],
        "entityType": row["entity_type"],
        "label": row["label"],
    } for row in rows]


def create_entity(request: Request, kind: str, payload: dict):
    row = guard(request, EDIT_GROUPS)
    with transaction() as conn:
        if kind == "contract":
            entity = normalize_contract(payload, None)
            if load_contract(conn, entity["id"]):
                raise HTTPException(409, "Строку уже изменили")
            saved = apply_saved(conn, kind, entity, 1)
            label = f"№ {saved['number']} · {saved['counterparty']}"
            action = "Договор добавлен"
        elif kind == "specification":
            entity = normalize_spec(payload, None)
            if load_spec(conn, entity["id"]):
                raise HTTPException(409, "Строку уже изменили")
            saved = apply_saved(conn, kind, entity, 1)
            label = saved["number"]
            action = "Спецификация добавлена"
        else:
            entity = normalize_payment(payload, None)
            if load_payment(conn, entity["id"]):
                raise HTTPException(409, "Строку уже изменили")
            saved = apply_saved(conn, kind, entity, 1)
            label = f"{saved['number']} · {saved['amount']}"
            action = "Операция добавлена"
        audit(conn, row["username"], action, kind if kind != "specification" else "specification", saved["id"], label, None, saved)
    return saved


def update_entity(request: Request, kind: str, entity_id: str, payload: dict):
    row = guard(request, EDIT_GROUPS)
    with transaction() as conn:
        current = {"contract": load_contract, "specification": load_spec, "payment": load_payment}[kind](conn, entity_id)
        if not current:
            raise HTTPException(404, "Запись не найдена")
        if int(payload.get("version") or 0) != int(current["version"]):
            raise HTTPException(409, "Строку уже изменили")
        if kind == "contract":
            entity = normalize_contract({**payload, "id": entity_id}, current)
            action, label = "Договор изменен", f"№ {entity['number']} · {entity['counterparty']}"
        elif kind == "specification":
            entity = normalize_spec({**payload, "id": entity_id}, current)
            action, label = "Спецификация изменена", entity["number"]
        else:
            entity = normalize_payment({**payload, "id": entity_id}, current)
            action, label = "Операция изменена", f"{entity['number']} · {entity['amount']}"
        saved = apply_saved(conn, kind, entity, int(current["version"]) + 1)
        audit(conn, row["username"], action, kind, entity_id, label, current, public_copy(saved))
    return saved


def delete_entity(request: Request, kind: str, entity_id: str, version: int):
    row = guard(request, EDIT_GROUPS)
    with transaction() as conn:
        current = {"contract": load_contract, "specification": load_spec, "payment": load_payment}[kind](conn, entity_id)
        if not current:
            raise HTTPException(404, "Запись не найдена")
        if version != int(current["version"]):
            raise HTTPException(409, "Строку уже изменили")
        if kind == "contract":
            before = contract_bundle(conn, entity_id)
            label = f"№ {current['number']} · {current['counterparty']}"
            action = "Договор удален"
            conn.execute("DELETE FROM contracts WHERE id = %s AND version = %s", (entity_id, version))
        elif kind == "specification":
            before, label, action = current, current["number"], "Спецификация удалена"
            conn.execute("DELETE FROM specifications WHERE id = %s AND version = %s", (entity_id, version))
        else:
            before, label, action = current, f"{current['number']} · {current['amount']}", "Операция удалена"
            conn.execute("DELETE FROM payments WHERE id = %s AND version = %s", (entity_id, version))
        audit(conn, row["username"], action, kind, entity_id, label, before, None)
    return JSONResponse({"ok": True})


@app.post("/api/contracts")
def post_contract(request: Request, payload: dict = Body()):
    return create_entity(request, "contract", payload)


@app.patch("/api/contracts/{entity_id}")
def patch_contract(request: Request, entity_id: str, payload: dict = Body()):
    return update_entity(request, "contract", entity_id, payload)


@app.delete("/api/contracts/{entity_id}")
def delete_contract(request: Request, entity_id: str, version: int):
    return delete_entity(request, "contract", entity_id, version)


@app.post("/api/specifications")
def post_spec(request: Request, payload: dict = Body()):
    return create_entity(request, "specification", payload)


@app.patch("/api/specifications/{entity_id}")
def patch_spec(request: Request, entity_id: str, payload: dict = Body()):
    return update_entity(request, "specification", entity_id, payload)


@app.delete("/api/specifications/{entity_id}")
def delete_spec(request: Request, entity_id: str, version: int):
    return delete_entity(request, "specification", entity_id, version)


@app.post("/api/payments")
def post_payment(request: Request, payload: dict = Body()):
    return create_entity(request, "payment", payload)


@app.patch("/api/payments/{entity_id}")
def patch_payment(request: Request, entity_id: str, payload: dict = Body()):
    return update_entity(request, "payment", entity_id, payload)


@app.delete("/api/payments/{entity_id}")
def delete_payment(request: Request, entity_id: str, version: int):
    return delete_entity(request, "payment", entity_id, version)


def restore_record(conn, kind: str, entity: dict):
    version = int(entity.get("version") or 1)
    row = conn.execute(f"SELECT version FROM { {'contract': 'contracts', 'specification': 'specifications', 'payment': 'payments'}[kind] } WHERE id = %s", (entity["id"],)).fetchone()
    if row:
        version = int(row["version"]) + 1
    apply_saved(conn, kind, entity, version)


@app.post("/api/audit/{audit_id}/rollback")
def rollback(request: Request, audit_id: int):
    row = guard(request, ROLLBACK_GROUPS)
    with transaction() as conn:
        entry = conn.execute("SELECT * FROM audit_log WHERE id = %s", (audit_id,)).fetchone()
        if not entry:
            raise HTTPException(404, "Запись журнала не найдена")
        before = entry["before_state"]
        kind = entry["entity_type"]
        if isinstance(before, dict) and "entity" in before and "specifications" in before:
            restore_record(conn, "contract", before["entity"])
            for spec in before.get("specifications") or []:
                restore_record(conn, "specification", spec)
            for payment in before.get("payments") or []:
                restore_record(conn, "payment", payment)
            after = before
        elif before is None:
            table = {"contract": "contracts", "specification": "specifications", "payment": "payments"}[kind]
            conn.execute(f"DELETE FROM {table} WHERE id = %s", (entry["entity_id"],))
            after = None
        else:
            restore_record(conn, kind, before)
            after = before
        audit(conn, row["username"], "Выполнен откат", kind, entry["entity_id"], f"Отменено: {entry['action']} — {entry['label']}", entry["after_state"], after)
    return {"ok": True}


@app.get("/")
def index_page():
    return FileResponse(ROOT / "static" / "index.html", headers={"Cache-Control": "no-cache"})
