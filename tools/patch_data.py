"""Переводит data/data.json на новую структуру:
- спецификации становятся дочерними договорами (parentContractId);
- расходные договоры получают fundingContractId (доходный договор-источник);
- платежи получают собственный контрагент и ссылку на источник финансирования;
- добавляются справочники ЦФО / БДДС / проектов.
Скрипт идемпотентен: повторный запуск ничего не ломает.
"""
import json
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "data" / "data.json"
d = json.loads(p.read_text(encoding="utf-8"))

contracts = d.get("contracts", [])
payments = d.get("payments", [])
by_id = {c["id"]: c for c in contracts}

# 1. Спецификации -> дочерние договоры
for s in d.pop("specifications", []) or []:
    if s["id"] in by_id:
        continue
    parent = by_id.get(s["contractId"])
    if not parent:
        continue
    amount = float(s.get("amount") or 0)
    rate = float(s.get("vatRate") or 0)
    child = {
        "id": s["id"],
        "number": s["number"],
        "date": s.get("date") or parent.get("date"),
        "counterparty": parent.get("counterparty", ""),
        "subject": s.get("subject", ""),
        "direction": parent.get("direction", ""),
        "kind": "fixed",
        "amount": amount,
        "vatRate": rate,
        "project": parent.get("project", ""),
        "responsible": parent.get("responsible", ""),
        "startDate": "",
        "endDate": "",
        "status": s.get("status") or "active",
        "comment": "",
        "reviewDate": s.get("date") or parent.get("date"),
        "registrationDate": s.get("date") or parent.get("date"),
        "documentCard": f"СП-{s['id'].split('-')[-1]}",
        "fundingSource": "",
        "amountWithoutVat": round(amount / (1 + rate / 100), 2) if rate else amount,
        "documentKind": "contract",
        "category": "specification",
        "otherExpense": False,
        "parentContractId": parent["id"],
        "fundingContractId": "",
    }
    contracts.append(child)
    by_id[child["id"]] = child
    for pay in payments:
        if pay.get("specificationId") == s["id"]:
            pay["contractId"] = s["id"]
            pay["specificationId"] = ""

# 2. Источник финансирования: расходники привязываем к доходникам
funding_map = {
    "contract-1": "contract-2",  # Вектор (развитие продукта) <- Север (внедрение ИС)
    "contract-3": "contract-4",  # Смирнов (эксплуатация) <- Ростех (лицензии)
    "contract-5": "contract-4",  # Офис-Снаб <- Ростех
    "contract-7": "contract-4",  # СтройМонтаж <- Ростех
    "contract-8": "contract-6",  # МедиаПлюс <- Центр компетенций
    "contract-9": "contract-10",  # Логистика-Транс <- ФинИнвест
}
for c in contracts:
    c.setdefault("parentContractId", "")
    c.setdefault("fundingContractId", "")
    if c.get("direction") == "income":
        c["fundingContractId"] = ""
    elif c["id"] in funding_map and not c["fundingContractId"]:
        c["fundingContractId"] = funding_map[c["id"]]
    if c["fundingContractId"]:
        c["fundingSource"] = by_id[c["fundingContractId"]]["number"]
    # дочерние договоры наследуют источник родителя
    if c["parentContractId"] and not c["fundingContractId"]:
        c["fundingContractId"] = by_id[c["parentContractId"]].get("fundingContractId", "")
        c["fundingSource"] = by_id[c["parentContractId"]].get("fundingSource", "")
    # одиночные спецификации/заявки без родителя -> лимит
    if c.get("category") in ("specification", "request", "addendum") and not c["parentContractId"]:
        c["category"] = "limit"

# 3. Платежи: собственный контрагент, вид документа, источник
for pay in payments:
    parent = by_id.get(pay.get("contractId") or "")
    pay.setdefault("counterparty", "")
    pay.setdefault("fundingContractId", "")
    if parent and not pay["counterparty"]:
        pay["counterparty"] = parent.get("counterparty", "")
    if pay.get("documentKind") in ("", None):
        pay["documentKind"] = "contract" if parent else "invoice"
    if pay.get("documentKind") == "none" and parent:
        # счета без договора раньше были привязаны к договору-заглушке
        pay["documentKind"] = "contract"
    pay["approvalVatRate"] = pay.get("approvalVatRate") or 22

# 4. Счёт без договора под доходником (демонстрация)
if not any(p["id"] == "payment-21" for p in payments):
    payments.append({
        "id": "payment-21",
        "contractId": "",
        "number": "С-0101",
        "date": "2026-07-22",
        "amount": 85000,
        "type": "expense",
        "paymentKind": "postpay",
        "status": "paid",
        "comment": "Счет без договора: аренда зала для презентации",
        "approvalDate": "2026-07-20",
        "paymentDate": "2026-07-22",
        "documentCard": "С-0101",
        "responsible": "Сидорова М.П.",
        "cfo": "Администрация",
        "bdds": "Административные",
        "approvalAmount": 85000,
        "approvalVatRate": 22,
        "specificationId": "",
        "approvalAmountWithoutVat": round(85000 / 1.22, 2),
        "approvalVatAmount": round(85000 - 85000 / 1.22, 2),
        "documentKind": "invoice",
        "subtype": "invoice",
        "counterparty": "ООО «Конгресс-Холл»",
        "fundingContractId": "contract-2",
        "project": "Внедрение ИС",
    })

# 5. Справочники
def uniq(values):
    seen, out = set(), []
    for v in values:
        v = (v or "").strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out

dicts = []
for kind, values in (
    ("cfo", uniq(p.get("cfo") for p in payments)),
    ("bdds", uniq(p.get("bdds") for p in payments)),
    ("project", uniq(c.get("project") for c in contracts)),
):
    for i, value in enumerate(values, start=1):
        dicts.append({"id": f"dict-{kind}-{i}", "kind": kind, "value": value})
d["dictionaries"] = dicts
d.pop("history", None)

d["contracts"] = contracts
d["payments"] = payments
p.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
print("ok", len(contracts), "contracts,", len(payments), "payments,", len(dicts), "dictionary values")
