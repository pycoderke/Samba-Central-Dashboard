import hashlib
import hmac
import json
import time

import frappe
from frappe import _
from frappe.utils import now_datetime


ALLOWED_ROLES = {"System Manager", "Sales Manager", "Sales Admin"}
EVENT_TYPES = {"Sale", "Return", "Gift", "Wastage", "Void"}


def require_dashboard_role():
    if not ALLOWED_ROLES.intersection(set(frappe.get_roles())):
        frappe.throw(_("System Manager, Sales Manager or Sales Admin role required"), frappe.PermissionError)


def _event_key(branch, event):
    value = "|".join((branch, str(event["source_key"]), str(event["ticket_id"]), str(event["fingerprint"])))
    return "SME-" + hashlib.sha256(value.encode()).hexdigest()


def _supplier_expenses(from_date, to_date, company=None):
    """Return submitted supplier payouts without counting unpaid invoices."""
    common = {"docstatus": 1, "posting_date": ["between", [from_date, to_date]]}
    if company:
        common["company"] = company

    supplier_names = set()
    expenses = []
    payment_filters = dict(common)
    payment_filters.update({"payment_type": "Pay", "party_type": "Supplier"})
    for row in frappe.get_all(
        "Payment Entry",
        filters=payment_filters,
        fields=["name", "posting_date", "party", "party_name", "base_paid_amount"],
        limit_page_length=10000,
    ):
        supplier_names.add(row.party)
        expenses.append({
            "date": row.posting_date,
            "entry_no": row.name,
            "payee": row.party_name or row.party,
            "amount": float(row.base_paid_amount or 0),
            "entry_type": "Payment Entry",
            "status": "Paid",
            "counted": 1,
        })

    journals = frappe.get_all(
        "Journal Entry",
        filters=common,
        fields=["name", "posting_date"],
        limit_page_length=10000,
    )
    journal_dates = {row.name: row.posting_date for row in journals}
    if journal_dates:
        account_rows = frappe.get_all(
            "Journal Entry Account",
            filters={
                "parent": ["in", list(journal_dates)],
                "party_type": "Supplier",
                "debit": [">", 0],
            },
            fields=["parent", "party", "debit"],
            limit_page_length=20000,
        )
        supplier_names.update(row.party for row in account_rows if row.party)
        for row in account_rows:
            expenses.append({
                "date": journal_dates[row.parent],
                "entry_no": row.parent,
                "payee": row.party or "Supplier",
                "amount": float(row.debit or 0),
                "entry_type": "Journal Entry",
                "status": "Paid",
                "counted": 1,
            })

    invoice_filters = dict(common)
    invoice_filters["outstanding_amount"] = [">", 0]
    for row in frappe.get_all(
        "Purchase Invoice",
        filters=invoice_filters,
        fields=["name", "posting_date", "supplier", "supplier_name", "outstanding_amount"],
        limit_page_length=10000,
    ):
        expenses.append({
            "date": row.posting_date,
            "entry_no": row.name,
            "payee": row.supplier_name or row.supplier,
            "amount": float(row.outstanding_amount or 0),
            "entry_type": "Purchase Invoice",
            "status": "Unpaid",
            "counted": 0,
        })

    if supplier_names:
        labels = {
            row.name: row.supplier_name
            for row in frappe.get_all(
                "Supplier",
                filters={"name": ["in", list(supplier_names)]},
                fields=["name", "supplier_name"],
                limit_page_length=10000,
            )
        }
        for row in expenses:
            row["payee"] = labels.get(row["payee"], row["payee"])

    expenses.sort(key=lambda row: (str(row["date"]), row["entry_no"]), reverse=True)
    return {
        "rows": expenses,
        "total": sum(row["amount"] for row in expenses if row["counted"]),
        "unpaid_total": sum(row["amount"] for row in expenses if not row["counted"]),
    }


@frappe.whitelist()
def supplier_expenses(from_date=None, to_date=None, company=None):
    require_dashboard_role()
    if not from_date or not to_date:
        frappe.throw(_("from_date and to_date are required"))
    return _supplier_expenses(from_date, to_date, company)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def ingest():
    raw = frappe.request.get_data() or b""
    branch = frappe.request.headers.get("X-Samba-Branch") or ""
    timestamp = frappe.request.headers.get("X-Samba-Timestamp") or ""
    nonce = frappe.request.headers.get("X-Samba-Nonce") or ""
    signature = frappe.request.headers.get("X-Samba-Signature") or ""
    if not branch or not timestamp or not nonce or not signature:
        frappe.throw(_("Missing signed-ingest headers"), frappe.AuthenticationError)
    try:
        if abs(int(time.time()) - int(timestamp)) > 300:
            raise ValueError
    except ValueError:
        frappe.throw(_("Expired or invalid timestamp"), frappe.AuthenticationError)
    source = frappe.get_doc("Samba Branch Source", branch)
    if not source.enabled:
        frappe.throw(_("Branch source is disabled"), frappe.AuthenticationError)
    secret = source.get_password("shared_secret")
    expected = hmac.new(secret.encode(), timestamp.encode() + b"\n" + nonce.encode() + b"\n" + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        frappe.throw(_("Invalid signature"), frappe.AuthenticationError)
    replay_key = f"samba-ingest-nonce:{branch}:{nonce}"
    if frappe.cache().get_value(replay_key):
        frappe.throw(_("Nonce already used"), frappe.AuthenticationError)
    frappe.cache().set_value(replay_key, 1, expires_in_sec=600)

    payload = json.loads(raw.decode("utf-8"))
    events = payload.get("events") or []
    if not isinstance(events, list) or len(events) > 500:
        frappe.throw(_("events must be a list of at most 500 rows"))
    accepted = duplicates = 0
    for event in events:
        required = ("source_key", "ticket_id", "posting_date", "fingerprint", "event_type")
        if any(event.get(field) in (None, "") for field in required):
            frappe.throw(_("An event is missing required fields"))
        event_type = str(event["event_type"]).title()
        if event_type not in EVENT_TYPES:
            frappe.throw(_("Unsupported event type: {0}").format(event_type))
        key = _event_key(branch, event)
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        payload_hash = hashlib.sha256(canonical.encode()).hexdigest()
        if frappe.db.exists("Samba Metric Event", key):
            duplicates += 1
            continue
        doc = frappe.get_doc({
            "doctype": "Samba Metric Event", "event_key": key,
            "branch_source": branch, "branch_name": source.branch_name,
            "source_key": event["source_key"], "database_name": event.get("database_name"),
            "department": event.get("department"), "posting_date": event["posting_date"],
            "posting_time": event.get("posting_time"), "ticket_id": int(event["ticket_id"]),
            "ticket_number": event.get("ticket_number"), "invoice_name": event.get("invoice_name"),
            "event_type": event_type, "customer": event.get("customer"),
            "waiter": event.get("waiter"), "cashier": event.get("cashier"),
            "payment_modes": event.get("payment_modes"), "total": float(event.get("total") or 0),
            "discount": float(event.get("discount") or 0), "fingerprint": event["fingerprint"],
            "payload_hash": payload_hash, "received_at": now_datetime(),
        })
        doc.insert(ignore_permissions=True)
        accepted += 1
    source.db_set("last_seen_at", now_datetime(), update_modified=False)
    source.db_set("last_database", payload.get("database_name") or "", update_modified=False)
    frappe.db.commit()
    return {"accepted": accepted, "duplicates": duplicates}


@frappe.whitelist()
def dashboard_data(filters=None):
    require_dashboard_role()
    filters = frappe.parse_json(filters) if isinstance(filters, str) else (filters or {})
    clauses = ["posting_date BETWEEN %(from_date)s AND %(to_date)s"]
    values = {"from_date": filters.get("from_date"), "to_date": filters.get("to_date")}
    for field in ("branch_source", "department", "event_type", "waiter", "cashier"):
        if filters.get(field):
            clauses.append(f"{field}=%({field})s"); values[field] = filters[field]
    if filters.get("payment_mode"):
        clauses.append("payment_modes LIKE %(payment_mode)s"); values["payment_mode"] = f"%{filters['payment_mode']}%"
    if filters.get("time_from"):
        clauses.append("posting_time >= %(time_from)s"); values["time_from"] = filters["time_from"]
    if filters.get("time_to"):
        clauses.append("posting_time <= %(time_to)s"); values["time_to"] = filters["time_to"]
    rows = frappe.db.sql(f"""SELECT event_key,branch_source,branch_name,database_name,department,
      posting_date,posting_time,ticket_id,ticket_number,invoice_name,event_type,customer,waiter,cashier,
      payment_modes,total,discount,fingerprint,received_at FROM `tabSamba Metric Event`
      WHERE {' AND '.join(clauses)} ORDER BY received_at DESC LIMIT 10000""", values, as_dict=True)
    latest = {}
    for row in rows:
        latest.setdefault((row.branch_source, row.database_name, row.ticket_id), row)
    rows = list(latest.values())
    grouped = {}
    for row in rows:
        key = (row.branch_name, row.department or "Unassigned")
        item = grouped.setdefault(key, {"branch": key[0], "department": key[1], "tickets": 0,
            "sales": 0.0, "discounts": 0.0, "returns": 0, "gifts": 0, "wastage": 0, "voids": 0})
        item["tickets"] += 1
        if row.event_type in ("Sale", "Return"):
            item["sales"] += float(row.total or 0)
        item["discounts"] += float(row.discount or 0)
        label = {"Return":"returns", "Gift":"gifts", "Wastage":"wastage", "Void":"voids"}.get(row.event_type)
        if label:
            item[label] += 1
    expenses = _supplier_expenses(filters.get("from_date"), filters.get("to_date"), filters.get("company"))
    return {
        "rows": rows[:2000],
        "expenses": expenses["rows"][:2000],
        "unpaid_expenses": expenses["unpaid_total"],
        "departments": sorted(grouped.values(), key=lambda row: (row["branch"], row["department"])),
        "summary": {
            "tickets": len(rows), "sales": sum(float(r.total or 0) for r in rows if r.event_type in ("Sale", "Return")),
            "discounts": sum(float(r.discount or 0) for r in rows),
            "returns": sum(1 for r in rows if r.event_type == "Return"),
            "gifts": sum(1 for r in rows if r.event_type == "Gift"),
            "wastage": sum(1 for r in rows if r.event_type == "Wastage"),
            "voids": sum(1 for r in rows if r.event_type == "Void"),
            "expenses": expenses["total"],
        },
    }


@frappe.whitelist()
def filter_options():
    require_dashboard_role()
    def values(field):
        return [row[0] for row in frappe.db.sql(f"SELECT DISTINCT `{field}` FROM `tabSamba Metric Event` WHERE IFNULL(`{field}`,'')!='' ORDER BY `{field}`")]
    return {field: values(field) for field in ("branch_source", "department", "event_type", "waiter", "cashier", "payment_modes")}
