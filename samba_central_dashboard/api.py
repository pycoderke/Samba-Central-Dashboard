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
    return {
        "rows": rows[:2000],
        "departments": sorted(grouped.values(), key=lambda row: (row["branch"], row["department"])),
        "summary": {
            "tickets": len(rows), "sales": sum(float(r.total or 0) for r in rows if r.event_type in ("Sale", "Return")),
            "discounts": sum(float(r.discount or 0) for r in rows),
            "returns": sum(1 for r in rows if r.event_type == "Return"),
            "gifts": sum(1 for r in rows if r.event_type == "Gift"),
            "wastage": sum(1 for r in rows if r.event_type == "Wastage"),
            "voids": sum(1 for r in rows if r.event_type == "Void"),
        },
    }


@frappe.whitelist()
def filter_options():
    require_dashboard_role()
    def values(field):
        return [row[0] for row in frappe.db.sql(f"SELECT DISTINCT `{field}` FROM `tabSamba Metric Event` WHERE IFNULL(`{field}`,'')!='' ORDER BY `{field}`")]
    return {field: values(field) for field in ("branch_source", "department", "event_type", "waiter", "cashier", "payment_modes")}
