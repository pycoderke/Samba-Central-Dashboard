import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields


def ensure_item_publish_field():
    create_custom_fields({
        "Item": [{
            "fieldname": "custom_sambapos_publish",
            "label": "Publish to SambaPOS",
            "fieldtype": "Select",
            "options": "\nPublish\nDo Not Publish",
            "insert_after": "disabled",
            "reqd": 1,
            "description": "Mandatory control for publishing this Item to branch SambaPOS databases.",
        }]
    }, update=True)


def after_install():
    for role in ("System Manager", "Sales Manager", "Sales Admin"):
        if not frappe.db.exists("Role", role):
            frappe.get_doc({"doctype": "Role", "role_name": role}).insert(ignore_permissions=True)
    ensure_item_publish_field()


def after_migrate():
    ensure_item_publish_field()
