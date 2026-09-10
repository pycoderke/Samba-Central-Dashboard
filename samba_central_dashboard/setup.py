import frappe


def after_install():
    for role in ("System Manager", "Sales Manager", "Sales Admin"):
        if not frappe.db.exists("Role", role):
            frappe.get_doc({"doctype": "Role", "role_name": role}).insert(ignore_permissions=True)
