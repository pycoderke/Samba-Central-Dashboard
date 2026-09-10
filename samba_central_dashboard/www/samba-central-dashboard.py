import frappe
from samba_central_dashboard.api import require_dashboard_role


def get_context(context):
    if frappe.session.user == "Guest":
        frappe.throw("Login required", frappe.PermissionError)
    require_dashboard_role()
    context.no_cache = 1
    context.title = "SambaPOS Central Dashboard"
