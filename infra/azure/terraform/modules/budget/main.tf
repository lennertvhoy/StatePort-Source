# Machine-enforced cost control for the alpha stack.
#
# The EUR 30 gate was previously procedural only ("recompute before apply").
# This consumption budget makes it machine-enforced at the Azure layer: when
# actual monthly spend on the resource group crosses the threshold, Azure
# emails the operator. It is an alert, not a hard stop — the 72-hour TTL and
# destroy discipline remain operator responsibilities.
#
# Budget currency follows the subscription's billing currency; the amount is
# a plain number. time_grain "Monthly" resets on the first of each month.

locals {
  # Consumption budgets require a first-of-month start date within the last
  # few months, so a static value would silently go stale. Computed from
  # timestamp(); the alpha stack never outlives 72 hours, so the resulting
  # per-plan diff is irrelevant.
  start_of_month = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
}

resource "azurerm_consumption_budget_resource_group" "this" {
  name              = "${var.name_prefix}-budget"
  resource_group_id = var.resource_group_id

  amount     = var.amount
  time_grain = "Monthly"

  time_period {
    start_date = local.start_of_month
  }

  notification {
    enabled        = true
    operator       = "GreaterThanOrEqualTo"
    threshold      = 90.0
    threshold_type = "Actual"
    contact_emails = [var.notification_email]
  }
}
