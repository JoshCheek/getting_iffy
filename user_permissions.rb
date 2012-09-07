require 'set'

class UserPermissions

  def initialize(user, cm_invoice)
    @user = user
    @cm_invoice = cm_invoice
  end

  def get_permissions
    @permissions ||= Set.new(user_permissions.concat invoice_permissions)
  end

  private

  def user_permissions
    return [] if @user.nil?
    [ true,                                       :DEFAULT_PERMISSION,
      has_cm_team_role,                           :CM_TEAM_ROLE_PERMISSION,
      can_see_invoices,                           :CM_INVOICE_USER_PERMISSION,
      can_see_invoices,                           :INVOICE_VIEW_PERMISSION,
      can_see_invoices,                           :ACCESS_ALL_INVOICE_PERMISSION,
      has_invoice_finance_role,                   :FINANCE_INVOICE_PERMISSION,
      has_application_access,                     :CM_INVOICE_USER_PERMISSION,
      has_application_access(:CM_INVOICE_ROLE),   :CM_ANY_INVOICE_PERMISSION,
      has_application_access(:PA_INVOICE_ROLE),   :PA_ANY_INVOICE_PERMISSION,
      has_application_access(:SDT_INVOICE_ROLE),  :SDT_ANY_INVOICE_PERMISSION,
    ].each_slice(2).select(&:first).map(&:last)
  end

  def invoice_permissions
    return [] unless @cm_invoice
    [ has_read_access,                                                    :INVOICE_VIEW_PERMISSION,
      has_edit_access,                                                    :COMMENT_ADD_PERMISSION,
      has_cm_invoice_close_right,                                         :INVOICE_CLOSE_PERMISSION,
      has_approve_access,                                                 :INVOICE_APPROVE_PERMISSION,
      has_reject_access,                                                  :INVOICE_REJECT_PERMISSION,
      has_configure_rules_access,                                         :CONFIGURE_RULES_PERMISSION,
      has_view_rules_access,                                              :VIEW_RULES_PERMISSION,
      has_invoice_log_access,                                             :INVOICE_LOG_PERMISSION,
      has_cm_edit_access && cm_invoice_editable?,                         :CM_EDIT_SETUP_PERMISSION,
      has_cm_edit_access && has_cm_status?,                               :CM_BILLING_PERIOD_EDIT_PERMISSION,
      has_cm_edit_access && has_cm_status? && @cm_invoice.in_transition?, :CM_EDIT_BILLING_PERIOD_TRANSITION_PERMISSION,
      has_cm_edit_access && can_add_billing_period?,                      :CM_BILLING_PERIOD_ADD_PERMISSION
    ].each_slice(2).select(&:first).map(&:last)
  end

  def can_see_invoices
    @can_see_invoices ||= has_cm_invoice_view_role || has_invoice_finance_role
  end

  def has_cm_status?
    approval_status == :CM_STATUS
  end

  def approval_status
    @approval_status ||= @cm_invoice.approval_status
  end

  def cm_invoice_editable?
    [:NEW_STATUS, :CM_STATUS].include? approval_status
  end

  def can_add_billing_period?
    [:APPROVED_STATUS, :NEW_STATUS].include? approval_status
  end
end
