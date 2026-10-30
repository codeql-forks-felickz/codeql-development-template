class AnalyticsController < ActionController::Base
  # Reduced from a Rails app: request-controlled hash keys are converted to
  # symbols and joined into a raw SQL select list.
  def index
    if params[:field].nil?
      fields = "*"
    else
      fields = custom_fields.join(",")
    end
    @analytics = Analytics.hits_by_ip(params[:ip], fields)
  end

  # Known imprecision: recent Rails versions identifier-quote a bare Symbol
  # passed to `select`, so this is likely not exploitable there. The model
  # cannot distinguish it from the symbol being turned back into a string.
  def select_bare_symbol
    Analytics.select(params[:col].to_sym) # $ SPURIOUS: Alert
  end

  def select_intern_interpolated
    Analytics.select("#{params[:col].intern}, id") # $ Alert
  end

  def select_keys_to_sym
    cols = params[:field].keys.map { |k| k.downcase.to_sym } # $ Source
    Analytics.select(cols.join(",")) # $ Alert
  end

  # Safe: keys are checked against an allowlist before use.
  ALLOWED_FIELDS = %w[ip_address referrer user_agent].freeze

  def select_allowlisted
    col = params[:col]
    if ALLOWED_FIELDS.include?(col)
      Analytics.select(col.to_sym)
    end
  end

  # Safe: constant symbol, no user input.
  def select_constant
    Analytics.select("ip_address".to_sym)
  end

  private

  def custom_fields
    params.require(:field).keys.map { |i| i.downcase.to_sym } # $ Source
  end
end

class Analytics < ActiveRecord::Base
  scope :hits_by_ip, ->(ip, col = "*") { select("#{col}").where(ip_address: ip).order("id DESC") } # $ Alert
end
