class BenefitFormsController < ActionController::Base
  # Reduced from the vulnerable download action: both the class name and the
  # path come from the request, so `type=File` yields arbitrary file reads.
  def download
    path = params[:name] # $ Source
    file = params[:type].constantize.new(path) # $ Alert
    send_file file, disposition: "attachment"
  end

  def download_safe_constantize
    path = params[:name] # $ Source
    file = params[:type].safe_constantize.new(path) # $ Alert
    send_file file
  end

  def download_const_get
    path = params[:name] # $ Source
    file = Object.const_get(params[:type]).new(path) # $ Alert
    send_file file
  end

  def download_constant_file_class
    path = params[:name] # $ Source
    file = "File".constantize.new(path) # $ Alert
    send_file file
  end

  # Baseline: already reported by the stock query.
  def download_direct
    send_file params[:name] # $ Alert
  end

  # Safe: the constructed class is a fixed, non-filesystem class.
  def report_fixed_class
    path = params[:name]
    report = "Report".constantize.new(path)
    render plain: report.to_s
  end

  # Safe: the constructor argument is not user controlled.
  def download_constant_path
    file = params[:type].constantize.new("public/forms/benefits.pdf")
    send_file file
  end

  # Safe: the path is restricted to an allow-list.
  def download_allow_listed
    path = params[:name]
    if %w[benefits.pdf dental.pdf].include?(path)
      file = params[:type].constantize.new(path)
      send_file file
    end
  end

  # Safe: an ordinary, statically-known constructor.
  def build_user
    User.new(params[:name])
  end
end
