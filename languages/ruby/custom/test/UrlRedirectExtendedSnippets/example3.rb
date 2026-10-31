# Safe: `params` and `redirect_to` are defined locally, so this is not a
# Rails controller snippet.
class Router
  def params
    {}
  end

  def redirect_to(url)
    url
  end

  def run
    redirect_to params[:url]
  end
end

