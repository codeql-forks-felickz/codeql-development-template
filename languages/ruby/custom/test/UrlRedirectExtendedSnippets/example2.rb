def go_back
  target = params[:url] # $ Source
  redirect_to target # $ Alert
end

# Safe: same-host-only redirect.
def go_home
  redirect_to params[:url], allow_other_host: false
end

# Safe: constant redirect target.
def go_root
  redirect_to "/"
end
