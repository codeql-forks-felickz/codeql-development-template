def legacy
redirect_to(params.update(action:'main')) # $ Alert
end

def go_back_or_to_fallback
  redirect_back_or_to params[:url], allow_other_host: false # $ Alert
end

def go_back_fallback
  redirect_back fallback_location: params[:url], allow_other_host: false # $ Alert
end
