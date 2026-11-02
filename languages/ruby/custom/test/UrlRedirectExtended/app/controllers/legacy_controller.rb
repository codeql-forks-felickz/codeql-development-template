class LegacyController < ApplicationController
  # `Hash#update` returns the tainted params, whose `host` key controls the
  # redirect target.
  def legacy
    redirect_to(params.update(action: "main")) # $ Alert
  end

  # Safe: only the controller and action are taken from a fixed hash.
  def main
    redirect_to({ action: "index" }.update(controller: "home"))
  end
end
