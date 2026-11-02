class ApplicationController < ActionController::Base
  force_ssl only: :checkout
end
