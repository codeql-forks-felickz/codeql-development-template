class AdminController < ApplicationController
  def dashboard
    @user_id = params[:user_id] # $ Source
    @page = params[:page].to_i
  end
end
