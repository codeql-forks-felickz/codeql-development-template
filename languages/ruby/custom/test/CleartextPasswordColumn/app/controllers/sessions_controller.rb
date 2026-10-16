class SessionsController < ApplicationController
  def create
    # Authentication compares the submitted password directly against the clear-text column.
    @user = User.where("login = ? AND password = '#{auth_params[:password]}'", auth_params[:login]).first # $ Alert
    @user ||= User.where("login = ? AND users.password = ?", auth_params[:login], auth_params[:password]).first # $ Alert
    @user ||= User.find_by(login: auth_params[:login], password: auth_params[:password]) # $ Alert
    @user ||= User.where({ password: auth_params[:password] }).first # $ Alert
    @user ||= Member.find_by(passwd: auth_params[:password]) # $ Alert

    # --- Safe counterparts: must not alert ---
    # Lookups that do not touch the password column.
    User.find_by(login: auth_params[:login])
    User.where("login = ?", auth_params[:login]).first
    User.where("password_reset_token = ?", params[:token]).first
    # The `accounts.password` column is hashed by the Account model.
    Account.find_by(password: auth_params[:password])
    # Proper verification with has_secure_password.
    Admin.find_by(login: auth_params[:login])&.authenticate(auth_params[:password])
  end

  protected

  def auth_params
    params.require(:user).permit(:login, :password)
  end
end
