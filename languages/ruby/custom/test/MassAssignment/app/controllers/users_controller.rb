class UsersController < ApplicationController
  skip_before_action :authenticated, only: [:new, :create, :signup]

  # Public signup action: `user_params` permits every key, so a client can set `user[admin]=true`.
  def signup
    @user = User.new(user_params) # $ Alert
  end

  def create
    user = User.new(user_params) # $ Alert
    user.save
  end

  def create_inline
    User.create(params.require(:user).permit!) # $ Alert
  end

  def create_unsafe_hash
    User.new(unsafe_user_params) # $ Alert
  end

  def create_empty_hash
    User.new(nested_any_params) # $ Alert
  end

  def update
    user = User.find(params[:id])
    user.update(user_params) # $ Alert
  end

  # Fully specified strong parameters are safe.
  def create_safe
    User.new(safe_user_params)
  end

  def update_safe
    user = User.find(params[:id])
    user.update(safe_user_params)
  end

  private

  def user_params
    params.require(:user).permit! # $ Source
  end

  def unsafe_user_params
    params[:user].to_unsafe_h # $ Source
  end

  def nested_any_params
    params.require(:user).permit(:email, settings: {}) # $ Source
  end

  def safe_user_params
    params.require(:user).permit(:email, :first_name, :last_name)
  end
end
