class AdminController < ApplicationController
  # Bypasses strong parameters with `to_unsafe_h`, so any attribute (e.g. `admin`) can be set.
  def update_user
    user = User.find_by_id(params[:admin_id])
    if user
      user_params = params[:user].to_unsafe_h if params[:user].respond_to?(:to_unsafe_h) # $ Source
      user_params ||= params[:user]

      filtered_params = user_params.reject { |k, v| (k == "password" || k == "password_confirmation") && v.blank? }

      user.update(filtered_params) # $ Alert
      user.save!
    end
  end
end
