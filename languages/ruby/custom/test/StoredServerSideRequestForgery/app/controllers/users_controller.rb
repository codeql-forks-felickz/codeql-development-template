class UsersController < ActionController::Base
  def update
    @user = User.find(params[:id])
    @user.avatar_url = params[:user][:avatar_url]
    @user.save
  end
end
