class ApplicationRecord < ActiveRecord::Base
end

class Message < ApplicationRecord
end

class User < ApplicationRecord
end

class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

class MessagesController < ApplicationController
  # BAD: the client controls `creator_id`, so any user can impersonate another sender.
  def create
    if Message.create(message_params) # $ Alert
      redirect_to "/messages"
    end
  end

  # BAD: inline allowlist containing `user_id`.
  def create_inline
    Message.new(params.require(:message).permit(:user_id, :message)).save # $ Alert
  end

  # BAD: update with a client-controlled owner field.
  def update
    message = Message.find(params[:id])
    message.update(message_params) # $ Alert
  end

  # BAD: setting a sensitive field on another record does not override this one.
  def create_with_unrelated_override
    user = User.new
    user.creator_id = current_user.id
    Message.create(message_params) # $ Alert
  end

  # GOOD: the ownership field is overridden on the updated record.
  def update_overridden
    message = Message.find(params[:id])
    message.update(message_params)
    message.creator_id = current_user.id
  end

  # GOOD: the ownership field is overridden server-side.
  def create_merged
    Message.create(message_params.merge(creator_id: current_user.id))
  end

  # GOOD: the ownership field is overridden server-side after mass assignment.
  def create_overridden
    message = Message.new(message_params)
    message.creator_id = current_user.id
    message.save
  end

  # GOOD: the ownership field is removed before mass assignment.
  def create_except
    Message.create(message_params.except(:creator_id))
  end

  # GOOD: the allowlist contains no ownership or privilege field.
  def create_safe
    Message.create(safe_message_params.merge(creator_id: current_user.id))
  end

  # GOOD: the allowlist contains no ownership or privilege field.
  def create_safe_plain
    Message.create(safe_message_params)
  end

  private

  def message_params
    params.require(:message).permit(:creator_id, :message, :read, :receiver_id) # $ Source
  end

  def safe_message_params
    params.require(:message).permit(:message, :receiver_id)
  end
end

class UsersController < ApplicationController
  # BAD: privilege escalation via `admin`.
  def update
    user = User.find(params[:id])
    user.update(params.require(:user).permit(:email, :admin)) # $ Alert
  end
end
