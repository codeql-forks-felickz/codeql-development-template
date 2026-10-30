class TodosController < ApplicationController
  def index
    @todos = Todo.where(user_id: current_user.id)
  end

  def archive
    @todos = Todo.all.order(:created_at).limit(10)
  end

  def recent
    @todos = Todo.where(user_id: current_user.id).to_a
  end

  def show
    @todo = Todo.find_by(id: params[:id])
  end

  def tags
    @tags = ["urgent", "later"]
  end

  def create
    Todo.create(body: params[:todo][:body], user_id: current_user.id)
    redirect_to todos_path
  end
end
