class Todo < ApplicationRecord
  belongs_to :user

  def summary
    "Todo ##{id}"
  end
end
