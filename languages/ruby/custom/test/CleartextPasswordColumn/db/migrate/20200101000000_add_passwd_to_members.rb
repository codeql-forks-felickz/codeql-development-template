class AddPasswdToMembers < ActiveRecord::Migration[6.0]
  def change
    add_column :members, :passwd, :string # $ Alert
    add_column :members, :password_hint_id, :integer
  end
end
