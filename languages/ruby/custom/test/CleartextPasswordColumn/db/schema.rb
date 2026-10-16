ActiveRecord::Schema.define(version: 20181206165206) do
  create_table "users", force: :cascade do |t|
    t.string   "login",      null: false
    t.string   "firstname"
    t.string   "password",   null: false # $ Alert
    t.datetime "created_at", null: false
    t.index ["password"], name: "index_users_on_password", using: :btree
  end

  create_table "admins", force: :cascade do |t|
    t.string   "login",           null: false
    t.string   "password_digest", null: false
    t.string   "password_reset_token"
    t.datetime "password_changed_at"
  end

  create_table "devise_users", force: :cascade do |t|
    t.string "encrypted_password", null: false
  end

  create_table "accounts", force: :cascade do |t|
    t.string "password"
  end

  create_table "api_clients", force: :cascade do |t|
    t.text "api_password"
  end

  create_table :legacy_logins do |t|
    t.text :passphrase # $ Alert
    t.column :admin_password, :string # $ Alert
  end
end
