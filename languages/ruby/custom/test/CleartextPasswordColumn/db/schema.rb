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
    t.string   "password"
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

  create_table "acts_as_authentic_accounts", force: :cascade do |t|
    t.string "password"
    t.string "api_password" # $ Alert
  end

  create_table "array_assignment_clients", force: :cascade do |t|
    t.text "api_password"
  end

  create_table "api_credentials", force: :cascade do |t|
    t.text "api_password"
  end

  create_table "setter_clients", force: :cascade do |t|
    t.text "api_password"
  end

  create_table "write_attribute_clients", force: :cascade do |t|
    t.text "api_password"
  end

  create_table "concern_clients", force: :cascade do |t|
    t.text "api_password"
  end

  create_table "members", force: :cascade do |t|
    t.string "password"
  end

  create_table "sorcery_accounts", force: :cascade do |t|
    t.string "password"
    t.string "api_password" # $ Alert
  end

  create_table "unprotected_api_clients", force: :cascade do |t|
    t.text "api_password" # $ Alert
  end

  create_table :legacy_logins do |t|
    t.text :passphrase # $ Alert
    t.column :admin_password, :string # $ Alert
  end
end
