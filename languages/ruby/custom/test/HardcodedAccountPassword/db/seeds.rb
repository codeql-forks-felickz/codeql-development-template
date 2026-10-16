# Seeded application accounts with source-controlled default passwords.
user1 = User.create(login: 'admin',
                    password: 'password', # $ Alert
                    firstname: "Stephen")
user2 = User.create(login: 'user', password: 'password') # $ Alert

# Short and long literals are both reported (no length heuristic).
User.create!(login: 'ops', password: 'changeme') # $ Alert
User.find_or_create_by(login: 'svc', passwd: 'S3rv1c3-Acc0unt-P@ss') # $ Alert

# Hash literal argument.
User.create({ login: 'root', password: 'toor' }) # $ Alert

# Literal flowing through a local variable is reported once, at the literal.
default_pw = 'letmein' # $ Alert
User.create(login: 'guest', password: default_pw, password_confirmation: default_pw)

# Updating an existing account.
admin = User.find_by(login: 'admin')
admin.update(password: 'admin123') # $ Alert
admin.update_attribute(:password, 'admin123') # $ Alert
admin.password = 'hunter2' # $ Alert

# --- Safe counterparts: must not alert ---
User.create(login: 'env', password: ENV['ADMIN_PASSWORD'])
User.create(login: 'rand', password: SecureRandom.hex(16))
User.create(login: 'blank', password: '')
User.create(login: 'named', firstname: 'password')
PlainSettings.create(password: 'not-a-record')
