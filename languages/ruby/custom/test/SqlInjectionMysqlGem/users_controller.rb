class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

# Legacy `mysql` / `ruby-mysql` gem API (`Mysql` class), as opposed to `Mysql2`.
class UsersController < ApplicationController
  def update
    con = Mysql.new "localhost", "user", "pwd"
    con.query "UPDATE users set name = " + params[:name] + # $ Source
      " where id = " + params[:id] # $ Source Alert
    con.close
  end

  def real_connect_query
    con = Mysql.real_connect("localhost", "user", "pwd", "db")
    con.real_query("DELETE FROM users WHERE id = #{params[:id]}") # $ Alert
  end

  def connect_prepare
    con = Mysql.connect("localhost", "user", "pwd", "db")
    con.prepare("SELECT * FROM users WHERE name = '#{params[:name]}'") # $ Alert
  end

  def init_real_connect
    con = Mysql.init.real_connect("localhost", "user", "pwd", "db")
    con.query("SELECT * FROM users WHERE id = " + params[:id]) # $ Alert
  end

  # Safe: user input is passed as a bound parameter, not concatenated.
  def update_prepared
    con = Mysql.new "localhost", "user", "pwd"
    stmt = con.prepare("UPDATE users set name = ? where id = ?")
    stmt.execute(params[:name], params[:id])
  end

  # Safe: user input is escaped before concatenation.
  def update_escaped
    con = Mysql.new "localhost", "user", "pwd"
    con.query("UPDATE users set name = '" + con.escape_string(params[:name]) + "'")
  end

  # Safe: constant query.
  def list
    con = Mysql.new "localhost", "user", "pwd"
    con.query("SELECT * FROM users")
  end
end
