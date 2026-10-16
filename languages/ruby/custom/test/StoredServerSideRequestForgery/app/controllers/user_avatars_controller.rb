require 'open-uri'
require 'net/http'

class UserAvatarsController < ActionController::Base
  ALLOWED_AVATAR_URLS = ["https://cdn.example.com/default.png"]

  # BAD: stored, user-controlled URL fetched with Kernel#open
  def show
    user = User.find(params[:id])
    if user && user.avatar_url
      send_data(open(user.avatar_url).read, disposition: 'inline') # $ Alert[rb/stored-request-forgery]
    end
  end

  # BAD: stored, user-controlled URL fetched with URI.open
  def show_uri_open
    user = User.find_by(id: params[:id])
    URI.open(user.avatar_url).read # $ Alert[rb/stored-request-forgery]
  end

  # BAD: stored, user-controlled host fetched with Net::HTTP
  def show_net_http
    user = User.where(id: params[:id]).first
    Net::HTTP.get(user.avatar_host, "/avatar.png") # $ Alert[rb/stored-request-forgery]
  end

  # GOOD: stored value only used as a path under a fixed host
  def show_prefixed
    user = User.find(params[:id])
    URI.open("https://cdn.example.com/#{user.avatar_url}").read
  end

  # GOOD: stored value checked against an allow-list
  def show_allow_listed
    user = User.find(params[:id])
    url = user.avatar_url
    if ALLOWED_AVATAR_URLS.include?(url)
      URI.open(url).read
    end
  end

  # GOOD: constant URL
  def show_default
    URI.open("https://cdn.example.com/default.png").read
  end
end
