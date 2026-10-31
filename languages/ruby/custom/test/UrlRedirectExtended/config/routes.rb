Rails.application.routes.draw do
  get "login" => "sessions#new"
  resources :sessions
  resources :accounts
end
