Rails.application.routes.draw do
  root 'todos#index'
  resources :todos, only: [:index, :new, :create, :update, :show, :destroy]
  resources :sessions, only: [:new, :create]

  # BAD: destroy action reachable via GET
  match 'todos/:id/complete', to: "todos#destroy", via: [:get, :delete] # $ Alert

  # BAD: state-changing actions routed from GET
  get 'users/:id/delete', to: "users#destroy" # $ Alert
  get 'users/:id/promote', to: "users#update" # $ Alert
  get 'users/new_account', to: "users#create" # $ Alert
  match 'posts/:id/remove', to: "posts#destroy", via: :all # $ Alert
  get 'comments/:id/delete', controller: "comments", action: "delete" # $ Alert

  # GOOD: state-changing actions routed from unsafe verbs
  match 'sessions', to: "sessions#destroy", via: :delete
  post 'users/:id/promote', to: "users#update"
  delete 'posts/:id', to: "posts#destroy"

  # GOOD: read-only actions routed from GET
  get 'users/:id', to: "users#show"
  get 'users/:id/edit', to: "users#edit"
end
