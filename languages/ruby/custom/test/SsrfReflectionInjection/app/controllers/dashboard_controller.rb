class DashboardController < ApplicationController
  ALLOWED_GRAPHS = %w[bar_graph pie_charts].freeze

  # Vulnerable: request parameter chooses the method invoked via `try` (CWE-470).
  def change_graph
    self.try(params[:graph]) # $ Alert

    if params[:graph] == "bar_graph"
      render "dashboard/bar_graph"
    else
      render "dashboard/pie_charts"
    end
  end

  # Vulnerable: implicit receiver and `try!`.
  def change_graph_bang
    try!(params[:graph]) # $ Alert
  end

  # Vulnerable: `send` family with a request parameter as method name.
  def change_graph_send
    name = params[:graph] # $ Source
    send(name) # $ Alert
    public_send(name) # $ Alert
    __send__(name) # $ Alert
  end

  # Safe: constant method name.
  def bar_graph_safe
    self.try(:bar_graph)
  end

  # Safe: attacker controls only part of the method name.
  def graph_suffix_safe
    self.try("render_" + params[:graph])
  end

  # Safe: request parameter is mapped to a fixed method name.
  def change_graph_mapped
    case params[:graph]
    when "bar_graph" then self.try(:bar_graph)
    else self.try(:pie_charts)
    end
  end

  # Safe: allowlist check on a constant array.
  def change_graph_allowlist
    graph = params[:graph]
    self.try(graph) if ALLOWED_GRAPHS.include?(graph)
  end

  private

  def bar_graph; end

  def pie_charts; end
end
