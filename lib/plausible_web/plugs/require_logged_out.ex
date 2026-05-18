defmodule PlausibleWeb.RequireLoggedOutPlug do
  import Plug.Conn

  alias Plausible.Auth.Plugin

  def init(opts \\ []) do
    opts
  end

  def call(conn, _opts) do
    if conn.assigns[:current_user] do
      if Plugin.enabled?() do
        conn
        |> Plugin.on_logged_in(conn.assigns[:current_user])
        |> Phoenix.Controller.redirect(to: "/sites")
        |> halt()
      else
        conn
        |> PlausibleWeb.UserAuth.set_logged_in_cookie()
        |> Phoenix.Controller.redirect(to: "/sites")
        |> halt()
      end
    else
      conn
    end
  end
end