defmodule PlausibleWeb.RequireAccountPlug do
  alias PlausibleWeb.Router.Helpers, as: Routes
  alias Plausible.Auth.Plugin
  import Plug.Conn

  @unverified_email_exceptions [
    ["activate"],
    ["settings"],
    ["settings", "security"],
    ["settings", "preferences"],
    ["settings", "api-keys"]
  ]

  @force_2fa_exceptions [
    ["2fa", "setup", "force-initiate"],
    ["2fa", "setup", "initiate"],
    ["2fa", "setup", "verify"],
    ["2fa", "verify"],
    ["2fa", "use_recovery_code"],
    ["settings"],
    ["settings", "security"],
    ["settings", "preferences"],
    ["settings", "api-keys"],
    ["logout"]
  ]

  def init(_), do: nil

  def call(conn, _opts) do
    conn
    |> require_user()
    |> require_verified_email()
    |> maybe_force_2fa()
  end

  defp require_user(conn) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> Phoenix.Controller.redirect(to: redirect_to(conn))
      |> halt()
    end
  end

  defp redirect_to(conn) do
    team_identifier = conn.assigns[:current_team_id]

    if team_identifier do
      Routes.auth_path(conn, :login_form, team_identifier: team_identifier)
    else
      Routes.auth_path(conn, :login_form)
    end
  end

  defp require_verified_email(conn) do
    user = conn.assigns[:current_user]

    if Plugin.enabled?() or user.email_verified or
         conn.path_info in @unverified_email_exceptions do
      conn
    else
      conn
      |> Phoenix.Controller.redirect(to: "/activate")
      |> halt()
    end
  end

  defp maybe_force_2fa(%{halted: true} = conn), do: conn

  defp maybe_force_2fa(conn) do
    if Plugin.enabled?() do
      conn
    else
      user = conn.assigns[:current_user]
      team = conn.assigns[:current_team]

      if conn.path_info not in @force_2fa_exceptions and must_enable_2fa?(user, team) do
        conn
        |> Phoenix.Controller.redirect(to: Routes.auth_path(conn, :force_initiate_2fa_setup))
        |> halt()
      else
        conn
      end
    end
  end

  defp must_enable_2fa?(user, team) do
    not Plausible.Auth.TOTP.enabled?(user) and Plausible.Teams.force_2fa_enabled?(team)
  end
end