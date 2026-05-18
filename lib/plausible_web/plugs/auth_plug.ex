defmodule PlausibleWeb.AuthPlug do
  @moduledoc """
  Plug for populating conn assigns with user data.

  Supports two authentication modes:
  1. Auth plugin (if configured) - validates via plugin mechanism
  2. Plausible session token - fallback for backwards compatibility

  Must be kept in sync with `PlausibleWeb.Live.AuthContext`.
  """

  use Plausible
  import Plug.Conn

  alias Plausible.Auth.Plugin
  alias PlausibleWeb.UserAuth

  def init(options) do
    options
  end

  def call(conn, _opts) do
    case Plugin.authenticate(conn) do
      {:ok, conn, user} ->
        conn = maybe_create_plausible_session(conn, user)
        check_subscription_and_assign(conn, user, nil)

      {:error, {:not_subscribed, redirect_url}} ->
        conn
        |> Phoenix.Controller.redirect(external: redirect_url)
        |> Plug.Conn.halt()

      :not_applied ->
        case UserAuth.get_user_session(conn) do
          {:ok, user_session} ->
            user = user_session.user
            check_subscription_and_assign(conn, user, user_session)

          {:error, :session_expired, user_session} ->
            assign(conn, :expired_session, user_session)

          _ ->
            conn
        end
    end
  end

  defp maybe_create_plausible_session(conn, user) do
    case UserAuth.get_user_session(conn) do
      {:ok, _} ->
        conn

      _ ->
        session = Plausible.Auth.UserSessions.create!(user, "Plugin Auth")
        token = session.token

        conn
        |> Plug.Conn.configure_session(renew: true)
        |> Plug.Conn.put_session(:user_token, token)
    end
  end

  defp assign_user_data(conn, user, user_session) do
    current_team_id_from_session = Plug.Conn.get_session(conn, "current_team_id")

    current_team_id =
      conn.params["__team"] || current_team_id_from_session || user.last_team_identifier

    {current_team, current_team_role} =
      if current_team_id do
        team_membership =
          Enum.find(user.team_memberships, %{}, &(&1.team.identifier == current_team_id))

        {Map.get(team_membership, :team), Map.get(team_membership, :role)}
      else
        {nil, nil}
      end

    conn =
      cond do
        current_team && current_team_id != current_team_id_from_session ->
          Plausible.Users.remember_last_team(user, current_team_id)
          Plug.Conn.put_session(conn, "current_team_id", current_team_id)

        is_nil(current_team) && not is_nil(current_team_id_from_session) ->
          Plausible.Users.remember_last_team(user, nil)
          Plug.Conn.delete_session(conn, "current_team_id")

        true ->
          conn
      end

    my_team =
      user.team_memberships
      |> Enum.find(%{}, &(&1.role == :owner and &1.team.setup_complete == false))
      |> Map.get(:team)

    teams_count = length(user.team_memberships)

    teams =
      user.team_memberships
      |> Enum.filter(& &1.team.setup_complete)
      |> Enum.sort_by(fn tm -> [tm.role != :owner, tm.team_id] end)
      |> Enum.map(&Map.fetch!(&1, :team))
      |> Enum.take(3)

    Plausible.OpenTelemetry.add_user_attributes(user)

    Sentry.Context.set_user_context(%{id: user.id, name: user.name, email: user.email})

    on_ee do
      Plausible.Audit.set_context(%{
        current_user: user,
        current_team: current_team
      })
    end

    conn
    |> assign(:current_user, user)
    |> assign(:current_user_session, user_session)
    |> assign(:my_team, my_team)
    |> assign(:current_team, current_team || my_team)
    |> assign(:current_team_role, current_team_role || (my_team && :owner))
    |> assign(:teams_count, teams_count)
    |> assign(:teams, teams)
    |> assign(:more_teams?, teams_count > 3)
  end

  defp check_subscription_and_assign(conn, user, user_session) do
    case plugin_subscription_check(user) do
      {:error, redirect_url} ->
        conn
        |> Phoenix.Controller.redirect(external: redirect_url)
        |> Plug.Conn.halt()

      :ok ->
        assign_user_data(conn, user, user_session)
    end
  end

  defp plugin_subscription_check(user) do
    try do
      Plausible.Auth.CenterServerPlugin.require_subscription!(user)
    rescue
      UndefinedFunctionError -> :ok
    end
  end
end
