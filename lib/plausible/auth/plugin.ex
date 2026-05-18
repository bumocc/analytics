defmodule Plausible.Auth.Plugin do
  @moduledoc """
  Authentication plugin behaviour and dispatcher.

  Allows swapping the authentication mechanism without modifying core code.
  Configure via:

      config :plausible, auth_plugin: Plausible.Auth.CenterServerPlugin

  Or via environment variable:

      PL_AUTH_PLUGIN=Plausible.Auth.CenterServerPlugin

  When not configured or set to nil, the default Plausible authentication is used.
  Plugin implementation files can be placed outside the project tree and loaded
  at startup via the PL_PLUGIN_PATH environment variable.
  """

  @type conn :: Plug.Conn.t()
  @type user :: Plausible.Auth.User.t()

  @doc "Whether this plugin is currently active."
  @callback enabled?() :: boolean()

  @doc "Generate a login redirect URL. Return nil if plugin doesn't handle login."
  @callback login_url(return_to :: String.t() | nil) :: String.t() | nil

  @doc """
  Handle authentication callback from external provider.

  Should return `{:ok, conn, user}` on success (conn may contain session modifications),
  or `{:error, reason}` on failure.
  """
  @callback handle_callback(conn, params :: map()) ::
              {:ok, conn, user} | {:error, atom()}

  @doc """
  Authenticate a request via the plugin (e.g. token in cookie/header).

  Return `{:ok, conn, user}` if authenticated, `:not_applied` if plugin
  doesn't handle this request, or `{:error, reason}` on failure.
  """
  @callback authenticate(conn) ::
              {:ok, conn, user} | :not_applied | {:error, atom()}

  @doc """
  Authenticate from LiveView session data.

  Return `{:ok, user}` if authenticated, `:not_applied` if plugin
  doesn't handle this session, or `{:error, reason}` on failure.
  """
  @callback authenticate_from_session(session :: map()) ::
              {:ok, user} | :not_applied | {:error, atom()}

  @doc "Called after user logs in. Can set cookies, session data, etc."
  @callback on_logged_in(conn, user) :: conn

  @doc "Called after user logs out. Can clear cookies, etc."
  @callback on_logged_out(conn) :: conn

  @doc "Whether to skip email verification requirement for plugin users."
  @callback skip_email_verification?() :: boolean()

  @doc "Whether to skip 2FA requirement for plugin users."
  @callback skip_2fa?() :: boolean()

  @doc "Whether to hide email change UI for plugin users."
  @callback hide_email_change?() :: boolean()

  @doc "Whether to hide password change UI for plugin users."
  @callback hide_password_change?() :: boolean()

  @doc "Whether to hide 2FA setup UI for plugin users."
  @callback hide_2fa_setup?() :: boolean()

  @doc "Whether to show the user avatar in the header."
  @callback show_avatar?() :: boolean()

  # --- Dispatcher ---

  @doc "Returns the configured auth plugin module, or nil."
  def module do
    case Application.get_env(:plausible, :auth_plugin) do
      nil -> nil
      mod when is_atom(mod) -> mod
    end
  end

  def enabled? do
    case module() do
      nil -> false
      mod -> mod.enabled?()
    end
  end

  def login_url(return_to \\ nil) do
    case module() do
      nil -> nil
      mod -> mod.login_url(return_to)
    end
  end

  def handle_callback(conn, params) do
    case module() do
      nil -> {:error, :no_plugin}
      mod -> mod.handle_callback(conn, params)
    end
  end

  def authenticate(conn) do
    case module() do
      nil -> :not_applied
      mod -> mod.authenticate(conn)
    end
  end

  def authenticate_from_session(session) do
    case module() do
      nil -> :not_applied
      mod -> mod.authenticate_from_session(session)
    end
  end

  def on_logged_in(conn, user) do
    case module() do
      nil -> conn
      mod -> mod.on_logged_in(conn, user)
    end
  end

  def on_logged_out(conn) do
    case module() do
      nil -> conn
      mod -> mod.on_logged_out(conn)
    end
  end

  def skip_email_verification? do
    case module() do
      nil -> false
      mod -> mod.skip_email_verification?()
    end
  end

  def skip_2fa? do
    case module() do
      nil -> false
      mod -> mod.skip_2fa?()
    end
  end

  def hide_email_change? do
    case module() do
      nil -> false
      mod -> mod.hide_email_change?()
    end
  end

  def hide_password_change? do
    case module() do
      nil -> false
      mod -> mod.hide_password_change?()
    end
  end

  def hide_2fa_setup? do
    case module() do
      nil -> false
      mod -> mod.hide_2fa_setup?()
    end
  end

  def show_avatar? do
    case module() do
      nil -> true
      mod -> mod.show_avatar?()
    end
  end

  @doc """
  Loads a plugin .ex file at runtime.

  Called during application startup when PL_PLUGIN_PATH is set.
  Compiles the file and ensures the specified module is loaded.
  """
  def load_plugin_file(path) when is_binary(path) do
    if File.exists?(path) do
      Code.compile_file(path)
    else
      raise "PL_PLUGIN_PATH points to non-existent file: #{path}"
    end
  end

  def load_plugin_file(_), do: :ok
end