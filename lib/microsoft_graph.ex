defmodule MicrosoftGraph do
  @moduledoc """
  An `HTTPoison.Base` implementation for interfacing with the [Microsoft Graph
  API](https://docs.microsoft.com/en-us/graph/overview).

  The following OAuth 2.0 grant types are supported:

  - [Client
    Credentials](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
    (default)
  - [Resource Owner Password
    Credentials](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc)

  ## Examples

  ### Make a request using the Client Credentials grant:

      MicrosoftGraph.get("/me")

  ### Make a request using the Resource Owner Password Credentials grant:

      MicrosoftGraph.get("/me", [],
        authentication: :password,
        username: "MyUsername@myTenant.com",
        password: "SuperS3cret"
      )

  ## Configuration

  The following configuration is required to authenticate and send requests to
  the Microsoft Graph API:

      config :microsoft_graph,
        key_pem: ..., # Private key in PEM format.
        certificate_pem: ..., # X.509 certificate in PEM format.
        client_id: "896f377b-2ae1-4b02-862a-16903be15348",
        tenant_id: "7f937921-32a7-4ff6-8bd2-9ea2ab503546"
  """

  use HTTPoison.Base

  alias HTTPoison.Error
  alias HTTPoison.Response
  alias Plug.Conn.Status
  alias X509.Certificate

  @base_url "https://graph.microsoft.com/v1.0"

  def request(request) do
    with {:ok, request} <- add_authorization(request),
         {:ok, response} <- request |> super() |> process_response_result() do
      {:ok, response}
    else
      {:error, {:unauthorized, _}} ->
        clear_token(request.options)

        with {:ok, request} <- add_authorization(request) do
          request |> super() |> process_response_result()
        end

      error ->
        error
    end
  end

  @impl true
  def process_url(url) do
    @base_url <> url
  end

  @impl true
  def process_request_headers(headers) do
    [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
      | headers
    ]
  end

  @impl true
  def process_request_body(body) do
    Jason.encode!(body)
  end

  @doc """
  Get all results for a paged resource.
  """
  def get_all(url, headers \\ [], options \\ []), do: do_get_all(url, headers, options, [])

  defp do_get_all(url, headers, options, values) do
    with {:ok, %{"value" => value} = response} <- get(url, headers, options) do
      values = values ++ value

      case response do
        %{"@odata.nextLink" => @base_url <> next} ->
          # Next link includes params, so clear them out if provided in options.
          options = Keyword.delete(options, :params)

          do_get_all(next, headers, options, values)

        _ ->
          {:ok, values}
      end
    end
  end

  # Add the `Authorization` header to a request.
  defp add_authorization(request) do
    with {:ok, token} <- get_token(request.options) do
      authorization = {"Authorization", "Bearer #{token}"}
      request = %{request | headers: [authorization | request.headers]}

      {:ok, request}
    end
  end

  # Get the cached authorization token, authenticating if not present.
  defp get_token(options) do
    auth_type = auth_type(options)

    case Agent.start_link(&Map.new/0, name: __MODULE__) do
      {:ok, agent} -> agent
      {:error, {:already_started, agent}} -> agent
    end
    |> Agent.get_and_update(fn tokens ->
      case Map.get(tokens, auth_type) do
        nil -> authenticate(auth_type, options)
        token -> {:ok, token}
      end
      |> case do
        {:ok, token} -> {{:ok, token}, Map.put(tokens, auth_type, token)}
        error -> {error, Map.put(tokens, auth_type, nil)}
      end
    end)
  end

  # Clear the cached authorization token.
  defp clear_token(options) do
    auth_type = auth_type(options)

    __MODULE__
    |> Process.whereis()
    |> Agent.update(fn tokens -> Map.put(tokens, auth_type, nil) end)
  end

  defp auth_type(options), do: Keyword.get(options, :authentication, :client_credentials)

  # Authenticate with the Client Credentials grant.
  #
  # https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
  defp authenticate(:client_credentials, _options) do
    authenticate(%{
      "grant_type" => "client_credentials"
    })
  end

  # Authenticate with the Resource Owner Password Credentials grant.
  #
  # https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc
  defp authenticate(:password, options) do
    authenticate(%{
      "grant_type" => "password",
      "username" => options[:username],
      "password" => options[:password]
    })
  end

  # Authenticate with Microsoft Identity Platform using OAauth 2.0.
  #
  # https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
  defp authenticate(params) do
    key_pem = Application.get_env(:microsoft_graph, :key_pem)
    certificate_pem = Application.get_env(:microsoft_graph, :certificate_pem)
    client_id = Application.get_env(:microsoft_graph, :client_id)
    tenant_id = Application.get_env(:microsoft_graph, :tenant_id)

    url = "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token"
    now = System.os_time(:second)
    expiration = 10 * 60

    certificate_binary = certificate_pem |> Certificate.from_pem!() |> Certificate.to_der()
    certificate_hash = :sha |> :crypto.hash(certificate_binary) |> Base.encode64()
    signer = Joken.Signer.create("RS256", %{"pem" => key_pem}, %{"x5t" => certificate_hash})

    claims = %{
      "aud" => "https://login.microsoftonline.com/#{tenant_id}/oauth2/token",
      "exp" => now + expiration,
      "iss" => client_id,
      "jti" => UUID.uuid4(),
      "nbf" => now,
      "sub" => client_id
    }

    token = Joken.generate_and_sign!(%{}, claims, signer)

    params =
      params
      |> Map.merge(%{
        "scope" => "https://graph.microsoft.com/.default",
        "client_id" => client_id,
        "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion" => token
      })
      |> URI.encode_query()

    headers = %{"Content-Type" => "application/x-www-form-urlencoded"}

    url
    |> HTTPoison.post(params, headers)
    |> process_response_result()
    |> case do
      {:ok, body} -> {:ok, Map.get(body, "access_token")}
      error -> error
    end
  end

  defp process_response_result({:ok, %Response{status_code: code, body: ""}})
       when code in 200..299,
       do: {:ok, Status.reason_atom(code)}

  defp process_response_result({:ok, %Response{status_code: code, body: body}})
       when code in 200..299,
       do: parse_response_body_to_json(body)

  defp process_response_result({:ok, %Response{status_code: code, body: ""}}),
    do: {:error, Status.reason_atom(code)}

  defp process_response_result({:ok, %Response{status_code: code, body: body}}),
    do: {:error, parse_response_body_to_json(body, code)}

  defp process_response_result({:error, %Error{reason: reason}}),
    do: {:error, reason}

  defp parse_response_body_to_json(body) do
    Jason.decode(body)
  end

  defp parse_response_body_to_json(body, code) do
    with {:ok, json} <- Jason.decode(body) do
      {Status.reason_atom(code), json}
    else
      _ -> {Status.reason_atom(code), body}
    end
  end
end
