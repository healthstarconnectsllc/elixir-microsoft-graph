defmodule MicrosoftGraph do
  @moduledoc """
  An `HTTPoison.Base` implementation for interfacing with the [Microsoft Graph
  API](https://docs.microsoft.com/en-us/graph/overview).

  This module uses the [client credentials
  grant](https://tools.ietf.org/html/rfc6749#section-4.4) and thus should only
  be used by trusted applications. It also uses [certificate
  credentials](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials).

  ## Configuration

  The following configuration is required to authenticate and send requests to the Microsoft Graph API:

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

  def request(request) do
    request
    |> super()
    |> process_response_result()
    |> case do
      {:error, {:unauthorized, _}} ->
        # Clear authentication and retry request when token expires.
        __MODULE__
        |> Process.whereis()
        |> Agent.update(fn _ -> nil end)

        request
        |> super()
        |> process_response_result()

      result ->
        result
    end
  end

  def process_url(url) do
    "https://graph.microsoft.com/v1.0" <> url
  end

  def process_request_headers(headers) do
    authorization =
      case get_token() do
        {:ok, token} -> "Bearer #{token}"
        {:error, _} -> nil
      end

    [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"},
      {"Authorization", authorization}
      | headers
    ]
  end

  def process_request_body(body) do
    Jason.encode!(body)
  end

  # Get the authorization token stored in an `Agent`, authorizing if not
  # present.
  defp get_token do
    case Agent.start_link(fn -> nil end, name: __MODULE__) do
      {:ok, agent} -> agent
      {:error, {:already_started, agent}} -> agent
    end
    |> Agent.get_and_update(fn token ->
      case token do
        nil -> authenticate()
        token -> {:ok, token}
      end
      |> case do
        {:ok, token} -> {{:ok, token}, token}
        {:error, reason} -> {{:error, reason}, nil}
      end
    end)
  end

  # Authenticate with Microsoft Identity Platform using OAauth 2.0 flow.
  #
  # - OAuth 2.0 Client Credentials Flow: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
  # - Authentication Certificate Credentials: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
  def authenticate do
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
      URI.encode_query(%{
        "scope" => "https://graph.microsoft.com/.default",
        "client_id" => client_id,
        "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion" => token,
        "grant_type" => "client_credentials"
      })

    headers = %{"Content-Type" => "application/x-www-form-urlencoded"}

    url
    |> HTTPoison.post(params, headers)
    |> process_response_result()
    |> case do
      {:ok, body} -> {:ok, Map.get(body, "access_token")}
      error -> error
    end
  end

  defp process_response_result(response_result) do
    case response_result do
      {:ok, %Response{status_code: code, body: ""}} when code in 200..299 ->
        {:ok, Status.reason_atom(code)}

      {:ok, %Response{status_code: code, body: body}} when code in 200..299 ->
        {:ok, Jason.decode!(body)}

      {:ok, %Response{status_code: code, body: ""}} ->
        {:error, Status.reason_atom(code)}

      {:ok, %Response{status_code: code, body: body}} ->
        {:error, {Status.reason_atom(code), body |> Jason.decode!() |> Map.get("error")}}

      {:error, %Error{reason: reason}} ->
        {:error, reason}
    end
  end
end
