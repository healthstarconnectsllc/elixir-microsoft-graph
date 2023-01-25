defmodule MicrosoftGraph.MixProject do
  use Mix.Project

  def project do
    [
      app: :microsoft_graph,
      version: "0.1.1",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:httpoison, "~> 1.6"},
      {:jason, "~> 1.2"},
      {:joken, "~> 2.3"},
      {:plug, "~> 1.11"},
      {:uuid, "~> 1.1"},
      {:x509, "~> 0.8.2"},
    ]
  end
end
