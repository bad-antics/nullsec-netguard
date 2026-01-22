defmodule NullSec.NetGuard.MixProject do
  use Mix.Project

  def project do
    [
      app: :nullsec_netguard,
      version: "1.0.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: escript(),
      description: "Network connection monitor with pattern matching and fault tolerance",
      package: package(),
      source_url: "https://github.com/bad-antics/nullsec-netguard"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"}
    ]
  end

  defp escript do
    [main_module: NullSec.NetGuard.CLI]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/bad-antics/nullsec-netguard"}
    ]
  end
end
