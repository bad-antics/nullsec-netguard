defmodule NullSec.NetGuard do
  @moduledoc """
  NullSec NetGuard - Network Connection Monitor
  
  Elixir security tool demonstrating:
  - Pattern matching for packet analysis
  - Immutable data structures
  - GenServer for stateful monitoring
  - Supervisor trees for fault tolerance
  - Option types via tagged tuples
  """

  use GenServer

  # Type specifications for safety
  @type connection :: %{
    src_ip: String.t(),
    src_port: non_neg_integer(),
    dst_ip: String.t(),
    dst_port: non_neg_integer(),
    protocol: :tcp | :udp | :icmp,
    state: :established | :syn_sent | :fin_wait | :closed,
    timestamp: DateTime.t()
  }

  @type threat_level :: :critical | :high | :medium | :low | :info
  @type analysis_result :: {:ok, map()} | {:error, String.t()}

  # Suspicious ports that may indicate threats
  @suspicious_ports [
    {4444, :critical, "Metasploit default"},
    {5555, :high, "Android ADB"},
    {6666, :high, "IRC backdoor"},
    {6667, :medium, "IRC"},
    {31337, :critical, "Elite backdoor"},
    {12345, :high, "NetBus trojan"},
    {27374, :critical, "SubSeven trojan"},
    {1080, :medium, "SOCKS proxy"},
    {3128, :medium, "Squid proxy"},
    {8080, :low, "HTTP proxy"},
    {9050, :medium, "Tor SOCKS"},
    {9051, :medium, "Tor control"},
    {4443, :medium, "Alternative HTTPS"},
    {8443, :low, "Alternative HTTPS"},
    {2222, :medium, "Alternative SSH"},
    {23, :high, "Telnet"},
    {21, :medium, "FTP"},
    {3389, :medium, "RDP"},
    {5900, :medium, "VNC"},
    {1433, :medium, "MSSQL"},
    {3306, :medium, "MySQL"},
    {5432, :medium, "PostgreSQL"},
    {27017, :medium, "MongoDB"},
    {6379, :medium, "Redis"}
  ]

  # Known malicious IP ranges (examples)
  @suspicious_ranges [
    {"10.0.0.0", "10.255.255.255", :info, "Private range"},
    {"192.168.0.0", "192.168.255.255", :info, "Private range"},
    {"172.16.0.0", "172.31.255.255", :info, "Private range"},
    {"0.0.0.0", "0.255.255.255", :high, "Invalid source"},
    {"127.0.0.0", "127.255.255.255", :medium, "Loopback"}
  ]

  # State structure
  defstruct connections: %{},
            alerts: [],
            stats: %{
              total_connections: 0,
              suspicious_connections: 0,
              blocked_connections: 0
            },
            config: %{
              alert_threshold: 100,
              rate_limit: 50,
              blocked_ips: MapSet.new()
            }

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the NetGuard monitoring server.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyzes a network connection for threats.
  """
  @spec analyze_connection(map()) :: analysis_result()
  def analyze_connection(conn) do
    GenServer.call(__MODULE__, {:analyze, conn})
  end

  @doc """
  Gets current monitoring statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Gets all current alerts.
  """
  @spec get_alerts() :: list()
  def get_alerts do
    GenServer.call(__MODULE__, :get_alerts)
  end

  @doc """
  Blocks an IP address.
  """
  @spec block_ip(String.t()) :: :ok
  def block_ip(ip) do
    GenServer.cast(__MODULE__, {:block_ip, ip})
  end

  @doc """
  Checks if an IP is blocked.
  """
  @spec blocked?(String.t()) :: boolean()
  def blocked?(ip) do
    GenServer.call(__MODULE__, {:blocked?, ip})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    config = Keyword.get(opts, :config, %{})
    initial_state = %__MODULE__{
      config: Map.merge(%__MODULE__{}.config, config)
    }
    {:ok, initial_state}
  end

  @impl true
  def handle_call({:analyze, conn}, _from, state) do
    case validate_connection(conn) do
      {:ok, validated_conn} ->
        {result, new_state} = do_analyze(validated_conn, state)
        {:reply, {:ok, result}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call(:get_alerts, _from, state) do
    {:reply, state.alerts, state}
  end

  @impl true
  def handle_call({:blocked?, ip}, _from, state) do
    {:reply, MapSet.member?(state.config.blocked_ips, ip), state}
  end

  @impl true
  def handle_cast({:block_ip, ip}, state) do
    new_blocked = MapSet.put(state.config.blocked_ips, ip)
    new_config = %{state.config | blocked_ips: new_blocked}
    {:noreply, %{state | config: new_config}}
  end

  # ============================================================================
  # Private Functions - Analysis
  # ============================================================================

  @spec validate_connection(map()) :: {:ok, connection()} | {:error, String.t()}
  defp validate_connection(conn) do
    with {:ok, src_ip} <- validate_ip(conn[:src_ip], "source IP"),
         {:ok, dst_ip} <- validate_ip(conn[:dst_ip], "destination IP"),
         {:ok, src_port} <- validate_port(conn[:src_port], "source port"),
         {:ok, dst_port} <- validate_port(conn[:dst_port], "destination port"),
         {:ok, protocol} <- validate_protocol(conn[:protocol]) do
      {:ok, %{
        src_ip: src_ip,
        src_port: src_port,
        dst_ip: dst_ip,
        dst_port: dst_port,
        protocol: protocol,
        state: conn[:state] || :established,
        timestamp: conn[:timestamp] || DateTime.utc_now()
      }}
    end
  end

  @spec validate_ip(any(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defp validate_ip(nil, field), do: {:error, "Missing #{field}"}
  defp validate_ip(ip, field) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> {:ok, ip}
      {:error, _} -> {:error, "Invalid #{field}: #{ip}"}
    end
  end
  defp validate_ip(_, field), do: {:error, "Invalid #{field} type"}

  @spec validate_port(any(), String.t()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  defp validate_port(nil, field), do: {:error, "Missing #{field}"}
  defp validate_port(port, _field) when is_integer(port) and port >= 0 and port <= 65535 do
    {:ok, port}
  end
  defp validate_port(port, field), do: {:error, "Invalid #{field}: #{inspect(port)}"}

  @spec validate_protocol(any()) :: {:ok, atom()} | {:error, String.t()}
  defp validate_protocol(nil), do: {:ok, :tcp}
  defp validate_protocol(proto) when proto in [:tcp, :udp, :icmp], do: {:ok, proto}
  defp validate_protocol("tcp"), do: {:ok, :tcp}
  defp validate_protocol("udp"), do: {:ok, :udp}
  defp validate_protocol("icmp"), do: {:ok, :icmp}
  defp validate_protocol(proto), do: {:error, "Invalid protocol: #{inspect(proto)}"}

  @spec do_analyze(connection(), %__MODULE__{}) :: {map(), %__MODULE__{}}
  defp do_analyze(conn, state) do
    # Check if IP is blocked
    if MapSet.member?(state.config.blocked_ips, conn.src_ip) do
      result = %{
        connection: conn,
        status: :blocked,
        threat_level: :critical,
        findings: ["Source IP is blocked"]
      }
      
      new_stats = %{state.stats | 
        total_connections: state.stats.total_connections + 1,
        blocked_connections: state.stats.blocked_connections + 1
      }
      
      {result, %{state | stats: new_stats}}
    else
      # Perform analysis
      findings = []
      |> check_suspicious_port(conn)
      |> check_ip_range(conn)
      |> check_protocol_anomalies(conn)
      
      threat_level = calculate_threat_level(findings)
      
      result = %{
        connection: conn,
        status: :analyzed,
        threat_level: threat_level,
        findings: Enum.map(findings, fn {_, _, msg} -> msg end)
      }
      
      # Update state
      new_state = update_state_with_analysis(state, conn, findings, threat_level)
      
      {result, new_state}
    end
  end

  @spec check_suspicious_port(list(), connection()) :: list()
  defp check_suspicious_port(findings, conn) do
    dst_finding = Enum.find(@suspicious_ports, fn {port, _, _} -> 
      port == conn.dst_port 
    end)
    
    src_finding = Enum.find(@suspicious_ports, fn {port, _, _} -> 
      port == conn.src_port 
    end)
    
    findings
    |> maybe_add_finding(dst_finding, "Destination port")
    |> maybe_add_finding(src_finding, "Source port")
  end

  @spec maybe_add_finding(list(), tuple() | nil, String.t()) :: list()
  defp maybe_add_finding(findings, nil, _prefix), do: findings
  defp maybe_add_finding(findings, {port, level, desc}, prefix) do
    [{port, level, "#{prefix} #{port}: #{desc}"} | findings]
  end

  @spec check_ip_range(list(), connection()) :: list()
  defp check_ip_range(findings, conn) do
    src_range = find_ip_range(conn.src_ip)
    dst_range = find_ip_range(conn.dst_ip)
    
    findings
    |> maybe_add_range_finding(src_range, "Source IP")
    |> maybe_add_range_finding(dst_range, "Destination IP")
  end

  @spec find_ip_range(String.t()) :: tuple() | nil
  defp find_ip_range(ip) do
    Enum.find(@suspicious_ranges, fn {start_ip, end_ip, _, _} ->
      ip_in_range?(ip, start_ip, end_ip)
    end)
  end

  @spec ip_in_range?(String.t(), String.t(), String.t()) :: boolean()
  defp ip_in_range?(ip, start_ip, end_ip) do
    with {:ok, ip_tuple} <- parse_ip(ip),
         {:ok, start_tuple} <- parse_ip(start_ip),
         {:ok, end_tuple} <- parse_ip(end_ip) do
      ip_to_int(ip_tuple) >= ip_to_int(start_tuple) and
        ip_to_int(ip_tuple) <= ip_to_int(end_tuple)
    else
      _ -> false
    end
  end

  @spec parse_ip(String.t()) :: {:ok, tuple()} | {:error, term()}
  defp parse_ip(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, tuple} -> {:ok, tuple}
      error -> error
    end
  end

  @spec ip_to_int(tuple()) :: non_neg_integer()
  defp ip_to_int({a, b, c, d}) do
    a * 16_777_216 + b * 65_536 + c * 256 + d
  end

  @spec maybe_add_range_finding(list(), tuple() | nil, String.t()) :: list()
  defp maybe_add_range_finding(findings, nil, _prefix), do: findings
  defp maybe_add_range_finding(findings, {_, _, level, desc}, prefix) do
    [{0, level, "#{prefix} in #{desc}"} | findings]
  end

  @spec check_protocol_anomalies(list(), connection()) :: list()
  defp check_protocol_anomalies(findings, conn) do
    case {conn.protocol, conn.dst_port} do
      {:tcp, 53} ->
        [{53, :medium, "TCP DNS (potential DNS tunneling)"} | findings]
      
      {:udp, port} when port < 1024 and port not in [53, 67, 68, 123, 161, 162, 514] ->
        [{port, :medium, "UDP to privileged port #{port}"} | findings]
      
      {:icmp, _} ->
        [{0, :low, "ICMP traffic detected"} | findings]
      
      _ ->
        findings
    end
  end

  @spec calculate_threat_level(list()) :: threat_level()
  defp calculate_threat_level([]), do: :info
  defp calculate_threat_level(findings) do
    findings
    |> Enum.map(fn {_, level, _} -> level end)
    |> Enum.max_by(&threat_priority/1)
  end

  @spec threat_priority(threat_level()) :: integer()
  defp threat_priority(:critical), do: 5
  defp threat_priority(:high), do: 4
  defp threat_priority(:medium), do: 3
  defp threat_priority(:low), do: 2
  defp threat_priority(:info), do: 1

  @spec update_state_with_analysis(%__MODULE__{}, connection(), list(), threat_level()) :: %__MODULE__{}
  defp update_state_with_analysis(state, conn, findings, threat_level) do
    # Update stats
    is_suspicious = threat_level in [:critical, :high, :medium]
    
    new_stats = %{state.stats |
      total_connections: state.stats.total_connections + 1,
      suspicious_connections: state.stats.suspicious_connections + (if is_suspicious, do: 1, else: 0)
    }
    
    # Add alert if suspicious
    new_alerts = if is_suspicious do
      alert = %{
        timestamp: DateTime.utc_now(),
        connection: conn,
        threat_level: threat_level,
        findings: findings
      }
      [alert | Enum.take(state.alerts, 999)]
    else
      state.alerts
    end
    
    # Store connection
    conn_key = "#{conn.src_ip}:#{conn.src_port}->#{conn.dst_ip}:#{conn.dst_port}"
    new_connections = Map.put(state.connections, conn_key, conn)
    
    %{state | 
      stats: new_stats, 
      alerts: new_alerts, 
      connections: new_connections
    }
  end
end

# ============================================================================
# CLI Module
# ============================================================================

defmodule NullSec.NetGuard.CLI do
  @moduledoc """
  Command-line interface for NetGuard.
  """

  alias NullSec.NetGuard

  @doc """
  Main entry point for CLI.
  """
  def main(args) do
    {opts, files, _} = OptionParser.parse(args,
      switches: [
        help: :boolean,
        live: :boolean,
        json: :boolean,
        block: :string
      ],
      aliases: [
        h: :help,
        l: :live,
        j: :json,
        b: :block
      ]
    )

    cond do
      opts[:help] ->
        print_help()

      opts[:block] ->
        block_ip(opts[:block])

      opts[:live] ->
        live_monitor()

      length(files) > 0 ->
        analyze_files(files, opts)

      true ->
        demo_mode(opts)
    end
  end

  defp print_help do
    IO.puts("""
    
    ╔══════════════════════════════════════════════════════════════════╗
    ║           NullSec NetGuard - Network Connection Monitor          ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    USAGE:
        netguard [OPTIONS] [FILES...]
    
    OPTIONS:
        -h, --help      Show this help message
        -l, --live      Live monitoring mode (requires root)
        -j, --json      Output results as JSON
        -b, --block IP  Block an IP address
    
    EXAMPLES:
        netguard connections.log     Analyze connection log
        netguard --live              Start live monitoring
        netguard --block 192.168.1.1 Block an IP address
    
    THREAT LEVELS:
        CRITICAL  Known malware ports, backdoors
        HIGH      Suspicious services, dangerous protocols
        MEDIUM    Unusual patterns, potential tunneling
        LOW       Minor concerns, informational
        INFO      Normal traffic
    
    """)
  end

  defp block_ip(ip) do
    {:ok, _pid} = NetGuard.start_link()
    NetGuard.block_ip(ip)
    IO.puts("✓ Blocked IP: #{ip}")
  end

  defp live_monitor do
    IO.puts("""
    
    ╔══════════════════════════════════════════════════════════════════╗
    ║                    NetGuard Live Monitoring                      ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    [!] Live monitoring requires root privileges and libpcap.
    [!] This is a demonstration mode with simulated connections.
    
    """)

    {:ok, _pid} = NetGuard.start_link()
    
    # Simulate live traffic
    simulate_traffic()
  end

  defp simulate_traffic do
    connections = [
      %{src_ip: "192.168.1.100", src_port: 54321, dst_ip: "8.8.8.8", dst_port: 53, protocol: :udp},
      %{src_ip: "10.0.0.50", src_port: 45000, dst_ip: "192.168.1.1", dst_port: 22, protocol: :tcp},
      %{src_ip: "172.16.0.100", src_port: 31337, dst_ip: "evil.example.com", dst_port: 4444, protocol: :tcp},
      %{src_ip: "192.168.1.200", src_port: 50000, dst_ip: "93.184.216.34", dst_port: 443, protocol: :tcp},
      %{src_ip: "10.0.0.25", src_port: 12345, dst_ip: "192.168.1.50", dst_port: 3389, protocol: :tcp},
      %{src_ip: "0.0.0.1", src_port: 1, dst_ip: "192.168.1.1", dst_port: 80, protocol: :tcp},
      %{src_ip: "192.168.1.10", src_port: 55555, dst_ip: "127.0.0.1", dst_port: 9050, protocol: :tcp}
    ]

    Enum.each(connections, fn conn ->
      Process.sleep(500)
      
      case NetGuard.analyze_connection(conn) do
        {:ok, result} ->
          print_connection_result(result)
        
        {:error, reason} ->
          IO.puts("  [ERROR] #{reason}")
      end
    end)

    IO.puts("\n" <> String.duplicate("─", 70))
    stats = NetGuard.get_stats()
    IO.puts("""
    
    SUMMARY:
      Total Connections:      #{stats.total_connections}
      Suspicious Connections: #{stats.suspicious_connections}
      Blocked Connections:    #{stats.blocked_connections}
    """)
  end

  defp print_connection_result(result) do
    conn = result.connection
    level_color = threat_color(result.threat_level)
    level_str = result.threat_level |> Atom.to_string() |> String.upcase()
    
    IO.puts("#{level_color}[#{level_str}]#{IO.ANSI.reset()} " <>
      "#{conn.src_ip}:#{conn.src_port} → #{conn.dst_ip}:#{conn.dst_port} " <>
      "(#{conn.protocol})")
    
    Enum.each(result.findings, fn finding ->
      IO.puts("         └─ #{finding}")
    end)
  end

  defp threat_color(:critical), do: IO.ANSI.red() <> IO.ANSI.bright()
  defp threat_color(:high), do: IO.ANSI.red()
  defp threat_color(:medium), do: IO.ANSI.yellow()
  defp threat_color(:low), do: IO.ANSI.cyan()
  defp threat_color(:info), do: IO.ANSI.green()

  defp analyze_files(files, opts) do
    {:ok, _pid} = NetGuard.start_link()
    
    Enum.each(files, fn file ->
      IO.puts("\nAnalyzing: #{file}")
      IO.puts(String.duplicate("─", 70))
      
      case parse_connection_log(file) do
        {:ok, connections} ->
          Enum.each(connections, fn conn ->
            case NetGuard.analyze_connection(conn) do
              {:ok, result} ->
                if opts[:json] do
                  IO.puts(Jason.encode!(result, pretty: true))
                else
                  print_connection_result(result)
                end
              
              {:error, reason} ->
                IO.puts("  [ERROR] #{reason}")
            end
          end)
        
        {:error, reason} ->
          IO.puts("  [ERROR] Could not parse file: #{reason}")
      end
    end)
  end

  defp parse_connection_log(file) do
    case File.read(file) do
      {:ok, content} ->
        connections = content
        |> String.split("\n", trim: true)
        |> Enum.map(&parse_log_line/1)
        |> Enum.filter(&(&1 != nil))
        
        {:ok, connections}
      
      {:error, reason} ->
        {:error, reason}
    end
  end

  # Parse netstat-style output: tcp 0 0 192.168.1.1:22 10.0.0.1:54321 ESTABLISHED
  defp parse_log_line(line) do
    case String.split(line, ~r/\s+/) do
      [proto, _, _, local, remote | _] ->
        with [src_ip, src_port] <- parse_addr(local),
             [dst_ip, dst_port] <- parse_addr(remote) do
          %{
            src_ip: src_ip,
            src_port: String.to_integer(src_port),
            dst_ip: dst_ip,
            dst_port: String.to_integer(dst_port),
            protocol: String.to_atom(proto)
          }
        else
          _ -> nil
        end
      
      _ -> nil
    end
  end

  defp parse_addr(addr) do
    case String.split(addr, ":") do
      [ip, port] -> [ip, port]
      _ -> nil
    end
  end

  defp demo_mode(opts) do
    IO.puts("""
    
    ╔══════════════════════════════════════════════════════════════════╗
    ║           NullSec NetGuard - Network Connection Monitor          ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    Running demonstration with sample connections...
    
    """)
    
    live_monitor()
  end
end
