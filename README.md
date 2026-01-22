# NullSec NetGuard

Network connection monitor built with Elixir, demonstrating functional programming patterns for security analysis.

## Security Features

- **Pattern Matching**: Elixir's pattern matching for packet classification
- **Immutable Data**: All connection data is immutable by default
- **Tagged Tuples**: `{:ok, result}` / `{:error, reason}` for safe error handling
- **GenServer**: Stateful monitoring with crash recovery
- **Supervisor Trees**: Fault-tolerant architecture
- **Type Specs**: Dialyzer-compatible type specifications

## Threat Detection

- 24+ suspicious port signatures
- IP range analysis (private, invalid, loopback)
- Protocol anomaly detection (DNS tunneling, etc.)
- Real-time alerting system
- Connection rate limiting
- IP blocking capability

## Installation

```bash
# Install dependencies
mix deps.get

# Build escript
mix escript.build
```

## Usage

```bash
# Show help
./nullsec_netguard --help

# Analyze connection log
./nullsec_netguard connections.log

# Live monitoring (demo mode)
./nullsec_netguard --live

# Block an IP
./nullsec_netguard --block 192.168.1.100

# JSON output
./nullsec_netguard -j connections.log
```

## API Usage

```elixir
# Start the monitor
{:ok, _pid} = NullSec.NetGuard.start_link()

# Analyze a connection
conn = %{
  src_ip: "192.168.1.100",
  src_port: 54321,
  dst_ip: "8.8.8.8",
  dst_port: 53,
  protocol: :udp
}

case NullSec.NetGuard.analyze_connection(conn) do
  {:ok, result} ->
    IO.inspect(result.threat_level)
    IO.inspect(result.findings)
  
  {:error, reason} ->
    IO.puts("Error: #{reason}")
end

# Get statistics
stats = NullSec.NetGuard.get_stats()

# Block an IP
NullSec.NetGuard.block_ip("10.0.0.1")

# Check if blocked
NullSec.NetGuard.blocked?("10.0.0.1")  # => true
```

## Threat Levels

| Level | Description |
|-------|-------------|
| CRITICAL | Known malware ports, backdoors |
| HIGH | Suspicious services, dangerous protocols |
| MEDIUM | Unusual patterns, potential tunneling |
| LOW | Minor concerns |
| INFO | Normal traffic |

## Suspicious Ports Detected

- **Critical**: 4444 (Metasploit), 31337 (Elite), 27374 (SubSeven)
- **High**: 5555 (ADB), 6666 (IRC backdoor), 12345 (NetBus), 23 (Telnet)
- **Medium**: 9050/9051 (Tor), 3389 (RDP), 5900 (VNC), database ports

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Application                        │
├─────────────────────────────────────────────────────┤
│  CLI Module          │  NetGuard GenServer          │
│  ┌─────────────┐    │  ┌───────────────────────┐   │
│  │ main/1      │    │  │ State:                │   │
│  │ parse_args  │────│──│  - connections        │   │
│  │ output      │    │  │  - alerts             │   │
│  └─────────────┘    │  │  - stats              │   │
│                      │  │  - config             │   │
│                      │  └───────────────────────┘   │
├─────────────────────────────────────────────────────┤
│  Analysis Pipeline (Pure Functions)                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ validate │─▶│ analyze  │─▶│ calculate_threat │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## License

MIT License - Part of the NullSec Framework

## Author

- GitHub: [bad-antics](https://github.com/bad-antics)
- Discord: [discord.gg/killers](https://discord.gg/killers)
