# Analyzer

A network traffic analyzer written in C that uses the `libnetfilter_queue` library for packet interception and
`nftables` for
firewall rule management. The program analyzes data streams in real-time and dynamically updates firewall sets based on
predefined rules.

## Features

* **Traffic Interception**: Integrates with `NFQUEUE` to process packets in userspace.
* **Protocol Analysis**: Parses IP, TCP, and TLS (SNI) to identify connections.
* **Processing Modules**:
    * **Domain Processor**: Tracks requests to domain names from a provided list.
    * **TCP Stream Processor**: Monitors the state of TCP sessions.
    * **Retransmit Processor**: Detects packet retransmissions.
* **nftables Integration**: Automatically populates `nftables sets` with identified IP addresses.
* **Flexible Configuration**: Configured via a TOML file.

## Dependencies and Requirements

* **Libraries**: Requires `libnetfilter_queue`, `libnftnl`, and `libmnl`.
* **Privileges**: Must be run with root privileges to manage NFQUEUE and nftables rules.

## Licenses

[MIT](https://choosealicense.com/licenses/mit/)
