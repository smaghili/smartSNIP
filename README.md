# Smart SNI and DNS Proxy Server

Production-ready SNI-based HTTPS proxy with DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) support.

## Features

- **DNS-over-HTTPS (DoH)** and **DNS-over-TLS (DoT)** support
- **SNI Proxy**: Transparent HTTPS traffic routing
- **Warp Support**: SOCKS5 proxy routing
- **Auto-Recovery**: Watchdog prevents resource exhaustion
- **Rate limiting** with token bucket algorithm

## Configuration

Edit `config.json`:

```json
{
  "host": "your-domain.com",
  "server_ip": "YOUR_SERVER_IP",
  "domains": {
    "youtube.com": "1.2.3.4",
    "google.com": "1.2.3.4",
    "facebook.com": "1.2.3.4",
    "instagram.com": "warp",
    "*.tiktok.com": "warp"
  }
}
```

- **IP Address**: Route directly to specified IP
- **`"warp"`**: Route through SOCKS5 proxy
- **Wildcard**: Use `*.domain.com` for subdomains

## Installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/smaghili/smartSNI/main/install.sh)
```

## Service Ports

- **443**: SNI Proxy (HTTPS)
- **8080**: DNS-over-HTTPS (DoH)
- **853**: DNS-over-TLS (DoT)

## Quick Test

```bash
# Test DoH
curl "http://localhost:8080/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

# Test SNI Proxy
curl -k https://your-domain.com
```

## Contributions

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.

## Credits

Special thanks to [Peyman](https://github.com/Ptechgithub) for auto install script

## License

This project is open-source and available under the [MIT License](LICENSE).
