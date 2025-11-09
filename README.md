# Smart SNI and DNS Proxy Server

Python-based DNS proxy with DoH/DoT support, SNI-based HTTPS proxying, and whitelist-only domain filtering.

## Features

- **DNS-over-HTTPS (DoH)** and **DNS-over-TLS (DoT)** support
- **Whitelist-only mode**: Only domains in `config.json` are proxied, others return REFUSED
- **SNI Proxy**: Transparently proxies HTTPS traffic for whitelisted domains
- **Rate limiting** with token bucket algorithm

## Configuration

Edit `config.json`:

```json
{
  "host": "your-domain.com",
  "domains": {
    "youtube": "1.2.3.4",
    "google": "1.2.3.4",
    "facebook": "1.2.3.4"
  }
}
```

Replace `1.2.3.4` with your server's public IP address.

Only domains in the list will be resolved through your proxy (returning your server's IP). All other DNS queries are resolved via Cloudflare DoH (1.1.1.1).

## Installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/smaghili/smartSNIP/main/install.sh)
```

## Contributions

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.

## Credits

Special thanks to [Peyman](https://github.com/Ptechgithub) for auto install script

## License

This project is open-source and available under the [MIT License](LICENSE).
