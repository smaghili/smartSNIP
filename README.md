# Smart DNS Anti-Sanction System

سیستم حرفه‌ای دور زدن تحریم‌های اینترنتی با استفاده از DNS-over-HTTPS (DoH) و SNI Proxy

## ویژگی‌ها

- **DNS-over-HTTPS (DoH)** و **DNS-over-TLS (DoT)**: رمزنگاری کامل درخواست‌های DNS
- **SNI Proxy**: مسیریابی شفاف ترافیک HTTPS از سرور خارج
- **پشتیبانی از WARP**: مسیریابی از طریق پروکسی Cloudflare
- **معماری دو سروره**: سرور ایران + سرور خارج
- **دور زدن تحریم‌های IP**: دسترسی به سایت‌های تحریم‌شده از طریق سرور خارج

## نصب

### سرور خارج (Foreign Server)
ابتدا روی سرور خارج از تحریم خود اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/smaghili/smartSNIP/main/install_foreign.sh)
```

این اسکریپت نصب می‌کند:
- سرور DoH (DNS-over-HTTPS) روی پورت 8080
- SNI Proxy برای مسیریابی ترافیک
- گواهی SSL خودکار
- پشتیبانی اختیاری WARP (Cloudflare Proxy)

### سرور ایران (Iran Server)
بعد از نصب سرور خارج، روی سرور داخل ایران اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/smaghili/smartSNIP/main/install_iran.sh)
```

این اسکریپت نصب می‌کند:
- سرور DoH/DoT محلی
- SNI Proxy برای ارتباط با سرور خارج
- پیکربندی خودکار Nginx

## پیکربندی

### سرور خارج (`foreign_config.json`)

```json
{
  "upstream_doh": "https://1.1.1.1/dns-query",
  "port": 8080,
  "domains": {}
}
```

### سرور ایران (`iran_config.json`)

```json
{
  "host": "your-iran-domain.com",
  "server_ip": "IRAN_SERVER_IP",
  "foreign_doh_url": "https://your-foreign-domain.com/dns-query",
  "domains": {
    "youtube": "FOREIGN_SERVER_IP",
    "googlevideo": "FOREIGN_SERVER_IP",
    "android": "FOREIGN_SERVER_IP",
    "twitter": "warp",
    "instagram": "warp"
  }
}
```

**توضیحات:**
- **IP سرور خارج**: ترافیک از سرور خارج شما عبور می‌کند
- **`"warp"`**: ترافیک از پروکسی Cloudflare WARP عبور می‌کند
- **مچینگ نرم**: کافی است بخشی از دامنه را بنویسید (مثلاً `youtube` برای همه زیردامنه‌های یوتیوب)

## پورت‌های سرویس

### سرور ایران
- **443**: SNI Proxy (HTTPS)
- **8080**: DoH Server (داخلی)
- **8443**: DoH Server (Nginx HTTPS)
- **853**: DoT Server

### سرور خارج
- **443**: SNI Proxy (HTTPS)
- **8080**: DoH Server (داخلی)
- **4443**: DoH Server (Nginx HTTPS)
- **50000**: WARP SOCKS5 Proxy (اختیاری)

## تست

### تست DoH سرور ایران
```bash
curl -H "Content-Type: application/dns-message" \
  --data-binary @<(echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d) \
  https://your-iran-domain.com/dns-query
```

### تست DoH سرور خارج
```bash
curl -H "Content-Type: application/dns-message" \
  --data-binary @<(echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d) \
  https://your-foreign-domain.com:4443/dns-query
```

## Contributions

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.

## Credits

Special thanks to [Peyman](https://github.com/Ptechgithub) for auto install script

## License

This project is open-source and available under the [MIT License](LICENSE).

