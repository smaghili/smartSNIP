# Smart DNS Anti-Sanction System

سیستم حرفه‌ای دور زدن تحریم‌های اینترنتی با استفاده از DNS-over-HTTPS (DoH) و SNI Proxy

## نیازمندی‌ها

### سرورها
- **۱ سرور در ایران**: با دسترسی عمومی و IP ثابت
- **۱ سرور در خارج از ایران**: بدون تحریم (مثلاً آلمان، هلند، فرانسه)

### دامنه‌ها
- **۲ ساب‌دامین (Subdomain)**:
  - یک ساب‌دامین برای سرور ایران (مثلاً `iran.yourdomain.com`)
  - یک ساب‌دامین برای سرور خارج (مثلاً `foreign.yourdomain.com`)

### پورت‌های مورد نیاز

#### سرور ایران
پورت‌های زیر باید باز (Open) باشند:
- **80** (HTTP): برای صدور گواهی SSL
- **443** (HTTPS): SNI Proxy
- **853** (DoT): DNS over TLS
- **8443** (HTTPS): DoH Server

#### سرور خارج
پورت‌های زیر باید باز (Open) باشند:
- **80** (HTTP): برای صدور گواهی SSL
- **443** (HTTPS): SNI Proxy
- **4443** (HTTPS): DoH Server
- **50000** (اختیاری): WARP SOCKS5 Proxy

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
  "foreign_doh_url": "https://your-foreign-domain.com:4443/dns-query",
  "domains": {
    "google": "FOREIGN_SERVER_IP",
    "filter.txt": "FOREIGN_SERVER_IP",
    "ban.txt": "FOREIGN_SERVER_IP",
    "warp.txt": "FOREIGN_SERVER_IP"
  }
}
```

**توضیحات:**
- **IP سرور خارج**: ترافیک از سرور خارج شما عبور می‌کند (`FOREIGN_SERVER_IP` را با IP واقعی جایگزین کنید)
- **فایل‌های دامنه**: می‌توانید دامنه‌های دلخواه خود را در فایل‌های `filter.txt`، `ban.txt` و `warp.txt` اضافه کنید
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

