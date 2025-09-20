#Developer : C1BENK

Fitur-fitur Tambahan yang Diperkenalkan:

1. Multi-threading untuk crawling yang lebih cepat
2. Subdomain enumeration untuk menemukan subdomain target
3. Sensitive file detection untuk menemukan file konfigurasi
4. JavaScript file analysis yang mendalam
5. Comment extraction dari HTML, CSS, dan JS
6. Metadata extraction dari halaman web
7. Advanced pattern matching dengan regex yang lebih akurat
8. Randomized user agents untuk menghindari deteksi
9. Rate limiting dengan delay acak
10. DNS resolution untuk validasi subdomain
11. Error handling yang lebih robust
12. Detailed reporting dengan informasi scan

Cara Penggunaan:

```bash
# Scan dasar
python advanced_scanner.py https://example.com

# Scan dengan depth lebih dalam
python advanced_scanner.py https://example.com -d 3 -t 15

# Scan dengan output file
python advanced_scanner.py https://example.com -o results.json

# Scan dengan timeout custom
python advanced_scanner.py https://example.com -T 20
```

pkg update && pkg upgrade -y
pkg install python git clang make pkg-config -y
# Optional yg sering berguna
pkg install openssl libxml2 libxslt -y

#Install
pip install requests beautifulsoup4 dnspython tldextract fake-useragent lxml html5lib cssselect python-dateutil
