# ProDuckX-DNS — ESP32-S3 DNS Sinkhole

DNS sinkhole (chặn quảng cáo/tracker ở tầng DNS) + dashboard web, chạy trên **ESP32-S3 N16R8** (16 MB flash, 8 MB PSRAM).

- Blocklist dạng **hash 40-bit FNV-1a** đã sắp xếp, lưu trên **LittleFS (flash)**.
- Khi chạy, blocklist được **nạp vào PSRAM** và tra bằng **binary search trên RAM** → nhanh, không I/O flash. Không có PSRAM thì tự fallback tra flash.
- Upstream hỗ trợ **UDP (mặc định), DoH và DoT**.
- **LED RGB** báo trạng thái.
- Dashboard giữ nguyên giao diện tại `http://produckx.local`.

## Phần cứng

| Thành phần | Giá trị |
|---|---|
| Board | ESP32-S3-WROOM-1 **N16R8** |
| Flash | 16 MB (QIO) |
| PSRAM | 8 MB (OPI / octal) |
| LED RGB | WS2812, mặc định **GPIO48** (đổi `-DRGB_LED_PIN=38` nếu board dùng GPIO38) |
| BOOT | GPIO0 — giữ khi khởi động để xoá WiFi đã lưu |

## Phân vùng flash (`partitions.csv`)

| Name | Offset | Size | Ghi chú |
|---|---|---|---|
| nvs | 0x9000 | 0x5000 | WiFi/Preferences |
| otadata | 0xe000 | 0x2000 | |
| app0 | 0x10000 | 0x300000 (3 MB) | firmware, đủ chỗ cho TLS |
| spiffs | 0x310000 | 0xCF0000 (~12.2 MB) | LittleFS: blocklist + cấu hình |

Dung lượng blocklist: **~2.5M domain** trong LittleFS (5 byte/domain). Giới hạn thực tế khi nạp PSRAM là **~1.5M domain** (8 MB / 5 byte).

## Cài đặt môi trường (Windows)

Yêu cầu: **Python 3.11** (dự án pin ở `.python-version`).

```powershell
# 1. Tạo virtualenv (bỏ qua nếu đã có thư mục venv/)
python -m venv venv

# 2. Kích hoạt venv — PowerShell
.\venv\Scripts\Activate.ps1
# ...hoặc cmd.exe:
#   venv\Scripts\activate.bat

# 3. Cài PlatformIO vào venv
pip install --upgrade pip
pip install platformio

# 4. Kiểm tra
pio --version        # hoặc: python -m platformio --version
```

> PowerShell báo `running scripts is disabled` → chạy `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` rồi kích hoạt lại.
> Linux/macOS: `python3 -m venv venv && source venv/bin/activate`.
> Không muốn activate? Cứ thay `pio` bằng `python -m platformio` trong mọi lệnh bên dưới (dùng `venv\Scripts\python.exe`).

## Build & nạp firmware

Chạy trong terminal đã kích hoạt venv:

```bash
pio run -e esp32s3                 # build
pio run -e esp32s3 -t upload       # nạp qua USB
pio run -e esp32s3 -t uploadfs     # nạp thư mục data/ (blocklist.bin)
pio device monitor                 # serial 115200
```

Lần build đầu PlatformIO sẽ tự tải platform `espressif32@6.9.0` (cần mạng).

Cấu hình WiFi/secret: copy `src/secrets.example.h` → `src/secrets.h`, sửa `WEB_USER` / `WEB_PASS` / `OTA_PASS`.
Nếu chưa cấu hình, thiết bị mở AP `ProDuckX-DNS` để nhập WiFi (captive portal).

## Tạo blocklist

```bash
python tools/build_blocklist.py [out.bin] [nguồn ...]
```

Mặc định ghi ra `data/blocklist.bin` (~100k domain). Muốn nhiều hơn, đổi nguồn `light-onlydomains.txt` → `pro-onlydomains.txt` (~370k) trong `DEFAULT_SOURCES`, hoặc truyền nguồn riêng.

Sau khi có file, có thể:
- Nạp qua USB: `pio run -t uploadfs`, hoặc
- Upload trong dashboard (mục **BLOCKLIST — UPLOAD**), hoặc
- Trỏ **BLOCKLIST — REMOTE AUTO-UPDATE** tới URL chứa `blocklist.bin`.

## Upstream DNS: DoH / DoT

Mặc định dùng DNS hệ thống/DHCP. Đổi resolver bằng endpoint `/setdns` (yêu cầu đang đăng nhập dashboard + header CSRF). Mở DevTools Console trên dashboard:

```js
const H = {'X-Requested-With':'produckx-adblock'};

// DNS over HTTPS
fetch('/setdns?doh='+encodeURIComponent('https://cloudflare-dns.com/dns-query'),{headers:H}).then(r=>r.text()).then(alert);
// DNS over TLS
fetch('/setdns?dot=1.1.1.1',{headers:H}).then(r=>r.text()).then(alert);
// Quay về DNS hệ thống / router / IP tĩnh
fetch('/setdns?reset=1',{headers:H});
fetch('/setdns?router=1',{headers:H});
fetch('/setdns?ip=9.9.9.9',{headers:H});
```

Cấu hình được lưu vào `/upstream.cfg` và giữ sau reboot.

Giá trị mặc định khi chưa cấu hình (có thể override qua `build_flags`):
- `DEFAULT_DOH_URL` = `https://cloudflare-dns.com/dns-query`
- `DEFAULT_DOT_HOST` = `1.1.1.1`

> DoH/DoT dùng `setInsecure()` (không pin chứng chỉ) — phù hợp cho resolver công cộng, không cần xác thực CA trên thiết bị.

## Đèn LED RGB (trạng thái)

| Màu | Ý nghĩa |
|---|---|
| Xanh dương | Đang khởi động |
| Đỏ nhấp nháy | Chưa kết nối WiFi / đang ở setup portal |
| Xanh lá | Đang chặn bình thường |
| Vàng | Đang tạm dừng chặn (pause) |
| Tím | Chưa có blocklist |

## Dashboard & API

- `http://produckx.local` (hoặc IP thiết bị), đăng nhập bằng `WEB_USER`/`WEB_PASS`.
- Các endpoint chính: `/stats.json`, `/ban`, `/addblock`, `/unblock`, `/addwhite`, `/unwhite`, `/pause`, `/resume`, `/setupdate`, `/setdns`, `/setip`, `/setdhcp`, `/upload`, `/update`.
- Mọi endpoint thay đổi trạng thái yêu cầu header `X-Requested-With: produckx-adblock` + session cookie.

## Ghi chú kỹ thuật

- Tra cứu: hash tên miền + mọi domain cha; whitelist thắng blocklist.
- Blocklist trong PSRAM được nạp lại mỗi khi cập nhật danh sách (`/upload`, `/fetchnow`).
- Nếu `malloc` PSRAM thất bại (board không có PSRAM/không bật), firmware tự dùng chỉ mục flash + cache như bản cũ.
- Hash 40-bit: có thể có va chạm (chặn nhầm rất ít), đánh đổi để giảm dung lượng.
