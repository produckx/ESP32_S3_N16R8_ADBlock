// ProDuckX-DNS — DNS sinkhole + web dashboard for the ESP32-S3 (N16R8).
// Blocklist = sorted 40-bit FNV-1a hashes: lưu ở flash (LittleFS), nạp vào PSRAM
// lúc chạy và binary-search trên RAM; fallback tra flash nếu không có PSRAM.
// Upstream hỗ trợ UDP (mặc định), DoH và DoT. LED RGB báo trạng thái.
// Dashboard at http://produckx.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <WiFiClientSecure.h>  // https fetch / DoH / DoT
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <WiFi.h>
#include <WebServer.h>
#include <HTTPClient.h>        // remote blocklist fetch / DoH
#include <ESPmDNS.h>
#include <Update.h>           // firmware OTA
#include <Preferences.h>      // NVS store for provisioned WiFi creds
#include "esp_heap_caps.h"    // ps_malloc (PSRAM)
#include "esp32-hal-rgb-led.h" // neopixelWrite (LED RGB WS2812)
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "esp_freertos_hooks.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- log ra cả 2 cổng ----
// Với ARDUINO_USB_CDC_ON_BOOT: Serial = USB-native (COM6), Serial0 = UART0 (cầu CP210x, COM5).
// Ghi song song để mở monitor ở cổng nào cũng thấy log.
struct TeePrint : Print {
  void begin(unsigned long baud) { Serial.begin(baud); Serial0.begin(baud); }
  size_t write(uint8_t c) override { Serial.write(c); Serial0.write(c); return 1; }
  size_t write(const uint8_t* b, size_t n) override { Serial.write(b, n); Serial0.write(b, n); return n; }
};
static TeePrint Log;
#define Serial Log   // mọi Serial.* bên dưới sẽ ghi ra cả hai cổng

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);   // compile-time fallback
static IPAddress upstreamDns;          // runtime upstream, see upstreamApply()
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
// Index/cache/table sizes for the ESP32 (4 MB flash); overridable via build_flags.
#ifndef INDEX_ENTRIES
#define INDEX_ENTRIES 4096   // 20 KB first-level flash index
#endif
#ifndef CACHE_SIZE
#define CACHE_SIZE 256       // must be power of 2
#endif
// MAX_RANGE must stay >= ceil(numHashes / INDEX_ENTRIES): inFlash() clamps the bucket
// it scans to MAX_RANGE hashes, so a smaller MAX_RANGE silently misses hashes that
// land in an overfull bucket. The default 112,556-domain list over INDEX_ENTRIES
// buckets is ~110 hashes/bucket, so MAX_RANGE=256 has headroom.
#ifndef MAX_RANGE
#define MAX_RANGE 256        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)
#endif

// ---- DoH / DoT defaults (có thể override lúc chạy qua /setdns?doh=|?dot=) ----
#ifndef DEFAULT_DOH_URL
#define DEFAULT_DOH_URL "https://cloudflare-dns.com/dns-query"
#endif
#ifndef DEFAULT_DOT_HOST
#define DEFAULT_DOT_HOST "1.1.1.1"
#endif

// ---- RGB status LED (WS2812) ----
#ifndef RGB_LED_PIN
#define RGB_LED_PIN 48
#endif

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// Bản sao blocklist trong PSRAM (nạp từ flash lúc boot). blRam != null -> tra RAM.
static uint8_t* blRam = nullptr;

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

#ifndef MAX_CLIENTS
#define MAX_CLIENTS 96
#endif
#ifndef MAX_CUSTOM
#define MAX_CUSTOM 200
#endif
#ifndef MAX_WHITE
#define MAX_WHITE 200
#endif
struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
Dev clients[MAX_CLIENTS]; int numClients = 0;

String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;
String whiteDom[MAX_WHITE]; uint64_t whiteHash[MAX_WHITE]; int numWhite = 0;
String blockUrl = "";

// recently blocked domains — RAM-only ring buffer (newest overwrites the oldest slot)
static const int MAX_HIST = 50;
struct HistEntry { char dom[64]; uint32_t ip; uint32_t t; };
HistEntry hist[MAX_HIST]; int histCount = 0, histHead = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// static IP (persisted in /net.cfg; absent = DHCP)
bool      staticIP = false;
IPAddress cfgIP, cfgGW, cfgSN, cfgDNS;

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// CPU usage tracking via FreeRTOS idle hooks
static volatile uint32_t idleCounter[2] = {0, 0};
static uint32_t maxIdlePerSec = 0;
static float currentCpuPct = 0.0f;
static uint32_t lastCpuSampleMs = 0;

static bool idleHook0() { idleCounter[0]++; return false; }
static bool idleHook1() { idleCounter[1]++; return false; }

static float getCpuPct() {
  uint32_t now = millis();
  uint32_t dt = now - lastCpuSampleMs;
  if (dt < 400) return currentCpuPct;
  uint32_t idles = idleCounter[0] + idleCounter[1];
  idleCounter[0] = 0; idleCounter[1] = 0;
  lastCpuSampleMs = now;
  uint32_t rate = (uint32_t)((uint64_t)idles * 1000ULL / dt);
  if (rate > maxIdlePerSec) maxIdlePerSec = rate;
  if (maxIdlePerSec > 0) {
    float idleRatio = (float)rate / (float)maxIdlePerSec;
    if (idleRatio > 1.0f) idleRatio = 1.0f;
    currentCpuPct = (1.0f - idleRatio) * 100.0f;
  }
  return currentCpuPct;
}

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

// Nạp toàn bộ blocklist từ flash vào PSRAM để tra cứu nhanh (không I/O flash).
// Không đủ PSRAM -> bỏ trống, inFlash() tự fallback tra flash.
static void loadBlocklistRam() {
  if (blRam) { free(blRam); blRam = nullptr; }
  if (!blocklist || numHashes == 0) return;
  size_t sz = (size_t)numHashes * HASH_BYTES;
  blRam = (uint8_t*)heap_caps_malloc(sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!blRam) { Serial.println("[ram] PSRAM alloc failed -> tra flash"); return; }
  blocklist.seek(0);
  size_t got = blocklist.read(blRam, sz);
  if (got != sz) { free(blRam); blRam = nullptr; Serial.println("[ram] read short -> tra flash"); return; }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
  Serial.printf("[ram] blocklist nap vao PSRAM: %u bytes\n", (unsigned)sz);
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  if (blRam) {   // binary search trên PSRAM
    uint32_t lo = 0, hi = numHashes;
    while (lo < hi) {
      uint32_t mid = lo + (hi - lo) / 2;
      uint64_t v = unpackHash(blRam + (size_t)mid * HASH_BYTES);
      if (v < h) lo = mid + 1;
      else if (v > h) hi = mid;
      else return true;
    }
    return false;
  }
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }
static bool inWhite(uint64_t h) { for (int i = 0; i < numWhite; i++) if (whiteHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  // whitelist wins: if the domain or any parent suffix is whitelisted, allow it
  for (const char* p = domain; p && *p; ) {
    if (inWhite(fnv40(p, strlen(p)))) return false;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  for (const char* p = domain; p && *p; ) {
    if (isBlockedHash(fnv40(p, strlen(p)))) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static String cleanDomain(String d) {
  d.trim();
  d.toLowerCase();
  if (d.startsWith("http://")) d = d.substring(7);
  else if (d.startsWith("https://")) d = d.substring(8);
  int slash = d.indexOf('/');
  if (slash >= 0) d = d.substring(0, slash);
  int colon = d.indexOf(':');
  if (colon > 0) d = d.substring(0, colon);
  if (d.startsWith("www.")) d = d.substring(4);
  while (d.startsWith(".")) d = d.substring(1);
  while (d.endsWith(".")) d = d.substring(0, d.length() - 1);
  d.trim();
  return d;
}

static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l = cleanDomain(l);
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d = cleanDomain(d);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++;
  memset(cacheValid, 0, sizeof(cacheValid));
  saveCustom(); return true;
}
static void removeCustom(String d) {
  d = cleanDomain(d);
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--;
    memset(cacheValid, 0, sizeof(cacheValid));
    saveCustom(); return;
  }
}
static void loadWhite() {
  numWhite = 0; File f = LittleFS.open("/whitelist.txt", "r"); if (!f) return;
  while (f.available() && numWhite < MAX_WHITE) {
    String l = f.readStringUntil('\n'); l = cleanDomain(l);
    if (l.length() && l.indexOf('.') > 0) { whiteDom[numWhite] = l; whiteHash[numWhite] = fnv40(l.c_str(), l.length()); numWhite++; }
  }
  f.close();
}
static void saveWhite() { File f = LittleFS.open("/whitelist.txt", "w"); if (!f) return; for (int i = 0; i < numWhite; i++) f.println(whiteDom[i]); f.close(); }
static bool addWhite(String d) {
  d = cleanDomain(d);
  if (!d.length() || d.indexOf('.') < 0 || numWhite >= MAX_WHITE) return false;
  for (int i = 0; i < numWhite; i++) if (whiteDom[i] == d) return false;
  whiteDom[numWhite] = d; whiteHash[numWhite] = fnv40(d.c_str(), d.length()); numWhite++; saveWhite(); return true;
}
static void removeWhite(String d) {
  d = cleanDomain(d);
  for (int i = 0; i < numWhite; i++) if (whiteDom[i] == d) {
    for (int j = i; j < numWhite - 1; j++) { whiteDom[j] = whiteDom[j+1]; whiteHash[j] = whiteHash[j+1]; }
    numWhite--; saveWhite(); return;
  }
}
// RAM-only log of recently blocked domains (ring buffer, newest overwrites oldest)
static void logBlocked(const char* d, uint32_t ip) {
  HistEntry& e = hist[histHead];
  strncpy(e.dom, d, sizeof(e.dom) - 1); e.dom[sizeof(e.dom) - 1] = 0;
  e.ip = ip; e.t = millis() / 1000;
  histHead = (histHead + 1) % MAX_HIST;
  if (histCount < MAX_HIST) histCount++;
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static bool isZeroMac(const uint8_t* m) {
  for (int i = 0; i < 6; i++) if (m[i] != 0) return false;
  return true;
}

static bool getMac(uint32_t ip, uint8_t* mac) {
  ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next) {
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) {
      memcpy(mac, eth->addr, 6);
      return true;
    }
    // If not in ARP cache, proactively send ARP request to discover it
    etharp_request(nif, &ipa);
  }
  return false;
}

static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) {
    if (clients[i].ip == ip) {
      clients[i].lastSeen = millis();
      if (isZeroMac(clients[i].mac)) getMac(ip, clients[i].mac);
      return &clients[i];
    }
  }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    memset(c->mac, 0, 6);
    getMac(ip, c->mac);
    return c;
  }
  return nullptr;
}

// ---------- upstream resolver ----------
// Allowed lookups are forwarded to one of:
//   built-in (default) - DNS mà ESP32 nhận được: DNS tĩnh (nếu bật IP tĩnh) hoặc DNS cấp qua
//                        DHCP; nếu rỗng/trùng chính ESP32 thì dùng gateway, cuối cùng là Quad9.
//   router             - the DNS the router hands out over DHCP (else the gateway), opt-in.
//   custom             - an address set on the dashboard.
//   doh / dot          - DNS over HTTPS / DNS over TLS (cấu hình qua /setdns).
// Persisted in /upstream.cfg: "router" | IPv4 | "doh\n<url>" | "dot\n<host>".
enum UpstreamMode { UP_BUILTIN, UP_ROUTER, UP_CUSTOM, UP_DOH, UP_DOT };
static UpstreamMode upstreamMode = UP_BUILTIN;
static IPAddress    upstreamSaved;               // the custom address, when UP_CUSTOM
static String       dohUrl  = DEFAULT_DOH_URL;   // used when UP_DOH
static String       dotHost = DEFAULT_DOT_HOST;  // used when UP_DOT
static const char*  upstreamSource = "built-in";
// 0.0.0.0 and 255.255.255.255 parse as valid IPv4 but would silently stop all forwarding.
static bool usableResolver(const IPAddress& ip) { return (uint32_t)ip != 0 && (uint32_t)ip != 0xFFFFFFFF; }
static void upstreamApply() {
  const IPAddress self = WiFi.localIP();
  if (upstreamMode == UP_DOH) { upstreamSource = "DoH"; return; }
  if (upstreamMode == UP_DOT) { upstreamSource = "DoT"; return; }
  if (upstreamMode == UP_CUSTOM) { upstreamDns = upstreamSaved; upstreamSource = "custom"; return; }
  if (upstreamMode == UP_ROUTER) {
    const IPAddress dhcp = WiFi.dnsIP(), gw = WiFi.gatewayIP();
    if ((uint32_t)dhcp != 0 && dhcp != self) { upstreamDns = dhcp; upstreamSource = "router (dhcp)"; return; }
    if ((uint32_t)gw != 0 && gw != self)     { upstreamDns = gw;   upstreamSource = "router (gateway)"; return; }
  }
  // built-in: ưu tiên DNS của chính ESP32 (static DNS nếu có, ngược lại DNS từ DHCP)
  const IPAddress sysDns = staticIP ? cfgDNS : WiFi.dnsIP();
  const IPAddress gw     = staticIP ? cfgGW  : WiFi.gatewayIP();
  if (usableResolver(sysDns) && sysDns != self) {
    upstreamDns = sysDns; upstreamSource = staticIP ? "static (dns)" : "dhcp (dns)"; return;
  }
  if (usableResolver(gw) && gw != self) { upstreamDns = gw; upstreamSource = "gateway"; return; }
  upstreamDns = UPSTREAM; upstreamSource = "fallback 9.9.9.9";
}
static void upstreamLoad() {
  upstreamMode = UP_BUILTIN;
  File f = LittleFS.open("/upstream.cfg", "r");
  if (f) {
    String l = f.readStringUntil('\n'); l.trim();
    String v = f.readStringUntil('\n'); v.trim();
    f.close();
    IPAddress ip;
    if (l == "router") upstreamMode = UP_ROUTER;
    else if (l == "doh" && v.length()) { dohUrl = v; upstreamMode = UP_DOH; }
    else if (l == "dot" && v.length()) { dotHost = v; upstreamMode = UP_DOT; }
    else if (l.length() && ip.fromString(l) && usableResolver(ip)) { upstreamSaved = ip; upstreamMode = UP_CUSTOM; }
  }
  upstreamApply();
}
static void upstreamSave() {
  if (upstreamMode == UP_BUILTIN) { LittleFS.remove("/upstream.cfg"); return; }
  File f = LittleFS.open("/upstream.cfg", "w"); if (!f) return;
  if (upstreamMode == UP_ROUTER)     f.println("router");
  else if (upstreamMode == UP_DOH) { f.println("doh"); f.println(dohUrl); }
  else if (upstreamMode == UP_DOT) { f.println("dot"); f.println(dotHost); }
  else                               f.println(upstreamSaved.toString());
  f.close();
}
// ---------- static IP (persisted in /net.cfg; absent = DHCP) ----------
static void loadNetCfg() {
  staticIP = false;
  File f = LittleFS.open("/net.cfg", "r"); if (!f) return;
  String a = f.readStringUntil('\n'); a.trim();
  String b = f.readStringUntil('\n'); b.trim();
  String c = f.readStringUntil('\n'); c.trim();
  String d = f.readStringUntil('\n'); d.trim();
  f.close();
  if (cfgIP.fromString(a) && cfgGW.fromString(b) && cfgSN.fromString(c) && cfgDNS.fromString(d) && (uint32_t)cfgIP != 0) staticIP = true;
}
static void saveNetCfg() {
  File f = LittleFS.open("/net.cfg", "w"); if (!f) return;
  f.println(cfgIP.toString()); f.println(cfgGW.toString()); f.println(cfgSN.toString()); f.println(cfgDNS.toString()); f.close();
}
static void loadBlockUrl() {
  blockUrl = ""; File f = LittleFS.open("/blockurl.cfg", "r"); if (!f) return;
  blockUrl = f.readStringUntil('\n'); blockUrl.trim(); f.close();
  if (blockUrl == "0.0.0.0") blockUrl = "";
}
static void saveBlockUrl() {
  if (!blockUrl.length() || blockUrl == "0.0.0.0") { LittleFS.remove("/blockurl.cfg"); blockUrl = ""; return; }
  File f = LittleFS.open("/blockurl.cfg", "w"); if (!f) return;
  f.println(blockUrl); f.close();
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  bool hasRedirect = blockUrl.length() > 0 && blockUrl != "0.0.0.0";
  IPAddress ansIP = hasRedirect ? WiFi.localIP() : IPAddress(0, 0, 0, 0);
  uint32_t ttl = hasRedirect ? 5 : 300;
  uint8_t ans[] = {
    0xC0, 0x0C, 0, 1, 0, 1,
    (uint8_t)(ttl >> 24), (uint8_t)(ttl >> 16), (uint8_t)(ttl >> 8), (uint8_t)ttl,
    0, 4,
    ansIP[0], ansIP[1], ansIP[2], ansIP[3]
  };
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int buildLocalAnswer(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  IPAddress lip = WiFi.localIP();
  uint8_t ans[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, lip[0], lip[1], lip[2], lip[3]};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// ---------- DNS over TLS (DoT) ----------
// DNS message đi trong TLS tới dotHost:853, mỗi message có tiền tố 2 byte độ dài.
static WiFiClientSecure dotCli;
static int dotExchange(const uint8_t* q, int qlen) {
  if (!dotCli.connected()) {
    dotCli.setInsecure();                          // không pin cert -> chấp nhận mọi CA
    if (!dotCli.connect(dotHost.c_str(), 853, 4000)) return 0;
  }
  uint8_t lb[2] = {(uint8_t)(qlen >> 8), (uint8_t)qlen};
  if (dotCli.write(lb, 2) != 2 || dotCli.write(q, qlen) != (size_t)qlen) { dotCli.stop(); return 0; }
  uint32_t t0 = millis();
  while (dotCli.connected() && dotCli.available() < 2 && millis() - t0 < 4000) delay(1);
  if (dotCli.available() < 2) { dotCli.stop(); return 0; }
  uint8_t h[2]; dotCli.read(h, 2);
  int len = (h[0] << 8) | h[1];
  if (len < 12 || len > (int)sizeof(buf)) { dotCli.stop(); return 0; }
  int n = 0;
  while (n < len && millis() - t0 < 6000) {
    if (dotCli.available()) { int r = dotCli.read(buf + n, min(len - n, (int)dotCli.available())); if (r > 0) n += r; }
    else if (!dotCli.connected()) break;
    else delay(1);
  }
  return n == len ? n : 0;
}

// ---------- DNS over HTTPS (DoH) ----------
// POST application/dns-message tới dohUrl, đọc body nhị phân là DNS response.
static WiFiClientSecure dohCli;
static int dohExchange(const uint8_t* q, int qlen) {
  HTTPClient http;
  dohCli.setInsecure();
  if (!http.begin(dohCli, dohUrl)) return 0;
  http.addHeader("Content-Type", "application/dns-message");
  http.addHeader("Accept", "application/dns-message");
  http.setTimeout(5000);
  int code = http.POST((uint8_t*)q, qlen);
  if (code != 200) { http.end(); return 0; }
  int len = http.getSize();
  WiFiClient* s = http.getStreamPtr();
  int n = 0; uint32_t t0 = millis();
  while ((len < 0 || n < len) && n < (int)sizeof(buf) && millis() - t0 < 6000) {
    if (s->available()) { int r = s->read(buf + n, min((int)sizeof(buf) - n, (int)s->available())); if (r > 0) n += r; }
    else if (!http.connected()) break;
    else delay(1);
  }
  http.end();
  return (n >= 12) ? n : 0;
}

// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: send with a fresh random txid
// and only accept a reply whose txid (and question section, for UDP) matches. The
// client's own txid is restored on the way back. Transport chọn theo upstreamMode.
static int forwardUpstream(int qlen, int qend) {
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)esp_random();    // ESP32's EspClass has no random()
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;

  int n = 0;
  if (upstreamMode == UP_DOH) {
    n = dohExchange(buf, qlen);
  } else if (upstreamMode == UP_DOT) {
    n = dotExchange(buf, qlen);
  } else {
    upstreamCli.flush();                                   // release any half-read buffer
    while (upstreamCli.parsePacket() > 0) upstreamCli.flush();   // drop stale late replies
    upstreamCli.beginPacket(upstreamDns, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
    const uint32_t t0 = millis();
    while (millis() - t0 < 1000) {                         // deadline, not a retry count
      int sz = upstreamCli.parsePacket();
      if (sz <= 0) { delay(1); continue; }
      const bool fromUp = upstreamCli.remoteIP() == upstreamDns && upstreamCli.remotePort() == UPSTREAM_PORT;
      int rn = upstreamCli.read(buf, sizeof(buf));
      upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
      if (!fromUp || rn < 12 || sz > (int)sizeof(buf)) continue;
      if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
      if (haveQ && (rn < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
      n = rn; break;
    }
  }
  if (n < 12) return 0;
  if ((((uint16_t)buf[0] << 8) | buf[1]) != wid) return 0;   // reply không khớp query
  buf[0] = cid0; buf[1] = cid1;
  return n;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool isLocalDomain = (strcmp(domain, "produckx.local") == 0 || strcmp(domain, "produckx") == 0);
    bool ban = c && c->banned;
    bool blocked = !isLocalDomain && (ban || (blockingOn && dl && isBlocked(domain)));
    int rlen;
    if (isLocalDomain) { rlen = buildLocalAnswer(qend, qtype); }
    else if (blocked)  {
      rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; if (dl) logBlocked(domain, (uint32_t)cip);
      Serial.printf("[dns] BLOCKED %s (qtype=%u) -> %s\n", domain, qtype,
                    (blockUrl.length() && blockUrl != "0.0.0.0") ? "redirect-to-ESP32" : "0.0.0.0");
    }
    else               { rlen = forwardUpstream(qlen, qend);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

// ---------- login session ----------
// The dashboard is behind a login page (credentials = WEB_USER / WEB_PASS in
// secrets.h). A successful login mints a random token and stores it in an
// HttpOnly cookie valid for 2 hours; every dashboard/API request must present
// it. This replaces HTTP Basic Auth for the web UI: browsers replay cached
// Basic Auth credentials cross-origin, whereas this cookie + the CSRF header
// does not, and it gives the dashboard a real logged-in / logged-out state.
static const char*    SESSION_COOKIE = "c3sid";
static const uint32_t SESSION_TTL_MS = 2UL * 60UL * 60UL * 1000UL;   // 2 hours
static String         sessionToken = "";       // current valid id ("" = logged out)
static uint32_t       sessionExpireMs = 0;     // millis() at which it dies

static String cookieValue(const char* name) {
  String c = web.header("Cookie"); if (!c.length()) return "";
  String key = String(name) + "=";
  int i = c.indexOf(key); if (i < 0) return "";
  int s = i + key.length();
  int e = c.indexOf(';', s);
  String v = (e < 0) ? c.substring(s) : c.substring(s, e);
  v.trim(); return v;
}
static bool sessionValid() {
  if (!sessionToken.length()) return false;
  if ((int32_t)(millis() - sessionExpireMs) >= 0) { sessionToken = ""; return false; }   // expired
  return cookieValue(SESSION_COOKIE) == sessionToken;
}
static String newSessionToken() {
  char t[33];
  for (int i = 0; i < 4; i++) {
    uint32_t r = esp_random();
    snprintf(t + i * 8, 9, "%08x", r);
  }
  return String(t);
}
static void sendLoginPage(const String& err) {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>ProDuckX-DNS &mdash; login</title>"
    "<style>"
    "*{box-sizing:border-box}"
    "body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px system-ui,sans-serif;color:#e2e8f0;"
    "background:radial-gradient(900px 500px at 10% -10%,#0b2942,transparent 55%),radial-gradient(700px 400px at 100% 0,#1e1b4b,transparent 50%),#020617}"
    ".card{width:380px;max-width:92vw;background:rgba(15,23,42,.75);border:1px solid #1e293b;border-radius:20px;padding:30px;backdrop-filter:blur(12px);box-shadow:0 20px 60px rgba(0,0,0,.45)}"
    ".logo{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;font-size:26px;background:rgba(16,185,129,.15);margin-bottom:14px}"
    "h1{margin:0;font-size:20px}p.sub{margin:4px 0 22px;color:#64748b;font-size:13px}"
    "label{display:block;font-size:12px;color:#94a3b8;margin:12px 0 6px}"
    "input{width:100%;padding:12px;border-radius:10px;border:1px solid #334155;background:#0b1220;color:#e2e8f0;font-size:14px;outline:none}"
    "input:focus{border-color:#10b981;box-shadow:0 0 0 3px rgba(16,185,129,.15)}"
    "button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:10px;background:#10b981;color:#04120c;font-weight:700;font-size:15px;cursor:pointer}"
    "button:hover{background:#34d399}.err{margin-top:14px;padding:10px;border-radius:8px;background:rgba(244,63,94,.12);color:#fda4af;font-size:13px}"
    "</style>"
    "<body><div class=card><div class=logo>&#128737;</div><h1>ProDuckX-DNS</h1><p class=sub>Login to dashboard</p>"
    "<form method=POST action=/login>"
    "<label>Username</label><input name=u placeholder='Username' autocomplete=username autofocus>"
    "<label>Password</label><input name=p type=password placeholder='Password' autocomplete=current-password>"
    "<button>Login</button>"
    "</form>";
  if (err.length()) html += "<p class=err>" + htmlEscape(err) + "</p>";
  html += "</div></body>";
  web.send(200, "text/html", html);
}
static void handleLoginPost() {
  if (web.arg("u") == WEB_USER && web.arg("p") == WEB_PASS) {
    sessionToken = newSessionToken();
    sessionExpireMs = millis() + SESSION_TTL_MS;
    web.sendHeader("Set-Cookie", String(SESSION_COOKIE) + "=" + sessionToken + "; Max-Age=7200; Path=/; HttpOnly");
    web.sendHeader("Location", "/");
    web.send(302, "text/plain", "");
    Serial.println("[web] login ok");
    return;
  }
  Serial.println("[web] login failed");
  web.sendHeader("Set-Cookie", String(SESSION_COOKIE) + "=; Max-Age=0; Path=/");
  sendLoginPage("Incorrect username or password");
}

static String getRequestHost() {
  String h = web.hostHeader();
  if (!h.length()) h = web.header("Host");
  if (h.length()) {
    int colon = h.indexOf(':'); if (colon > 0) h = h.substring(0, colon);
    h.trim(); h.toLowerCase();
  }
  return h;
}

static bool isDashboardHost() {
  String h = getRequestHost();
  if (!h.length()) return false;
  if (h == WiFi.localIP().toString() || h == "produckx.local" || h == "produckx") return true;
  return false;
}

static bool handleBlockedRedirect() {
  if (blockUrl.length() > 0 && blockUrl != "0.0.0.0") {
    String dest = blockUrl;
    String h = getRequestHost();
    if (h.length()) {
      dest += (dest.indexOf('?') >= 0 ? "&domain=" : "?domain=") + h;
    }
    web.sendHeader("Location", dest);
    web.send(302, "text/plain", "Redirecting to " + dest);
    Serial.printf("[http-sinkhole] redirect %s -> %s\n", h.c_str(), dest.c_str());
    return true;
  }
  return false;
}

static void handleStats() {
  if (!sessionValid()) { web.send(401, "text/plain", "login required"); return; }
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  uint32_t totalHeap = ESP.getHeapSize();
  uint32_t freeHeap = ESP.getFreeHeap();
  uint32_t usedHeap = (totalHeap > freeHeap) ? (totalHeap - freeHeap) : 0;
  float ramPct = totalHeap ? ((float)usedHeap * 100.0f / (float)totalHeap) : 0.0f;
  float cpuPct = getCpuPct();
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + freeHeap + ",\"ram\":" + String(ramPct, 1) + ",\"cpu\":" + String(cpuPct, 1) +
             ",\"uptime\":\"" + ut + "\"" +
             ",\"dns\":\"" + upstreamDns.toString() + "\",\"dnsSource\":\"" + upstreamSource + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) {
    Dev& c = clients[i];
    if (isZeroMac(c.mac)) getMac(c.ip, c.mac);
    IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}";
  }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"white\":[";
  for (int i = 0; i < numWhite; i++) { j += (i ? "," : ""); j += "\"" + jesc(whiteDom[i]) + "\""; }
  j += "],\"staticip\":" + String(staticIP ? "true" : "false") +
       ",\"netip\":\"" + String(staticIP ? cfgIP.toString() : "") +
       "\",\"netgw\":\"" + String(staticIP ? cfgGW.toString() : "") +
       "\",\"netsubnet\":\"" + String(staticIP ? cfgSN.toString() : "") +
       "\",\"netdns\":\"" + String(staticIP ? cfgDNS.toString() : "") + "\"" +
       ",\"blockurl\":\"" + jesc(blockUrl) + "\"";
  j += ",\"hist\":[";
  for (int k = 0; k < histCount; k++) {
    int idx = (histHead - 1 - k + MAX_HIST) % MAX_HIST;   // newest first
    HistEntry& e = hist[idx];
    j += (k ? "," : "");
    j += "{\"d\":\"" + jesc(String(e.dom)) + "\",\"ip\":\"" + IPAddress(e.ip).toString() +
         "\",\"t\":" + (uint32_t)(up >= e.t ? up - e.t : 0) + "}";
  }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Auth is the login session (see sessionValid()): the dashboard's own JS sets a
// custom header that a plain <img>/<form> CSRF vector cannot, so a cross-site
// page can't drive these endpoints even if the victim's browser carries the
// session cookie. (HTTP Basic Auth was the old scheme; the cookie replaced it.)
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "produckx-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (sessionValid()) return true;
  web.send(401, "text/plain", "login required");
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// A new list is written to /blocklist.new and only replaces the live list after it
// validates. If the filesystem has room for both, the live list stays in use the whole
// time (and survives a bad/truncated download). Only when space is short is the live
// list freed first; then a rejected download leaves the device fail-open (forwarding,
// no blocking) until the next good update.
static void reopenBlocklist() {
  if (blRam) { free(blRam); blRam = nullptr; }
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
  loadBlocklistRam();
}
static size_t fsFree() {
  return LittleFS.totalBytes() - LittleFS.usedBytes();
}
static bool swapKeptLive = false;                    // live list still open during this swap?
static void beginBlocklistSwap(size_t expected) {    // expected = incoming size, 0 if unknown
  LittleFS.remove("/blocklist.new");
  if (!expected && blocklist) expected = blocklist.size();   // unknown: assume similar size
  swapKeptLive = expected && fsFree() > expected + 16384;     // 16 KB littlefs slack
  if (!swapKeptLive) {                               // no room for both: free the old list
    if (blocklist) blocklist.close();
    numHashes = 0;
    LittleFS.remove(BLOCKLIST_PATH);
  }
  Serial.printf("[swap] incoming ~%u B, free %u B -> %s\n", (unsigned)expected, (unsigned)fsFree(),
                swapKeptLive ? "keeping live list during update" : "freed live list first");
}
// Valid = non-empty, whole 5-byte entries, complete (if the size was announced), and
// strictly ascending. The ordering check rejects HTML error pages, other forks' formats
// and corrupted files, which the old "size % 5 == 0" test let through.
static bool validBlocklistFile(const char* path, size_t expectSize, String& why) {
  File f = LittleFS.open(path, "r");
  if (!f) { why = "missing"; return false; }
  size_t sz = f.size();
  if (!sz || sz % HASH_BYTES) { f.close(); why = "size " + String((unsigned)sz) + " not a multiple of 5"; return false; }
  if (expectSize && sz != expectSize) { f.close(); why = "truncated (" + String((unsigned)sz) + "/" + String((unsigned)expectSize) + " B)"; return false; }
  uint8_t b[HASH_BYTES * 100]; uint64_t prev = 0; bool first = true; size_t idx = 0;
  while (f.available()) {
    int n = f.read(b, sizeof(b)); if (n <= 0) break;
    for (int k = 0; k + HASH_BYTES <= n; k += HASH_BYTES, idx++) {
      uint64_t v = unpackHash(b + k);
      if (!first && v <= prev) { f.close(); why = "not a sorted blocklist (entry " + String((unsigned)idx) + ")"; return false; }
      prev = v; first = false;
    }
  }
  f.close(); return true;
}
static bool commitNewBlocklist(size_t expectSize, String& why) {   // /blocklist.new -> live
  bool ok = validBlocklistFile("/blocklist.new", expectSize, why);
  if (ok) {
    if (blocklist) blocklist.close();
    LittleFS.remove(BLOCKLIST_PATH);
    LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  } else {
    LittleFS.remove("/blocklist.new");
    Serial.printf("[swap] rejected: %s%s\n", why.c_str(), swapKeptLive ? " (kept current list)" : "");
    if (swapKeptLive) return false;                  // live list never left; nothing to reopen
  }
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static String upWhy;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.send(401, "text/plain", "login required"); return; }
  web.send(upOk ? 200 : 500, "text/plain", upOk ? String("ok") : "rejected: " + upWhy);
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && sessionValid();
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; beginBlocklistSwap(0);            // ESP32 WebServer has no clientContentLength(); 0 = unknown
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist(0, upWhy);
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); if (!swapKeptLive) reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs;
  cs.setInsecure();                // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  int len = http.getSize();
  beginBlocklistSwap(len > 0 ? (size_t)len : 0);
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; if (!swapKeptLive) reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  String why;
  bool ok = commitNewBlocklist(len > 0 ? (size_t)len : 0, why);
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains")
                    : ("rejected: " + why + (swapKeptLive ? " (kept current list)" : ""));
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.send(401, "text/plain", "login required"); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && sessionValid();
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort();
    Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true);
  bool forcePortal = prefs.getBool("portal", false);
  bool nvs = prefs.getString("ssid", "").length() > 0;
  prefs.end();
  if (forcePortal) return false;
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  bool forcePortal = prefs.getBool("portal", false);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  if (forcePortal) {
    prefs.begin("wifi", false);
    prefs.remove("portal");
    prefs.end();
    Serial.println("WiFi: reset requested -> entering setup portal directly");
    return false;
  }
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false);
  if (staticIP) { WiFi.config(cfgIP, cfgGW, cfgSN, cfgDNS); Serial.printf("WiFi: static IP %s\n", cfgIP.toString().c_str()); }
  WiFi.begin(ssid, pass);
#if defined(WIFI_TX_POWER)
  WiFi.setTxPower((wifi_power_t)WIFI_TX_POWER);    // e.g. -DWIFI_TX_POWER=WIFI_POWER_8_5dBm
#endif
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>ProDuckX-DNS setup</title>"
    // CSS nhúng: trang setup chạy ở AP mode KHÔNG có internet nên không dùng CDN.
    "<style>"
    "*{box-sizing:border-box}"
    "body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px system-ui,sans-serif;color:#e2e8f0;"
    "background:radial-gradient(900px 500px at 10% -10%,#0b2942,transparent 55%),radial-gradient(700px 400px at 100% 0,#1e1b4b,transparent 50%),#020617}"
    ".card{width:440px;max-width:92vw;background:rgba(15,23,42,.75);border:1px solid #1e293b;border-radius:20px;padding:30px;backdrop-filter:blur(12px);box-shadow:0 20px 60px rgba(0,0,0,.45)}"
    ".logo{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;font-size:26px;background:rgba(16,185,129,.15);margin-bottom:14px}"
    "h1{margin:0;font-size:20px}p.sub{margin:4px 0 18px;color:#64748b;font-size:13px}"
    "select,input{width:100%;padding:12px;margin:7px 0;border-radius:10px;border:1px solid #334155;background:#0b1220;color:#e2e8f0;font-size:14px;outline:none}"
    "select:focus,input:focus{border-color:#10b981;box-shadow:0 0 0 3px rgba(16,185,129,.15)}"
    "button{border:0;border-radius:10px;cursor:pointer;font-weight:600}"
    ".scan{width:100%;padding:10px;margin-bottom:4px;background:#1e293b;color:#cbd5e1;font-size:13px}"
    ".scan:hover{background:#334155}"
    ".go{width:100%;padding:13px;margin-top:14px;background:#10b981;color:#04120c;font-size:15px;font-weight:700}"
    ".go:hover{background:#34d399}"
    "</style>"
    "<body><div class=card><div class=logo>&#128737;</div>"
    "<h1>ProDuckX-DNS</h1><p class=sub>Chon WiFi va nhap mat khau. Thiet bi se khoi dong lai va ket noi.</p>"
    "<form method=POST action=/wifisave>"
    // A real <select> is usable on every phone; the datalist this used to be
    // renders an affordance in several in-app browsers but no list, so picking
    // a network looked impossible. Typing the name still covers hidden APs.
    "<select name=s id=apsel>" + portalOpts + "</select>"
    "<button type=button class=scan onclick=rescan(this)>Quet lai</button>"
    "<input name=s2 placeholder='hoac nhap ten WiFi (AP an)'>"
    "<input name=p type=password placeholder='Mat khau WiFi'>"
    "<button class=go>Ket noi</button>"
    "</form>"
    "<script>async function rescan(b){b.disabled=true;b.textContent='Scanning...';"
    "try{let r=await fetch('/scan');document.getElementById('apsel').innerHTML=await r.text();}"
    "finally{b.disabled=false;b.textContent='Scan';}}</script>"
    "</div></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s2"); ss.trim();          // typed name wins
  if (!ss.length()) ss = web.arg("s");           // ...otherwise the picked one
  String pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  // Đổi WiFi = mạng mới -> bỏ IP tĩnh cũ, quay về DHCP
  staticIP = false; LittleFS.remove("/net.cfg");
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>produckx.local</b>.</body>");
  delay(900); ESP.restart();
}
// Build the <option> list of nearby networks (deduped, strongest first).
// Retries because the very first scan right after boot / a mode change can
// legitimately come back empty.
static void portalScanNetworks() {
  int n = 0;
  for (int attempt = 1; attempt <= 4 && n <= 0; attempt++) {
    if (attempt > 1) delay(800);
    n = WiFi.scanNetworks(false, true);       // blocking, include hidden SSIDs
    Serial.printf("[setup] scan %d/4: %d networks\n", attempt, n);
  }
  portalOpts = "<option value=''>-- pick your network --</option>";
  if (n > 0) {
    const int MAX_AP = 32;
    String ssids[MAX_AP]; int32_t rssi[MAX_AP]; int cnt = 0;
    for (int i = 0; i < n && i < 64; i++) {
      String s = WiFi.SSID(i);
      if (!s.length()) continue;
      int32_t r = WiFi.RSSI(i);
      bool dup = false;
      for (int j = 0; j < cnt; j++) if (ssids[j] == s) { if (r > rssi[j]) rssi[j] = r; dup = true; break; }
      if (!dup && cnt < MAX_AP) { ssids[cnt] = s; rssi[cnt] = r; cnt++; }
    }
    for (int i = 0; i + 1 < cnt; i++)          // strongest signal first
      for (int j = i + 1; j < cnt; j++)
        if (rssi[j] > rssi[i]) { int32_t tr = rssi[i]; rssi[i] = rssi[j]; rssi[j] = tr; String ts = ssids[i]; ssids[i] = ssids[j]; ssids[j] = ts; }
    for (int i = 0; i < cnt && i < 20; i++)
      portalOpts += "<option value='" + htmlEscape(ssids[i]) + "'>" + htmlEscape(ssids[i]) + " (" + String(rssi[i]) + " dBm)</option>";
  }
  WiFi.scanDelete();
}

static void ledSet(uint8_t r, uint8_t g, uint8_t b);   // định nghĩa ở dưới, gần setup()

// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  // AP_STA (not AP-only): the soft-AP lets the phone open the setup page while
  // the station interface stays free to scan. In AP-only mode scanNetworks()
  // returns nothing, which left the "pick your network" list empty.
  WiFi.mode(WIFI_AP_STA);
  delay(200);
  WiFi.softAP("ProDuckX-DNS");
  WiFi.setTxPower(WIFI_POWER_8_5dBm);          // the phone is right next to it
  IPAddress apIP = WiFi.softAPIP();
  portalScanNetworks();                        // AP is up now; scan runs alongside it
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/scan", []() { portalScanNetworks(); web.send(200, "text/html", portalOpts); });  // rescan on demand
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"ProDuckX-DNS\" and a setup page pops up (or http://%s)\n",
                apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis(), blinkMs = 0; bool blinkOn = false;
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (millis() - blinkMs > 400) { blinkMs = millis(); blinkOn = !blinkOn; ledSet(blinkOn ? 40 : 0, 0, 0); }  // đỏ nhấp nháy: chưa có WiFi
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

// ---------- RGB status LED (WS2812) ----------
// Xanh lá = đang chặn bình thường; vàng = tạm dừng; tím = chưa có blocklist;
// đỏ nhấp nháy = chưa kết nối WiFi (setup portal); xanh dương = đang khởi động.
static void ledSet(uint8_t r, uint8_t g, uint8_t b) {
  neopixelWrite(RGB_LED_PIN, r, g, b);
}
static void ledStatus() {
  static uint32_t lastMs = 0;
  if (millis() - lastMs < 500) return;
  lastMs = millis();
  if (!blockingOn)                 ledSet(40, 24, 0);   // vàng: paused
  else if (numHashes == 0)         ledSet(30, 0, 40);   // tím: no blocklist
  else                             ledSet(0, 30, 0);    // xanh lá: active
}

void setup() {
  Serial.begin(115200); delay(300);
  esp_register_freertos_idle_hook_for_cpu(idleHook0, 0);
  esp_register_freertos_idle_hook_for_cpu(idleHook1, 1);
  idleCounter[0] = 0; idleCounter[1] = 0;
  delay(100);
  maxIdlePerSec = (idleCounter[0] + idleCounter[1]) * 10;
  lastCpuSampleMs = millis();
  Serial.println("\n[produckx-adblock] booting");
  ledSet(0, 0, 30);   // xanh dương: khởi động
  Serial.printf("[mem] PSRAM: %u bytes\n", (unsigned)heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
    loadBlocklistRam();
  }
  loadCustom(); loadWhite(); loadBanned(); loadUpdateCfg(); upstreamLoad(); loadNetCfg(); loadBlockUrl();
  Serial.printf("custom: %d, banned: %d, blockurl: %s\n", numCustom, numBanned, blockUrl.c_str());
  Serial.printf("[mem] free heap %u bytes\n", (unsigned)ESP.getFreeHeap());

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
  const int BOOT_PIN = 0;     // ESP32 BOOT button (GPIO9 is a flash pin there)
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  const IPAddress shownSN = staticIP ? cfgSN : WiFi.subnetMask();
  const IPAddress shownGW = staticIP ? cfgGW : WiFi.gatewayIP();
  Serial.printf("Subnet: %s\n", shownSN.toString().c_str());
  Serial.printf("Gateway: %s\n", shownGW.toString().c_str());
  upstreamApply();                              // DHCP is up now (matters for "router" mode)
  Serial.printf("upstream DNS: %s (%s)\n", upstreamDns.toString().c_str(), upstreamSource);
  if (MDNS.begin("produckx")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://produckx.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  { const char* hdrs[] = { CSRF_HEADER, "Cookie", "Host" }; web.collectHeaders(hdrs, 3); }  // CSRF header + session cookie + Host
  web.on("/login", HTTP_GET, []() { sendLoginPage(""); });
  web.on("/login", HTTP_POST, handleLoginPost);
  web.on("/logout", []() {
    sessionToken = "";
    web.sendHeader("Set-Cookie", String(SESSION_COOKIE) + "=; Max-Age=0; Path=/");
    web.sendHeader("Location", "/login");
    web.send(302, "text/plain", "");
  });
  web.on("/", []() {
    if (!isDashboardHost()) {
      if (handleBlockedRedirect()) return;
      web.send(404, "text/plain", "Blocked by ProDuckX-DNS");
      return;
    }
    if (!sessionValid()) { web.sendHeader("Location", "/login"); web.send(302, "text/plain", ""); return; }
    web.send_P(200, "text/html", PAGE);
  });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/addwhite", []() { if (!requireAuth()) return; addWhite(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unwhite", []() { if (!requireAuth()) return; removeWhite(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() {
    if (!requireAuth()) return;
    web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false);
    prefs.clear();
    prefs.putBool("portal", true);
    prefs.end();
    // Quên WiFi cũ -> xóa luôn IP tĩnh để mạng mới dùng DHCP
    staticIP = false;
    LittleFS.remove("/net.cfg");
    delay(500);
    ESP.restart();
  });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.on("/setdns", []() {               // /setdns?ip=|?router=1|?reset=1|?doh=<url>|?dot=<host>
    if (!requireAuth()) return;
    if (web.hasArg("reset")) upstreamMode = UP_BUILTIN;
    else if (web.hasArg("router")) upstreamMode = UP_ROUTER;
    else if (web.hasArg("doh")) {
      String u = web.arg("doh"); u.trim();
      if (!u.startsWith("https://")) { web.send(400, "text/plain", "DoH URL phai bat dau bang https://"); return; }
      dohUrl = u; upstreamMode = UP_DOH;
    }
    else if (web.hasArg("dot")) {
      String h = web.arg("dot"); h.trim();
      if (!h.length()) { web.send(400, "text/plain", "thieu DoT host"); return; }
      dotHost = h; upstreamMode = UP_DOT;
    }
    else {
      IPAddress v;
      if (!v.fromString(web.arg("ip"))) { web.send(400, "text/plain", "not an IPv4 address"); return; }
      if (!usableResolver(v)) { web.send(400, "text/plain", "0.0.0.0 / broadcast is not a resolver"); return; }
      if (v == WiFi.localIP()) { web.send(400, "text/plain", "that is this device; pick another resolver"); return; }
      upstreamSaved = v; upstreamMode = UP_CUSTOM;
    }
    upstreamSave(); upstreamApply();
    Serial.printf("[dns] upstream -> %s (%s)\n", upstreamDns.toString().c_str(), upstreamSource);
    web.send(200, "text/plain", (upstreamMode == UP_DOH) ? ("DoH " + dohUrl)
                                       : (upstreamMode == UP_DOT) ? ("DoT " + dotHost)
                                       : upstreamDns.toString());
  });
  web.on("/setip", []() {                 // /setip?ip=&gw=&subnet=&dns= — static IP, reboots to apply
    if (!requireAuth()) return;
    IPAddress ip, gw, sn, dns;
    if (!ip.fromString(web.arg("ip")) || !gw.fromString(web.arg("gw")) ||
        !sn.fromString(web.arg("subnet")) || !dns.fromString(web.arg("dns")) || (uint32_t)ip == 0) {
      web.send(400, "text/plain", "invalid IPv4 address"); return;
    }
    cfgIP = ip; cfgGW = gw; cfgSN = sn; cfgDNS = dns; staticIP = true; saveNetCfg();
    Serial.printf("[net] static %s gw %s sn %s dns %s -> rebooting\n",
                  cfgIP.toString().c_str(), cfgGW.toString().c_str(), cfgSN.toString().c_str(), cfgDNS.toString().c_str());
    web.send(200, "text/plain", "saved — rebooting to apply");
    delay(500); ESP.restart();
  });
  web.on("/setdhcp", []() {               // drop /net.cfg and return to DHCP, reboots to apply
    if (!requireAuth()) return;
    staticIP = false; LittleFS.remove("/net.cfg");
    web.send(200, "text/plain", "saved — rebooting to apply");
    delay(500); ESP.restart();
  });
  web.on("/setblockurl", []() {
    if (!requireAuth()) return;
    blockUrl = web.hasArg("u") ? web.arg("u") : "";
    blockUrl.trim();
    saveBlockUrl();
    web.send(200, "text/plain", "ok");
  });
  web.onNotFound([]() {
    if (!isDashboardHost()) {
      if (handleBlockedRedirect()) return;
    }
    web.send(404, "text/plain", "Not found");
  });
  web.begin();
  ArduinoOTA.setHostname("produckx");   // pio run -t upload --upload-port produckx.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  ledStatus();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
