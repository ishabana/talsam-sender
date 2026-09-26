#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <SPI.h>
#include <lvgl.h>
#include <xpt2046.h>
#include <esp_lcd_panel_io.h>
#include <esp_lcd_panel_ops.h>
#include <esp_lcd_panel_vendor.h>
#include <esp_system.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>
#include "pins.h"
#include "abjad.h"
#include "secrets.h"
#include "page.h"
#include "boot_image.h"

// Wire format, must match pc/lib.ts:
// "ABJ1" | nonce(12) | AES-256-GCM(ciphertext of "name\ntext") | tag(16), AAD = "ABJ1"
static const uint16_t PORT = 4646;
static const char SALT[] = "abjad-talisman-v1";
static const int KDF_ITER = 50000;
static const uint8_t MAGIC[4] = {'A', 'B', 'J', '1'};
static const size_t INPUT_LIMIT = 400;  // bytes of UTF-8
static const size_t MAX_PACKET = 512;

// Touch calibration read from this board's factory NVS data.
// ponytail: fixed per board; recalibrate if taps land off.
static const int TOUCH_X_MIN = 221, TOUCH_X_MAX = 1855, TOUCH_Y_MIN = 155, TOUCH_Y_MAX = 1773;

static XPT2046 touch(SPI, TOUCHSCREEN_CS_PIN, TOUCHSCREEN_IRQ_PIN);
static lv_disp_draw_buf_t drawBuf;
static lv_disp_drv_t dispDrv;
static lv_indev_drv_t indevDrv;
static WiFiUDP udp;
static WebServer web(80);
static bool udpUp = false;
static uint8_t key[32];

static lv_obj_t *statusLbl, *logBox, *inputLbl, *kb;
static String input;
static bool arabicKb = true;

// ---------- crypto ----------

static void deriveKey() {
  mbedtls_md_context_t md;
  mbedtls_md_init(&md);
  mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_pkcs5_pbkdf2_hmac(&md, (const uint8_t *)TALISMAN_PASSPHRASE, strlen(TALISMAN_PASSPHRASE),
                            (const uint8_t *)SALT, strlen(SALT), KDF_ITER, sizeof key, key);
  mbedtls_md_free(&md);
}

static size_t seal(const String &plain, uint8_t *out) {
  size_t len = plain.length();
  memcpy(out, MAGIC, 4);
  esp_fill_random(out + 4, 12);
  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
  mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, len, out + 4, 12, MAGIC, 4,
                            (const uint8_t *)plain.c_str(), out + 16, 16, out + 16 + len);
  mbedtls_gcm_free(&g);
  return len + 32;
}

// Returns false on wrong key, tampering or garbage.
static bool openPacket(const uint8_t *in, size_t n, char *plain) {
  if (n < 32 || memcmp(in, MAGIC, 4)) return false;
  size_t len = n - 32;
  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
  int err = mbedtls_gcm_auth_decrypt(&g, len, in + 4, 12, MAGIC, 4, in + n - 16, 16, in + 16, (uint8_t *)plain);
  mbedtls_gcm_free(&g);
  plain[len] = 0;
  return err == 0;
}

// ---------- display + touch (same setup as LilyGO factory firmware) ----------

static void flushCb(lv_disp_drv_t *drv, const lv_area_t *a, lv_color_t *px) {
  esp_lcd_panel_draw_bitmap((esp_lcd_panel_handle_t)drv->user_data, a->x1, a->y1, a->x2 + 1, a->y2 + 1, px);
  lv_disp_flush_ready(drv);
}

static void touchCb(lv_indev_drv_t *, lv_indev_data_t *d) {
  if (touch.pressed()) {
    d->state = LV_INDEV_STATE_PR;
    d->point.x = touch.X();
    d->point.y = touch.Y();
  } else {
    d->state = LV_INDEV_STATE_REL;
  }
}

static void initDisplay() {
  esp_lcd_i80_bus_handle_t bus = NULL;
  esp_lcd_i80_bus_config_t busCfg = {
      .dc_gpio_num = DC_PIN,
      .wr_gpio_num = PCLK_PIN,
      .clk_src = LCD_CLK_SRC_PLL160M,
      .data_gpio_nums = {LCD_DATA0_PIN, LCD_DATA1_PIN, LCD_DATA2_PIN, LCD_DATA3_PIN,
                         LCD_DATA4_PIN, LCD_DATA5_PIN, LCD_DATA6_PIN, LCD_DATA7_PIN},
      .bus_width = 8,
      .max_transfer_bytes = 240 * 320 * sizeof(uint16_t)};
  ESP_ERROR_CHECK(esp_lcd_new_i80_bus(&busCfg, &bus));

  esp_lcd_panel_io_handle_t io = NULL;
  esp_lcd_panel_io_i80_config_t ioCfg = {
      .cs_gpio_num = CS_PIN,
      .pclk_hz = 10 * 1000 * 1000,
      .trans_queue_depth = 10,
      .lcd_cmd_bits = 8,
      .lcd_param_bits = 8,
      .dc_levels = {.dc_idle_level = 0, .dc_cmd_level = 0, .dc_dummy_level = 0, .dc_data_level = 1},
      .flags = {.swap_color_bytes = 1}};
  ESP_ERROR_CHECK(esp_lcd_new_panel_io_i80(bus, &ioCfg, &io));

  esp_lcd_panel_handle_t panel = NULL;
  esp_lcd_panel_dev_config_t panelCfg = {
      .reset_gpio_num = RST_PIN, .color_space = ESP_LCD_COLOR_SPACE_RGB, .bits_per_pixel = 16};
  ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io, &panelCfg, &panel));
  esp_lcd_panel_reset(panel);
  esp_lcd_panel_init(panel);
  esp_lcd_panel_mirror(panel, false, true);
  esp_lcd_panel_swap_xy(panel, true);  // landscape 320x240
  pinMode(BK_LIGHT_PIN, OUTPUT);
  digitalWrite(BK_LIGHT_PIN, HIGH);

  lv_init();
  lv_color_t *buf = (lv_color_t *)heap_caps_malloc(320 * 240 * sizeof(lv_color_t), MALLOC_CAP_SPIRAM);
  lv_disp_draw_buf_init(&drawBuf, buf, NULL, 320 * 240);
  lv_disp_drv_init(&dispDrv);
  dispDrv.hor_res = 320;
  dispDrv.ver_res = 240;
  dispDrv.flush_cb = flushCb;
  dispDrv.draw_buf = &drawBuf;
  dispDrv.user_data = panel;
  dispDrv.full_refresh = 1;
  lv_disp_drv_register(&dispDrv);

  SPI.begin(TOUCHSCREEN_SCLK_PIN, TOUCHSCREEN_MISO_PIN, TOUCHSCREEN_MOSI_PIN);
  touch.begin(240, 320);
  touch.setCal(TOUCH_X_MIN, TOUCH_X_MAX, TOUCH_Y_MIN, TOUCH_Y_MAX, 240, 320);
  touch.setRotation(3);
  lv_indev_drv_init(&indevDrv);
  indevDrv.type = LV_INDEV_TYPE_POINTER;
  indevDrv.read_cb = touchCb;
  lv_indev_drv_register(&indevDrv);
}

// ---------- talisman view ----------

static const lv_color_t GOLD = lv_color_hex(0xE8C170);
static const lv_color_t INK = lv_color_hex(0x10122B);

static String arabicDigits(long n) {
  String s(n), out;
  for (char c : s) {
    if (c >= '0' && c <= '9') {
      out += (char)0xD9;
      out += (char)(0xA0 + c - '0');  // U+0660..U+0669
    } else {
      out += c;
    }
  }
  return out;
}

static void showTalisman(const char *text) {
  long total = abjadSum(text), sq[16];
  lv_obj_t *p = lv_obj_create(lv_layer_top());
  lv_obj_set_size(p, 320, 240);
  lv_obj_set_style_bg_color(p, INK, 0);
  lv_obj_set_style_radius(p, 0, 0);
  lv_obj_set_style_border_width(p, 0, 0);
  lv_obj_set_style_pad_all(p, 0, 0);
  lv_obj_set_style_text_color(p, GOLD, 0);
  lv_obj_clear_flag(p, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(p, [](lv_event_t *e) { lv_obj_del_async(lv_event_get_target(e)); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *t = lv_label_create(p);
  lv_obj_set_width(t, 312);
  lv_label_set_long_mode(t, LV_LABEL_LONG_DOT);
  lv_obj_set_style_text_align(t, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_text(t, text);
  lv_obj_align(t, LV_ALIGN_TOP_MID, 0, 2);

  lv_obj_t *v = lv_label_create(p);
  lv_label_set_text(v, (String("الجمل ") + arabicDigits(total)).c_str());
  lv_obj_align(v, LV_ALIGN_TOP_MID, 0, 22);

  if (!wafq(total, sq)) {
    lv_obj_t *n = lv_label_create(p);
    lv_label_set_text(n, "القيمة أقل من ٣٠، لا وفق");
    lv_obj_center(n);
    return;
  }
  for (int i = 0; i < 16; i++) {
    lv_obj_t *c = lv_label_create(p);
    lv_obj_set_size(c, 60, 46);
    lv_obj_set_pos(c, 40 + (i % 4) * 60, 44 + (i / 4) * 48);
    lv_obj_set_style_border_width(c, 1, 0);
    lv_obj_set_style_border_color(c, GOLD, 0);
    lv_obj_set_style_pad_top(c, 14, 0);
    lv_obj_set_style_text_align(c, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_text(c, arabicDigits(sq[i]).c_str());
  }
}

// ---------- chat UI ----------

// ---------- web: talismans public, messages stay sealed ----------

// Last messages as sealed packets. The page gets only the abjad total (for the
// wafq) and the ciphertext; decryption happens in the viewer's browser/terminal.
static const int HISTORY = 10;
static struct { long total; uint8_t pkt[MAX_PACKET]; size_t n; } history[HISTORY];
static int historyCount = 0;

static void remember(long total, const uint8_t *pkt, size_t n) {
  if (historyCount == HISTORY) memmove(history, history + 1, sizeof history[0] * --historyCount);
  history[historyCount].total = total;
  memcpy(history[historyCount].pkt, pkt, n);
  history[historyCount++].n = n;
}

static void serveMessages() {
  String json = "[";
  for (int i = 0; i < historyCount; i++) {
    json += (i ? ",{\"total\":" : "{\"total\":") + String(history[i].total) + ",\"packet\":\"";
    for (size_t j = 0; j < history[i].n; j++) {
      char h[3];
      sprintf(h, "%02x", history[i].pkt[j]);
      json += h;
    }
    json += "\"}";
  }
  web.send(200, "application/json", json + "]");
}

static void addLog(const String &who, const String &text) {
  if (lv_obj_get_child_cnt(logBox) >= 20) lv_obj_del(lv_obj_get_child(logBox, 0));
  lv_obj_t *l = lv_label_create(logBox);
  lv_obj_set_width(l, lv_pct(100));
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_label_set_text(l, (who + ": " + text).c_str());
  lv_obj_add_flag(l, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_user_data(l, strdup(text.c_str()));
  lv_obj_add_event_cb(l, [](lv_event_t *e) {
    showTalisman((const char *)lv_obj_get_user_data(lv_event_get_target(e)));
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_add_event_cb(l, [](lv_event_t *e) { free(lv_obj_get_user_data(lv_event_get_target(e))); },
                      LV_EVENT_DELETE, NULL);
  lv_obj_scroll_to_view(l, LV_ANIM_OFF);
}

static void sendMessage() {
  if (!input.length()) return;
  if (!udpUp) {
    lv_label_set_text(statusLbl, "No WiFi, not sent");
    return;
  }
  uint8_t pkt[MAX_PACKET];
  size_t n = seal(String(DEVICE_NAME) + "\n" + input, pkt);
  udp.beginPacket(WiFi.broadcastIP(), PORT);
  udp.write(pkt, n);
  udp.endPacket();
  remember(abjadSum(input.c_str()), pkt, n);
  addLog("me", input);
  showTalisman(input.c_str());
  input = "";
  lv_label_set_text(inputLbl, "");
}

// Arabic letters in abjad order, laid out right to left.
static const char *AR_MAP[] = {
    "ط", "ح", "ز", "و", "ه", "د", "ج", "ب", "ا", "\n",
    "ص", "ف", "ع", "س", "ن", "م", "ل", "ك", "ي", "\n",
    "ظ", "ض", "ذ", "خ", "ث", "ت", "ش", "ر", "ق", "\n",
    "إرسال", "ABC", "حذف", "مسافة", "ء", "ى", "ة", "غ", ""};
static const lv_btnmatrix_ctrl_t AR_CTRL[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 1, 1, 2, 1, 1, 1, 1};
static const char *EN_MAP[] = {
    "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "\n",
    "a", "s", "d", "f", "g", "h", "j", "k", "l", "\n",
    "z", "x", "c", "v", "b", "n", "m", "?", "!", "\n",
    "Send", "عربي", "Del", "space", ",", ".", ""};
static const lv_btnmatrix_ctrl_t EN_CTRL[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 1, 1, 3, 1, 1};

static void setKeyboard() {
  lv_btnmatrix_set_map(kb, arabicKb ? AR_MAP : EN_MAP);
  lv_btnmatrix_set_ctrl_map(kb, arabicKb ? AR_CTRL : EN_CTRL);
}

static void onKey(lv_event_t *e) {
  lv_obj_t *m = lv_event_get_target(e);
  const char *t = lv_btnmatrix_get_btn_text(m, lv_btnmatrix_get_selected_btn(m));
  if (!t) return;
  if (!strcmp(t, "ABC") || !strcmp(t, "عربي")) {
    arabicKb = !arabicKb;
    setKeyboard();
    return;
  }
  if (!strcmp(t, "إرسال") || !strcmp(t, "Send")) {
    sendMessage();
    return;
  }
  if (!strcmp(t, "حذف") || !strcmp(t, "Del")) {
    while (input.length()) {  // drop one whole UTF-8 character
      char c = input[input.length() - 1];
      input.remove(input.length() - 1);
      if ((c & 0xC0) != 0x80) break;
    }
  } else if (input.length() + strlen(t) <= INPUT_LIMIT) {
    input += (!strcmp(t, "مسافة") || !strcmp(t, "space")) ? " " : t;
  }
  lv_label_set_text(inputLbl, input.c_str());
}

static void buildUi() {
  lv_obj_t *scr = lv_scr_act();
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

  statusLbl = lv_label_create(scr);
  lv_obj_set_pos(statusLbl, 4, 1);
  lv_label_set_text(statusLbl, "...");

  logBox = lv_obj_create(scr);
  lv_obj_set_pos(logBox, 0, 18);
  lv_obj_set_size(logBox, 320, 72);
  lv_obj_set_style_pad_all(logBox, 3, 0);
  lv_obj_set_style_radius(logBox, 0, 0);
  lv_obj_set_flex_flow(logBox, LV_FLEX_FLOW_COLUMN);

  inputLbl = lv_label_create(scr);
  lv_obj_set_pos(inputLbl, 0, 90);
  lv_obj_set_size(inputLbl, 320, 30);
  lv_obj_set_style_pad_all(inputLbl, 6, 0);
  lv_obj_set_style_border_width(inputLbl, 1, 0);
  lv_obj_set_style_border_color(inputLbl, GOLD, 0);
  lv_label_set_long_mode(inputLbl, LV_LABEL_LONG_DOT);
  lv_label_set_text(inputLbl, "");

  kb = lv_btnmatrix_create(scr);
  lv_obj_set_pos(kb, 0, 120);
  lv_obj_set_size(kb, 320, 120);
  lv_obj_set_style_pad_all(kb, 2, 0);
  lv_obj_set_style_pad_gap(kb, 2, 0);
  lv_obj_add_event_cb(kb, onKey, LV_EVENT_VALUE_CHANGED, NULL);
  setKeyboard();
}

// ---------- main ----------

void setup() {
  pinMode(PWR_ON_PIN, OUTPUT);
  digitalWrite(PWR_ON_PIN, HIGH);
  pinMode(PWR_EN_PIN, OUTPUT);
  digitalWrite(PWR_EN_PIN, HIGH);
  Serial.begin(115200);

  initDisplay();
  buildUi();
  // Boot screen covers the UI while the key is derived (~5 s).
  lv_obj_t *boot = lv_obj_create(lv_layer_top());
  lv_obj_set_size(boot, 320, 240);
  lv_obj_set_style_bg_color(boot, lv_color_black(), 0);
  lv_obj_set_style_border_width(boot, 0, 0);
  lv_obj_set_style_radius(boot, 0, 0);
  lv_obj_set_style_pad_all(boot, 0, 0);
  lv_obj_center(lv_img_create(boot));
  lv_img_set_src(lv_obj_get_child(boot, 0), &boot_image);
  lv_refr_now(NULL);
  uint32_t t0 = millis();
  deriveKey();
  Serial.printf("key derived in %lu ms\n", millis() - t0);
  lv_obj_del(boot);
  Serial.printf("self-check: abjad(الله)=%ld (expect 66)\n", abjadSum("الله"));

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  // Browsers get the page; PowerShell (`irm <board> | iex`) gets the terminal client,
  // wrapped in & { } so its variables stay out of the user's session.
  static const char *uaHeader[] = {"User-Agent"};
  web.collectHeaders(uaHeader, 1);
  web.on("/", [] {
    if (web.header("User-Agent").indexOf("PowerShell") < 0) {
      web.send_P(200, "text/html; charset=utf-8", PAGE);
      return;
    }
    extern const char ps1[] asm("_binary_data_wafq_client_ps1_start");
    String s = String("& {\n") + ps1 + "\n}\n";
    s.replace("'thmi.local'", "'" + web.hostHeader() + "'");
    web.send(200, "text/plain; charset=utf-8", s);
  });
  web.on("/messages.json", serveMessages);
  web.on("/wafq.tgz", [] {
    extern const uint8_t tgz[] asm("_binary_data_wafq_tgz_start");
    extern const uint8_t tgzEnd[] asm("_binary_data_wafq_tgz_end");
    web.send_P(200, "application/gzip", (const char *)tgz, tgzEnd - tgz);
  });
  // Node-free client for plain Windows.
  web.on("/wafq-client.ps1", [] {
    extern const char ps1[] asm("_binary_data_wafq_client_ps1_start");
    web.send_P(200, "text/plain; charset=utf-8", ps1);
  });
  web.on("/wafq.cmd", [] {
    extern const char cmd[] asm("_binary_data_wafq_cmd_start");
    web.send_P(200, "text/plain; charset=utf-8", cmd);
  });
  web.begin();
}

void loop() {
  lv_timer_handler();

  static uint32_t lastCheck = 0;
  if (millis() - lastCheck > 1000) {
    lastCheck = millis();
    bool up = WiFi.status() == WL_CONNECTED;
    if (up && !udpUp) {
      udpUp = udp.begin(PORT);
      MDNS.begin(DEVICE_NAME);  // reachable as <DEVICE_NAME>.local
    }
    if (!up && udpUp) {
      udp.stop();
      udpUp = false;
    }
    static String shown;
    String s = up ? String(DEVICE_NAME) + "  " + WiFi.localIP().toString() : String("WiFi connecting...");
    if (s != shown) lv_label_set_text(statusLbl, (shown = s).c_str());
  }
  web.handleClient();

  if (udpUp && udp.parsePacket() > 0) {
    static uint8_t buf[MAX_PACKET];
    static char plain[MAX_PACKET];
    int n = udp.read(buf, sizeof buf);
    char *nl;
    if (n > 0 && openPacket(buf, n, plain) && (nl = strchr(plain, '\n'))) {
      *nl = 0;
      if (strcmp(plain, DEVICE_NAME)) {  // skip own broadcast echo
        remember(abjadSum(nl + 1), buf, n);
        addLog(plain, nl + 1);
        showTalisman(nl + 1);
      }
    }
  }
  delay(5);
}
