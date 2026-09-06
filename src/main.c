/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include "pico_keys.h"

#if !defined(ENABLE_EMULATION)
#include "tusb.h"
#endif
#if defined(ENABLE_EMULATION)
#include "emulation.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#include "rom/gpio.h"
#include "tinyusb.h"
#include "esp_efuse.h"
#define BOOT_PIN GPIO_NUM_0
#elif defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "bsp/board.h"
#include "pico/aon_timer.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
#endif

#include "random.h"
#include "apdu.h"
#include "usb.h"
#include "mbedtls/sha256.h"

extern void do_flash();
extern void low_flash_init();
extern int init_otp_files();

app_t apps[16];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

static bool aid_matches(const uint8_t *registered_aid, const uint8_t *aid, size_t aid_len) {
    return aid_len >= registered_aid[0] &&
        memcmp(registered_aid + 1, aid, registered_aid[0]) == 0;
}

__attribute__((weak)) bool picokey_app_policy(const uint8_t *aid, size_t aid_len) {
    (void) aid;
    (void) aid_len;
    return true;
}

bool app_exists(const uint8_t *aid, size_t aid_len) {
    for (int a = 0; a < num_apps; a++) {
        if (aid_matches(apps[a].aid, aid, aid_len)) {
            return true;
        }
    }
    return false;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    for (int a = 0; a < num_apps; a++) {
        if (apps[a].aid[0] == aid[0] &&
            memcmp(apps[a].aid + 1, aid + 1, aid[0]) == 0) {
            return 1;
        }
    }
    if (num_apps < sizeof(apps) / sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        apps[num_apps].aid = aid;
        num_apps++;
        return 1;
    }
    return 0;
}

static int select_app_impl(const uint8_t *aid, size_t aid_len) {
    app_t *candidate = NULL;
    for (int a = 0; a < num_apps; a++) {
        if (aid_matches(apps[a].aid, aid, aid_len) &&
            (!candidate || apps[a].aid[0] > candidate->aid[0])) {
            candidate = &apps[a];
        }
    }
    if (!candidate) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }

    if (!picokey_app_policy(candidate->aid + 1, candidate->aid[0])) {
        if (candidate == current_app) {
            if (current_app->unload) {
                current_app->unload();
            }
            current_app = NULL;
        }
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }

    bool reselect = candidate == current_app;
    if (!reselect && current_app && current_app->unload) {
        current_app->unload();
    }
    if (!reselect) {
        current_app = NULL;
    }

    int ret = candidate->select_aid(candidate, reselect ? 0 : 1);
    if (ret == PICOKEY_OK) {
        current_app = candidate;
        return PICOKEY_OK;
    }

    if (reselect && current_app && current_app->unload) {
        current_app->unload();
    }
    current_app = NULL;
    return ret;
}

int select_app(const uint8_t *aid, size_t aid_len) {
    return select_app_impl(aid, aid_len);
}


int (*button_pressed_cb)(uint8_t) = NULL;

void execute_tasks();

static bool req_button_pending = false;

bool is_req_button_pending() {
    return __atomic_load_n(&req_button_pending, __ATOMIC_ACQUIRE);
}

static bool cancel_button = false;

void button_cancel_request(void) {
    __atomic_store_n(&cancel_button, true, __ATOMIC_RELEASE);
}

void button_cancel_clear(void) {
    __atomic_store_n(&cancel_button, false, __ATOMIC_RELEASE);
}

bool button_cancel_is_requested(void) {
    return __atomic_load_n(&cancel_button, __ATOMIC_ACQUIRE);
}

#ifdef _MSC_VER
#include <windows.h>
struct timezone
{
    __int32  tz_minuteswest; /* minutes W of Greenwich */
    bool  tz_dsttime;     /* type of dst correction */
};
int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
    (void)tzp;
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = (long)((time - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}
#endif
#if !defined(ENABLE_EMULATION)
#ifdef ESP_PLATFORM
bool picok_board_button_read() {
    int boot_state = gpio_get_level(BOOT_PIN);
    return boot_state == 0;
}
#elif defined(PICO_PLATFORM)
bool __no_inline_not_in_flash_func(picok_get_bootsel_button)() {
    const uint CS_PIN_INDEX = 1;

    // Must disable interrupts, as interrupt handlers may be in flash, and we
    // are about to temporarily disable flash access!
    uint32_t flags = save_and_disable_interrupts();

    // Set chip select to Hi-Z
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    // Note we can't call into any sleep functions in flash right now
    for (volatile int i = 0; i < 1000; ++i);

    // The HI GPIO registers in SIO can observe and control the 6 QSPI pins.
    // Note the button pulls the pin *low* when pressed.
#if PICO_RP2040
    #define CS_BIT (1u << 1)
#else
    #define CS_BIT SIO_GPIO_HI_IN_QSPI_CSN_BITS
#endif
    bool button_state = !(sio_hw->gpio_hi_in & CS_BIT);

    // Need to restore the state of chip select, else we are going to have a
    // bad time when we return to code in flash!
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(flags);

    return button_state;
}
bool picok_board_button_read(void) {
  return picok_get_bootsel_button();
}
#else
bool picok_board_button_read(void) {
    return true; // always unpressed
}
#endif
#define BUTTON_DEBOUNCE_MS 40U
#define BUTTON_MULTI_PRESS_WINDOW_MS 1000U

bool button_pressed_state = false;
bool button_raw_state = false;
uint32_t button_raw_changed_time = 0;
uint32_t button_pressed_time = 0;
uint8_t button_press = 0;
bool wait_button() {
    /* Disabled by default. As LED may not be properly configured,
       it will not be possible to indicate button press unless it
       is commissioned. */
    uint32_t button_timeout = 0;
    if (phy_data.up_btn_present) {
        button_timeout = phy_data.up_btn * 1000;
    }
    if (button_timeout == 0) {
        return false;
    }
    uint32_t start_button = board_millis();
    bool timeout = false;
    button_cancel_clear();
    uint32_t led_mode = led_get_mode();
    led_set_mode(MODE_BUTTON);
    __atomic_store_n(&req_button_pending, true, __ATOMIC_RELEASE);
    while (picok_board_button_read() == false && !button_cancel_is_requested()) {
#if defined(ESP_PLATFORM)
        vTaskDelay(1);
#elif defined(PICO_PLATFORM)
        sleep_ms(1);
#endif
        if (start_button + button_timeout < board_millis()) { /* timeout */
            timeout = true;
            break;
        }
    }
    if (!timeout) {
        while (picok_board_button_read() == true && !button_cancel_is_requested()) {
#if defined(ESP_PLATFORM)
            vTaskDelay(1);
#elif defined(PICO_PLATFORM)
            sleep_ms(1);
#endif
            if (start_button + 15000 < board_millis()) { /* timeout */
                timeout = true;
                break;
            }
        }
    }
    led_set_mode(led_mode);
    __atomic_store_n(&req_button_pending, false, __ATOMIC_RELEASE);
    return timeout || button_cancel_is_requested();
}

__attribute__((weak)) int picokey_init() {
    return 0;
}

#endif

bool set_rtc = false;

bool has_set_rtc() {
    return set_rtc;
}

void set_rtc_time(time_t t) {
#ifdef PICO_PLATFORM
    struct timespec tv = {.tv_sec = t, .tv_nsec = 0};
    aon_timer_set_time(&tv);
#else
    struct timeval tv = {.tv_sec = t, .tv_usec = 0};
    settimeofday(&tv, NULL);
#endif
    set_rtc = true;
}

time_t get_rtc_time() {
#ifdef PICO_PLATFORM
    struct timespec tv;
    aon_timer_get_time(&tv);
    return tv.tv_sec;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
#endif
}

struct apdu apdu;

void init_rtc() {
#ifdef PICO_PLATFORM
    struct timespec tv = {0};
    tv.tv_sec = 1577836800; // 2020-01-01
    aon_timer_start(&tv);
#endif
}

extern void hwrng_task();
extern void usb_task();
__attribute__((weak)) void picokey_extra_transport_init() {}
__attribute__((weak)) void picokey_extra_transport_task() {}

void execute_tasks()
{
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    tud_task(); // tinyusb device task
#endif
#if !defined(ESP_PLATFORM) || !CONFIG_PICO_FIDO2_QEMU
    usb_task();
#endif
    picokey_extra_transport_task();
    led_blinking_task();
}

void core0_loop() {
    while (1) {
        execute_tasks();
        hwrng_task();
        if (low_flash_is_pending() && card_try_claim_maintenance()) {
            do_flash();
            card_release_maintenance();
        }
#ifndef ENABLE_EMULATION
        if (button_pressed_cb && board_millis() > 1000 && !is_busy()) { // wait 1 second to boot up
            uint32_t now = board_millis();
            bool raw_button_state = picok_board_button_read();
            if (raw_button_state != button_raw_state) {
                button_raw_state = raw_button_state;
                button_raw_changed_time = now;
            }
            if (button_raw_state != button_pressed_state &&
                now - button_raw_changed_time >= BUTTON_DEBOUNCE_MS) {
                button_pressed_state = button_raw_state;
                if (button_pressed_state == false) { // stable release
                    if (button_pressed_time == 0 ||
                        now - button_pressed_time >= BUTTON_MULTI_PRESS_WINDOW_MS) {
                        button_press = 1;
                    }
                    else if (button_press < UINT8_MAX) {
                        button_press++;
                    }
                    button_pressed_time = now;
                }
            }
            if (button_pressed_time > 0 && button_press > 0 &&
                now - button_pressed_time >= BUTTON_MULTI_PRESS_WINDOW_MS &&
                button_pressed_state == false) {
                if (button_pressed_cb != NULL) {
                    (*button_pressed_cb)(button_press);
                }
                button_pressed_time = 0;
                button_press = 0;
            }
        }
#endif
#ifdef ESP_PLATFORM
    vTaskDelay(pdMS_TO_TICKS(10));
#endif
    }
}

char pico_serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
uint8_t pico_serial_hash[32];
pico_unique_board_id_t pico_serial;
#ifdef ESP_PLATFORM
#define pico_get_unique_board_id(a) do { uint32_t value; esp_efuse_read_block(EFUSE_BLK1, &value, 0, 32); memcpy((uint8_t *)(a), &value, sizeof(uint32_t)); esp_efuse_read_block(EFUSE_BLK1, &value, 32, 32); memcpy((uint8_t *)(a)+4, &value, sizeof(uint32_t)); } while(0)
extern tinyusb_config_t tusb_cfg;
extern const uint8_t desc_config[];
TaskHandle_t hcore0 = NULL, hcore1 = NULL;
int app_main() {
#else
#ifndef PICO_PLATFORM
#define pico_get_unique_board_id(a) memset(a, 0, sizeof(*(a)))
#endif
int main(void) {
#endif
    pico_get_unique_board_id(&pico_serial);
    memset(pico_serial_str, 0, sizeof(pico_serial_str));
    for (size_t i = 0; i < sizeof(pico_serial); i++) {
        snprintf(&pico_serial_str[2 * i], 3, "%02X", pico_serial.id[i]);
    }
    mbedtls_sha256(pico_serial.id, sizeof(pico_serial.id), pico_serial_hash, false);

#ifndef ENABLE_EMULATION
#ifdef PICO_PLATFORM
    board_init();
    stdio_init_all();
#endif

#else
    if (emul_init("127.0.0.1", 35963) != 0) {
        return 1;
    }
#endif

    random_init();

    int otp_ret = init_otp_files();
    if (otp_ret != PICOKEY_OK) {
        printf("OTP initialization failed [%d]\n", otp_ret);
        return otp_ret;
    }

    low_flash_init();

    scan_flash();

    init_rtc();

#ifndef ENABLE_EMULATION
    phy_init();
#endif

    led_init();

    usb_init();
    picokey_extra_transport_init();

#ifndef ENABLE_EMULATION
#ifdef ESP_PLATFORM
    gpio_pad_select_gpio(BOOT_PIN);
    gpio_set_direction(BOOT_PIN, GPIO_MODE_INPUT);
    gpio_pullup_en(BOOT_PIN);
    gpio_pulldown_dis(BOOT_PIN);

    tusb_cfg.string_descriptor[3] = pico_serial_str;
    if (phy_data.usb_product_present) {
        tusb_cfg.string_descriptor[2] = phy_data.usb_product;
    }
    static char tmps[4][32];
    for (int i = 4; i < tusb_cfg.string_descriptor_count; i++) {
        strlcpy(tmps[i-4], tusb_cfg.string_descriptor[2], sizeof(tmps[0]));
        strlcat(tmps[i-4], " ", sizeof(tmps[0]));
        strlcat(tmps[i-4], tusb_cfg.string_descriptor[i], sizeof(tmps[0]));
        tusb_cfg.string_descriptor[i] = tmps[i-4];
    }
    tusb_cfg.configuration_descriptor = desc_config;

#if !CONFIG_PICO_FIDO2_QEMU
    tinyusb_driver_install(&tusb_cfg);
#endif
#else
    tusb_init();
#endif
#endif

#ifndef ENABLE_EMULATION
    picokey_init();
#endif

#ifdef ESP_PLATFORM
    if (xTaskCreatePinnedToCore(core0_loop, "core0", CONFIG_PICOKEYS_ESP32_CORE_STACK_SIZE,
                               NULL, CONFIG_TINYUSB_TASK_PRIORITY - 1, &hcore0,
                               ESP32_CORE0) != pdPASS) {
        printf("core0 task creation failed\n");
        return 1;
    }
#else
    core0_loop();
#endif

    return 0;
}
