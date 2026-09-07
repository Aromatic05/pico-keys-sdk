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
#ifdef PICO_PLATFORM
#include "bsp/board.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#include "esp_compat.h"
#elif defined(ENABLE_EMULATION)
#include "emulation.h"
#endif

led_driver_t *led_driver = NULL;

#define LED_STATE_INTERACTION_SHIFT 8U
#define LED_STATE_BASE_MASK         0xFFU
#define LED_STATE_INTERACTION_MASK  0xFFU

#define LED_TOUCH_WHITE_1_MS        120U
#define LED_TOUCH_DARK_MS           80U
#define LED_TOUCH_WHITE_2_MS        120U
#define LED_TOUCH_FEEDBACK_MS       (LED_TOUCH_WHITE_1_MS + LED_TOUCH_DARK_MS + LED_TOUCH_WHITE_2_MS)

#define LED_ON_NO_BLINK             ((1000U << LED_ON_SHIFT) | (0U << LED_OFF_SHIFT))

enum {
    RENDER_BOOTING = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_RED << LED_COLOR_SHIFT) | (500U << LED_ON_SHIFT) | (500U << LED_OFF_SHIFT),
    RENDER_NORMAL_IDLE = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_BLUE << LED_COLOR_SHIFT) | LED_ON_NO_BLINK,
    RENDER_USB_SUSPENDED = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_BLUE << LED_COLOR_SHIFT) | (1000U << LED_ON_SHIFT) | (2000U << LED_OFF_SHIFT),
    RENDER_PROCESSING = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_CYAN << LED_COLOR_SHIFT) | (50U << LED_ON_SHIFT) | (50U << LED_OFF_SHIFT),
    RENDER_MAINTENANCE = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_GREEN << LED_COLOR_SHIFT) | LED_ON_NO_BLINK,
    RENDER_ERROR = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_RED << LED_COLOR_SHIFT) | (100U << LED_ON_SHIFT) | (100U << LED_OFF_SHIFT),
    RENDER_WAITING_TOUCH = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_YELLOW << LED_COLOR_SHIFT) | (250U << LED_ON_SHIFT) | (250U << LED_OFF_SHIFT),
};

static uint32_t led_state_word = LED_BASE_BOOTING;
static uint32_t led_touch_accepted_ms = 0;

static uint32_t led_state_pack(led_base_state_t base, led_interaction_state_t interaction) {
    return ((uint32_t)base & LED_STATE_BASE_MASK) |
           (((uint32_t)interaction & LED_STATE_INTERACTION_MASK) << LED_STATE_INTERACTION_SHIFT);
}

static led_base_state_t led_state_base(uint32_t word) {
    return (led_base_state_t)(word & LED_STATE_BASE_MASK);
}

static led_interaction_state_t led_state_interaction(uint32_t word) {
    return (led_interaction_state_t)((word >> LED_STATE_INTERACTION_SHIFT) & LED_STATE_INTERACTION_MASK);
}

led_state_snapshot_t led_state_snapshot(void) {
    uint32_t word = __atomic_load_n(&led_state_word, __ATOMIC_ACQUIRE);
    led_state_snapshot_t snapshot = {
        .base = led_state_base(word),
        .interaction = led_state_interaction(word),
        .interaction_started_ms = __atomic_load_n(&led_touch_accepted_ms, __ATOMIC_ACQUIRE),
    };
    return snapshot;
}

void led_state_transition(led_event_t event) {
    uint32_t current;
    uint32_t next;
    do {
        current = __atomic_load_n(&led_state_word, __ATOMIC_ACQUIRE);
        led_base_state_t base = led_state_base(current);
        led_interaction_state_t interaction = led_state_interaction(current);

        switch (event) {
            case LED_EVENT_USB_MOUNTED:
            case LED_EVENT_USB_RESUMED:
                if (base != LED_BASE_MAINTENANCE && base != LED_BASE_ERROR) {
                    base = LED_BASE_NORMAL_IDLE;
                }
                break;
            case LED_EVENT_USB_UNMOUNTED:
                if (base != LED_BASE_MAINTENANCE && base != LED_BASE_ERROR) {
                    base = LED_BASE_BOOTING;
                    interaction = LED_INTERACTION_NONE;
                }
                break;
            case LED_EVENT_USB_SUSPENDED:
                if (base != LED_BASE_MAINTENANCE && base != LED_BASE_ERROR) {
                    base = LED_BASE_USB_SUSPENDED;
                    interaction = LED_INTERACTION_NONE;
                }
                break;
            case LED_EVENT_PROCESSING_BEGIN:
                if (base != LED_BASE_MAINTENANCE && base != LED_BASE_ERROR) {
                    base = LED_BASE_PROCESSING;
                }
                break;
            case LED_EVENT_PROCESSING_END:
                if (base == LED_BASE_PROCESSING) {
                    base = LED_BASE_NORMAL_IDLE;
                }
                break;
            case LED_EVENT_MAINTENANCE_BEGIN:
                if (base != LED_BASE_ERROR) {
                    base = LED_BASE_MAINTENANCE;
                    interaction = LED_INTERACTION_NONE;
                }
                break;
            case LED_EVENT_TOUCH_WAIT_BEGIN:
                if (base != LED_BASE_ERROR) {
                    interaction = LED_INTERACTION_WAITING_TOUCH;
                }
                break;
            case LED_EVENT_TOUCH_ACCEPTED:
                if (interaction == LED_INTERACTION_WAITING_TOUCH) {
                    __atomic_store_n(&led_touch_accepted_ms, board_millis(), __ATOMIC_RELEASE);
                    interaction = LED_INTERACTION_TOUCH_ACCEPTED;
                }
                break;
            case LED_EVENT_TOUCH_CANCELLED:
                interaction = LED_INTERACTION_NONE;
                break;
            case LED_EVENT_ERROR:
                base = LED_BASE_ERROR;
                interaction = LED_INTERACTION_NONE;
                break;
            default:
                return;
        }

        next = led_state_pack(base, interaction);
        if (next == current) {
            return;
        }
    } while (!__atomic_compare_exchange_n(&led_state_word, &current, next, false,
                                           __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
}

#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
static void led_state_expire_touch(uint32_t now) {
    uint32_t current = __atomic_load_n(&led_state_word, __ATOMIC_ACQUIRE);
    if (led_state_interaction(current) != LED_INTERACTION_TOUCH_ACCEPTED) {
        return;
    }
    uint32_t started = __atomic_load_n(&led_touch_accepted_ms, __ATOMIC_ACQUIRE);
    if (now - started < LED_TOUCH_FEEDBACK_MS) {
        return;
    }
    uint32_t next = led_state_pack(led_state_base(current), LED_INTERACTION_NONE);
    __atomic_compare_exchange_n(&led_state_word, &current, next, false,
                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static uint32_t led_render_base(led_base_state_t base) {
    switch (base) {
        case LED_BASE_NORMAL_IDLE:
            return RENDER_NORMAL_IDLE;
        case LED_BASE_USB_SUSPENDED:
            return RENDER_USB_SUSPENDED;
        case LED_BASE_PROCESSING:
            return RENDER_PROCESSING;
        case LED_BASE_MAINTENANCE:
            return RENDER_MAINTENANCE;
        case LED_BASE_ERROR:
            return RENDER_ERROR;
        case LED_BASE_BOOTING:
        default:
            return RENDER_BOOTING;
    }
}
#endif

void led_blinking_task() {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    static uint32_t start_ms = 0;
    static uint32_t stop_ms = 0;
    static uint32_t last_led_update_ms = 0;
    static uint32_t last_mode = UINT32_MAX;
    static uint8_t led_state = false;
    uint32_t now = board_millis();
    led_state_expire_touch(now);
    led_state_snapshot_t snapshot = led_state_snapshot();

    if (snapshot.interaction == LED_INTERACTION_TOUCH_ACCEPTED) {
        uint32_t age = now - snapshot.interaction_started_ms;
        bool white = age < LED_TOUCH_WHITE_1_MS ||
                     (age >= LED_TOUCH_WHITE_1_MS + LED_TOUCH_DARK_MS && age < LED_TOUCH_FEEDBACK_MS);
        if (now - last_led_update_ms > 2) {
            led_driver->set_color(white ? LED_COLOR_WHITE : LED_COLOR_OFF,
                                  white ? MAX_BTNESS : 0, white ? 1.f : 0.f);
            last_led_update_ms = now;
        }
        last_mode = UINT32_MAX;
        return;
    }

    uint32_t mode = snapshot.interaction == LED_INTERACTION_WAITING_TOUCH
        ? RENDER_WAITING_TOUCH
        : led_render_base(snapshot.base);
    uint8_t state = led_state;
#ifdef PICO_DEFAULT_LED_PIN_INVERTED
    state = !state;
#endif
    uint32_t led_brightness = (mode & LED_BTNESS_MASK) >> LED_BTNESS_SHIFT;
    uint32_t led_color = (mode & LED_COLOR_MASK) >> LED_COLOR_SHIFT;
    uint32_t led_off = (mode & LED_OFF_MASK) >> LED_OFF_SHIFT;
    uint32_t led_on = (mode & LED_ON_MASK) >> LED_ON_SHIFT;
    bool steady = led_off == 0;

    if (mode != last_mode) {
        start_ms = now;
        led_state = true;
        state = true;
        stop_ms = now + led_on;
        last_mode = mode;
    }

    float progress = steady ? 1.f : 0.f;

    if (!steady && stop_ms > start_ms) {
        progress = (float)(now - start_ms) / (stop_ms - start_ms);
    }

    if (!steady && !state) {
        progress = 1. - progress;
    }
    if (__atomic_load_n(&phy_data.opts, __ATOMIC_ACQUIRE) & PHY_OPT_LED_STEADY) {
        progress = 1;
    }

    // limit the frequency of LED status updates
    if (now - last_led_update_ms > 2) {
        led_driver->set_color(led_color, led_brightness, progress);
        last_led_update_ms = now;
    }

    if (!steady && now >= stop_ms){
        start_ms = stop_ms;
        led_state ^= 1; // toggle
        stop_ms = start_ms + (led_state ? led_on : led_off);
    }
#endif
}

void led_off_all() {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    led_driver->set_color(LED_COLOR_OFF, 0, 0);
#endif
}

extern led_driver_t led_driver_pico;
extern led_driver_t led_driver_cyw43;
extern led_driver_t led_driver_ws2812;
extern led_driver_t led_driver_neopixel;
extern led_driver_t led_driver_pimoroni;

void led_driver_init_dummy() {
    // Do nothing
}

void led_driver_color_dummy(uint8_t color, uint32_t led_brightness, float progress) {
    (void)color;
    (void)led_brightness;
    (void)progress;
    // Do nothing
}

led_driver_t led_driver_dummy = {
    .init = led_driver_init_dummy,
    .set_color = led_driver_color_dummy,
};

void led_init() {
    led_driver = &led_driver_dummy;
#if defined(ESP_PLATFORM) && CONFIG_PICO_FIDO2_QEMU
    return;
#endif
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    // Guess default driver
#if defined(PIMORONI_TINY2040) || defined(PIMORONI_TINY2350)
    led_driver = &led_driver_pimoroni;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_PIMORONI;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : PICO_DEFAULT_LED_PIN;
#elif defined(CYW43_WL_GPIO_LED_PIN)
    led_driver = &led_driver_cyw43;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_CYW43;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : CYW43_WL_GPIO_LED_PIN;
#elif defined(PICO_DEFAULT_WS2812_PIN)
    led_driver = &led_driver_ws2812;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_WS2812;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : PICO_DEFAULT_WS2812_PIN;
#elif defined(ESP_PLATFORM)
    #if defined(CONFIG_IDF_TARGET_ESP32S3)
        #define NEOPIXEL_PIN GPIO_NUM_48
    #elif defined(CONFIG_IDF_TARGET_ESP32S2)
        #define NEOPIXEL_PIN GPIO_NUM_15
    #elif defined(CONFIG_IDF_TARGET_ESP32C6)
        #define NEOPIXEL_PIN GPIO_NUM_8
    #else
        #define NEOPIXEL_PIN GPIO_NUM_27
    #endif
    led_driver = &led_driver_neopixel;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_NEOPIXEL;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : NEOPIXEL_PIN;
#elif defined(PICO_DEFAULT_LED_PIN)
    led_driver = &led_driver_pico;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_PICO;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : PICO_DEFAULT_LED_PIN;
#endif
    if (phy_data.led_driver_present) {
        switch (phy_data.led_driver) {
#ifdef ESP_PLATFORM
            case PHY_LED_DRIVER_NEOPIXEL:
                led_driver = &led_driver_neopixel;
                break;
#else
            case PHY_LED_DRIVER_PICO:
                led_driver = &led_driver_pico;
                break;
#ifdef CYW43_WL_GPIO_LED_PIN
            case PHY_LED_DRIVER_CYW43:
                led_driver = &led_driver_cyw43;
                break;
#endif
            case PHY_LED_DRIVER_WS2812:
                led_driver = &led_driver_ws2812;
                break;
            case PHY_LED_DRIVER_PIMORONI:
                led_driver = &led_driver_pimoroni;
                break;
#endif
            default:
                break;
        }
    }
    phy_data.led_driver_present = true;
    phy_data.led_gpio_present = true;
    led_driver->init();
    led_state_transition(LED_EVENT_USB_UNMOUNTED);
#endif
}
