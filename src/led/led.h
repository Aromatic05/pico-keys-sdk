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

#ifndef _LED_H_
#define _LED_H_

#include <stdbool.h>
#include <stdint.h>

enum {
    LED_COLOR_OFF = 0,
    LED_COLOR_RED,
    LED_COLOR_GREEN,
    LED_COLOR_BLUE,
    LED_COLOR_YELLOW,
    LED_COLOR_MAGENTA,
    LED_COLOR_CYAN,
    LED_COLOR_WHITE
};

#define LED_OFF_BITS        12
#define LED_OFF_SHIFT       0
#define LED_OFF_MASK        (((1 << LED_OFF_BITS) - 1) << LED_OFF_SHIFT)
#define LED_ON_BITS         12
#define LED_ON_SHIFT        LED_OFF_BITS
#define LED_ON_MASK         (((1 << LED_ON_BITS) - 1) << LED_ON_SHIFT)
#define LED_COLOR_BITS      3
#define LED_COLOR_SHIFT     (LED_ON_BITS + LED_OFF_BITS)
#define LED_COLOR_MASK      (((1 << LED_COLOR_BITS) - 1) << LED_COLOR_SHIFT)
#define LED_BTNESS_BITS     4
#define LED_BTNESS_SHIFT    (LED_ON_BITS + LED_OFF_BITS + LED_COLOR_BITS)
#define LED_BTNESS_MASK     (((1 << LED_BTNESS_BITS) - 1 ) << LED_BTNESS_SHIFT)

#define MAX_BTNESS          ((1 << LED_BTNESS_BITS) - 1)
#define HALF_BTNESS         ((1 << (LED_BTNESS_BITS - 1)) - 1)

typedef enum {
    LED_BASE_BOOTING = 0,
    LED_BASE_NORMAL_IDLE,
    LED_BASE_USB_SUSPENDED,
    LED_BASE_PROCESSING,
    LED_BASE_MAINTENANCE,
    LED_BASE_ERROR,
} led_base_state_t;

typedef enum {
    LED_INTERACTION_NONE = 0,
    LED_INTERACTION_WAITING_TOUCH,
    LED_INTERACTION_TOUCH_ACCEPTED,
} led_interaction_state_t;

typedef enum {
    LED_EVENT_USB_MOUNTED = 0,
    LED_EVENT_USB_UNMOUNTED,
    LED_EVENT_USB_SUSPENDED,
    LED_EVENT_USB_RESUMED,
    LED_EVENT_PROCESSING_BEGIN,
    LED_EVENT_PROCESSING_END,
    LED_EVENT_MAINTENANCE_BEGIN,
    LED_EVENT_TOUCH_WAIT_BEGIN,
    LED_EVENT_TOUCH_ACCEPTED,
    LED_EVENT_TOUCH_CANCELLED,
    LED_EVENT_ERROR,
} led_event_t;

typedef struct {
    led_base_state_t base;
    led_interaction_state_t interaction;
    uint32_t interaction_started_ms;
} led_state_snapshot_t;

extern void led_state_transition(led_event_t event);
extern led_state_snapshot_t led_state_snapshot(void);
extern void led_blinking_task();
extern void led_off_all();
extern void led_init();

typedef struct {
    void (*init)();
    void (*set_color)(uint8_t color, uint32_t led_brightness, float progress);
} led_driver_t;

extern led_driver_t *led_driver;

#endif // _LED_H_
