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
#include <assert.h>
#include "pico_keys.h"
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "bsp/board.h"
#endif
#include "usb.h"
#include "apdu.h"
#ifndef ENABLE_EMULATION
#include "tusb.h"
#else
#include "emulation.h"
#endif

#ifndef ENABLE_EMULATION
void tud_mount_cb(void) {
    led_set_mode(MODE_MOUNTED);
}

void tud_umount_cb(void) {
    led_set_mode(MODE_NOT_MOUNTED);
}

void tud_suspend_cb(bool remote_wakeup_en) {
    (void)remote_wakeup_en;
    led_set_mode(MODE_SUSPENDED);
}

void tud_resume_cb(void) {
    led_set_mode(MODE_MOUNTED);
}
#endif

// For memcpy
#include <string.h>

// Device specific functions
static uint32_t timeout_counter[CARD_INTERFACE_CAPACITY];
static uint8_t card_locked_itf = 0; // no locked
static void *(*card_locked_func)(void *) = NULL;
#ifndef ENABLE_EMULATION
static mutex_t mutex;
static mutex_t card_state_mutex;
extern void usb_desc_setup();
#endif
static bool card_command_active = false;
static uint8_t card_command_itf = ITF_INVALID;
#if !defined(PICO_PLATFORM) && !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#ifdef _MSC_VER
#include "pthread_win32.h"
#endif
pthread_t hcore0, hcore1;
#endif

#ifdef USB_ITF_HID
    uint8_t ITF_HID_CTAP = ITF_INVALID, ITF_HID_KB = ITF_INVALID;
    uint8_t ITF_HID = ITF_INVALID, ITF_KEYBOARD = ITF_INVALID;
    uint8_t ITF_HID_TOTAL = 0;
    extern void hid_init();
#endif

#ifdef USB_ITF_CCID
    uint8_t ITF_SC_CCID = ITF_INVALID, ITF_SC_WCID = ITF_INVALID;
    uint8_t ITF_CCID = ITF_INVALID, ITF_WCID = ITF_INVALID;
    uint8_t ITF_SC_TOTAL = 0;
    extern void ccid_init();
#endif
uint8_t ITF_TOTAL = 0;

void usb_set_timeout_counter(uint8_t itf, uint32_t v) {
    timeout_counter[itf] = v;
}

uint8_t card_register_interface(uint32_t timeout_ms) {
    if (ITF_TOTAL >= CARD_INTERFACE_CAPACITY) {
        return ITF_INVALID;
    }
    bool idle = card_locked_itf == ITF_TOTAL && card_locked_func == NULL;
    uint8_t itf = ITF_TOTAL++;
    timeout_counter[itf] = timeout_ms;
    if (idle) {
        card_locked_itf = ITF_TOTAL;
    }
    return itf;
}

bool card_is_idle() {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&card_state_mutex);
#endif
    bool idle = !card_command_active;
#ifndef ENABLE_EMULATION
    mutex_exit(&card_state_mutex);
#endif
    return idle;
}

bool card_is_owned_by(uint8_t itf) {
    return card_locked_itf == itf;
}

bool card_try_claim(uint8_t itf) {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&card_state_mutex);
#endif
    bool claimed = !card_command_active;
    if (claimed) {
        card_command_active = true;
        card_command_itf = itf;
    }
#ifndef ENABLE_EMULATION
    mutex_exit(&card_state_mutex);
#endif
    return claimed;
}

bool card_try_claim_maintenance(void) {
    return card_try_claim(CARD_OWNER_MAINTENANCE);
}

void card_release_maintenance(void) {
    card_release(CARD_OWNER_MAINTENANCE);
}

void card_release(uint8_t itf) {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&card_state_mutex);
#endif
    if (card_command_active && card_command_itf == itf) {
        card_command_active = false;
        card_command_itf = ITF_INVALID;
    }
#ifndef ENABLE_EMULATION
    mutex_exit(&card_state_mutex);
#endif
}

bool card_command_is_owned_by(uint8_t itf) {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&card_state_mutex);
#endif
    bool owned = card_command_active && card_command_itf == itf;
#ifndef ENABLE_EMULATION
    mutex_exit(&card_state_mutex);
#endif
    return owned;
}

queue_t usb_to_card_q = {0};
queue_t card_to_usb_q = {0};

#ifndef ENABLE_EMULATION
extern tusb_desc_device_t desc_device;
extern char *string_desc_itf[4], *string_desc_arr[];
#endif

__attribute__((weak)) uint8_t picokey_usb_interface_policy(uint8_t configured) {
    return configured;
}

__attribute__((weak)) void picokey_usb_identity_policy(uint8_t enabled_usb_itf, uint16_t *vid, uint16_t *pid) {
    (void)enabled_usb_itf;
    (void)vid;
    (void)pid;
}

__attribute__((weak)) uint16_t picokey_usb_device_version_policy(uint16_t configured) {
    return configured;
}

void usb_init()
{
#ifndef ENABLE_EMULATION
    if (phy_data.vidpid_present) {
        desc_device.idVendor = phy_data.vid;
        desc_device.idProduct = phy_data.pid;
    }
    else {
        phy_data.vid = desc_device.idVendor;
        phy_data.pid = desc_device.idProduct;
        phy_data.vidpid_present = true;
    }
    mutex_init(&mutex);
    mutex_init(&card_state_mutex);
#endif
    card_command_active = false;
    card_command_itf = ITF_INVALID;
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);

    uint8_t enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_WCID | PHY_USB_ITF_HID | PHY_USB_ITF_KB;
#ifndef ENABLE_EMULATION
    if (phy_data.enabled_usb_itf_present) {
        enabled_usb_itf = phy_data.enabled_usb_itf;
    }
    enabled_usb_itf = picokey_usb_interface_policy(enabled_usb_itf);
    uint16_t usb_vid = desc_device.idVendor;
    uint16_t usb_pid = desc_device.idProduct;
    picokey_usb_identity_policy(enabled_usb_itf, &usb_vid, &usb_pid);
    desc_device.idVendor = usb_vid;
    desc_device.idProduct = usb_pid;
    desc_device.bcdDevice = picokey_usb_device_version_policy(desc_device.bcdDevice);
    phy_data.vid = usb_vid;
    phy_data.pid = usb_pid;
#endif

#ifdef USB_ITF_HID
    ITF_HID_TOTAL = 0;
#endif
#ifdef USB_ITF_CCID
    ITF_SC_TOTAL = 0;
#endif
    ITF_TOTAL = 0;
    memset(timeout_counter, 0, sizeof(timeout_counter));
#ifdef USB_ITF_HID
    if (enabled_usb_itf & PHY_USB_ITF_HID) {
        ITF_HID_CTAP = ITF_HID_TOTAL++;
        ITF_HID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[5];
#endif
    }
    if (enabled_usb_itf & PHY_USB_ITF_KB) {
        ITF_HID_KB = ITF_HID_TOTAL++;
        ITF_KEYBOARD = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[6];
#endif
    }
#endif
#ifdef USB_ITF_CCID
    if (enabled_usb_itf & PHY_USB_ITF_CCID) {
        ITF_SC_CCID = ITF_SC_TOTAL++;
        ITF_CCID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[7];
#endif
    }
    if (enabled_usb_itf & PHY_USB_ITF_WCID) {
        ITF_SC_WCID = ITF_SC_TOTAL++;
        ITF_WCID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[8];
#endif
    }
#endif
    assert(ITF_TOTAL <= CARD_INTERFACE_CAPACITY);
    card_locked_itf = ITF_TOTAL;
#ifdef USB_ITF_HID
    if (ITF_HID_TOTAL > 0) {
        hid_init();
    }
#endif
#ifdef USB_ITF_CCID
    if (ITF_SC_TOTAL > 0) {
        ccid_init();
    }
#endif
#ifdef ESP_PLATFORM
    usb_desc_setup();
#endif
}

uint32_t timeout = 0;
void timeout_stop() {
    timeout = 0;
}

void timeout_start() {
    timeout = board_millis();
}

bool is_busy() {
    return timeout > 0;
}

void usb_send_event(uint32_t flag) {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&mutex);
#endif
    queue_add_blocking(&usb_to_card_q, &flag);
    if (flag == EV_CMD_AVAILABLE) {
        timeout_start();
    }
    uint32_t m;
    queue_remove_blocking(&card_to_usb_q , &m);
#ifndef ENABLE_EMULATION
    mutex_exit(&mutex);
#endif
}

extern void low_flash_init();
void card_init_core1() {
    low_flash_init_core1();
}

uint16_t finished_data_size = 0;

static void card_exit_unchecked(void);

static bool card_start(uint8_t itf, void *(*func)(void *)) {
    timeout_start();
    if (card_locked_itf != itf || card_locked_func != func) {
        if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
            card_exit_unchecked();
        }
        if (func) {
            multicore_reset_core1();
#ifdef ESP_PLATFORM
            if (multicore_launch_func_core1(func) != pdPASS) {
                hcore1 = NULL;
                timeout_stop();
                return false;
            }
#else
            multicore_launch_func_core1(func);
#endif
        }
        led_set_mode(MODE_MOUNTED);
        card_locked_itf = itf;
        card_locked_func = func;
    }
    return true;
}

bool card_start_claimed(uint8_t itf, void *(*func)(void *)) {
    if (!card_command_is_owned_by(itf)) {
        return false;
    }
    return card_start(itf, func);
}

bool card_exit_claimed(uint8_t itf) {
    if (!card_command_is_owned_by(itf)) {
        return false;
    }
    card_exit_unchecked();
    return true;
}

static void card_exit_unchecked(void) {
    if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
        usb_send_event(EV_EXIT);
        uint32_t m;
        while (queue_is_empty(&usb_to_card_q) == false) {
            if (queue_try_remove(&usb_to_card_q, &m) == false) {
                break;
            }
        }
        while (queue_is_empty(&card_to_usb_q) == false) {
#ifndef ENABLE_EMULATION
            mutex_enter_blocking(&mutex);
#endif
            if (queue_try_remove(&card_to_usb_q, &m) == false) {
                break;
            }
#ifndef ENABLE_EMULATION
            mutex_exit(&mutex);
#endif
        }
        led_set_mode(MODE_SUSPENDED);
#ifdef ESP_PLATFORM
        hcore1 = NULL;
#endif
    }
    card_locked_itf = ITF_TOTAL;
    card_locked_func = NULL;
}
extern void hid_task();
extern void ccid_task();
extern void emul_task();
void usb_task() {
#ifdef USB_ITF_HID
    hid_task();
#endif
#ifdef ENABLE_EMULATION
    emul_task();
#else
#ifdef USB_ITF_CCID
    ccid_task();
#endif
#endif
}

int card_status(uint8_t itf) {
    if (card_locked_itf == itf) {
        uint32_t m = 0x0;
#ifndef ENABLE_EMULATION
        mutex_enter_blocking(&mutex);
#endif
        bool has_m = queue_try_remove(&card_to_usb_q, &m);
#ifndef ENABLE_EMULATION
        mutex_exit(&mutex);
#endif
        //if (m != 0)
        //    printf("\n ------ M = %lu\n",m);
        if (has_m) {
            if (m == EV_EXEC_FINISHED) {
                if (low_flash_is_pending()) {
                    do_flash();
                    if (low_flash_is_pending()) {
                        queue_try_add(&card_to_usb_q, &m);
                        return PICOKEY_ERR_FILE_NOT_FOUND;
                    }
                }
                timeout_stop();
                led_set_mode(MODE_MOUNTED);
                return PICOKEY_OK;
            }
#ifndef ENABLE_EMULATION
            else if (m == EV_PRESS_BUTTON) {
                uint32_t flag = wait_button() ? EV_BUTTON_TIMEOUT : EV_BUTTON_PRESSED;
                queue_try_add(&usb_to_card_q, &flag);
            }
#endif
            return PICOKEY_ERR_FILE_NOT_FOUND;
        }
        else {
            if (timeout > 0) {
                if (timeout + timeout_counter[itf] < board_millis()) {
                    timeout = board_millis();
                    return PICOKEY_ERR_BLOCKED;
                }
            }
        }
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

#ifndef USB_ITF_CCID
#include "device/usbd_pvt.h"
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 0;
    return NULL;
}
#endif
