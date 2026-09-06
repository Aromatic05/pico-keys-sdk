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

#ifndef _USB_H_
#define _USB_H_

#if defined(ENABLE_EMULATION)
#include "emulation.h"
#elif defined(ESP_PLATFORM)
#include "esp_compat.h"
#elif defined(PICO_PLATFORM)
#include "pico/util/queue.h"
#else
#include "queue.h"
#include "board.h"
#endif

#include "compat.h"

/* USB thread */
#define EV_CARD_CHANGE        1
#define EV_TX_FINISHED        2
#define EV_EXEC_ACK_REQUIRED  4
#define EV_EXEC_FINISHED      8
#define EV_RX_DATA_READY     16
#define EV_PRESS_BUTTON      32

/* Card thread */
#define EV_MODIFY_CMD_AVAILABLE   1
#define EV_VERIFY_CMD_AVAILABLE   2
#define EV_CMD_AVAILABLE          4
#define EV_EXIT                   8
#define EV_BUTTON_TIMEOUT        16
#define EV_BUTTON_PRESSED        32

enum { ITF_INVALID = 0xFF };
enum { CARD_OWNER_MAINTENANCE = 0xFE };
enum {
    HID_TRANSPORT_CAPACITY = 2,
    CCID_TRANSPORT_CAPACITY = 2,
    CARD_INTERFACE_CAPACITY = 8,
};

#ifdef USB_ITF_HID
    extern uint8_t ITF_HID_CTAP, ITF_HID_KB;
    extern uint8_t ITF_HID, ITF_KEYBOARD;
    extern uint8_t ITF_HID_TOTAL;
#endif

#ifdef USB_ITF_CCID
    extern uint8_t ITF_SC_CCID, ITF_SC_WCID;
    extern uint8_t ITF_CCID, ITF_WCID;
    extern uint8_t ITF_SC_TOTAL;
#endif
extern uint8_t ITF_TOTAL;

enum {
    REPORT_ID_KEYBOARD = 0,
    REPORT_ID_COUNT
};

#if defined(ESP_PLATFORM) && defined(USB_ITF_HID) && defined(USB_ITF_CCID)
#define TUSB_SMARTCARD_CCID_EPS 2
#else
#define TUSB_SMARTCARD_CCID_EPS 3
#endif

extern void usb_task();
extern queue_t usb_to_card_q;
extern queue_t card_to_usb_q;

extern bool card_try_claim(uint8_t itf);
extern bool card_try_claim_maintenance(void);
extern void card_release_maintenance(void);
extern bool card_start_claimed(uint8_t itf, void *(*func)(void *));
extern bool card_exit_claimed(uint8_t itf);
extern void card_release(uint8_t itf);
extern bool card_command_is_owned_by(uint8_t itf);
extern int card_status(uint8_t itf);
extern uint8_t card_register_interface(uint32_t timeout_ms);
extern bool card_is_idle();
extern bool card_is_owned_by(uint8_t itf);
extern void usb_init();
extern uint8_t picokey_usb_interface_policy(uint8_t configured);
extern void picokey_usb_identity_policy(uint8_t enabled_usb_itf, uint16_t *vid, uint16_t *pid);
extern uint16_t picokey_usb_device_version_policy(uint16_t configured);

extern uint16_t finished_data_size;
extern void usb_set_timeout_counter(uint8_t itf, uint32_t v);
extern void card_init_core1();

extern void usb_send_event(uint32_t flag);
extern void timeout_stop();
extern void timeout_start();
extern bool is_busy();

#ifdef USB_ITF_HID
extern void driver_exec_finished_hid(uint16_t size_next);
extern void driver_exec_finished_cont_hid(uint8_t itf, uint16_t size_next, uint16_t offset);
#endif

#ifdef USB_ITF_CCID
extern void driver_exec_finished_ccid(uint8_t itf, uint16_t size_next);
extern void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size_next, uint16_t offset);
extern uint16_t driver_exec_finished_fast_ccid(uint8_t itf, const uint8_t *data, uint16_t size, uint16_t final_sw, uint16_t remaining);
#endif

#ifdef ENABLE_EMULATION
extern void driver_exec_finished_emul(uint8_t itf, uint16_t size_next);
extern void driver_exec_finished_cont_emul(uint8_t itf, uint16_t size_next, uint16_t offset);
#endif

#define USB_BUFFER_SIZE         2048

PACK(
typedef struct {
    uint8_t buffer[USB_BUFFER_SIZE];
    uint16_t r_ptr;
    uint16_t w_ptr;
}) usb_buffer_t;

typedef enum {
    WRITE_UNKNOWN = 0,
    WRITE_PENDING,
    WRITE_FAILED,
    WRITE_SUCCESS,
} write_status_t;

#endif
