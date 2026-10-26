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

#include "random.h"
#include "pico_keys.h"
#ifdef PICO_PLATFORM
#include "bsp/board.h"
#endif
#ifndef ENABLE_EMULATION
#include "tusb.h"
#include "device/usbd_pvt.h"
#else
#include "emulation.h"
#endif
#include "ccid.h"
#include "usb_descriptors.h"
#include "apdu.h"
#include "usb.h"
#include <assert.h>

#if MAX_RES_APDU_DATA_SIZE > MAX_CMD_APDU_DATA_SIZE
#define USB_BUF_SIZE (MAX_RES_APDU_DATA_SIZE + 20 + 9)
#else
#define USB_BUF_SIZE (MAX_CMD_APDU_DATA_SIZE + 20 + 9)
#endif

#define CCID_SET_PARAMS         0x61 /* non-ICCD command  */
#define CCID_POWER_ON           0x62
#define CCID_POWER_OFF          0x63
#define CCID_SLOT_STATUS        0x65 /* non-ICCD command */
#define CCID_SECURE             0x69 /* non-ICCD command */
#define CCID_GET_PARAMS         0x6C /* non-ICCD command */
#define CCID_RESET_PARAMS       0x6D /* non-ICCD command */
#define CCID_XFR_BLOCK          0x6F
#define CCID_DATA_BLOCK_RET     0x80
#define CCID_SLOT_STATUS_RET    0x81 /* non-ICCD result */
#define CCID_PARAMS_RET         0x82 /* non-ICCD result */
#define CCID_SETDATARATEANDCLOCKFREQUENCY 0x73
#define CCID_SETDATARATEANDCLOCKFREQUENCY_RET 0x84

#define CCID_MSG_SEQ_OFFSET     6
#define CCID_MSG_STATUS_OFFSET  7
#define CCID_MSG_ERROR_OFFSET   8
#define CCID_MSG_CHAIN_OFFSET   9
#define CCID_MSG_DATA_OFFSET    10  /* == CCID_MSG_HEADER_SIZE */
#define CCID_MAX_MSG_DATA_SIZE  USB_BUF_SIZE

#define CCID_STATUS_RUN     0x00
#define CCID_STATUS_PRESENT 0x01
#define CCID_STATUS_NOTPRESENT  0x02
#define CCID_CMD_STATUS_OK  0x00
#define CCID_CMD_STATUS_ERROR   0x40
#define CCID_CMD_STATUS_TIMEEXT 0x80

void driver_exec_busy_ccid(uint8_t itf, uint8_t seq);
#ifndef ENABLE_EMULATION
static void driver_exec_busy_status_ccid(uint8_t itf, uint8_t seq);
#endif

#define CCID_ERROR_XFR_OVERRUN  0xFC

/*
 * Since command-byte is at offset 0,
 * error with offset 0 means "command not supported".
 */
#define CCID_OFFSET_CMD_NOT_SUPPORTED 0
#define CCID_OFFSET_DATA_LEN 1
#define CCID_OFFSET_PARAM 8

#define CCID_THREAD_TERMINATED 0xffff
#define CCID_ACK_TIMEOUT 0x6600

PACK(
typedef struct {
    uint8_t bMessageType;
    uint32_t dwLength;
    uint8_t bSlot;
    uint8_t bSeq;
    uint8_t abRFU0;
    uint16_t abRFU1;
    uint8_t apdu; //Actually it is an array
}) ccid_header_t;

uint8_t ccid_status = 1;
#ifndef ENABLE_EMULATION
static uint8_t itf_num;
#endif

static usb_buffer_t ccid_rx[CCID_TRANSPORT_CAPACITY];
/* PIV attestation signs into a 2048-byte DER workspace starting immediately
 * after the 10-byte CCID header. The generic usb_buffer_t has only 2048
 * bytes and puts r_ptr/w_ptr immediately afterward: writing the DER tail
 * corrupts those pointers. Reserve the full APDU workspace plus the header
 * and status for this transport's response buffer instead. */
typedef struct {
    uint8_t buffer[USB_BUF_SIZE];
    uint16_t r_ptr;
    uint16_t w_ptr;
} ccid_tx_buffer_t;
static ccid_tx_buffer_t ccid_tx[CCID_TRANSPORT_CAPACITY];
static usb_buffer_t ccid_request[CCID_TRANSPORT_CAPACITY];
static uint8_t ccid_active_seq[CCID_TRANSPORT_CAPACITY];
static bool ccid_rx_overflow[CCID_TRANSPORT_CAPACITY];
/* Keep fast CCID responses out of the APDU result buffer: a Time Extension
 * must never overwrite certificate bytes being generated on the worker. */
#define CCID_FAST_FRAME_SIZE 64
static uint8_t ccid_fast_storage[CCID_TRANSPORT_CAPACITY][CCID_FAST_FRAME_SIZE];
#ifndef ENABLE_EMULATION
static uint8_t ccid_fast_pending[CCID_TRANSPORT_CAPACITY][CCID_FAST_FRAME_SIZE];
static uint16_t ccid_fast_length[CCID_TRANSPORT_CAPACITY];
static uint16_t ccid_fast_offset[CCID_TRANSPORT_CAPACITY];
/* One CCID response at a time: TinyUSB vendor buffers are byte streams. */
static uint16_t ccid_inflight_length[CCID_TRANSPORT_CAPACITY];
static volatile uint32_t ccid_inflight_acked[CCID_TRANSPORT_CAPACITY];
static volatile bool ccid_bus_reset_pending;
static bool ccid_drop_completion[CCID_TRANSPORT_CAPACITY];
/* PC/SC treats an immediate CMD_SLOT_BUSY during PowerOn/XfrBlock as a
 * transaction failure. Keep its complete USB request in the RX buffer while
 * a short BLE command owns the card, instead of consuming and failing it. */
#define CCID_BUSY_GRACE_MS 350U
static bool ccid_busy_wait_started[CCID_TRANSPORT_CAPACITY];
static uint32_t ccid_busy_wait_since[CCID_TRANSPORT_CAPACITY];
#ifdef ESP_PLATFORM
_Static_assert(CFG_TUD_VENDOR_TX_BUFSIZE >= USB_BUF_SIZE,
               "CCID complete response must fit the TinyUSB TX FIFO");
#endif
#endif

int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read);

void ccid_write_offset(uint8_t itf, uint16_t size, uint16_t offset) {
    ccid_tx[itf].w_ptr += size + offset;
    ccid_tx[itf].r_ptr += offset;
}

void ccid_write(uint8_t itf, uint16_t size) {
    ccid_write_offset(itf, size, 0);
}

static ccid_header_t *ccid_response[CCID_TRANSPORT_CAPACITY];
static ccid_header_t *ccid_resp_fast[CCID_TRANSPORT_CAPACITY];
static ccid_header_t *ccid_header[CCID_TRANSPORT_CAPACITY];

uint8_t sc_itf_to_usb_itf(uint8_t itf) {
    if (itf == ITF_SC_CCID) {
        return ITF_CCID;
    }
    else if (itf == ITF_SC_WCID) {
        return ITF_WCID;
    }
    return itf;
}

static apdu_session_id_t sc_itf_to_apdu_session(uint8_t itf) {
    return itf == ITF_SC_WCID ? APDU_SESSION_WCID : APDU_SESSION_CCID;
}

void ccid_init_buffers() {
    if (ITF_SC_TOTAL == 0) {
        return;
    }
    assert(ITF_SC_TOTAL <= CCID_TRANSPORT_CAPACITY);
    memset(ccid_rx, 0, sizeof(ccid_rx));
    memset(ccid_tx, 0, sizeof(ccid_tx));
    memset(ccid_request, 0, sizeof(ccid_request));
    memset(ccid_active_seq, 0, sizeof(ccid_active_seq));
    memset(ccid_rx_overflow, 0, sizeof(ccid_rx_overflow));
    memset(ccid_fast_storage, 0, sizeof(ccid_fast_storage));
#ifndef ENABLE_EMULATION
    memset(ccid_fast_pending, 0, sizeof(ccid_fast_pending));
    memset(ccid_fast_length, 0, sizeof(ccid_fast_length));
    memset(ccid_fast_offset, 0, sizeof(ccid_fast_offset));
    memset(ccid_inflight_length, 0, sizeof(ccid_inflight_length));
    memset((void *)ccid_inflight_acked, 0, sizeof(ccid_inflight_acked));
    memset(ccid_drop_completion, 0, sizeof(ccid_drop_completion));
    memset(ccid_busy_wait_started, 0, sizeof(ccid_busy_wait_started));
    memset(ccid_busy_wait_since, 0, sizeof(ccid_busy_wait_since));
#endif
    memset(ccid_header, 0, sizeof(ccid_header));
    memset(ccid_response, 0, sizeof(ccid_response));
    memset(ccid_resp_fast, 0, sizeof(ccid_resp_fast));
}

int driver_init_ccid(uint8_t itf) {
    ccid_header[itf] = (ccid_header_t *) (ccid_rx[itf].buffer + ccid_rx[itf].r_ptr);
    ccid_resp_fast[itf] = (ccid_header_t *) ccid_fast_storage[itf];
//    apdu.header = &ccid_header->apdu;

    usb_set_timeout_counter(sc_itf_to_usb_itf(itf), 1500);

    //ccid_tx[itf].w_ptr = ccid_tx[itf].r_ptr = 0;

    return PICOKEY_OK;
}

#ifndef ENABLE_EMULATION
static bool ccid_defer_busy_request(uint8_t itf, uint8_t message_type) {
    if (message_type != CCID_POWER_ON && message_type != CCID_POWER_OFF &&
        message_type != CCID_XFR_BLOCK) {
        ccid_busy_wait_started[itf] = false;
        return false;
    }
    if (card_is_idle()) {
        ccid_busy_wait_started[itf] = false;
        return false;
    }
    uint32_t now = board_millis();
    if (!ccid_busy_wait_started[itf]) {
        ccid_busy_wait_started[itf] = true;
        ccid_busy_wait_since[itf] = now;
        return true;
    }
    if ((uint32_t)(now - ccid_busy_wait_since[itf]) < CCID_BUSY_GRACE_MS) {
        return true;
    }
    /* Persistent contention retains the existing standards-compliant BUSY
     * response. A new request gets a fresh grace period. */
    ccid_busy_wait_started[itf] = false;
    return false;
}
#endif

void tud_vendor_rx_cb(uint8_t itf, const uint8_t *buffer, uint16_t bufsize) {
    (void)buffer;
    (void)bufsize;
    uint32_t len = tud_vendor_n_available(itf);
    do {
        uint16_t space = (uint16_t)(sizeof(ccid_rx[itf].buffer) - ccid_rx[itf].w_ptr);
        if (space == 0) {
            uint8_t discard[64];
            uint16_t drop = len > sizeof(discard) ? sizeof(discard) : (uint16_t)len;
            drop = (uint16_t)tud_vendor_n_read(itf, discard, drop);
            if (drop == 0) {
                break;
            }
            ccid_rx_overflow[itf] = true;
            len -= drop;
            continue;
        }
        uint16_t tlen = len > space ? space : (uint16_t)len;
        tlen = (uint16_t)tud_vendor_n_read(itf, ccid_rx[itf].buffer + ccid_rx[itf].w_ptr, tlen);
        if (tlen == 0) {
            break;
        }
        ccid_rx[itf].w_ptr += tlen;
        len -= tlen;
    } while (len > 0);
}

int driver_write_ccid(uint8_t itf, const uint8_t *tx_buffer, uint16_t buffer_size) {
#ifndef ENABLE_EMULATION
    /* Do not flush a partial USB transfer for an intact CCID frame. The
     * underlying TinyUSB vendor FIFO is a byte stream, not a frame queue. */
    if (tud_vendor_n_write_available(itf) < buffer_size) {
        return 0;
    }
#endif
    if (*tx_buffer != 0x81) {
        DEBUG_PAYLOAD(tx_buffer, buffer_size);
    }
    /* TinyUSB's FIFO write may start an IN transfer immediately once a
     * full USB packet is queued. Its completion callback runs on a
     * different FreeRTOS task on ESP32-S3: publish the expected length
     * BEFORE writing or the callback can arrive while the length is zero,
     * losing the ACK and permanently blocking the CCID queue. */
#ifndef ENABLE_EMULATION
    __atomic_store_n(&ccid_inflight_acked[itf], 0, __ATOMIC_RELEASE);
    __atomic_store_n(&ccid_inflight_length[itf], buffer_size, __ATOMIC_RELEASE);
#endif
    int r = tud_vendor_n_write(itf, tx_buffer, buffer_size);
    if (r > 0) {
#ifndef ENABLE_EMULATION
        __atomic_store_n(&ccid_inflight_length[itf], (uint16_t)r, __ATOMIC_RELEASE);
#endif
        tud_vendor_n_flush(itf);
        /* Byte ownership moves only by the amount actually accepted. */
        ccid_tx[itf].r_ptr += (uint16_t)r;
    } else {
#ifndef ENABLE_EMULATION
        __atomic_store_n(&ccid_inflight_length[itf], 0, __ATOMIC_RELEASE);
#endif
    }
#ifdef ENABLE_EMULATION
    tud_vendor_tx_cb(itf, r);
#endif
    return r;
}

int ccid_write_fast(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
#ifndef ENABLE_EMULATION
    if (buffer_size > CCID_FAST_FRAME_SIZE || ccid_fast_length[itf] != 0) {
        return 0;
    }
    /* The APDU GET RESPONSE cursor may advance once the whole frame has
     * been staged, independently of when the USB controller can accept it. */
    memcpy(ccid_fast_pending[itf], buffer, buffer_size);
    ccid_fast_length[itf] = buffer_size;
    ccid_fast_offset[itf] = 0;
    return buffer_size;
#else
    int r = tud_vendor_n_write(itf, buffer, buffer_size);
    if (r > 0) {
        tud_vendor_n_flush(itf);
    }
#ifdef ENABLE_EMULATION
    tud_vendor_tx_cb(itf, r);
#endif
    return r;
#endif
}

int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read) {
    (void) rx_read;
    if (ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr >= 10) {
        driver_init_ccid(itf);
        if (ccid_header[itf]->dwLength > USB_BUFFER_SIZE - 10) {
            //Invalid length
            uint8_t seq = ccid_header[itf]->bSeq;
            ccid_rx[itf].r_ptr = ccid_rx[itf].w_ptr = 0;

            ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
            ccid_resp_fast[itf]->dwLength = 2;
            ccid_resp_fast[itf]->bSlot = 0;
            ccid_resp_fast[itf]->bSeq = seq;
            ccid_resp_fast[itf]->abRFU0 = ccid_status;
            ccid_resp_fast[itf]->abRFU1 = 0;
            memcpy(&ccid_resp_fast[itf]->apdu, "\x6F\x00", 2);
            ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 12);
            return 0;
        }
        if (ccid_header[itf]->dwLength <= (uint32_t)(ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr - 10)){
#ifndef ENABLE_EMULATION
            /* Do not remove a valid PC/SC request until a transient BLE
             * owner had the opportunity to release the shared card. */
            if (ccid_defer_busy_request(itf, ccid_header[itf]->bMessageType)) {
                return 0;
            }
#endif
            uint16_t frame_len = (uint16_t)(ccid_header[itf]->dwLength + CCID_MSG_HEADER_SIZE);
            memcpy(ccid_request[itf].buffer, ccid_header[itf], frame_len);
            ccid_header_t *request = (ccid_header_t *)ccid_request[itf].buffer;
            ccid_rx[itf].r_ptr += frame_len;
            if (ccid_rx[itf].r_ptr >= ccid_rx[itf].w_ptr) {
                ccid_rx[itf].r_ptr = ccid_rx[itf].w_ptr = 0;
            }

            size_t apdu_sent = 0;
            if (request->bMessageType != CCID_SLOT_STATUS) {
                DEBUG_PAYLOAD((uint8_t *)request, request->dwLength + CCID_MSG_HEADER_SIZE);
            }
            if (request->bMessageType == CCID_SLOT_STATUS) {
                ccid_resp_fast[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_resp_fast[itf]->dwLength = 0;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = request->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
            }
            else if (request->bMessageType == CCID_POWER_ON) {
                /* A card power cycle starts a fresh authentication/application session. */
#ifndef ENABLE_EMULATION
                uint8_t usb_itf = sc_itf_to_usb_itf(itf);
                if (!card_try_claim(usb_itf)) {
                    driver_exec_busy_ccid(itf, request->bSeq);
                    return 0;
                }
#endif
                apdu_reset_session(sc_itf_to_apdu_session(itf));
                size_t size_atr = (ccid_atr ? ccid_atr[0] : 0);
                ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
                ccid_resp_fast[itf]->dwLength = (uint32_t)size_atr;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = request->bSeq;
                ccid_resp_fast[itf]->abRFU0 = 0;
                ccid_resp_fast[itf]->abRFU1 = 0;
                memcpy(&ccid_resp_fast[itf]->apdu, ccid_atr + 1, size_atr);
                if (ccid_status == 1) {
                    //card_start(apdu_thread);
                }
                ccid_status = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], (uint16_t)(size_atr + 10));
#ifndef ENABLE_EMULATION
                card_release(usb_itf);
#endif
            }
            else if (request->bMessageType == CCID_POWER_OFF) {
                /* Do not carry PIN/management authentication across ICC power-off. */
#ifndef ENABLE_EMULATION
                uint8_t usb_itf = sc_itf_to_usb_itf(itf);
                if (!card_try_claim(usb_itf)) {
                    driver_exec_busy_status_ccid(itf, request->bSeq);
                    return 0;
                }
#endif
                apdu_reset_session(sc_itf_to_apdu_session(itf));
                if (ccid_status == 0) {
                    //card_exit(0);
                }
                ccid_status = 1;
                ccid_resp_fast[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_resp_fast[itf]->dwLength = 0;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = request->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
#ifndef ENABLE_EMULATION
                card_release(usb_itf);
#endif
            }
            else if (request->bMessageType == CCID_SET_PARAMS ||
                     request->bMessageType == CCID_GET_PARAMS ||
                     request->bMessageType == CCID_RESET_PARAMS) {
                /* Values from gnuk. Not specified in ICCD spec. */
                const uint8_t params[] =  {
                    0x11, /* bmFindexDindex */
                    0x10, /* bmTCCKST1 */
                    0xFE, /* bGuardTimeT1 */
                    0x55, /* bmWaitingIntegersT1 */
                    0x03, /* bClockStop */
                    0xFE, /* bIFSC */
                    0    /* bNadValue */
                };
                ccid_resp_fast[itf]->bMessageType = CCID_PARAMS_RET;
                ccid_resp_fast[itf]->dwLength = sizeof(params);
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = request->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0x0100;
                memcpy(&ccid_resp_fast[itf]->apdu, params, sizeof(params));
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], sizeof(params) + 10);
            }
            else if (request->bMessageType == CCID_SETDATARATEANDCLOCKFREQUENCY) {
                ccid_resp_fast[itf]->bMessageType = CCID_SETDATARATEANDCLOCKFREQUENCY_RET;
                ccid_resp_fast[itf]->dwLength = 8;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = request->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0;
                memset(&ccid_resp_fast[itf]->apdu, 0, 8);
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 18);
            }
            else if (request->bMessageType == CCID_XFR_BLOCK) {
#ifndef ENABLE_EMULATION
                uint8_t usb_itf = sc_itf_to_usb_itf(itf);
                if (!card_try_claim(usb_itf)) {
                    driver_exec_busy_ccid(itf, request->bSeq);
                    return 0;
                }
#endif
                ccid_response[itf] = (ccid_header_t *) (ccid_tx[itf].buffer + ccid_tx[itf].w_ptr);
                ccid_active_seq[itf] = request->bSeq;
                ccid_response[itf]->bSeq = ccid_active_seq[itf];
                uint16_t apdu_len = (uint16_t)request->dwLength;
                apdu.rdata = &ccid_response[itf]->apdu;
                apdu_sent = apdu_process(sc_itf_to_apdu_session(itf), itf,
                                         &request->apdu, apdu_len);
#ifndef ENABLE_EMULATION
                if (apdu_sent > 0) {
                    if (!card_start_claimed(usb_itf, apdu_thread)) {
                        card_release(usb_itf);
                        driver_exec_busy_ccid(itf, request->bSeq);
                        return 0;
                    }
                    usb_send_event(EV_CMD_AVAILABLE);
                }
                else {
                    card_release(usb_itf);
                }
#endif
            }
            return (uint16_t)apdu_sent;
        }
    }
    return 0;
}

static void ccid_busy_response(uint8_t itf, uint8_t seq, uint8_t response_type) {
    ccid_resp_fast[itf]->bMessageType = response_type;
    ccid_resp_fast[itf]->dwLength = 0;
    ccid_resp_fast[itf]->bSlot = 0;
    ccid_resp_fast[itf]->bSeq = seq;
    ccid_resp_fast[itf]->abRFU0 = ccid_status | CCID_CMD_STATUS_ERROR;
    ccid_resp_fast[itf]->abRFU1 = 0xE0; /* CMD_SLOT_BUSY */
    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
}

void driver_exec_busy_ccid(uint8_t itf, uint8_t seq) {
    ccid_busy_response(itf, seq, CCID_DATA_BLOCK_RET);
}

#ifndef ENABLE_EMULATION
static void driver_exec_busy_status_ccid(uint8_t itf, uint8_t seq) {
    ccid_busy_response(itf, seq, CCID_SLOT_STATUS_RET);
}
#endif

void driver_exec_timeout_ccid(uint8_t itf) {
#ifndef ENABLE_EMULATION
    /* A prior Time Extension already queued is still pending delivery. */
    if (ccid_fast_length[itf] != 0) {
        return;
    }
#endif
    ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_resp_fast[itf]->dwLength = 0;
    ccid_resp_fast[itf]->bSlot = 0;
    ccid_resp_fast[itf]->bSeq = ccid_active_seq[itf];
    ccid_resp_fast[itf]->abRFU0 = CCID_CMD_STATUS_TIMEEXT;
    ccid_resp_fast[itf]->abRFU1 = 0;
    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
}

void driver_exec_finished_ccid(uint8_t itf, uint16_t size_next) {
    driver_exec_finished_cont_ccid(itf, size_next, 0);
}

void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size_next, uint16_t offset) {
#ifndef ENABLE_EMULATION
    if (ccid_tx[itf].w_ptr != 0) {
        return; /* Another DataBlock still owns the single-frame buffer. */
    }
#endif
    /* Never append an unbounded response or place a header beyond the
     * staging buffer. Oversize application output becomes a protocol error,
     * instead of corrupting the CCID queue metadata. */
    size_t room = sizeof(ccid_tx[itf].buffer);
    size_t base = (size_t)ccid_tx[itf].w_ptr + offset;
    if (base > room || (size_t)size_next + CCID_MSG_HEADER_SIZE > room - base) {
        if (ccid_tx[itf].w_ptr != 0) {
            return; /* The previous reply still owns the staging buffer. */
        }
        offset = 0;
        size_next = 2;
        ccid_tx[itf].buffer[CCID_MSG_DATA_OFFSET] = 0x6F;
        ccid_tx[itf].buffer[CCID_MSG_DATA_OFFSET + 1] = 0x00;
    }
    ccid_response[itf] = (ccid_header_t *) (ccid_tx[itf].buffer + ccid_tx[itf].w_ptr + offset);
    ccid_response[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response[itf]->dwLength = size_next;
    ccid_response[itf]->bSlot = 0;
    ccid_response[itf]->bSeq = ccid_active_seq[itf];
    ccid_response[itf]->abRFU0 = ccid_status;
    ccid_response[itf]->abRFU1 = 0;
    ccid_write_offset(itf, size_next+10, offset);
}

uint16_t driver_exec_finished_fast_ccid(uint8_t itf, const uint8_t *data, uint16_t size, uint16_t final_sw, uint16_t remaining) {
    const uint16_t max_data = USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE - 2;
    uint16_t chunk = size > max_data ? max_data : size;
    uint16_t left = remaining - chunk;
    uint16_t sw = left == 0 ? final_sw : make_uint16_t_be(0x61, left >= 256 ? 0 : (uint8_t)left);

    ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_resp_fast[itf]->dwLength = chunk + 2;
    ccid_resp_fast[itf]->bSlot = 0;
    ccid_resp_fast[itf]->bSeq = ccid_active_seq[itf];
    ccid_resp_fast[itf]->abRFU0 = ccid_status;
    ccid_resp_fast[itf]->abRFU1 = 0;
    uint8_t *payload = (uint8_t *)ccid_resp_fast[itf] + CCID_MSG_DATA_OFFSET;
    memcpy(payload, data, chunk);
    put_uint16_t_be(sw, payload + chunk);
    if (ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf],
                        chunk + CCID_MSG_HEADER_SIZE + 2) == 0) {
        return 0;
    }
    return chunk;
}

#ifndef ENABLE_EMULATION
/* Run on the main USB service task. The TinyUSB completion callback only
 * increments the acknowledged byte count; buffer ownership remains here. */
static bool ccid_tx_pump(uint8_t itf) {
    uint16_t in_flight = __atomic_load_n(&ccid_inflight_length[itf], __ATOMIC_ACQUIRE);
    if (in_flight != 0) {
        if (__atomic_load_n(&ccid_inflight_acked[itf], __ATOMIC_ACQUIRE) < in_flight) {
            return true;
        }
        __atomic_store_n(&ccid_inflight_length[itf], 0, __ATOMIC_RELEASE);
        /* The callback runs before TinyUSB schedules the final short packet
         * or ZLP. Do not queue the next CCID header from this same tick:
         * otherwise two complete messages can turn into one USB transfer. */
        return true;
    }

    if (ccid_fast_length[itf] != 0) {
        if (ccid_fast_offset[itf] == ccid_fast_length[itf]) {
            /* The complete fast frame was acknowledged by the host. */
            ccid_fast_length[itf] = ccid_fast_offset[itf] = 0;
        } else {
            uint16_t remaining = ccid_fast_length[itf] - ccid_fast_offset[itf];
            if (tud_vendor_n_write_available(itf) >= remaining) {
                /* A 64-byte fast response can auto-flush inside write().
                 * Arm the in-flight transfer before TinyUSB sees it. */
                __atomic_store_n(&ccid_inflight_acked[itf], 0, __ATOMIC_RELEASE);
                __atomic_store_n(&ccid_inflight_length[itf], remaining, __ATOMIC_RELEASE);
                uint32_t accepted = tud_vendor_n_write(
                    itf, ccid_fast_pending[itf] + ccid_fast_offset[itf], remaining);
                if (accepted != 0) {
                    ccid_fast_offset[itf] += (uint16_t)accepted;
                    __atomic_store_n(&ccid_inflight_length[itf], (uint16_t)accepted,
                                     __ATOMIC_RELEASE);
                    tud_vendor_n_write_flush(itf);
                } else {
                    __atomic_store_n(&ccid_inflight_length[itf], 0, __ATOMIC_RELEASE);
                }
            }
            return true;
        }
    }

    if (ccid_tx[itf].w_ptr != 0) {
        if (ccid_tx[itf].r_ptr == ccid_tx[itf].w_ptr) {
            /* The full DataBlock has actually completed its USB transfer. */
            ccid_tx[itf].r_ptr = ccid_tx[itf].w_ptr = 0;
        } else {
            driver_write_ccid(itf, ccid_tx[itf].buffer + ccid_tx[itf].r_ptr,
                              ccid_tx[itf].w_ptr - ccid_tx[itf].r_ptr);
            return true;
        }
    }
    return false;
}
#endif

#ifndef ENABLE_EMULATION
static void ccid_sync_bus_reset(void) {
    if (!__atomic_exchange_n(&ccid_bus_reset_pending, false, __ATOMIC_ACQ_REL)) {
        return;
    }
    bool discard[CCID_TRANSPORT_CAPACITY] = { false };
    for (uint8_t itf = 0; itf < ITF_SC_TOTAL; ++itf) {
        discard[itf] = card_command_is_owned_by(sc_itf_to_usb_itf(itf));
    }
    /* TinyUSB has discarded its endpoint FIFO. Purge all stale CCID headers
     * and unacknowledgeable in-flight replies on core0, not the USB callback
     * thread. Do not abort the APDU worker in mid-Flash write. */
    ccid_init_buffers();
    for (uint8_t itf = 0; itf < ITF_SC_TOTAL; ++itf) {
        ccid_drop_completion[itf] = discard[itf];
    }
}
#endif

void ccid_task() {
#ifndef ENABLE_EMULATION
    ccid_sync_bus_reset();
#endif
    for (int itf = 0; itf < ITF_SC_TOTAL; itf++) {
#ifndef ENABLE_EMULATION
        /* One regular DataBlock owns its staging buffer until USB has sent
         * the whole frame. Do not consume a worker completion and append
         * another frame before this reply has been acknowledged. */
        if (ccid_tx[itf].w_ptr != 0) {
            ccid_tx_pump((uint8_t)itf);
            continue;
        }
#endif
        int status = card_status(sc_itf_to_usb_itf(itf));
        if (status == PICOKEY_OK) {
#ifndef ENABLE_EMULATION
            if (!ccid_drop_completion[itf]) {
#endif
            driver_exec_finished_ccid(itf, finished_data_size);
#ifndef ENABLE_EMULATION
            }
            ccid_drop_completion[itf] = false;
#endif
            card_release(sc_itf_to_usb_itf(itf));
        }
        else if (status == PICOKEY_ERR_BLOCKED) {
#ifndef ENABLE_EMULATION
            if (!ccid_drop_completion[itf])
#endif
            driver_exec_timeout_ccid(itf);
        }
#ifndef ENABLE_EMULATION
        /* Time Extensions must be transmitted while the APDU worker still
         * owns the card. A pending response blocks subsequent CCID requests. */
        bool tx_pending = ccid_tx_pump((uint8_t)itf);
#endif
        if (card_command_is_owned_by(sc_itf_to_usb_itf(itf))) {
            continue;
        }
#ifndef ENABLE_EMULATION
        if (tx_pending) {
            continue;
        }
#else
        if (ccid_tx[itf].w_ptr > ccid_tx[itf].r_ptr) {
            driver_write_ccid(itf, ccid_tx[itf].buffer + ccid_tx[itf].r_ptr,
                              ccid_tx[itf].w_ptr - ccid_tx[itf].r_ptr);
            if (ccid_tx[itf].r_ptr == ccid_tx[itf].w_ptr) {
                ccid_tx[itf].r_ptr = ccid_tx[itf].w_ptr = 0;
            }
        }
#endif
        if (ccid_rx_overflow[itf]) {
            ccid_rx[itf].r_ptr = ccid_rx[itf].w_ptr = 0;
            ccid_rx_overflow[itf] = false;
        }
        else if (ccid_tx[itf].w_ptr == ccid_tx[itf].r_ptr &&
                 ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr >= CCID_MSG_HEADER_SIZE) {
            driver_process_usb_packet_ccid(
                (uint8_t)itf,
                (uint16_t)(ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr));
        }
    }
}

void ccid_init() {
    ccid_init_buffers();
}

#ifndef ENABLE_EMULATION

void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes) {
    uint16_t in_flight = itf < CCID_TRANSPORT_CAPACITY ?
        __atomic_load_n(&ccid_inflight_length[itf], __ATOMIC_ACQUIRE) : 0;
    if (in_flight != 0) {
        __atomic_add_fetch(&ccid_inflight_acked[itf], sent_bytes, __ATOMIC_RELEASE);
    }
    tud_vendor_n_write_flush(itf);
}

static void ccid_init_cb(void) {
    vendord_init();
}

static void ccid_reset_cb(uint8_t rhport) {
    itf_num = 0;
    vendord_reset(rhport);
    /* Defer all CCID application state changes to core0. */
    __atomic_store_n(&ccid_bus_reset_pending, true, __ATOMIC_RELEASE);
}

static uint16_t ccid_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len) {
    TU_VERIFY( itf_desc->bInterfaceClass == TUSB_CLASS_SMART_CARD && itf_desc->bInterfaceSubClass == 0 && itf_desc->bInterfaceProtocol == 0, 0);

    //vendord_open expects a CLASS_VENDOR interface class
    uint16_t const drv_len = sizeof(tusb_desc_interface_t) + sizeof(struct ccid_class_descriptor) + TUSB_SMARTCARD_CCID_EPS * sizeof(tusb_desc_endpoint_t);
    TU_VERIFY(max_len >= drv_len, 0);
    uint8_t itf_vendor[sizeof(tusb_desc_interface_t) + sizeof(struct ccid_class_descriptor) +
                       TUSB_SMARTCARD_CCID_EPS * sizeof(tusb_desc_endpoint_t)];
    memcpy(itf_vendor, itf_desc, drv_len);
    ((tusb_desc_interface_t *) itf_vendor)->bInterfaceClass = TUSB_CLASS_VENDOR_SPECIFIC;
#if TUSB_SMARTCARD_CCID_EPS == 3
    ((tusb_desc_interface_t *) itf_vendor)->bNumEndpoints -= 1;
    vendord_open(rhport, (tusb_desc_interface_t *)itf_vendor, drv_len - sizeof(tusb_desc_endpoint_t));
    tusb_desc_endpoint_t const *desc_ep = (tusb_desc_endpoint_t const *)((uint8_t *)itf_desc + drv_len - sizeof(tusb_desc_endpoint_t));
    TU_ASSERT(usbd_edpt_open(rhport, desc_ep), 0);
    uint8_t msg[] = { 0x50, 0x03 };
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    usbd_edpt_xfer(rhport, desc_ep->bEndpointAddress, msg, sizeof(msg));
#else
    usbd_edpt_xfer(rhport, desc_ep->bEndpointAddress, msg, sizeof(msg), sizeof(msg));
#endif
#else
    vendord_open(rhport, (tusb_desc_interface_t *)itf_vendor, drv_len);
#endif

    itf_num = itf_desc->bInterfaceNumber;
    return drv_len;
}

// Support for parameterized reset via vendor interface control request
static bool ccid_control_xfer_cb(uint8_t __unused rhport,
                                 uint8_t stage,
                                 tusb_control_request_t const *request) {
    // nothing to do with DATA & ACK stage
    TU_LOG2("-------- CCID CTRL XFER\n");
    if (stage != CONTROL_STAGE_SETUP) {
        return true;
    }

    if (request->wIndex == itf_num) {
        TU_LOG2("-------- bmRequestType %x, bRequest %x, wValue %x, wLength %x\n",
                request->bmRequestType,
                request->bRequest,
                request->wValue,
                request->wLength);
/*
 #if PICO_STDIO_USB_RESET_INTERFACE_SUPPORT_RESET_TO_BOOTSEL
        if (request->bRequest == RESET_REQUEST_BOOTSEL) {
 #ifdef PICO_STDIO_USB_RESET_BOOTSEL_ACTIVITY_LED
            uint gpio_mask = 1u << PICO_STDIO_USB_RESET_BOOTSEL_ACTIVITY_LED;
 #else
            uint gpio_mask = 0u;
 #endif
 #if !PICO_STDIO_USB_RESET_BOOTSEL_FIXED_ACTIVITY_LED
            if (request->wValue & 0x100) {
                gpio_mask = 1u << (request->wValue >> 9u);
            }
 #endif
            reset_usb_boot(gpio_mask, (request->wValue & 0x7f) | PICO_STDIO_USB_RESET_BOOTSEL_INTERFACE_DISABLE_MASK);
            // does not return, otherwise we'd return true
        }
 #endif
 #if PICO_STDIO_USB_RESET_INTERFACE_SUPPORT_RESET_TO_FLASH_BOOT
        if (request->bRequest == RESET_REQUEST_FLASH) {
            watchdog_reboot(0, 0, PICO_STDIO_USB_RESET_RESET_TO_FLASH_DELAY_MS);
            return true;
        }
 #endif
 */
        return true;
    }
    return false;
}

static bool ccid_xfer_cb(uint8_t rhport,
                         uint8_t ep_addr,
                         xfer_result_t result,
                         uint32_t xferred_bytes) {
    //printf("------ CALLED XFER_CB\n");
    return vendord_xfer_cb(rhport, ep_addr, result, xferred_bytes);
    //return true;
}

static const usbd_class_driver_t ccid_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID",
#endif
    .init             = ccid_init_cb,
    .reset            = ccid_reset_cb,
    .open             = ccid_open,
    .control_xfer_cb  = ccid_control_xfer_cb,
    .xfer_cb          = ccid_xfer_cb,
    .sof              = NULL
};

// Implement callback to add our custom driver
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 1;
    return &ccid_driver;
}
#endif
