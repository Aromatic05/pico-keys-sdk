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

#include "apdu.h"
#include "pico_keys.h"
#include "usb.h"
#include <stdio.h>
#ifdef ESP_PLATFORM
#include "esp_compat.h"
#endif
#ifdef ENABLE_EMULATION
#include "emulation.h"
#endif

#define APDU_CHAIN_BUFFER_SIZE 2038
#define APDU_RESPONSE_BUFFER_SIZE 2064

typedef struct apdu_session_state {
    app_t *selected_app;
    bool is_chaining;
    uint16_t chain_len;
    uint8_t chain_buf[APDU_CHAIN_BUFFER_SIZE];
    uint8_t response_buf[APDU_RESPONSE_BUFFER_SIZE];
    uint16_t response_offset;
    uint16_t response_remaining;
    uint16_t response_sw;
} apdu_session_state_t;

static apdu_session_state_t apdu_sessions[APDU_SESSION_COUNT];
static apdu_session_id_t active_session_id = APDU_SESSION_CCID;
static apdu_session_state_t *active_session = &apdu_sessions[APDU_SESSION_CCID];

extern uint32_t timeout;

static void apdu_activate_session(apdu_session_id_t session) {
    active_session_id = session;
    active_session = &apdu_sessions[session];
    current_app = active_session->selected_app;
}

apdu_session_id_t apdu_current_session(void) {
    return active_session_id;
}

static void apdu_commit_session(void) {
    active_session->selected_app = current_app;
}

static void apdu_clear_response(apdu_session_state_t *session) {
    session->response_offset = 0;
    session->response_remaining = 0;
    session->response_sw = 0;
}

static void apdu_send_continuation(uint8_t itf, uint16_t size) {
#ifndef ENABLE_EMULATION
#ifdef USB_ITF_HID
    if (itf == ITF_HID_CTAP) {
        driver_exec_finished_cont_hid(itf, size, 0);
    }
#endif
#ifdef USB_ITF_CCID
    if (itf == ITF_SC_CCID || itf == ITF_SC_WCID) {
        driver_exec_finished_cont_ccid(itf, size, 0);
    }
#endif
#else
    driver_exec_finished_cont_emul(itf, size, 0);
#endif
}

static void apdu_reset_transport_state(apdu_session_state_t *session) {
    session->is_chaining = false;
    session->chain_len = 0;
    apdu_clear_response(session);
    /* Request/response storage is transport-owned; do not invalidate it here. */
    apdu.header = NULL;
    apdu.data = NULL;
    apdu.nc = 0;
    apdu.ne = 0;
    apdu.sw = 0;
    apdu.rlen = 0;
    finished_data_size = 0;
    timeout_stop();
}

int apdu_select_app(apdu_session_id_t session, const uint8_t *aid, size_t aid_len) {
    apdu_activate_session(session);
    app_t *previous_app = current_app;
    int ret = select_app(aid, aid_len);
    if (ret != PICOKEY_OK && current_app == previous_app && current_app) {
        if (current_app->unload) {
            current_app->unload();
        }
        current_app = NULL;
    }
    apdu_commit_session();
    return ret;
}

int apdu_ensure_app(apdu_session_id_t session, const uint8_t *aid, size_t aid_len) {
    apdu_activate_session(session);
    if (current_app && current_app->aid &&
        aid_len >= current_app->aid[0] &&
        memcmp(current_app->aid + 1, aid, current_app->aid[0]) == 0 &&
        picokey_app_policy(current_app->aid + 1, current_app->aid[0])) {
        return PICOKEY_OK;
    }
    return apdu_select_app(session, aid, aid_len);
}

void apdu_reset_warm_session(apdu_session_id_t session) {
    apdu_activate_session(session);
    if (current_app && current_app->unload) {
        current_app->unload();
    }
    apdu_reset_transport_state(active_session);
    apdu_commit_session();
}

void apdu_reset_session(apdu_session_id_t session) {
    apdu_reset_warm_session(session);
    current_app = NULL;
    apdu_commit_session();
}

int process_apdu() {
    led_set_mode(MODE_PROCESSING);
    int result = SW_FILE_NOT_FOUND();
    bool select_by_aid = INS(apdu) == 0xA4 && P1(apdu) == 0x04 &&
        (P2(apdu) == 0x00 || P2(apdu) == 0x04);

    if (!select_by_aid && current_app && current_app->aid &&
        !picokey_app_policy(current_app->aid + 1, current_app->aid[0])) {
        if (current_app->unload) {
            current_app->unload();
        }
        current_app = NULL;
        active_session->is_chaining = false;
        active_session->chain_len = 0;
        result = SW_INS_NOT_SUPPORTED();
        goto done;
    }

    if (CLA(apdu) & 0x10) {
        if (active_session->chain_len + apdu.nc >= sizeof(active_session->chain_buf)) {
            result = SW_CLA_NOT_SUPPORTED();
            goto done;
        }
        memcpy(active_session->chain_buf + active_session->chain_len, apdu.data, apdu.nc);
        active_session->chain_len += (uint16_t)apdu.nc;
        active_session->is_chaining = true;
        result = SW_OK();
        goto done;
    }

    if (active_session->is_chaining) {
        memmove(apdu.data + active_session->chain_len, apdu.data, apdu.nc);
        memcpy(apdu.data, active_session->chain_buf, active_session->chain_len);
        apdu.nc += active_session->chain_len;
        active_session->is_chaining = false;
        active_session->chain_len = 0;
    }

    if (select_by_aid) {
        result = select_app(apdu.data, apdu.nc) == PICOKEY_OK ? SW_OK() : SW_FILE_NOT_FOUND();
        goto done;
    }

    if (current_app && current_app->process_apdu) {
        result = current_app->process_apdu();
    }

done:
    apdu_commit_session();
    return result;
}

uint16_t apdu_process(apdu_session_id_t session, uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    apdu_activate_session(session);
    apdu.header = (uint8_t *) buffer;
    apdu.nc = apdu.ne = 0;
    if (buffer_size == 4) {
        apdu.nc = apdu.ne = 0;
        if (apdu.ne == 0) {
            apdu.ne = 256;
        }
    }
    else if (buffer_size == 5) {
        apdu.nc = 0;
        apdu.ne = apdu.header[4];
        if (apdu.ne == 0) {
            apdu.ne = 256;
        }
    }
    else if (apdu.header[4] == 0x0 && buffer_size >= 7) {
        if (buffer_size == 7) {
            apdu.ne = get_uint16_t_be(apdu.header + 5);
            if (apdu.ne == 0) {
                apdu.ne = 65536;
            }
        }
        else {
            apdu.ne = 0;
            apdu.nc = get_uint16_t_be(apdu.header + 5);
            apdu.data = apdu.header + 7;
            if (apdu.nc + 7 + 2 == buffer_size) {
                apdu.ne = get_uint16_t_be(apdu.header + buffer_size - 2);
                if (apdu.ne == 0) {
                    apdu.ne = 65536;
                }
            }
        }
    }
    else {
        apdu.nc = apdu.header[4];
        apdu.data = apdu.header + 5;
        apdu.ne = 0;
        if (apdu.nc + 5 + 1 == buffer_size) {
            apdu.ne = apdu.header[buffer_size - 1];
            if (apdu.ne == 0) {
                apdu.ne = 256;
            }
        }
    }

    if (apdu.header[1] == 0xc0) {
        timeout_stop();
        uint16_t chunk = active_session->response_remaining;
        if ((uint32_t)chunk > apdu.ne) {
            chunk = (uint16_t)apdu.ne;
        }
#ifndef ENABLE_EMULATION
#ifdef USB_ITF_CCID
        if (itf == ITF_SC_CCID || itf == ITF_SC_WCID) {
            uint16_t sent = driver_exec_finished_fast_ccid(
                itf,
                active_session->response_buf + active_session->response_offset,
                chunk,
                active_session->response_sw,
                active_session->response_remaining);
            active_session->response_offset += sent;
            active_session->response_remaining -= sent;
            apdu.sw = 0;
            apdu.rlen = 0;
            if (active_session->response_remaining == 0) {
                apdu_clear_response(active_session);
            }
            return 0;
        }
#endif
#endif
        memcpy(apdu.rdata,
               active_session->response_buf + active_session->response_offset,
               chunk);
        active_session->response_offset += chunk;
        active_session->response_remaining -= chunk;
        if (active_session->response_remaining == 0) {
            put_uint16_t_be(active_session->response_sw, apdu.rdata + chunk);
            apdu_send_continuation(itf, chunk + 2);
            apdu.sw = 0;
            apdu.rlen = 0;
            apdu_clear_response(active_session);
        }
        else {
            apdu.rdata[chunk] = 0x61;
            apdu.rdata[chunk + 1] = active_session->response_remaining >= 256 ? 0 : (uint8_t)active_session->response_remaining;
            apdu_send_continuation(itf, chunk + 2);
        }
    }
    else {
        apdu.sw = 0;
        apdu.rlen = 0;
        apdu_clear_response(active_session);
        return 1;
    }
    return 0;
}

uint16_t set_res_sw(uint8_t sw1, uint8_t sw2) {
    apdu.sw = make_uint16_t_be(sw1, sw2);
    if (sw1 != 0x90) {
        res_APDU_size = 0;
    }
    return make_uint16_t_be(sw1, sw2);
}

void *apdu_thread(void *arg) {
    (void)arg;
    card_init_core1();
    while (1) {
        uint32_t m = 0;
        queue_remove_blocking(&usb_to_card_q, &m);
        uint32_t flag = m + 1;
        queue_add_blocking(&card_to_usb_q, &flag);

        if (m == EV_VERIFY_CMD_AVAILABLE || m == EV_MODIFY_CMD_AVAILABLE) {
            set_res_sw(0x6f, 0x00);
            goto done;
        }
        else if (m == EV_EXIT) {
            break;
        }

        process_apdu();

done:   ;
        apdu_finish();

        finished_data_size = apdu_next();
        flag = EV_EXEC_FINISHED;
        queue_add_blocking(&card_to_usb_q, &flag);
#ifdef ESP_PLATFORM
        vTaskDelay(pdMS_TO_TICKS(10));
#endif
    }
    // The worker lifecycle is transport scheduling, not an application session boundary.
    return NULL;
}

void apdu_finish() {
    put_uint16_t_be(apdu.sw, apdu.rdata + apdu.rlen);
    // timeout_stop();
#ifndef ENABLE_EMULATION
    /* It was fixed in the USB handling. Keep it just in case */
    //if ((apdu.rlen + 2 + 10) % 64 == 0) {     // FIX for strange behaviour with PSCS and multiple of 64
    //    apdu.ne = apdu.rlen - 2;
    //}
#endif
}

uint16_t apdu_next() {
    if (apdu.sw != 0) {
        if (apdu.rlen <= apdu.ne) {
            apdu_clear_response(active_session);
            return apdu.rlen + 2;
        }

        memcpy(active_session->response_buf, apdu.rdata, apdu.rlen);
        active_session->response_offset = (uint16_t)apdu.ne;
        apdu.rlen -= (uint16_t)apdu.ne;
        active_session->response_remaining = apdu.rlen;
        active_session->response_sw = apdu.sw;
        apdu.rdata[apdu.ne] = 0x61;
        apdu.rdata[apdu.ne + 1] = apdu.rlen >= 256 ? 0 : (uint8_t)apdu.rlen;
        return (uint16_t)(apdu.ne + 2);
    }
    apdu_clear_response(active_session);
    return 0;
}
