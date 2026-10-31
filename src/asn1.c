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

#include "pico_keys.h"
#include "asn1.h"

int asn1_ctx_init(uint8_t *data, uint16_t len, asn1_ctx_t *ctx) {
    if (!ctx) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    ctx->data = data;
    ctx->len = len;
    return PICOKEY_OK;
}

int asn1_ctx_clear(asn1_ctx_t *ctx) {
    ctx->data = NULL;
    ctx->len = 0;
    return PICOKEY_OK;
}

uint16_t asn1_len(asn1_ctx_t *ctx) {
    if (ctx->data && ctx->len > 0) {
        return ctx->len;
    }
    return 0;
}

uint32_t asn1_get_uint(asn1_ctx_t *ctx) {
    uint32_t d = ctx->data[0];
    for (uint16_t lt = 1; lt < MIN(ctx->len, sizeof(uint32_t)); lt++) {
        d <<= 8;
        d |= ctx->data[lt];
    }
    return d;
}

uint16_t asn1_len_tag(uint16_t tag, uint16_t len) {
    uint16_t ret = 1 + format_tlv_len(len, NULL) + len;
    if (tag > 0x00ff) {
        return ret + 1;
    }
    return ret;
}

uint8_t format_tlv_len(uint16_t len, uint8_t *out) {
    if (len < 128) {
        if (out) {
            *out = (uint8_t)len;
        }
        return 1;
    }
    else if (len < 256) {
        if (out) {
            *out++ = 0x81;
            *out++ = (uint8_t)len;
        }
        return 2;
    }
    if (out) {
        *out++ = 0x82;
        put_uint16_t_be(len, out);
    }
    return 3;
}

int walk_tlv(const asn1_ctx_t *ctxi,
             uint8_t **p,
             uint16_t *tag,
             uint16_t *tag_len,
             uint8_t **data) {
    if (!ctxi || !ctxi->data || !p) {
        return 0;
    }
    if (!*p) {
        *p = (uint8_t *) ctxi->data;
    }
    if (*p < ctxi->data || *p >= ctxi->data + ctxi->len) {
        return 0;
    }
    uint8_t *cur = *p;
    size_t remaining = (size_t)(ctxi->data + ctxi->len - cur);
    uint16_t tg = 0x0;
    uint16_t tgl = 0;
    tg = *cur++;
    remaining--;
    if ((tg & 0x1f) == 0x1f) {
        if (remaining < 1) return 0;
        tg <<= 8;
        tg |= *cur++;
        remaining--;
    }
    if (remaining < 1) return 0;
    tgl = *cur++;
    remaining--;
    if (tgl == 0x82) {
        if (remaining < 2) return 0;
        tgl = (uint16_t)*cur++ << 8;
        tgl |= *cur++;
        remaining -= 2;
    }
    else if (tgl == 0x81) {
        if (remaining < 1) return 0;
        tgl = *cur++;
        remaining--;
    }
    else if (tgl >= 0x80) {
        return 0;
    }
    if (tgl > remaining) return 0;
    if (tag) {
        *tag = tg;
    }
    if (tag_len) {
        *tag_len = tgl;
    }
    if (data) {
        *data = cur;
    }
    *p = cur + tgl;
    return 1;
}

bool asn1_find_tag(const asn1_ctx_t *ctxi,
                   uint16_t itag,
                   asn1_ctx_t *ctxo) {
    uint16_t tag = 0x0;
    uint8_t *p = NULL;
    uint8_t *tdata = NULL;
    uint16_t tlen = 0;
    while (walk_tlv(ctxi, &p, &tag, &tlen, &tdata)) {
        if (itag == tag) {
            if (ctxo != NULL) {
                ctxo->data = tdata;
                ctxo->len = tlen;
            }
            return true;
        }
    }
    return false;
}
