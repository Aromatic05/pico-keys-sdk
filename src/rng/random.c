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

#define HWRNG_PRE_LOOP 32

#include <stdlib.h>
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#endif
#include <string.h>
#ifdef ESP_PLATFORM
#include "esp_random.h"
#endif

#include "hwrng.h"

#define RANDOM_BYTES_LENGTH 32
#define MAX_RANDOM_BUFFER 1024
static uint32_t random_word[RANDOM_BYTES_LENGTH / sizeof(uint32_t)];
static uint8_t random_return_buffer[MAX_RANDOM_BUFFER];

void random_init(void) {
    hwrng_init(random_word, RANDOM_BYTES_LENGTH / sizeof(uint32_t));

    for (int i = 0; i < HWRNG_PRE_LOOP; i++) {
        hwrng_get();
    }
}

/*
 * Free pointer to random 32-byte
 */
void random_bytes_free(const uint8_t *p) {
    if (p == random_return_buffer) {
        /* Do not leave old random material in the static return buffer. */
        volatile uint8_t *out = random_return_buffer;
        for (size_t i = 0; i < sizeof(random_return_buffer); ++i) {
            out[i] = 0;
        }
    } else if (p == (const uint8_t *)random_word) {
        memset(random_word, 0, RANDOM_BYTES_LENGTH);
        hwrng_flush();
    }
}

/*
 * Return pointer to random 32-byte
 */
const uint8_t *random_bytes_get(size_t len) {
    if (len > MAX_RANDOM_BUFFER) {
        return NULL;
    }
#ifdef ESP_PLATFORM
    /* ESP-S3 provides hardware-conditioned random bytes directly. The old
     * 32-byte HWRNG ring was replenished only every 10ms core0 tick and made
     * RSA key generation take minutes despite working hardware entropy. */
    esp_fill_random(random_return_buffer, len);
#else
    for (size_t ix = 0; ix < len; ix += RANDOM_BYTES_LENGTH) {
        hwrng_wait_full();
        size_t count = len - ix < RANDOM_BYTES_LENGTH ? len - ix : RANDOM_BYTES_LENGTH;
        memcpy(random_return_buffer + ix, random_word, count);
        random_bytes_free((const uint8_t *) random_word);
    }
#endif
    return random_return_buffer;
}

/*
 * Random byte iterator
 */
int random_gen(void *arg, unsigned char *out, size_t out_len) {
    if (out == NULL && out_len != 0) {
        return -1;
    }
#ifdef ESP_PLATFORM
    (void)arg;
    if (out_len != 0) {
        esp_fill_random(out, out_len);
    }
#else
    /* A fresh word is consumed for every call, including arg == NULL.
     * The previous per-caller index reused the same bytes when multiple
     * consumers requested less than 32 bytes with independent contexts. */
    size_t remaining = out_len;
    while (remaining > 0) {
        uint32_t word = hwrng_get();
        size_t count = remaining < sizeof(word) ? remaining : sizeof(word);
        memcpy(out, &word, count);
        out += count;
        remaining -= count;
    }
    if (arg != NULL) {
        *(uint8_t *)arg = (uint8_t)((*(uint8_t *)arg + out_len) % RANDOM_BYTES_LENGTH);
    }
#endif
    return 0;
}

#ifdef ENABLE_PQC
void randombytes(uint8_t *buf, size_t n) {
    random_gen(NULL, buf, n);
}
#endif
