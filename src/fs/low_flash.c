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


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#include "pico_keys.h"
#include <string.h>
#include "crypto_utils.h"
#ifdef PICO_PLATFORM
 #include "pico/stdlib.h"
 #include "hardware/flash.h"
 #include "hardware/sync.h"
 #include "pico/mutex.h"
 #include "pico/sem.h"
 #include "pico/multicore.h"
 #include "pico/bootrom.h"
 #include "boot/picobin.h"
#else
 #ifdef ESP_PLATFORM
  #include "esp_compat.h"
  #include "esp_partition.h"
  const esp_partition_t *part0;
  #define save_and_disable_interrupts() 1
  #define flash_range_erase(a,b) esp_partition_erase_range(part0, a, b)
  #define flash_range_program(a,b,c) esp_partition_write(part0, a, b, c)
  #define restore_interrupts(a) (void)a
 #else
  #ifdef _MSC_VER
   #include <windows.h>
   #include <io.h>
   #define O_RDWR _O_RDWR
   #define O_CREAT _O_CREAT
   #define open _open
   #define write _write
   #define mode_t unsigned short
   #define lseek _lseek
   #include "mman.h"
  #else
   #include <unistd.h>
   #include <sys/mman.h>
  #endif
  #include "queue.h"
 #endif
 #define FLASH_SECTOR_SIZE       PICO_KEYS_FLASH_SECTOR_SIZE
 #define XIP_BASE 0
 int fd_map = 0;
 uint8_t *map = NULL;
 #include <fcntl.h>
#endif
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
extern uint32_t FLASH_SIZE_BYTES;
#else
#define FLASH_SIZE_BYTES   (8 * 1024 * 1024)
#endif

#define TOTAL_FLASH_PAGES 6
#define FLASH_LOCKOUT_RETRIES 5

extern void flash_set_bounds(uintptr_t start, uintptr_t end);
extern uintptr_t flash_read_uintptr(uintptr_t addr);

extern const uintptr_t start_data_pool;
extern const uintptr_t end_rom_pool;
extern uintptr_t end_data_pool;

typedef struct page_flash {
    uint8_t page[FLASH_SECTOR_SIZE];
    uintptr_t address;
    bool ready;
    bool erase;
    size_t page_size; //this param is for easy erase. It allows to erase with a single call. IT DOES NOT APPLY TO WRITE
} page_flash_t;

static page_flash_t flash_pages[TOTAL_FLASH_PAGES];

static mutex_t mtx_flash;
static semaphore_t sem_flash;

#ifndef ENABLE_EMULATION
static bool locked_out = false;
#else
static bool locked_out = true;
#endif

static uint8_t ready_pages = 0;

bool flash_available = false;

#if defined(ESP_PLATFORM) || (defined(ENABLE_EMULATION) && !defined(_MSC_VER))
#define FLASH_JOURNAL_SLOTS          8u
#define FLASH_JOURNAL_SECTORS        (FLASH_JOURNAL_SLOTS * 2u)
#define FLASH_JOURNAL_HEADER_MAGIC   0x324a4b50u /* PKJ2 */
#define FLASH_JOURNAL_COMMIT_MAGIC   0x54494d43u /* CMIT */
#define FLASH_JOURNAL_DONE_MAGIC     0x454e4f44u /* DONE */
#define FLASH_JOURNAL_VERSION        2u

typedef struct flash_journal_meta {
    uint32_t header_magic;
    uint32_t header_magic_inv;
    uint32_t generation;
    uint32_t target;
    uint32_t crc32;
    uint32_t crc32_inv;
    uint32_t version;
    uint16_t batch_index;
    uint16_t batch_count;
    uint32_t commit;
    uint32_t commit_inv;
    uint32_t reserved1[2];
    uint32_t done;
    uint32_t done_inv;
    uint32_t reserved2[2];
} flash_journal_meta_t;

#define FLASH_JOURNAL_HEADER_LEN  offsetof(flash_journal_meta_t, commit)
#define FLASH_JOURNAL_MARKER_LEN  16u

_Static_assert(sizeof(flash_journal_meta_t) == 64,
               "flash journal metadata must remain 64 bytes");
_Static_assert(FLASH_JOURNAL_HEADER_LEN == 32,
               "flash journal header must remain 32 bytes");
_Static_assert((offsetof(flash_journal_meta_t, commit) % 16u) == 0,
               "flash journal commit must be 16-byte aligned");
_Static_assert((offsetof(flash_journal_meta_t, done) % 16u) == 0,
               "flash journal done must be 16-byte aligned");

static uintptr_t journal_base_addr = 0;
static uintptr_t journal_target_start = 0;
static uintptr_t journal_target_end = 0;
static uint32_t journal_next_generation = 1;
static unsigned journal_next_slot = 0;

#if defined(ESP_PLATFORM) && defined(CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST) && CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST
static volatile bool qemu_journal_cut_after_target_erase = false;

void low_flash_qemu_arm_journal_cut_after_target_erase(void) {
    qemu_journal_cut_after_target_erase = true;
}
#endif

static uint32_t journal_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(crc & 1u));
        }
    }
    return ~crc;
}

static int journal_raw_erase(uintptr_t addr) {
#if defined(ESP_PLATFORM)
    return flash_range_erase(addr - XIP_BASE, FLASH_SECTOR_SIZE) == ESP_OK
        ? PICOKEY_OK : PICOKEY_ERR_MEMORY_FATAL;
#else
    uintptr_t sector = addr & ~(uintptr_t)(FLASH_SECTOR_SIZE - 1u);
    memset(map + sector, 0, FLASH_SECTOR_SIZE);
    if (msync(map + sector, FLASH_SECTOR_SIZE, MS_SYNC) != 0 || fsync(fd_map) != 0) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    return PICOKEY_OK;
#endif
}

static int journal_raw_program(uintptr_t addr, const uint8_t *data, size_t len) {
    if (data == NULL || len == 0 || len > FLASH_SECTOR_SIZE) {
        return PICOKEY_ERR_NULL_PARAM;
    }
#if defined(ESP_PLATFORM)
    if (part0 != NULL && part0->encrypted &&
        (((addr - XIP_BASE) & 0x0fu) != 0 || (len & 0x0fu) != 0)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    return flash_range_program(addr - XIP_BASE, data, len) == ESP_OK
        ? PICOKEY_OK : PICOKEY_ERR_MEMORY_FATAL;
#else
    memcpy(map + addr, data, len);
    uintptr_t sector = addr & ~(uintptr_t)(FLASH_SECTOR_SIZE - 1u);
    if (msync(map + sector, FLASH_SECTOR_SIZE, MS_SYNC) != 0 || fsync(fd_map) != 0) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    return PICOKEY_OK;
#endif
}

static uintptr_t journal_slot_data_addr(unsigned slot) {
    return journal_base_addr + (uintptr_t)slot * 2u * FLASH_SECTOR_SIZE;
}

static uintptr_t journal_slot_meta_addr(unsigned slot) {
    return journal_slot_data_addr(slot) + FLASH_SECTOR_SIZE;
}

static bool journal_meta_valid(const flash_journal_meta_t *meta) {
    return meta != NULL &&
           meta->header_magic == FLASH_JOURNAL_HEADER_MAGIC &&
           meta->header_magic_inv == ~meta->header_magic &&
           meta->version == FLASH_JOURNAL_VERSION &&
           meta->batch_count > 0 &&
           meta->batch_count <= FLASH_JOURNAL_SLOTS &&
           meta->batch_index < meta->batch_count &&
           meta->commit == FLASH_JOURNAL_COMMIT_MAGIC &&
           meta->commit_inv == ~meta->commit &&
           meta->crc32_inv == ~meta->crc32 &&
           (meta->target & (FLASH_SECTOR_SIZE - 1u)) == 0 &&
           meta->target >= journal_target_start &&
           meta->target + FLASH_SECTOR_SIZE <= journal_target_end;
}

static bool journal_generation_newer(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

static uint32_t journal_next_generation_value(uint32_t generation) {
    generation++;
    return generation == 0 ? 1 : generation;
}

static unsigned journal_batch_start_slot(unsigned slot, unsigned batch_index) {
    return (slot + FLASH_JOURNAL_SLOTS -
            (batch_index % FLASH_JOURNAL_SLOTS)) % FLASH_JOURNAL_SLOTS;
}

static int journal_mark_done(unsigned slot) {
    const uint32_t done_block[4] = {
        FLASH_JOURNAL_DONE_MAGIC,
        ~FLASH_JOURNAL_DONE_MAGIC,
        UINT32_MAX,
        UINT32_MAX,
    };
    return journal_raw_program(journal_slot_meta_addr(slot) +
                               offsetof(flash_journal_meta_t, done),
                               (const uint8_t *)done_block,
                               sizeof(done_block));
}

static int journal_recover_if_needed(void) {
    int latest_slot = -1;
    const flash_journal_meta_t *latest = NULL;
    for (unsigned slot = 0; slot < FLASH_JOURNAL_SLOTS; slot++) {
        const flash_journal_meta_t *meta =
            (const flash_journal_meta_t *)(map + journal_slot_meta_addr(slot));
        if (!journal_meta_valid(meta)) {
            continue;
        }
        if (latest == NULL || journal_generation_newer(meta->generation,
                                                        latest->generation)) {
            latest = meta;
            latest_slot = (int)slot;
        }
    }

    if (latest == NULL) {
        journal_next_generation = 1;
        journal_next_slot = 0;
        return PICOKEY_OK;
    }

    const uint32_t generation = latest->generation;
    const unsigned batch_count = latest->batch_count;
    const unsigned start_slot = journal_batch_start_slot(
        (unsigned)latest_slot, latest->batch_index);
    const flash_journal_meta_t *members[FLASH_JOURNAL_SLOTS] = {0};
    int member_slots[FLASH_JOURNAL_SLOTS];
    for (unsigned i = 0; i < FLASH_JOURNAL_SLOTS; i++) {
        member_slots[i] = -1;
    }

    /* A transaction is published only after every member has a valid commit
     * marker. During staging, target sectors are untouched, so an incomplete
     * highest generation is simply the complete old state. */
    for (unsigned slot = 0; slot < FLASH_JOURNAL_SLOTS; slot++) {
        const flash_journal_meta_t *meta =
            (const flash_journal_meta_t *)(map + journal_slot_meta_addr(slot));
        if (!journal_meta_valid(meta) || meta->generation != generation) {
            continue;
        }
        if (meta->batch_count != batch_count) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        unsigned index = meta->batch_index;
        if (members[index] != NULL) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        if (slot != (start_slot + index) % FLASH_JOURNAL_SLOTS) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        members[index] = meta;
        member_slots[index] = (int)slot;
    }

    bool complete = true;
    for (unsigned i = 0; i < batch_count; i++) {
        if (members[i] == NULL) {
            complete = false;
            break;
        }
    }

    journal_next_slot = (start_slot + batch_count) % FLASH_JOURNAL_SLOTS;
    journal_next_generation = journal_next_generation_value(generation);
    if (!complete) {
        return PICOKEY_OK;
    }

    /* Validate the complete journal set before replaying any target. */
    for (unsigned i = 0; i < batch_count; i++) {
        const flash_journal_meta_t *meta = members[i];
        const uint8_t *journal_page =
            map + journal_slot_data_addr((unsigned)member_slots[i]);
        if (journal_crc32(journal_page, FLASH_SECTOR_SIZE) != meta->crc32) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        for (unsigned j = 0; j < i; j++) {
            if (members[j]->target == meta->target) {
                return PICOKEY_ERR_MEMORY_FATAL;
            }
        }
    }

    const flash_journal_meta_t *leader = members[0];
    if (leader->done != FLASH_JOURNAL_DONE_MAGIC ||
        leader->done_inv != ~leader->done) {
        /* Replaying the whole batch is idempotent. A second power loss during
         * replay leaves the same complete journal available on next boot. */
        for (unsigned i = 0; i < batch_count; i++) {
            const flash_journal_meta_t *meta = members[i];
            const uint8_t *journal_page =
                map + journal_slot_data_addr((unsigned)member_slots[i]);
            if (journal_raw_erase(meta->target) != PICOKEY_OK ||
                journal_raw_program(meta->target, journal_page,
                                    FLASH_SECTOR_SIZE) != PICOKEY_OK) {
                return PICOKEY_ERR_MEMORY_FATAL;
            }
        }
        if (journal_mark_done((unsigned)member_slots[0]) != PICOKEY_OK) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
    }
    return PICOKEY_OK;
}

static int journal_preflight_legacy_store(uintptr_t legacy_start,
                                          uintptr_t reserved_end) {
    uintptr_t base = flash_read_uintptr(end_data_pool);
    if (base == 0 || base == UINTPTR_MAX || base == (uintptr_t)0xefefefefu) {
        return PICOKEY_OK;
    }

    size_t guard = 0;
    while (base != 0) {
        if (base < legacy_start || base >= end_data_pool) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        if (base < reserved_end) {
            return PICOKEY_ERR_NO_MEMORY;
        }
        uintptr_t next = flash_read_uintptr(base);
        if (next == base || ++guard > 4096) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        base = next;
    }
    return PICOKEY_OK;
}

static int journal_stage_sector(unsigned slot, uint32_t generation,
                                unsigned batch_index, unsigned batch_count,
                                uintptr_t target, const uint8_t *page,
                                unsigned cut_index, unsigned target_index,
                                const char *cut_phase, unsigned cut_program_bytes) {
    if (page == NULL || target < journal_target_start ||
        target + FLASH_SECTOR_SIZE > journal_target_end ||
        (target & (FLASH_SECTOR_SIZE - 1u)) != 0 ||
        slot >= FLASH_JOURNAL_SLOTS || batch_count == 0 ||
        batch_count > FLASH_JOURNAL_SLOTS || batch_index >= batch_count) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }

    uintptr_t journal_data_addr = journal_slot_data_addr(slot);
    uintptr_t journal_meta_addr = journal_slot_meta_addr(slot);

    /* Invalidate any completed previous transaction before touching the
     * journal data sector.  If the last target write succeeded but clearing
     * metadata was interrupted, stale valid metadata must never be paired
     * with bytes from a new transaction. */
    if (journal_raw_erase(journal_meta_addr) != PICOKEY_OK) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
    if (cut_index > 0 && target_index == cut_index && cut_phase != NULL &&
        strcmp(cut_phase, "journal-after-meta-erase") == 0) {
        fprintf(stderr, "PICO_KEYS_EMU_COMMIT_CUT_JOURNAL_AFTER_META_ERASE index=%u\n",
                target_index);
        _exit(97);
    }
#endif
    if (journal_raw_erase(journal_data_addr) != PICOKEY_OK) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
    if (cut_index > 0 && target_index == cut_index && cut_phase != NULL &&
        strcmp(cut_phase, "journal-after-data-erase") == 0) {
        fprintf(stderr, "PICO_KEYS_EMU_COMMIT_CUT_JOURNAL_AFTER_DATA_ERASE index=%u\n",
                target_index);
        _exit(97);
    }
    if (cut_index > 0 && target_index == cut_index && cut_phase != NULL &&
        strcmp(cut_phase, "journal-mid-data") == 0) {
        unsigned bytes = cut_program_bytes;
        if (bytes == 0 || bytes >= FLASH_SECTOR_SIZE) {
            bytes = 256;
        }
        if (journal_raw_program(journal_data_addr, page, bytes) != PICOKEY_OK) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        fprintf(stderr,
                "PICO_KEYS_EMU_COMMIT_CUT_JOURNAL_MID_DATA index=%u bytes=%u\n",
                target_index, bytes);
        _exit(97);
    }
#endif
    if (journal_raw_program(journal_data_addr, page, FLASH_SECTOR_SIZE) != PICOKEY_OK) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }

    flash_journal_meta_t meta = {
        .header_magic = FLASH_JOURNAL_HEADER_MAGIC,
        .header_magic_inv = ~FLASH_JOURNAL_HEADER_MAGIC,
        .generation = generation,
        .target = (uint32_t)target,
        .crc32 = journal_crc32(page, FLASH_SECTOR_SIZE),
        .crc32_inv = 0,
        .version = FLASH_JOURNAL_VERSION,
        .batch_index = (uint16_t)batch_index,
        .batch_count = (uint16_t)batch_count,
        .commit = UINT32_MAX,
        .commit_inv = UINT32_MAX,
        .reserved1 = {UINT32_MAX, UINT32_MAX},
        .done = UINT32_MAX,
        .done_inv = UINT32_MAX,
        .reserved2 = {UINT32_MAX, UINT32_MAX},
    };
    meta.crc32_inv = ~meta.crc32;
    if (journal_raw_program(journal_meta_addr, (const uint8_t *)&meta,
                            FLASH_JOURNAL_HEADER_LEN) != PICOKEY_OK) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
    if (cut_index > 0 && target_index == cut_index && cut_phase != NULL &&
        strcmp(cut_phase, "journal-before-commit") == 0) {
        fprintf(stderr, "PICO_KEYS_EMU_COMMIT_CUT_JOURNAL_BEFORE_COMMIT index=%u\n",
                target_index);
        _exit(97);
    }
#endif
    const uint32_t commit_block[4] = {
        FLASH_JOURNAL_COMMIT_MAGIC,
        ~FLASH_JOURNAL_COMMIT_MAGIC,
        UINT32_MAX,
        UINT32_MAX,
    };
    if (journal_raw_program(journal_meta_addr + offsetof(flash_journal_meta_t, commit),
                            (const uint8_t *)commit_block,
                            sizeof(commit_block)) != PICOKEY_OK) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
    if (cut_index > 0 && target_index == cut_index && cut_phase != NULL &&
        strcmp(cut_phase, "journal-after-meta") == 0) {
        fprintf(stderr, "PICO_KEYS_EMU_COMMIT_CUT_JOURNAL_AFTER_META index=%u addr=0x%lx\n",
                target_index, (unsigned long)target);
        _exit(97);
    }
#endif

    return PICOKEY_OK;
}

static int journal_apply_sector(uintptr_t target, const uint8_t *page,
                                unsigned cut_index, unsigned target_index,
                                const char *cut_phase, unsigned cut_program_bytes) {
    if (page == NULL || target < journal_target_start ||
        target + FLASH_SECTOR_SIZE > journal_target_end ||
        (target & (FLASH_SECTOR_SIZE - 1u)) != 0) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }

    if (journal_raw_erase(target) != PICOKEY_OK) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
#if defined(ESP_PLATFORM) && defined(CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST) && CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST
    if (qemu_journal_cut_after_target_erase) {
        qemu_journal_cut_after_target_erase = false;
        printf("JOURNAL_RECOVERY_QEMU_CUT_READY target=0x%lx\n", (unsigned long)target);
        fflush(stdout);
        for (;;) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
#endif
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
    if (cut_index > 0 && target_index == cut_index && cut_phase != NULL &&
        strcmp(cut_phase, "after-erase") == 0) {
        fprintf(stderr, "PICO_KEYS_EMU_COMMIT_CUT_AFTER_ERASE index=%u addr=0x%lx\n",
                target_index, (unsigned long)target);
        _exit(97);
    }
    if (cut_index > 0 && target_index == cut_index && cut_phase != NULL &&
        strcmp(cut_phase, "mid-program") == 0) {
        unsigned bytes = cut_program_bytes;
        if (bytes == 0 || bytes >= FLASH_SECTOR_SIZE) {
            bytes = 256;
        }
        if (journal_raw_program(target, page, bytes) != PICOKEY_OK) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        fprintf(stderr,
                "PICO_KEYS_EMU_COMMIT_CUT_MID_PROGRAM index=%u addr=0x%lx bytes=%u\n",
                target_index, (unsigned long)target, bytes);
        _exit(97);
    }
#endif
    if (journal_raw_program(target, page, FLASH_SECTOR_SIZE) != PICOKEY_OK) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
    if (cut_index > 0 && target_index == cut_index && cut_phase == NULL) {
        fprintf(stderr, "PICO_KEYS_EMU_COMMIT_CUT_PAGE index=%u addr=0x%lx\n",
                target_index, (unsigned long)target);
        _exit(97);
    }
#endif
    return PICOKEY_OK;
}

static int journal_commit_batch(page_flash_t **pages, unsigned count,
                                unsigned cut_index, const char *cut_phase,
                                unsigned cut_program_bytes) {
    if (pages == NULL || count == 0 || count > FLASH_JOURNAL_SLOTS ||
        count > TOTAL_FLASH_PAGES) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }

    const unsigned start_slot = journal_next_slot;
    const uint32_t generation = journal_next_generation;

    /* First make the complete replacement generation durable in the journal.
     * No target sector is modified until all members have commit markers. */
    for (unsigned i = 0; i < count; i++) {
        if (pages[i] == NULL || !pages[i]->ready || pages[i]->erase) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        unsigned slot = (start_slot + i) % FLASH_JOURNAL_SLOTS;
        int ret = journal_stage_sector(
            slot, generation, i, count,
            pages[i]->address, pages[i]->page,
            cut_index, i + 1u, cut_phase, cut_program_bytes);
        if (ret != PICOKEY_OK) {
            return ret;
        }
    }

    /* Once the batch is completely staged, every target may be replayed from
     * the same generation after an interrupted local/QEMU power cycle. */
    for (unsigned i = 0; i < count; i++) {
        int ret = journal_apply_sector(
            pages[i]->address, pages[i]->page,
            cut_index, i + 1u, cut_phase, cut_program_bytes);
        if (ret != PICOKEY_OK) {
            return ret;
        }
    }

    if (journal_mark_done(start_slot) != PICOKEY_OK) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    journal_next_slot = (start_slot + count) % FLASH_JOURNAL_SLOTS;
    journal_next_generation = journal_next_generation_value(generation);
    return PICOKEY_OK;
}
#endif


//this function has to be called from the core 0
void do_flash() {
    if (mutex_try_enter(&mtx_flash, NULL) == true) {
        if (locked_out == true && flash_available == true && ready_pages > 0) {
#if defined(ESP_PLATFORM) || (defined(ENABLE_EMULATION) && !defined(_MSC_VER))
            page_flash_t *journal_pages[TOTAL_FLASH_PAGES] = {0};
            unsigned journal_page_count = 0;
            for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
                if (flash_pages[r].ready) {
                    journal_pages[journal_page_count++] = &flash_pages[r];
                }
            }
#endif
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
            unsigned commit_cut_after = 0;
            unsigned commit_cut_done = 0;
            unsigned commit_cut_pending = journal_page_count;
            const char *commit_cut_phase = NULL;
            unsigned commit_cut_program_bytes = 0;
            const char *commit_cut_arm = getenv("PICO_KEYS_EMU_COMMIT_CUT_ARM_FILE");
            if (commit_cut_arm != NULL && access(commit_cut_arm, F_OK) == 0) {
                const char *after = getenv("PICO_KEYS_EMU_COMMIT_CUT_AFTER_PAGES");
                commit_cut_after = after != NULL ? (unsigned)strtoul(after, NULL, 0) : 1;
                if (commit_cut_after == 0) {
                    commit_cut_after = 1;
                }
                commit_cut_phase = getenv("PICO_KEYS_EMU_COMMIT_CUT_PHASE");
                if (commit_cut_phase != NULL && strcmp(commit_cut_phase, "mid-program") == 0) {
                    const char *program_bytes = getenv("PICO_KEYS_EMU_COMMIT_CUT_PROGRAM_BYTES");
                    commit_cut_program_bytes = program_bytes != NULL
                        ? (unsigned)strtoul(program_bytes, NULL, 0) : 256;
                    if (commit_cut_program_bytes == 0 || commit_cut_program_bytes >= FLASH_SECTOR_SIZE) {
                        commit_cut_program_bytes = 256;
                    }
                }
                /* The legacy full-page cut is only useful for a multi-sector
                 * transaction. Sub-sector cuts deliberately exercise a
                 * single sector's erase/program window as well. */
                if (commit_cut_phase == NULL && commit_cut_pending < 2) {
                    commit_cut_after = 0;
                }
            }
            if (commit_cut_after > 0) {
                fprintf(stderr,
                        "PICO_KEYS_EMU_COMMIT_CUT_ARMED pending=%u after=%u phase=%s bytes=%u\n",
                        commit_cut_pending, commit_cut_after,
                        commit_cut_phase != NULL ? commit_cut_phase : "after-page",
                        commit_cut_program_bytes);
            }
#endif
            //printf(" DO_FLASH AVAILABLE\n");
#if defined(ESP_PLATFORM) || (defined(ENABLE_EMULATION) && !defined(_MSC_VER))
            bool journal_batch_ok = true;
            if (journal_page_count > 0) {
                int commit_ret;
#if defined(ESP_PLATFORM)
                for (int retries = 0; retries < FLASH_LOCKOUT_RETRIES &&
                     multicore_lockout_start_timeout_us(1000) == false; retries++) {
                }
                uint32_t ints = save_and_disable_interrupts();
                commit_ret = journal_commit_batch(
                    journal_pages, journal_page_count, 0, NULL, 0);
                restore_interrupts(ints);
                for (int retries = 0; retries < FLASH_LOCKOUT_RETRIES &&
                     multicore_lockout_end_timeout_us(1000) == false; retries++) {
                }
#else
                commit_ret = journal_commit_batch(
                    journal_pages, journal_page_count,
                    commit_cut_after, commit_cut_phase, commit_cut_program_bytes);
#endif
                if (commit_ret != PICOKEY_OK) {
                    printf("ERROR: CRASH-SAFE FLASH BATCH COMMIT FAILED %d\n", commit_ret);
                    journal_batch_ok = false;
                }
                else {
                    for (unsigned i = 0; i < journal_page_count; i++) {
                        journal_pages[i]->ready = false;
                        ready_pages--;
                    }
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
                    commit_cut_done += journal_page_count;
#endif
                }
            }
#endif
            for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
                if (flash_pages[r].ready == true) {
#if defined(ESP_PLATFORM) || (defined(ENABLE_EMULATION) && !defined(_MSC_VER))
                    /* Journal-backed platforms commit all ready sectors above
                     * as one generation. A failed batch remains cached. */
                    continue;
#elif defined(PICO_PLATFORM)
                    //printf("WRITTING %X\n",flash_pages[r].address-XIP_BASE);
                    for (int retries = 0; retries < FLASH_LOCKOUT_RETRIES && multicore_lockout_start_timeout_us(1000) == false; retries++) {
                    }
                    //printf("WRITTING %X\n",flash_pages[r].address-XIP_BASE);
                    uint32_t ints = save_and_disable_interrupts();
                    flash_range_erase(flash_pages[r].address - XIP_BASE, FLASH_SECTOR_SIZE);
                    flash_range_program(flash_pages[r].address - XIP_BASE, flash_pages[r].page, FLASH_SECTOR_SIZE);
                    restore_interrupts(ints);
                    for (int retries = 0; retries < FLASH_LOCKOUT_RETRIES && multicore_lockout_end_timeout_us(1000) == false; retries++) {
                    }
                    //printf("WRITEN %X !\n",flash_pages[r].address);
#else
                    memcpy(map + flash_pages[r].address, flash_pages[r].page, FLASH_SECTOR_SIZE);
#endif
                    flash_pages[r].ready = false;
                    ready_pages--;
                }
                else if (flash_pages[r].erase == true) {
#if defined(ESP_PLATFORM) || (defined(ENABLE_EMULATION) && !defined(_MSC_VER))
                    if (!journal_batch_ok) {
                        continue;
                    }
#endif
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
                    for (int retries = 0; retries < FLASH_LOCKOUT_RETRIES && multicore_lockout_start_timeout_us(1000) == false; retries++) {
                    }
                    //printf("WRITTING\n");
                    flash_range_erase(flash_pages[r].address - XIP_BASE, flash_pages[r].page_size ? ((int) (flash_pages[r].page_size / FLASH_SECTOR_SIZE)) * FLASH_SECTOR_SIZE : FLASH_SECTOR_SIZE);
                    for (int retries = 0; retries < FLASH_LOCKOUT_RETRIES && multicore_lockout_end_timeout_us(1000) == false; retries++) {
                    }
#else
                    memset(map + flash_pages[r].address, 0, FLASH_SECTOR_SIZE);
#if defined(ENABLE_EMULATION) && !defined(_MSC_VER)
                    if (commit_cut_after > 0) {
                        msync(map + flash_pages[r].address, FLASH_SECTOR_SIZE, MS_SYNC);
                        fsync(fd_map);
                        commit_cut_done++;
                        fprintf(stderr,
                                "PICO_KEYS_EMU_COMMIT_CUT_PAGE index=%u addr=0x%lx erase=1\n",
                                commit_cut_done, (unsigned long)flash_pages[r].address);
                        if (commit_cut_done == commit_cut_after) {
                            fprintf(stderr, "PICO_KEYS_EMU_COMMIT_CUT_EXIT\n");
                            _exit(97);
                        }
                    }
#endif
#endif
                    flash_pages[r].erase = false;
                    ready_pages--;
                }
            }
#if !defined(PICO_PLATFORM) && !defined(ESP_PLATFORM)
            msync(map, FLASH_SIZE_BYTES, MS_SYNC);
#endif
            if (ready_pages != 0) {
                printf("ERROR: DO FLASH DOES NOT HAVE ZERO PAGES\n");
            }
        }
        flash_available = ready_pages != 0;
#ifdef ESP_PLATFORM
        esp_partition_munmap(fd_map);
        esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA, (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map);
#endif
        mutex_exit(&mtx_flash);
    }
    sem_release(&sem_flash);
}

#ifdef PICO_RP2040
void phymarker_write();
#endif
//this function has to be called from the core 0
void low_flash_init() {
#ifdef PICO_RP2040
    phymarker_write();
#endif
    memset(flash_pages, 0, sizeof(page_flash_t) * TOTAL_FLASH_PAGES);
    mutex_init(&mtx_flash);
    sem_init(&sem_flash, 0, 1);

    uint32_t data_start_addr;
    uint32_t data_end_addr;
#if defined(ESP_PLATFORM)
    part0 = esp_partition_find_first(0x40, 0x1, "part0");
    esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA, (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map);
    data_start_addr = 0;
    data_end_addr = part0->size;
    FLASH_SIZE_BYTES = part0->size;
#elif defined(PICO_PLATFORM)
    uint8_t txbuf[6] = {0x9f};
    uint8_t rxbuf[6] = {0};
    flash_do_cmd(txbuf, rxbuf, 4);

    FLASH_SIZE_BYTES = (1 << rxbuf[3]);
#ifdef PICO_RP2350
    __attribute__((aligned(4))) uint8_t workarea[4 * 1024];
    int rc = rom_load_partition_table(workarea, sizeof(workarea), false);
    if (rc) {
        reset_usb_boot(0, 0);
    }

    uint8_t boot_partition = 1;
    rc = rom_get_partition_table_info((uint32_t*)workarea, 0x8, PT_INFO_PARTITION_LOCATION_AND_FLAGS | PT_INFO_SINGLE_PARTITION | (boot_partition << 24));

    if (rc != 3) {
        data_start_addr = (FLASH_SIZE_BYTES >> 1);
        data_end_addr = FLASH_SIZE_BYTES;
    } else {
        uint16_t first_sector_number = (((uint32_t*)workarea)[1] & PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB;
        uint16_t last_sector_number = (((uint32_t*)workarea)[1] & PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB;
        data_start_addr = first_sector_number * FLASH_SECTOR_SIZE;
        data_end_addr = (last_sector_number + 1) * FLASH_SECTOR_SIZE;
        if (data_end_addr > FLASH_SIZE_BYTES) {
            data_end_addr = FLASH_SIZE_BYTES;
        }
    }
    data_end_addr -= 2 * FLASH_SECTOR_SIZE;
#else
    data_start_addr = (FLASH_SIZE_BYTES >> 1);
    data_end_addr = FLASH_SIZE_BYTES;
#endif

    data_start_addr += XIP_BASE;
    data_end_addr += XIP_BASE;
#else
    fd_map = open("memory.flash", O_RDWR | O_CREAT, (mode_t) 0600);
    lseek(fd_map, FLASH_SIZE_BYTES - 1, SEEK_SET);
    if (write(fd_map, "", 1) != 1) {
        perror("memory.flash");
        exit(EXIT_FAILURE);
    }
    map = mmap(0, FLASH_SIZE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd_map, 0);
    data_start_addr = 0;
    data_end_addr = FLASH_SIZE_BYTES;
#endif
#if defined(ESP_PLATFORM) || (defined(ENABLE_EMULATION) && !defined(_MSC_VER))
    uintptr_t legacy_start_addr = data_start_addr;
    journal_base_addr = data_start_addr;
    data_start_addr += FLASH_JOURNAL_SECTORS * FLASH_SECTOR_SIZE;
    journal_target_start = data_start_addr;
    journal_target_end = data_end_addr;
    int journal_ret = journal_recover_if_needed();
    if (journal_ret != PICOKEY_OK) {
        fprintf(stderr, "FATAL ERROR: flash journal recovery failed: %d\n", journal_ret);
        fflush(stderr);
        abort();
    }
#ifdef ESP_PLATFORM
    esp_partition_munmap(fd_map);
    esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA,
                       (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map);
#endif
    flash_set_bounds(legacy_start_addr, data_end_addr);
    int preflight_ret = journal_preflight_legacy_store(legacy_start_addr,
                                                       data_start_addr);
    if (preflight_ret != PICOKEY_OK) {
        fprintf(stderr, "FATAL ERROR: legacy store overlaps flash journal reserve: %d\n",
                preflight_ret);
        fflush(stderr);
        abort();
    }
#endif
    flash_set_bounds(data_start_addr, data_end_addr);
}

void low_flash_init_core1() {
    mutex_enter_blocking(&mtx_flash);
    multicore_lockout_victim_init();
    locked_out = true;
    mutex_exit(&mtx_flash);
}

void wait_flash_finish() {
    sem_acquire_blocking(&sem_flash); //blocks until released
    //wake up
    sem_acquire_blocking(&sem_flash); //decrease permits
}

void low_flash_available() {
    mutex_enter_blocking(&mtx_flash);
    flash_available = true;
    mutex_exit(&mtx_flash);
}

bool low_flash_is_pending() {
    mutex_enter_blocking(&mtx_flash);
    bool pending = flash_available && ready_pages > 0;
    mutex_exit(&mtx_flash);
    return pending;
}

page_flash_t *find_free_page(uintptr_t addr) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    /* Existing ownership always wins. Searching a free slot first can create
     * two cache entries for the same sector and split a transaction's writes. */
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if ((flash_pages[r].ready || flash_pages[r].erase) &&
            flash_pages[r].address == addr_alg) {
            return &flash_pages[r];
        }
    }
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if (!flash_pages[r].ready && !flash_pages[r].erase) {
            page_flash_t *p = &flash_pages[r];
#ifdef PICO_PLATFORM
            memcpy(p->page, (uint8_t *) addr_alg, FLASH_SECTOR_SIZE);
#else
            memcpy(p->page, (addr >= start_data_pool && addr <= end_rom_pool + sizeof(uintptr_t)) ? (uint8_t *) (map + addr_alg) : (uint8_t *) addr_alg, FLASH_SECTOR_SIZE);
#endif
            ready_pages++;
            p->address = addr_alg;
            p->ready = true;
            p->erase = false;
            p->page_size = 0;
            return p;
        }
    }
    return NULL;
}

int flash_preflight_pages(const uintptr_t *addrs, size_t count) {
    if (addrs == NULL || count == 0) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    mutex_enter_blocking(&mtx_flash);
    unsigned free_slots = 0;
    for (int i = 0; i < TOTAL_FLASH_PAGES; ++i) {
        if (!flash_pages[i].ready && !flash_pages[i].erase) {
            free_slots++;
        }
    }

    unsigned needed = 0;
    for (size_t i = 0; i < count; ++i) {
        uintptr_t sector = addrs[i] & -FLASH_SECTOR_SIZE;
        bool existing = false;
        for (int p = 0; p < TOTAL_FLASH_PAGES; ++p) {
            if ((flash_pages[p].ready || flash_pages[p].erase) &&
                flash_pages[p].address == sector) {
                if (flash_pages[p].erase) {
                    mutex_exit(&mtx_flash);
                    return PICOKEY_ERR_MEMORY_FATAL;
                }
                existing = true;
                break;
            }
        }
        if (existing) {
            continue;
        }
        bool duplicate = false;
        for (size_t j = 0; j < i; ++j) {
            if ((addrs[j] & -FLASH_SECTOR_SIZE) == sector) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            needed++;
        }
    }
    int ret = needed <= free_slots ? PICOKEY_OK : PICOKEY_ERR_NO_MEMORY;
    mutex_exit(&mtx_flash);
    return ret;
}

#ifdef ENABLE_EMULATION
int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
uint8_t *flash_read(uintptr_t addr);

int low_flash_cache_selftest(void) {
    uint8_t value = 0;
    for (unsigned i = 0; i < TOTAL_FLASH_PAGES; ++i) {
        value = (uint8_t)(0x10 + i);
        int ret = flash_program_block(start_data_pool + i * FLASH_SECTOR_SIZE,
                                      &value, sizeof(value));
        if (ret != PICOKEY_OK) {
            printf("LOW_FLASH_CACHE_SELFTEST_FAIL: fill page %u returned %d\n", i, ret);
            return ret;
        }
    }
    if (ready_pages != TOTAL_FLASH_PAGES) {
        printf("LOW_FLASH_CACHE_SELFTEST_FAIL: expected %u cached pages, got %u\n",
               TOTAL_FLASH_PAGES, ready_pages);
        return PICOKEY_ERR_MEMORY_FATAL;
    }

    value = 0xA5;
    int ret = flash_program_block(start_data_pool, &value, sizeof(value));
    if (ret != PICOKEY_OK) {
        printf("LOW_FLASH_CACHE_SELFTEST_FAIL: rewrite cached page returned %d\n", ret);
        return ret;
    }
    if (ready_pages != TOTAL_FLASH_PAGES || *flash_read(start_data_pool) != value) {
        printf("LOW_FLASH_CACHE_SELFTEST_FAIL: cached-page ownership changed\n");
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    printf("LOW_FLASH_CACHE_SELFTEST_PASS\n");
    return PICOKEY_OK;
}
#endif

int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len) {
    page_flash_t *p = NULL;

    if (!data || len == 0) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    if ((addr & (FLASH_SECTOR_SIZE - 1)) + len > FLASH_SECTOR_SIZE) {
        return PICOKEY_ERR_NO_MEMORY;
    }

    mutex_enter_blocking(&mtx_flash);
    if (!(p = find_free_page(addr))) {
        mutex_exit(&mtx_flash);
        printf("ERROR: ALL FLASH PAGES CACHED\n");
        return PICOKEY_ERR_NO_MEMORY;
    }
    if (p->erase) {
        mutex_exit(&mtx_flash);
        printf("ERROR: FLASH WRITE CONFLICTS WITH PENDING ERASE\n");
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    memcpy(&p->page[addr & (FLASH_SECTOR_SIZE - 1)], data, len);
    //printf("Flash: modified page %X with data %x at [%x]\n",(uintptr_t)addr,(uintptr_t)data,addr&(FLASH_SECTOR_SIZE-1));
    mutex_exit(&mtx_flash);
    return PICOKEY_OK;
}

int flash_program_halfword(uintptr_t addr, uint16_t data) {
    return flash_program_block(addr, (const uint8_t *) &data, sizeof(uint16_t));
}

int flash_program_word(uintptr_t addr, uint32_t data) {
    return flash_program_block(addr,  (const uint8_t *) &data, sizeof(uint32_t));
}

int flash_program_uintptr(uintptr_t addr, uintptr_t data) {
    return flash_program_block(addr,  (const uint8_t *) &data, sizeof(uintptr_t));
}

uint8_t *flash_read(uintptr_t addr) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    mutex_enter_blocking(&mtx_flash);
    if (ready_pages > 0) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            if (flash_pages[r].ready && flash_pages[r].address == addr_alg) {
                uint8_t *v = &flash_pages[r].page[addr & (FLASH_SECTOR_SIZE - 1)];
                mutex_exit(&mtx_flash);
                return v;
            }
        }
    }
    uint8_t *v = (uint8_t *) addr;
    mutex_exit(&mtx_flash);
#if !defined(PICO_PLATFORM)
    if (addr >= start_data_pool && addr <= end_rom_pool + sizeof(uintptr_t)) {
        v += (uintptr_t) map;
    }
#endif
    return v;
}

uintptr_t flash_read_uintptr(uintptr_t addr) {
    uint8_t *p = flash_read(addr);
    uintptr_t v = 0x0;
    for (size_t i = 0; i < sizeof(uintptr_t); i++) {
        v |= (uintptr_t) p[i] << (8 * i);
    }
    return v;
}
uint16_t flash_read_uint16(uintptr_t addr) {
    uint8_t *p = flash_read(addr);
    uint16_t v = 0x0;
    for (size_t i = 0; i < sizeof(uint16_t); i++) {
        v |= p[i] << (8 * i);
    }
    return v;
}
uint8_t flash_read_uint8(uintptr_t addr) {
    return *flash_read(addr);
}

int flash_erase_page(uintptr_t addr, size_t page_size) {
    page_flash_t *p = NULL;

    mutex_enter_blocking(&mtx_flash);
    if (!(p = find_free_page(addr))) {
        mutex_exit(&mtx_flash);
        printf("ERROR: ALL FLASH PAGES CACHED\n");
        return PICOKEY_ERR_NO_MEMORY;
    }
    p->erase = true;
    p->ready = false;
    p->page_size = page_size;
    mutex_exit(&mtx_flash);

    return PICOKEY_OK;
}

bool flash_check_blank(const uint8_t *p_start, size_t size) {
    const uint8_t *p;

    for (p = p_start; p < p_start + size; p++) {
        if (*p != 0xff) {
            return false;
        }
    }
    return true;
}

#ifdef PICO_RP2040
typedef struct {
    uint64_t magic;
    uint16_t version;
    uint16_t flags;
    uint8_t  uid[PICO_UNIQUE_BOARD_ID_SIZE_BYTES];
    uint32_t crc32;
} __attribute__ ((packed)) phymarker_t;

uintptr_t __phymarker_start = (uintptr_t)0x10100000;

const uint64_t PHYSICAL_MARKER_MAGIC = 0x5049434F4B455953ULL; // "PICOKEYS"

void phymarker_write() {
    const uint64_t magic = *(uint64_t *)__phymarker_start;
    if (magic == PHYSICAL_MARKER_MAGIC) {
        return;
    }
    phymarker_t pm = {
        .magic = PHYSICAL_MARKER_MAGIC, // "PICOKEYS"
        .version = 0x0001,
        .flags = 0x0000,
        .crc32 = 0x00000000
    };
    memcpy(pm.uid, pico_serial.id, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
    pm.crc32 = crc32c((const uint8_t *)&pm, sizeof(phymarker_t) - sizeof(uint32_t));

    uint8_t buf[FLASH_PAGE_SIZE] = {0};
    memcpy(buf, &pm, sizeof(phymarker_t));
    uint32_t ints = save_and_disable_interrupts();

    flash_range_erase((uint32_t)__phymarker_start - XIP_BASE, FLASH_SECTOR_SIZE);
    flash_range_program((uint32_t)__phymarker_start - XIP_BASE, (const uint8_t *)buf, sizeof(buf));

    restore_interrupts(ints);
}

#endif
