/*
 * Copyright 2022 Foundries.io
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "logging_levels.h"
#define LIBRARY_LOG_NAME "aknano_flash"
#define LIBRARY_LOG_LEVEL LOG_INFO
#include "logging_stack.h"

#include "aknano_priv.h"

#include "mflash_common.h"
#include "mflash_drv.h"

#define AKNANO_STORAGE_FLASH_OFFSET 0x600000
#define FLASH_PAGE_SIZE 256
#define FLASH_SECTOR_SIZE 4096

// Sectors used for AKNANO data
#define AKNANO_FLASH_SECTORS_COUNT 10

status_t aknano_init_flash_storage()
{
    int mflash_result = mflash_drv_init();

    if (mflash_result != 0) {
        LogError(("mflash_drv_init error %d", mflash_result));
        return -1;
    }
    return 0;
}

status_t aknano_read_flash_storage(int offset, void *output, size_t outputMaxLen)
{
    int mflash_result = mflash_drv_read(AKNANO_STORAGE_FLASH_OFFSET + offset, output, outputMaxLen / 4 * 4);

    if (mflash_result != 0) {
        LogError(("aknano_read_flash_storage: mflash_drv_read error %d", mflash_result));
        return -1;
    }
    return 0;
}

/* offset needs to be aligned to MFLASH_SECTOR_SIZE (4K) */
status_t aknano_write_data_to_flash(int offset, const void *data, size_t data_len)
{
    size_t total_processed = 0;
    size_t chunk_len;
    unsigned char page_buffer[MFLASH_PAGE_SIZE];
    int32_t chunk_flash_addr = offset;
    int32_t mflash_result;
    int32_t next_erase_addr = offset;
    status_t ret = 0;

    do{
        /* The data is expected for be received by page sized chunks (except for the last one) */
        int remaining_bytes = data_len - total_processed;
        if (remaining_bytes < MFLASH_PAGE_SIZE)
            chunk_len = remaining_bytes;
        else
            chunk_len = MFLASH_PAGE_SIZE;

        memcpy(page_buffer, data + total_processed, chunk_len);

        if (chunk_len > 0) {
            /* Perform erase when encountering next sector */
            if (chunk_flash_addr >= next_erase_addr) {
                mflash_result = mflash_drv_sector_erase(next_erase_addr);
                if (mflash_result != 0) {
                    LogError(("store_update_image: Error erasing sector %ld", mflash_result));
                    ret = -2;
                    break;
                }
                next_erase_addr += MFLASH_SECTOR_SIZE;
            }

            /* Clear the unused portion of the buffer (applicable to the last chunk) */
            if (chunk_len < MFLASH_PAGE_SIZE)
                memset((uint8_t *)page_buffer + chunk_len, 0xFF, MFLASH_PAGE_SIZE - chunk_len);

            /* Program the page */
            mflash_result = mflash_drv_page_program(chunk_flash_addr, (uint32_t *)page_buffer);
            if (mflash_result != 0) {
                LogError(("store_update_image: Error storing page %ld", mflash_result));
                ret = -1;
                break;
            }

            total_processed += chunk_len;
            chunk_flash_addr += chunk_len;

            // LogInfo(("store_update_image: processed %i bytes", total_processed));
        }
    } while (chunk_len == MFLASH_PAGE_SIZE);

    return ret;
}

status_t aknano_write_data_to_storage(int offset, const void *data, size_t data_len)
{
    return aknano_write_data_to_flash(AKNANO_STORAGE_FLASH_OFFSET + offset, data, data_len);
}

#ifdef AKNANO_ALLOW_PROVISIONING
static status_t aknano_clear_flash_sector(int offset)
{
    int mflash_result = mflash_drv_sector_erase(AKNANO_STORAGE_FLASH_OFFSET + offset);

    if (mflash_result != 0)
        LogError(("EraseSector error %d", mflash_result));

    return 0;
}

/* Data needs to be a 256 bytes array */
static status_t aknano_write_flash_page(int offset, void *data)
{
    int mflash_result = mflash_drv_page_program(AKNANO_STORAGE_FLASH_OFFSET + offset, data);

    if (mflash_result != 0)
        LogError(("aknano_write_flash_page error %d", mflash_result));
    return 0;
}

int aknano_clear_provisioned_data()
{
    int offset;

    LogInfo(("Clearing provisioned device data from flash"));
    for (offset = 0; offset < AKNANO_FLASH_SECTORS_COUNT * FLASH_SECTOR_SIZE; offset += FLASH_SECTOR_SIZE)
        aknano_clear_flash_sector(offset);
    return 0;
}

status_t aknano_store_provisioning_data(const char *uuid, const char *serial, char *cert_buf, const char *key_buf)
{
    int offset;
    char uuid_and_serial[256];

    aknano_clear_provisioned_data();

    memcpy(uuid_and_serial, uuid, AKNANO_MAX_UUID_LENGTH);
    memcpy(uuid_and_serial + 128, serial, AKNANO_MAX_SERIAL_LENGTH);
    aknano_write_flash_page(AKNANO_FLASH_OFF_DEV_UUID, uuid_and_serial);
#ifndef AKNANO_ENABLE_EL2GO
    if (cert_buf)
        for (offset = 0; offset < AKNANO_CERT_BUF_SIZE; offset += FLASH_PAGE_SIZE)
            aknano_write_flash_page(AKNANO_FLASH_OFF_DEV_CERTIFICATE + offset, cert_buf + offset);

    if (key_buf)
        for (offset = 0; offset < AKNANO_CERT_BUF_SIZE; offset += FLASH_PAGE_SIZE)
            aknano_write_flash_page(AKNANO_FLASH_OFF_DEV_KEY + offset, key_buf + offset);

#endif
    // Clear execution settings area of the flash
    aknano_clear_flash_sector(AKNANO_FLASH_OFF_STATE_BASE);
}

#endif
