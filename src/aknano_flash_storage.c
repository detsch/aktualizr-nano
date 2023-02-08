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


status_t aknano_read_and_verify_flash_storage(int offset, void *output, size_t outputMaxLen)
{
    status_t ret;
    uint32_t data_len;
    uint32_t signature[64/4];
    int mflash_result;
    
    LogInfo(("aknano_read_and_verify_flash_storage offset=0x%X", offset));
    mflash_result = mflash_drv_read(AKNANO_STORAGE_FLASH_OFFSET + offset, &data_len, sizeof(data_len));
    if (mflash_result != 0) {
        LogError(("aknano_read_flash_storage: mflash_drv_read error %d", mflash_result));
        return -1;
    }
    
    mflash_result = mflash_drv_read(AKNANO_STORAGE_FLASH_OFFSET + offset + sizeof(data_len), signature, sizeof(signature));
    if (mflash_result != 0) {
        LogError(("aknano_read_flash_storage: mflash_drv_read error %d", mflash_result));
        return -1;
    }

    mflash_result = mflash_drv_read(AKNANO_STORAGE_FLASH_OFFSET + offset + AKNANO_DATA_HEADER_SIZE, output, outputMaxLen / 4 * 4);
    if (mflash_result != 0) {
        LogError(("aknano_read_flash_storage: mflash_drv_read error %d", mflash_result));
        return -1;
    }

    // ret = aknano_verify_data(output, data_len, (const unsigned char*)signature, 64);
    LogInfo(("aknano_read_and_verify_flash_storage offset=0x%X data_len=%d verify=%d DONE", offset, ret));

    return 0;
}


/* offset needs to be aligned to MFLASH_SECTOR_SIZE (4K) */
status_t aknano_write_data_to_flash(int offset,
                                    const void *data,
                                    size_t data_len,
                                    const void *header,
                                    size_t header_len)
{
    size_t total_processed = 0;
    size_t data_chunk_len;
    unsigned char page_buffer[MFLASH_PAGE_SIZE];
    int header_chunk_len;
    int32_t chunk_flash_addr = offset;
    int32_t mflash_result;
    int32_t next_erase_addr = offset;
    status_t ret = 0;
    size_t total_len = data_len;
    bool first = true;


    LogInfo(("aknano_write_data_to_flash header_len=%d data_len=%d\r\n", header_len, data_len));
    /* Assuming data header will always fit in the first flash page */
    if (header != NULL && header_len > MFLASH_PAGE_SIZE) {
        LogError(("aknano_write_data_to_flash: header_len %u is too big (max %u)", header_len, MFLASH_PAGE_SIZE));
        return -1;
    }

    do {
        if (first && header && header_len) {
            memcpy(page_buffer, header, header_len);
            header_chunk_len = header_len;
        } else {
            header_chunk_len = 0;
        }

        /* The data is expected to be received in page sized chunks (except for the last one) */
        int remaining_bytes = data_len - total_processed;
        if (remaining_bytes < (MFLASH_PAGE_SIZE - header_chunk_len))
            data_chunk_len = remaining_bytes;
        else
            data_chunk_len = (MFLASH_PAGE_SIZE - header_chunk_len);

        memcpy(page_buffer + header_chunk_len, data + total_processed, data_chunk_len);

        if (data_chunk_len + header_chunk_len > 0) {
            /* Perform erase when encountering next sector */
            if (chunk_flash_addr >= next_erase_addr) {
                mflash_result = mflash_drv_sector_erase(next_erase_addr);
                if (mflash_result != 0) {
                    LogError(("aknano_write_data_to_flash: Error erasing sector %ld", mflash_result));
                    ret = -2;
                    break;
                }
                next_erase_addr += MFLASH_SECTOR_SIZE;
            }

            /* Clear the unused portion of the buffer (applicable to the last chunk) */
            if ((data_chunk_len + header_chunk_len) < MFLASH_PAGE_SIZE)
                memset((uint8_t *)page_buffer + data_chunk_len + header_chunk_len, 0xFF, MFLASH_PAGE_SIZE - data_chunk_len - header_chunk_len);

            /* Program the page */
            if (data_chunk_len == 80) {
                LogInfo(("page_buffer 1=%s\r\n", page_buffer+header_len));
                LogInfo(("page_buffer 2=%s\r\n", page_buffer+header_len+40));
            }
            mflash_result = mflash_drv_page_program(chunk_flash_addr, (uint32_t *)page_buffer);
            LogInfo(("mflash_drv_page_program data_chunk_len=%d, header_chunk_len=%d", data_chunk_len, header_chunk_len));
            if (mflash_result != 0) {
                LogError(("aknano_write_data_to_flash: Error storing page %ld", mflash_result));
                ret = -1;
                break;
            }

            total_processed += data_chunk_len;
            chunk_flash_addr += data_chunk_len + header_chunk_len;
        }
        first = false;
    } while ((data_chunk_len + header_chunk_len) == MFLASH_PAGE_SIZE);

    return ret;
}

status_t aknano_write_data_to_storage(int offset, const void *data, uint32_t data_len)
{
    unsigned char header[AKNANO_DATA_HEADER_SIZE] = {0};
    size_t signature_len = 64;

    memcpy(header, &data_len, 4);
    aknano_sign_data(data, data_len, header+4, &signature_len);

    return aknano_write_data_to_flash(AKNANO_STORAGE_FLASH_OFFSET + offset, data, data_len, header, sizeof(header));
}


void aknano_update_settings_in_flash(struct aknano_settings *aknano_settings)
{
    char flashPageBuffer[256];

    memset(flashPageBuffer, 0, sizeof(flashPageBuffer));
    memcpy(flashPageBuffer, &aknano_settings->last_applied_version, sizeof(int));
    memcpy(flashPageBuffer + sizeof(int), &aknano_settings->last_confirmed_version, sizeof(int));
    memcpy(flashPageBuffer + sizeof(int) * 2, aknano_settings->ongoing_update_correlation_id,
           sizeof(aknano_settings->ongoing_update_correlation_id));
#ifdef AKNANO_ENABLE_EXPLICIT_REGISTRATION
    flashPageBuffer[sizeof(int) * 2 + sizeof(aknano_settings->ongoing_update_correlation_id)] =
        aknano_settings->is_device_registered;
#endif
    LogInfo(("Writing settings to flash..."));
    aknano_write_data_to_storage(AKNANO_FLASH_OFF_STATE_BASE, flashPageBuffer, sizeof(flashPageBuffer));
}


// void aknano_read_settings_from_flash(struct aknano_settings *aknano_settings)
// {
//     char flashPageBuffer[256];

//     memset(flashPageBuffer, 0, sizeof(flashPageBuffer));
//     memcpy(flashPageBuffer, &aknano_settings->last_applied_version, sizeof(int));
//     memcpy(flashPageBuffer + sizeof(int), &aknano_settings->last_confirmed_version, sizeof(int));
//     memcpy(flashPageBuffer + sizeof(int) * 2, aknano_settings->ongoing_update_correlation_id,
//            sizeof(aknano_settings->ongoing_update_correlation_id));
// #ifdef AKNANO_ENABLE_EXPLICIT_REGISTRATION
//     flashPageBuffer[sizeof(int) * 2 + sizeof(aknano_settings->ongoing_update_correlation_id)] =
//         aknano_settings->is_device_registered;
// #endif
//     LogInfo(("Writing settings to flash..."));
//     aknano_write_data_to_storage(AKNANO_FLASH_OFF_STATE_BASE, flashPageBuffer, sizeof(flashPageBuffer));
// }



#ifdef AKNANO_ALLOW_PROVISIONING
static status_t aknano_clear_flash_sector(int offset)
{
    int mflash_result = mflash_drv_sector_erase(AKNANO_STORAGE_FLASH_OFFSET + offset);

    if (mflash_result != 0)
        LogError(("EraseSector error %d", mflash_result));

    return 0;
}

// /* Data needs to be a 256 bytes array */
// static status_t aknano_write_flash_page(int offset, void *data)
// {
//     int mflash_result = mflash_drv_page_program(AKNANO_STORAGE_FLASH_OFFSET + offset, data);

//     if (mflash_result != 0)
//         LogError(("aknano_write_flash_page error %d", mflash_result));
//     return 0;
// }

int aknano_clear_provisioned_data()
{
    int offset;

    LogInfo(("Clearing provisioned device data from flash"));
    for (offset = 0; offset < AKNANO_FLASH_SECTORS_COUNT * MFLASH_SECTOR_SIZE; offset += MFLASH_SECTOR_SIZE)
        aknano_clear_flash_sector(offset);
    return 0;
}

status_t aknano_save_uuid_and_serial(const char *uuid, const char *serial, char *cert_buf, const char *key_buf)
{
    int offset;
    char uuid_and_serial[AKNANO_MAX_UUID_LENGTH + AKNANO_MAX_SERIAL_LENGTH];

    aknano_clear_provisioned_data();
    memcpy(uuid_and_serial, uuid, AKNANO_MAX_UUID_LENGTH);
    memcpy(uuid_and_serial + AKNANO_MAX_UUID_LENGTH, serial, AKNANO_MAX_SERIAL_LENGTH);
    // aknano_write_flash_page(AKNANO_FLASH_OFF_DEV_UUID, uuid_and_serial);
    aknano_write_data_to_storage(AKNANO_FLASH_OFF_DEV_ID_BASE, uuid_and_serial, sizeof(uuid_and_serial));
}

#endif
