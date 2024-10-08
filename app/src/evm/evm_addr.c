/*******************************************************************************
 *   (c) 2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "evm_addr.h"

#include <stdio.h>

#include "app_mode.h"
#include "coin_evm.h"
#include "crypto_evm.h"
#include "zxerror.h"
#include "zxformat.h"
#include "zxmacros.h"

zxerr_t eth_addr_getNumItems(uint8_t *num_items) {
    if (*num_items == 0) {
        return zxerr_no_data;
    }
    zemu_log_stack("eth_addr_getNumItems");
    *num_items = 1;
    if (app_mode_expert()) {
        *num_items = 2;
    }
    return zxerr_ok;
}

zxerr_t eth_addr_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                         uint8_t pageIdx, uint8_t *pageCount) {
    if (outKey == NULL || outVal == NULL || pageCount == NULL) {
        return zxerr_no_data;
    }
    char buffer[300] = {0};
    uint8_t *addr = G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_ETH;

    // Add "0x" prefix to the address
    snprintf(buffer, sizeof(buffer), "0x");
    MEMCPY(buffer + 2, addr, ETH_ADDR_LEN * 2);

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "EVM Address");
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return zxerr_ok;
        case 1: {
            if (!app_mode_expert()) {
                return zxerr_no_data;
            }

            snprintf(outKey, outKeyLen, "Path");
            bip32_to_str(buffer, sizeof(buffer), hdPathEth, hdPathEth_len);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return zxerr_ok;
        }
        default:
            return zxerr_no_data;
    }
}
