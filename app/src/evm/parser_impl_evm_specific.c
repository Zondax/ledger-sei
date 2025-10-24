/*******************************************************************************
 *  (c) 2018 - 2025 Zondax AG
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

#include "parser_impl_evm_specific.h"

#include <stdint.h>

#include "app_mode.h"
#include "bignum.h"
#include "coin.h"
#include "evm_erc20.h"
#include "evm_utils.h"
#include "zxformat.h"

#define SUPPORTED_NETWORKS_EVM_LEN 2
#define SEI_MAINNET_CHAINID 1329
#define SEI_DEVNET_CHAINID 713715
#define DECIMAL_BASE 10
#define SEI_TOKEN_SYMBOL "SEI "

const uint64_t supported_networks_evm[SUPPORTED_NETWORKS_EVM_LEN] = {SEI_MAINNET_CHAINID, SEI_DEVNET_CHAINID};

const uint8_t supported_networks_evm_len = SUPPORTED_NETWORKS_EVM_LEN;

const erc20_tokens_t supportedTokens[] = {{{0x9c, 0x1c, 0xb7, 0x40, 0xf3, 0xb6, 0x31, 0xed, 0x53, 0x60,
                                            0x00, 0x58, 0xae, 0x5b, 0x2f, 0x83, 0xe1, 0x5d, 0x9f, 0xbf},
                                           "SEI ",
                                           18}

};

const uint8_t supportedTokensSize = sizeof(supportedTokens) / sizeof(supportedTokens[0]);

parser_error_t getNumItemsEthAppSpecific(eth_tx_t *txObj, uint8_t *numItems) {
    if (numItems == NULL) {
        return parser_unexpected_error;
    }
    // Verify that tx is ERC20
    if (validateERC20(txObj)) {
        if (txObj->tx_type == legacy || txObj->tx_type == eip2930) {
            *numItems = 8;
        } else {
            *numItems = 10;
        }
        return parser_ok;
    }

    // Common items
    if (txObj->tx_type == legacy || txObj->tx_type == eip2930) {
        *numItems = 4;
    } else {
        *numItems = 6;
    }

    // Check if the transaction is blindsigned if so show EVM hash
    *numItems -= (txObj->is_blindsign ? 0 : 1);

    // Check if the transaction has data or to address to show
    *numItems += ((txObj->tx.data.rlpLen != 0) ? 1 : 0) + ((txObj->tx.to.rlpLen != 0) ? 1 : 0);

    return parser_ok;
}

static parser_error_t printEVMMaxFees(const eth_tx_t *ethObj, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                      uint8_t *pageCount) {
    if (ethObj == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    uint256_t gas_limit = {0};
    uint256_t gas_price = {0};

    // Gas limit and gas price
    CHECK_ERROR(rlp_readUInt256(&ethObj->tx.gasLimit, &gas_limit));
    CHECK_ERROR(rlp_readUInt256(&ethObj->tx.gasPrice, &gas_price));

    // multiply gas limit and gas price
    uint256_t max_fees = {0};
    mul256(&gas_limit, &gas_price, &max_fees);

    char bufferUI[100] = {0};
    if (!tostring256(&max_fees, DECIMAL_BASE, bufferUI, sizeof(bufferUI))) {
        return parser_unexpected_error;
    }

    // Add symbol, add decimals, page number
    if (intstr_to_fpstr_inplace(bufferUI, sizeof(bufferUI), COIN_DECIMALS) == 0) {
        return parser_unexpected_value;
    }

    number_inplace_trimming(bufferUI, 1);

    if (z_str3join(bufferUI, sizeof(bufferUI), SEI_TOKEN_SYMBOL, NULL) != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);

    return parser_ok;
}

#define LESS_THAN_64_DIGIT(num_digit) \
    if (num_digit > 64) return parser_value_out_of_range;

__Z_INLINE bool format_quantity(const uint8_t *num, uint16_t num_len, uint8_t *bcd, uint16_t bcdSize, char *bignum,
                                uint16_t bignumSize) {
    bignumBigEndian_to_bcd(bcd, bcdSize, num, num_len);
    return bignumBigEndian_bcdprint(bignum, bignumSize, bcd, bcdSize);
}

static parser_error_t printBigIntFixedPointSpecific(const uint8_t *number, uint16_t number_len, char *outVal,
                                                    uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount,
                                                    uint16_t decimals) {
    if (number == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    LESS_THAN_64_DIGIT(number_len);

    char bignum[160] = {0};
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(&overlapped, sizeof(overlapped));

    if (!format_quantity(number, number_len, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    if (fpstr_to_str(overlapped.output, sizeof(overlapped.output), bignum, decimals)) {
        return parser_unexpected_value;
    }

    number_inplace_trimming(overlapped.output, 1);

    if (z_str3join(overlapped.output, sizeof(overlapped.output), SEI_TOKEN_SYMBOL, NULL) != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t printERC20TransferAppSpecific(__Z_UNUSED const parser_context_t *ctx, eth_tx_t *txObj, uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    if (outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    *pageCount = 1;

    if (txObj->tx_type == eip1559 && displayIdx >= 8) {
        displayIdx++;
    }

    if ((txObj->tx_type == legacy || txObj->tx_type == eip2930) && displayIdx >= 5) {
        displayIdx += 3;
    }

    char data_array[40] = {0};
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Receiver");
            rlp_t to = {.kind = RLP_KIND_STRING, .ptr = (txObj->tx.data.ptr + 4 + 12), .rlpLen = ETH_ADDRESS_LEN};
            CHECK_ERROR(printEVMAddress(&to, outVal, outValLen, pageIdx, pageCount));
            break;

        case 1:
            snprintf(outKey, outKeyLen, "Contract");
            rlp_t contractAddress = {.kind = RLP_KIND_STRING, .ptr = txObj->tx.to.ptr, .rlpLen = ETH_ADDRESS_LEN};
            CHECK_ERROR(printEVMAddress(&contractAddress, outVal, outValLen, pageIdx, pageCount));
            break;

        case 2:
            snprintf(outKey, outKeyLen, "Network");
            switch (txObj->chainId.chain_id_decoded) {
                case SEI_MAINNET_CHAINID:
                    snprintf(outVal, outValLen, "Sei Mainnet");
                    break;
                case SEI_DEVNET_CHAINID:
                    snprintf(outVal, outValLen, "Sei Devnet");
                    break;
                default:
                    return parser_invalid_chain_id;
            }
            break;

        case 3:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printERC20Value(txObj, outVal, outValLen, pageIdx, pageCount));
            break;

        case 4:
            snprintf(outKey, outKeyLen, "Nonce");
            CHECK_ERROR(printRLPNumber(&txObj->tx.nonce, outVal, outValLen, pageIdx, pageCount));
            break;

        case 5:
            snprintf(outKey, outKeyLen, "Max Priority Fee");
            CHECK_ERROR(printRLPNumber(&txObj->tx.max_priority_fee_per_gas, outVal, outValLen, pageIdx, pageCount));
            break;

        case 6:
            snprintf(outKey, outKeyLen, "Max Fee");
            CHECK_ERROR(printRLPNumber(&txObj->tx.max_fee_per_gas, outVal, outValLen, pageIdx, pageCount));
            break;

        case 7:
            snprintf(outKey, outKeyLen, "Gas limit");
            CHECK_ERROR(printRLPNumber(&txObj->tx.gasLimit, outVal, outValLen, pageIdx, pageCount));
            break;

        case 8:
            snprintf(outKey, outKeyLen, "Max Fees");
            CHECK_ERROR(printEVMMaxFees(txObj, outVal, outValLen, pageIdx, pageCount));
            break;

        case 9:
            snprintf(outKey, outKeyLen, "Value");
            CHECK_ERROR(printRLPNumber(&txObj->tx.value, outVal, outValLen, pageIdx, pageCount));
            break;

        case 10:
            snprintf(outKey, outKeyLen, "Data");
            array_to_hexstr(data_array, sizeof(data_array), txObj->tx.data.ptr,
                            txObj->tx.data.rlpLen > DATA_BYTES_TO_PRINT ? DATA_BYTES_TO_PRINT : txObj->tx.data.rlpLen);

            if (txObj->tx.data.rlpLen > DATA_BYTES_TO_PRINT) {
                snprintf(data_array + (2 * DATA_BYTES_TO_PRINT), 4, "...");
            }

            pageString(outVal, outValLen, data_array, pageIdx, pageCount);
            break;

        default:
            return parser_display_page_out_of_range;
    }

    return parser_ok;
}

parser_error_t printGenericAppSpecific(const parser_context_t *ctx, eth_tx_t *txObj, uint8_t displayIdx, char *outKey,
                                       uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                       uint8_t *pageCount) {
    if (outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    *pageCount = 1;

    char data_array[40] = {0};

    if ((displayIdx >= 2 && txObj->tx.data.rlpLen == 0) || txObj->tx.to.rlpLen == 0) {
        displayIdx += 1;
    }

    if (txObj->tx_type == eip1559 && displayIdx >= 6) {
        displayIdx++;
    }

    if ((txObj->tx_type == legacy || txObj->tx_type == eip2930) && displayIdx >= 3) {
        displayIdx += 3;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "To");
            rlp_t contractAddress = {.kind = RLP_KIND_STRING, .ptr = txObj->tx.to.ptr, .rlpLen = ETH_ADDRESS_LEN};
            CHECK_ERROR(printEVMAddress(&contractAddress, outVal, outValLen, pageIdx, pageCount));
            break;

        case 1:
            snprintf(outKey, outKeyLen, "Amount");
            printBigIntFixedPointSpecific(txObj->tx.value.ptr, txObj->tx.value.rlpLen, outVal, outValLen, pageIdx, pageCount,
                                          COIN_DECIMALS);
            break;

        case 2:
            snprintf(outKey, outKeyLen, "Data");
            array_to_hexstr(data_array, sizeof(data_array), txObj->tx.data.ptr,
                            txObj->tx.data.rlpLen > DATA_BYTES_TO_PRINT ? DATA_BYTES_TO_PRINT : txObj->tx.data.rlpLen);

            if (txObj->tx.data.rlpLen > DATA_BYTES_TO_PRINT) {
                snprintf(data_array + (2 * DATA_BYTES_TO_PRINT), 4, "...");
            }

            pageString(outVal, outValLen, data_array, pageIdx, pageCount);
            break;

        case 3:
            snprintf(outKey, outKeyLen, "Max Priority Fee");
            CHECK_ERROR(printRLPNumber(&txObj->tx.max_priority_fee_per_gas, outVal, outValLen, pageIdx, pageCount));
            break;

        case 4:
            snprintf(outKey, outKeyLen, "Max Fee");
            CHECK_ERROR(printRLPNumber(&txObj->tx.max_fee_per_gas, outVal, outValLen, pageIdx, pageCount));
            break;

        case 5:
            snprintf(outKey, outKeyLen, "Gas limit");
            CHECK_ERROR(printRLPNumber(&txObj->tx.gasLimit, outVal, outValLen, pageIdx, pageCount));
            break;

        case 6:
            snprintf(outKey, outKeyLen, "Max Fees");
            CHECK_ERROR(printEVMMaxFees(txObj, outVal, outValLen, pageIdx, pageCount));
            break;

        case 7:
            snprintf(outKey, outKeyLen, "Nonce");
            CHECK_ERROR(printRLPNumber(&txObj->tx.nonce, outVal, outValLen, pageIdx, pageCount));
            break;

        case 8:
            CHECK_ERROR(printEthHash(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount));
            break;

        default:
            return parser_display_page_out_of_range;
    }

    return parser_ok;
}
