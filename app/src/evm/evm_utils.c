/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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
#include "evm_utils.h"

#include <stdio.h>
#include <zxmacros.h>

#include "bignum.h"
#include "coin_evm.h"
#include "rlp.h"
#include "zxerror.h"
#include "zxformat.h"

#define CHECK_RLP_LEN(BUFF_LEN, RLP_LEN)            \
    {                                               \
        uint64_t buff_len = BUFF_LEN;               \
        uint64_t rlp_len = RLP_LEN;                 \
        if (buff_len < rlp_len) return rlp_no_data; \
    }

uint64_t saturating_add(uint64_t a, uint64_t b) {
    uint64_t num = a + b;
    if (num < a || num < b) return UINT64_MAX;

    return num;
}

uint32_t saturating_add_u32(uint32_t a, uint32_t b) {
    uint32_t num = a + b;

    if (num < a || num < b) return UINT32_MAX;

    return num;
}

parser_error_t be_bytes_to_u64(const uint8_t *bytes, uint8_t len, uint64_t *num) {
    if (bytes == NULL || num == NULL || len == 0 || len > sizeof(uint64_t)) {
        return parser_unexpected_error;
    }

    *num = 0;

    // fast path
    if (len == 1) {
        *num = bytes[0];
        return 0;
    }

    uint8_t *num_ptr = (uint8_t *)num;
    for (uint8_t i = 0; i < len; i++) {
        *num_ptr = bytes[len - i - 1];
        num_ptr++;
    }

    return parser_ok;
}

rlp_error_t get_tx_rlp_len(const uint8_t *buffer, uint32_t len, uint64_t *read, uint64_t *to_read) {
    if (buffer == NULL || len == 0) return rlp_no_data;

    if (read == NULL || to_read == NULL) return rlp_no_data;

    // get alias
    const uint8_t *data = buffer;
    uint64_t offset = 0;

    *read = 0;
    *to_read = 0;

    // skip version if present/recognized
    //  otherwise tx is probably legacy so no version, just rlp data
    uint8_t version = data[offset];
    if (version == 1 || version == 2) {
        offset += 1;
        *read += 1;
    }

    // get rlp marker
    uint8_t marker = data[offset];

    if ((marker - 0xC0) * (marker - 0xF7) <= 0) {
        *read += 1;
        uint8_t l = marker - 0xC0;
        *to_read = l;
        return rlp_ok;
    }

    if (marker >= 0xF8) {
        offset += 1;

        // For lists longer than 55 bytes the length is encoded
        // differently.
        // The number of bytes that compose the length is encoded
        // in the marker
        // And then the length is just the number BE encoded
        uint64_t num_bytes = (marker - 0xF7);

        uint64_t num;
        if (be_bytes_to_u64(&data[offset], num_bytes, &num) != 0) return rlp_invalid_data;

        // marker byte + number of bytes used to encode the len
        *read += 1 + num_bytes;
        *to_read = num;

        return rlp_ok;
    }

    // should not happen as previous conditional covers all possible values
    return rlp_invalid_data;
}

parser_error_t printRLPNumber(const rlp_t *num, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (num == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    uint256_t tmpUint256 = {0};
    char tmpBuffer[100] = {0};

    CHECK_ERROR(rlp_readUInt256(num, &tmpUint256));
    if (!tostring256(&tmpUint256, 10, tmpBuffer, sizeof(tmpBuffer))) {
        return parser_unexpected_error;
    }
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);

    return parser_ok;
}

#define LESS_THAN_64_DIGIT(num_digit) \
    if (num_digit > 64) return parser_value_out_of_range;

__Z_INLINE bool format_quantity(const uint8_t *num, uint16_t num_len, uint8_t *bcd, uint16_t bcdSize, char *bignum,
                                uint16_t bignumSize) {
    bignumBigEndian_to_bcd(bcd, bcdSize, num, num_len);
    return bignumBigEndian_bcdprint(bignum, bignumSize, bcd, bcdSize);
}

parser_error_t printBigIntFixedPoint(const uint8_t *number, uint16_t number_len, char *outVal, uint16_t outValLen,
                                     uint8_t pageIdx, uint8_t *pageCount, uint16_t decimals) {
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

    if (z_str3join(overlapped.output, sizeof(overlapped.output), NULL, SEI_TOKEN_SYMBOL) != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t printEVMAddress(const rlp_t *address, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (address == NULL || outVal == NULL || address->ptr == NULL || pageCount == NULL || address->rlpLen != ETH_ADDR_LEN) {
        return parser_unexpected_error;
    }

    char tmpBuffer[67] = {0};
    tmpBuffer[0] = '0';
    tmpBuffer[1] = 'x';
    if (!array_to_hexstr(tmpBuffer + 2, sizeof(tmpBuffer) - 2, address->ptr, address->rlpLen)) {
        return parser_unexpected_error;
    }
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t printEVMMaxFees(const eth_tx_t *ethObj, char *outVal, uint16_t outValLen, uint8_t pageIdx,
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

    if (z_str3join(bufferUI, sizeof(bufferUI), NULL, SEI_TOKEN_SYMBOL) != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);

    return parser_ok;
}
