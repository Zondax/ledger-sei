/*******************************************************************************
 *   (c) 2018 - 2022 Zondax AG
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
#include "crypto_helper.h"

#include "bech32.h"
#include "coin.h"
#include "crypto.h"
#include "zxformat.h"
#define CX_SHA256_SIZE 32
#define CX_RIPEMD160_SIZE 20

uint8_t crypto_encodePubkey(const uint8_t *pubkey, char *out, uint16_t out_len) {
    if (pubkey == NULL || out == NULL) {
        return 0;
    }

    // Hash it
    uint8_t hashed1_pk[CX_SHA256_SIZE] = {0};
    crypto_sha256(pubkey, PK_LEN_SECP256K1, hashed1_pk, CX_SHA256_SIZE);

    uint8_t hashed2_pk[CX_RIPEMD160_SIZE] = {0};
    CHECK_ZXERR(ripemd160_32(hashed2_pk, hashed1_pk))

    CHECK_ZXERR(bech32EncodeFromBytes(out, out_len, "sei", hashed2_pk, CX_RIPEMD160_SIZE, 1, BECH32_ENCODING_BECH32))

    return strlen(out);
}
