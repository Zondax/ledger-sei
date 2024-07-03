/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define CLA 0x62

#define HDPATH_LEN_DEFAULT 5
#define HDPATH_0_DEFAULT (0x80000000u | 0x2c)   // 44
#define HDPATH_1_DEFAULT (0x80000000u | 0x3cu)  // 60

#define HDPATH_2_DEFAULT (0x80000000u | 0u)
#define HDPATH_3_DEFAULT (0u)
#define HDPATH_4_DEFAULT (0u)

#define PK_LEN_SECP256K1 33u
#define PK_LEN_SECP256K1_UNCOMPRESSED 65u
#define SECP256K1_ADDR_MAX_LEN 60u

#define MAX_SIGN_SIZE 256u

#define COIN_AMOUNT_DECIMAL_PLACES 6
#define COIN_TICKER "SEI "

#define MENU_MAIN_APP_LINE1 "Sei"
#define MENU_MAIN_APP_LINE2 "Ready"
#define MENU_MAIN_APP_LINE2_SECRET "???"
#define APPVERSION_LINE1 "Sei"
#define APPVERSION_LINE2 "v" APPVERSION

#define COIN_DEFAULT_CHAINID "atlantic-2"

#define COIN_MAX_CHAINID_LEN 20u
#define INDEXING_TMP_KEYSIZE 70u
#define INDEXING_TMP_VALUESIZE 70u
#define INDEXING_GROUPING_REF_TYPE_SIZE 70u
#define INDEXING_GROUPING_REF_FROM_SIZE 70u

#define COIN_DEFAULT_DENOM_FACTOR 6u
#define COIN_DEFAULT_DENOM_TRIMMING 6u

#define COIN_DEFAULT_DENOM_BASE "sei"
#define COIN_DEFAULT_DENOM_REPR "SEI"

// Coin denoms may be up to 128 characters long
// https://github.com/cosmos/cosmos-sdk/blob/master/types/coin.go#L780
// https://github.com/cosmos/ibc-go/blob/main/docs/architecture/adr-001-coin-source-tracing.md
#define COIN_DENOM_MAXSIZE 129
#define COIN_AMOUNT_MAXSIZE 50

#ifdef __cplusplus
}
#endif
