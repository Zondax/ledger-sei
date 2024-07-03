/*******************************************************************************
 *   (c) 2018, 2019 Zondax GmbH
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

#include <parser_common.h>
#include <stdint.h>

#include "coin.h"
#include "parser_impl.h"
#include "parser_txdef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NUM_REQUIRED_ROOT_PAGES 7

typedef enum {
    root_item_chain_id = 0,
    root_item_account_number,
    root_item_sequence,
    root_item_msgs,
    root_item_memo,
    root_item_fee,
    root_item_tip,
} root_item_e;

typedef struct {
    bool root_item_start_token_valid[NUM_REQUIRED_ROOT_PAGES];
    // token where the root_item starts (negative for non-existing)
    uint16_t root_item_start_token_idx[NUM_REQUIRED_ROOT_PAGES];

    // total items
    uint16_t total_item_count;
    // number of items the root_item contains
    uint8_t root_item_number_subitems[NUM_REQUIRED_ROOT_PAGES];

    uint8_t is_default_chain;
} display_cache_t;

parser_error_t parser_is_expert_mode_or_not_default_chainid(bool *expert_or_default);

const char *get_required_root_item(root_item_e i);

parser_error_t parser_display_query(uint16_t displayIdx, char *outKey, uint16_t outKeyLen, uint16_t *ret_value_token_index);

parser_error_t parser_display_numItems(uint8_t *num_items);

parser_error_t parser_display_make_friendly();

parser_error_t parser_formatAmount(uint16_t amountToken, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                   uint8_t *pageCount);

bool parser_isAmount(char *key);
#ifdef __cplusplus
}
#endif
