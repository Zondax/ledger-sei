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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json_parser.h"
typedef struct {
    // These are internal values used for tracking the state of the query/search
    uint16_t _item_index_current;

    // maximum json tree level. Beyond this tree depth, key/values are flattened
    uint8_t max_level;

    // maximum tree traversal depth. This limits possible stack overflow issues
    uint8_t max_depth;

    // Index of the item to retrieve
    int16_t item_index;
    // Chunk of the item to retrieve (assuming partitioning based on out_val_len chunks)
    int16_t page_index;

    // These fields (out_*) are where query results are placed
    char *out_key;
    uint16_t out_key_len;
    char *out_val;
    int16_t out_val_len;
} tx_query_t;

typedef struct {
    // Buffer to the original tx blob
    const char *tx;

    // parsed data (tokens, etc.)
    parsed_json_t json;

    // internal flags
    struct {
        bool cache_valid : 1;
        bool msg_type_grouping : 1;           // indicates if msg type grouping is enabled
        bool msg_from_grouping : 1;           // indicates if msg from grouping is enabled
        bool msg_from_grouping_hide_all : 1;  // indicates if msg from grouping should hide all
    } flags;

    // indicates that N identical msg_type fields have been detected
    uint8_t filter_msg_type_count;
    int32_t filter_msg_type_valid_idx;

    // indicates that N identical msg_from fields have been detected
    uint8_t filter_msg_from_count;
    int32_t filter_msg_from_valid_idx;
    const char *own_addr;

    // current tx query
    tx_query_t query;
} parser_tx_t;

#ifdef __cplusplus
}
#endif
