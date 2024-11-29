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

#include <hexutils.h>
#include <json/json.h>
#include <parser_txdef.h>

#include <fstream>
#include <iostream>

#include "app_mode.h"
#include "expected_output.h"
#include "gmock/gmock.h"
#include "parser.h"
#include "testcases.h"
#include "utils/common.h"

using ::testing::TestWithParam;

class JsonTestsA : public ::testing::TestWithParam<testcase_t> {
   public:
    struct PrintToStringParamName {
        template <class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << p.index << "_" << p.name;
            return ss.str();
        }
    };
};

// Retrieve testcases from json file
std::vector<testcase_t> GetJsonTestCases(std::string jsonFile) {
    auto answer = std::vector<testcase_t>();

    const Json::CharReaderBuilder builder;
    Json::Value obj;

    const std::string fullPathJsonFile = std::string(TESTVECTORS_DIR) + jsonFile;

    std::ifstream inFile(fullPathJsonFile);
    if (!inFile.is_open()) {
        return answer;
    }

    // Retrieve all test cases
    JSONCPP_STRING errs;
    Json::parseFromStream(builder, inFile, &obj, &errs);
    std::cout << "Number of testcases: " << obj.size() << std::endl;

    for (int i = 0; i < obj.size(); i++) {
        auto outputs = std::vector<std::string>();
        for (auto s : obj[i]["output"]) {
            outputs.push_back(s.asString());
        }

        auto outputs_expert = std::vector<std::string>();
        for (auto s : obj[i]["output_expert"]) {
            outputs_expert.push_back(s.asString());
        }

        answer.push_back(testcase_t{obj[i]["index"].asUInt64(), obj[i]["name"].asString(), obj[i]["blob"].asString(),
                                    outputs, outputs_expert});
    }

    return answer;
}

std::string CleanTestname(std::string s) {
    s.erase(remove_if(s.begin(), s.end(),
                      [](char v) -> bool {
                          return v == ':' || v == ' ' || v == '/' || v == '-' || v == '.' || v == '_' || v == '#';
                      }),
            s.end());
    return s;
}

// Retrieve testcases from json file
template <typename Generator>
std::vector<testcase_t> GetEVMJsonTestCases(const std::string &jsonFile, Generator gen_ui_output) {
    auto answer = std::vector<testcase_t>();

    const Json::CharReaderBuilder builder;
    Json::Value obj;

    const std::string fullPathJsonFile = std::string(TESTVECTORS_DIR) + jsonFile;

    std::ifstream inFile(fullPathJsonFile);
    if (!inFile.is_open()) {
        return answer;
    }

    // Retrieve all test cases
    JSONCPP_STRING errs;
    Json::parseFromStream(builder, inFile, &obj, &errs);
    std::cout << "Number of testcases: " << obj.size() << std::endl;

    for (auto &i : obj) {
        // auto outputs = GenerateExpectedUIOutput(i, false);
        // auto outputs_expert = GenerateExpectedUIOutput(i, true);
        auto outputs = gen_ui_output(i, false);
        auto outputs_expert = gen_ui_output(i, true);

        auto name = CleanTestname(i["description"].asString());

        answer.push_back(testcase_t{answer.size() + 1, name, i["encoded_tx_hex"].asString(), outputs, outputs_expert});
    }

    return answer;
}

void check_testcase(const testcase_t &tc, bool expert_mode, bool is_eth) {
    app_mode_set_expert(expert_mode);

    parser_error_t err;
    parser_context_t ctx;

    uint8_t buffer[5000];
    uint16_t bufferLen = parseHexString(buffer, sizeof(buffer), tc.blob.c_str());

    if (is_eth) {
        err = parser_parse_eth(&ctx, buffer, bufferLen);
    } else {
        err = parser_parse(&ctx, buffer, bufferLen);
    }
    ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);

    auto output = dumpUI(&ctx, 39, 39, is_eth);

    std::cout << std::endl;
    for (const auto &i : output) {
        std::cout << i << std::endl;
    }
    std::cout << std::endl << std::endl;

    std::vector<std::string> expected = app_mode_expert() ? tc.expected_expert : tc.expected;

    EXPECT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); i++) {
        if (i < output.size()) {
            EXPECT_THAT(output[i], testing::Eq(expected[i]));
        }
    }
}

class VerifyEvmTransactions : public JsonTestsA {};
class VerifyJSONTransactions : public JsonTestsA {};

INSTANTIATE_TEST_SUITE_P(EVMTransactions, VerifyEvmTransactions,
                         ::testing::ValuesIn(GetEVMJsonTestCases("testvectors/evm.json", EVMGenerateExpectedUIOutput)),
                         JsonTestsA::PrintToStringParamName());

INSTANTIATE_TEST_SUITE_P(JSONTransactions, VerifyJSONTransactions,
                         ::testing::ValuesIn(GetJsonTestCases("testvectors/amino.json")),
                         JsonTestsA::PrintToStringParamName());

TEST_P(VerifyEvmTransactions, CheckUIOutput_CurrentTX_Normal) { check_testcase(GetParam(), false, true); }
TEST_P(VerifyJSONTransactions, CheckUIOutput_CurrentTX_Normal) { check_testcase(GetParam(), false, false); }
TEST_P(VerifyJSONTransactions, CheckUIOutput_CurrentTX_Expert) { check_testcase(GetParam(), true, false); }
