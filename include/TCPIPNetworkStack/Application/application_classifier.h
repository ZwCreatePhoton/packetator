#include <vector>
#include <cstdint>
#include <regex>

#include "application.h"

#pragma once

const std::regex HTTP_REQUEST_REGEX(R"(^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|BCOPY|BDELETE|BMOVE|BPROPFIND|BPROPATH|COPY|DELETE|LOCK|MKCOL|MOVE|NOTIFY|POLL|PROPFIND|PROPPATCH|SEARCH|SUBSCRIBE|UNLOCK|UNSUBSCRIBE|ACL|BASELINE-CONTROL|BIND|CHECKIN|CHECKOUT|LABEL|LINK|MERGE|MKACTIVITY|MKCALENDAR|MKREDIRECTREF|MKWORKSPACE|ORDERPATCH|PATCH|PRI|REBIND|REPORT|UNBIND|UNCHECKOUT|UNLINK|UPDATE|UPDATEREDIRECTREF|VERSION-CONTROL))");
const std::regex HTTP_RESPONSE_REGEX(R"(^(?:HTTP))");
const std::vector<uint8_t> HTTP_RESPONSE_BYTES = {'H', 'T', 'T', 'P'};

const std::regex FTP_COMMAND_REGEX(R"(^(?:[A-Z][A-Z][A-Z][A-Z]))");
const std::regex FTP_BANNER_REGEX(R"(^(?:220))");

const std::regex SMTP_HELO_REGEX(R"(^(?:HELO|EHLO))");
const std::regex SMTP_BANNER_REGEX(R"(^(?:220))");


// Tries to guess the application protocol
class ApplicationClassifier
{
    public:

        ApplicationClassifier() = delete;

        static Application::Protocol guess(const std::vector<uint8_t> &rx_data, const std::vector<uint8_t> &tx_data);
};
