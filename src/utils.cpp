#include <cstdio> // testing
#include <vector>
#include <set>
#include <cctype>

#include "utils.h"

#include <algorithm>

std::string random_mac_address(std::string prefix)
{
    std::string mac = prefix;
    prefix.erase(std::remove(prefix.begin(), prefix.end(), ':'), prefix.end());
    const char* digits = "0123456789ABCDEF";
    for (short i=prefix.length()/2; i < 6; i++)
    {
        short tp = rand() % 256;
        std::string octet = std::string(1, digits[tp / 16]) + std::string(1, digits[tp % 16]);
        mac.append(":" + octet);
    }
    return mac;
}

void print_hex_memory(void *mem, const int len) {
    int i;
    unsigned char *p = (unsigned char *)mem;
    for (i=0;i<len;i++) {
        if ((i%16==0) && i) printf("\n");
        printf("%02x ", p[i]);
    }
    printf("\n");
}

bool is_bijective(std::map<std::string, std::string> &m)
{
    std::vector<std::string> values{};
    std::set<std::string> unique_values{};
    for (auto const& x : m)
    {
        values.push_back(x.second);
        unique_values.insert(x.second);
    }
    return values.size() == unique_values.size();
}

std::vector<uint8_t> buffered_data(const std::vector<std::vector<uint8_t>>& buffered_segments)
{
    std::vector<uint8_t> buffered_data{};
    for (auto &segment :buffered_segments)
        buffered_data.insert(std::end(buffered_data), std::begin(segment), std::end(segment));
    return buffered_data;
}

int isValidMacAddress(const char* mac) {
    int i = 0;
    int s = 0;

    while (*mac) {
        if (isxdigit(*mac)) {
            i++;
        }
        else if (*mac == ':' || *mac == '-') {

            if (i == 0 || i / 2 - 1 != s)
                break;

            ++s;
        }
        else {
            s = -1;
        }


        ++mac;
    }

    return (i == 12 && (s == 5 || s == 0));
}

std::vector<std::string> split(std::string str,std::string sep)
{
    char* cstr=const_cast<char*>(str.c_str());
    char* current;
    std::vector<std::string> arr;
    current=strtok(cstr,sep.c_str());
    while(current!=NULL){
        arr.push_back(current);
        current=strtok(NULL,sep.c_str());
    }
    return arr;
}