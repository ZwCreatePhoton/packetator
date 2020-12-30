#include <map>
#include <vector>
#include <cstring>

#pragma once
static bool debug_output = false;
static const std::vector<uint8_t> empty_vector{};

bool is_bijective(std::map<std::string, std::string> &);

void print_hex_memory(void *mem, const int len);

std::vector<uint8_t> buffered_data(const std::vector<std::vector<uint8_t>>& buffered_segments);

int isValidMacAddress(const char* mac);

std::vector<std::string> split(std::string str,std::string sep);