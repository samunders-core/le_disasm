#ifndef LE_DISASM_SYMBOL_MAP_H_
#define LE_DISASM_SYMBOL_MAP_H_

#include <iostream>
#include <map>
#include <regex>
#include <string>

#include "type.h"

struct SymbolMap {
    struct Properties final {
        std::string name;
        uint32_t address;
        uint32_t size;
        Type type;

        Properties(uint32_t address_, uint32_t size_, std::string name_, Type type_) {
            address = address_;
            size = size_;
            name = name_;
            type = type_;
        }

        Properties(const Properties &other) { *this = other; }

        Properties(void) {
            address = 0;
            size = 0;
            name = std::string("");
            type = UNKNOWN;
        }
    };

    std::map<uint32_t, SymbolMap::Properties> map;
    std::string file_name;

    std::string getFileName(std::string path) {
        const size_t last_slash_idx = path.find_last_of("\\/");
        if (std::string::npos != last_slash_idx) {
            path.erase(0, last_slash_idx + 1);
        }

        return path;
    }

    SymbolMap(char const *path) {
        std::ifstream is(path, std::ofstream::in);

        if (is.is_open()) {
            file_name = getFileName(std::string(path));

            /* IDA 7.0 Freeware allows to copy and paste the functions list into a text file.
             * The pattern used by the le_disasm map file is compliant to that list.
             *
             * \1 symbol_name	\2 type	\3 start_address	\4 region_size
             */
            const std::regex re("^([^\\s]+)\\s+([^\\s]+)\\s+([0-9a-fA-F]+)\\s+([0-9a-fA-F]+)\\s+[\\s\\S]*$");
            std::smatch m;
            std::string line;

            is.seekg(std::ios::beg);

            while (std::getline(is, line)) {
                if (std::regex_match(line, m, re)) {
                    if (m.size() == 5) {
                        std::string name = m[1];
                        uint32_t address = std::stol(m[3], 0, 16);
                        uint32_t size = std::stol(m[4], 0, 16);

                        if ((name.find("lut_") != std::string::npos) and (size % sizeof(uint32_t) == 0)) {
                            map[address] = Properties(address, size, name, SWITCH);
                        } else if (name.find("sub_") != std::string::npos) {
                            map[address] = Properties(address, size, name, FUNCTION);
                        } else if (name.find("data_") != std::string::npos) {
                            map[address] = Properties(address, size, name, DATA);
                        }
                    }
                }
            }
            is.close();
        }
    }

    std::string findSymbolName(const uint32_t address) {
        return map.count(address) ? map[address].name : std::string("");
    }

    std::string getFileName() { return file_name; }
};

#endif /* LE_DISASM_SYMBOL_MAP_H_ */
