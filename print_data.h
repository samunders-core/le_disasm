#ifndef LE_DISASM_PRINT_DATA_H_
#define LE_DISASM_PRINT_DATA_H_

static int getIndent(Type type) {
    if (JUMP == type || CASE == type) {
        return 1;
    } else if (FUNCTION == type || FUNC_GUESS == type) {
        std::cout << "\n\n";
        //		print_separator();
    } else if (SWITCH == type) {
        std::cout << '\n';
    }
    return 0;
}

static std::ostream &printTypedAddress(std::ostream &os, uint32_t address, Type type) {
    switch (type) {
        case FUNCTION:
            return printAddress(os, address, "_") << "_func";
        case FUNC_GUESS:
            return printAddress(os, address, "_") << "_func";  //"_funcGuess";
        case JUMP:
            return printAddress(os, address, "_") << "_jump";
        case DATA:
            return printAddress(os, address, "_") << "_data";
        case SWITCH:
            return printAddress(os, address, "_") << "_switch";
        case CASE:
            return printAddress(os, address, "_") << "_case";
        default:
            return printAddress(os, address, "_") << "_unknown";
    }
}

std::ostream &printLabel(uint32_t address, Type type, char const *prefix = "") {
    for (int indent = getIndent(type); indent-- > 0; std::cout << '\t')
        ;
    printTypedAddress(std::cout << prefix, address, type) << ":";
    //	TODO: if (!lab->get_name().empty()) {
    //		std::cout << "\t/* " << lab->get_address() << " */";
    //	}
    return std::cout;
}

static bool data_is_address(const ImageObject &obj, uint32_t addr, size_t len, LinearExecutable &lx) {
    if (len >= 4) {
        const std::map<uint32_t, uint32_t> &fups = lx.fixups[obj.index()];
        return fups.find(addr - obj.base_address()) != fups.end();
    }
    return false;
}

static bool data_is_zeros(const ImageObject &obj, uint32_t addr, size_t len, size_t &rlen) {
    size_t x;
    const uint8_t *data = obj.get_data_at(addr);

    for (x = 0; x < len; x++) {
        if (data[x] != 0) {
            break;
        }
    }

    if (x < 4) {
        return false;
    }
    rlen = x;
    return true;
}

static bool data_is_string(const ImageObject &obj, uint32_t addr, size_t len, size_t &rlen, bool &zero_terminated) {
    size_t x;
    const uint8_t *data = obj.get_data_at(addr);

    for (x = 0; x < len; x++) {
        if ((data[x] < 0x20 or data[x] >= 0x7f) and not(data[x] == '\t' or data[x] == '\n' or data[x] == '\r')) {
            break;
        }
    }

    if (x < 4) {
        return false;
    }

    if (x < len and data[x] == 0) {
        zero_terminated = true;
        x += 1;
    } else {
        zero_terminated = false;
    }
    rlen = x;
    return true;
}

static void print_escaped_string(const uint8_t *data, size_t len) {
    size_t n;

    for (n = 0; n < len; n++) {
        if (data[n] == '\t')
            std::cout << "\\t";
        else if (data[n] == '\r')
            std::cout << "\\r";
        else if (data[n] == '\n')
            std::cout << "\\n";
        else if (data[n] == '\\')
            std::cout << "\\\\";
        else if (data[n] == '"')
            std::cout << "\\\"";
        else
            std::cout << (char)data[n];
    }
}

void completeStringQuoting(int &bytes_in_line, int resetTo = 0) {
    if (bytes_in_line > 0) {
        std::cout << "\"\n";
        bytes_in_line = resetTo;
    }
}

static size_t getLen(const Region &reg, const ImageObject &obj, Analyzer &anal,
                     std::map<uint32_t /*offset*/, uint32_t /*address*/> &fups,
                     std::map<uint32_t, uint32_t>::const_iterator &itr, uint32_t addr) {
    size_t len = reg.end_address() - addr;

    std::map<uint32_t, Type>::iterator label = anal.regions.labelTypes.upper_bound(addr);
    if (anal.regions.labelTypes.end() != label) {
        len = std::min<size_t>(len, label->first - addr);
    }

    while (fups.end() != itr and itr->first <= addr - obj.base_address()) {
        ++itr;
    }

    if (itr != fups.end()) {
        len = std::min<size_t>(len, itr->first - (addr - obj.base_address()));
    }
    return len;
}

static void printDataAfterFixup(const ImageObject &obj, LinearExecutable &lx, Analyzer &anal, uint32_t &addr,
                                size_t len, int &bytes_in_line) {
    size_t size;
    bool zt;
    while (len > 0) {
        if (data_is_address(obj, addr, len, lx)) {
            completeStringQuoting(bytes_in_line);
            uint32_t value = read_le<uint32_t>(obj.get_data_at(addr));
            printTypedAddress(std::cout << "\t\t.long   ", value, anal.regions.labelTypes[value]) << std::endl;

            addr += 4;
            len -= 4;
        } else if (data_is_zeros(obj, addr, len, size)) {
            completeStringQuoting(bytes_in_line);

            std::cout << "\t\t.fill   0x" << std::hex << size << std::endl;
            addr += size;
            len -= size;
        } else if (data_is_string(obj, addr, len, size, zt)) {
            completeStringQuoting(bytes_in_line);

            if (zt) {
                std::cout << "\t\t.string \"";
            } else {
                std::cout << "\t\t.ascii   \"";
            }
            print_escaped_string(obj.get_data_at(addr), size - zt);

            std::cout << "\"\n";

            addr += size;
            len -= size;
        } else {
            char buffer[8];

            if (bytes_in_line == 0) std::cout << "\t\t.ascii  \"";

            snprintf(buffer, sizeof(buffer), "\\x%02x", *obj.get_data_at(addr));
            std::cout << buffer;

            bytes_in_line += 1;

            if (bytes_in_line == 8) {
                std::cout << "\"\n";
                bytes_in_line = 0;
            }

            addr++;
            len--;
        }
    }
}

void printDataTypeRegion(const Region &reg, const ImageObject &obj, LinearExecutable &lx, Image &img, Analyzer &anal) {
    int bytes_in_line = 0;
    uint32_t addr = reg.address();
    std::map<uint32_t /*offset*/, uint32_t /*address*/> &fups = lx.fixups[obj.index()];
    for (std::map<uint32_t, uint32_t>::const_iterator itr = fups.begin(); addr < reg.end_address();) {
        std::map<uint32_t, Type>::iterator label = anal.regions.labelTypes.find(addr);
        if (anal.regions.labelTypes.end() != label) {
            completeStringQuoting(bytes_in_line);
            std::cout << std::endl;

            printLabel(addr, DATA) << std::endl; /*<< stringNameFromValue(FIXME: too late to do it here,
                                                    printTypedAddress() needs to do the same) */
        }
        size_t len = getLen(reg, obj, anal, fups, itr, addr);
        printDataAfterFixup(obj, lx, anal, addr, len, bytes_in_line);
    }
    completeStringQuoting(bytes_in_line, bytes_in_line);
}

#endif /* LE_DISASM_PRINT_DATA_H_ */
