#ifndef LE_DISASM_LE_OBJECT_PAGE_HEADER_H_
#define LE_DISASM_LE_OBJECT_PAGE_HEADER_H_

#include "../error.h"
#include "../little_endian.h"

struct ObjectPageHeader {
    enum ObjectPageType { LEGAL = 0, ITERATED = 1, INVALID = 2, ZERO_FILLED = 3, LAST = 4 };

    uint16_t first_number; /* 00h */
    uint8_t second_number; /* 02h */
    ObjectPageType type;   /* 03h */

    void readFrom(std::istream &is) {
        read_le(is, first_number);
        read_le(is, second_number);
        uint8_t byte;
        for (read_le(is, byte); byte > 4;) {
            throw Error() << "Invalid object page type: " << byte;
        }
        type = (ObjectPageType)byte;
    }
};

#endif /* LE_DISASM_LE_OBJECT_PAGE_HEADER_H_ */
