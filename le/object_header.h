#ifndef OBJECT_HEADER_H
#define OBJECT_HEADER_H

#include <istream>

#include "../little_endian.h"

struct ObjectHeader {

    enum {
        READABLE = 1 << 0,
        WRITABLE = 1 << 1,
        EXECUTABLE = 1 << 2,
        RESOURCE = 1 << 3,
        DISCARDABLE = 1 << 4,
        SHARED = 1 << 5,
        PRELOADED = 1 << 6,
        INVALID = 1 << 7
    };

    uint32_t virtual_size; /* 00h */
    uint32_t base_address; /* 04h */
    uint32_t flags; /* 08h */
    uint32_t first_page_index; /* 0Ch */
    uint32_t page_count; /* 10h */
    uint32_t reserved; /* 14h */

    void readFrom(std::istream &is) {
        read_le(is, virtual_size);
        read_le(is, base_address);
        read_le(is, flags);
        read_le(is, first_page_index);
        read_le(is, page_count);
        read_le(is, reserved);
        --first_page_index;
    }

    bool isExecutable() const {
    	return (flags & EXECUTABLE) != 0;
    }
};

#endif /* OBJECT_HEADER_H */

