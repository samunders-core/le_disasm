#ifndef OBJECT_HEADER_H
#define OBJECT_HEADER_H

#include <istream>

#include "../little_endian.h"

struct ObjectHeader {

    enum {
        READABLE = 1 << 0, /* 0001h = Readable Object */
        WRITABLE = 1 << 1, /* 0002h = Writable Object */
        EXECUTABLE = 1 << 2, /* 0004h = Executable Object */
        RESOURCE = 1 << 3, /* 0008h = Resource Object */
        DISCARDABLE = 1 << 4, /* 0010h = Discardable Object */
        SHARED = 1 << 5, /* 0020h = Object is Shared */
        PRELOADED = 1 << 6, /* 0040h = Object has Preload Pages */
        INVALID = 1 << 7, /* 0080h = Object has Invalid Pages */
		ZERO_FILL = 1 << 8, /* 0100h = Object has Zero Filled Pages */
		ALIAS_REQUIRED = 1 << 12, /* 1000h = 16:16 Alias Required */
		BIG_DEFAULT = 1 << 13 /* 2000h = Big/Default Bit Setting */
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

    bool isDefaultObjectBitness32Bit() const {
    	return  (flags & BIG_DEFAULT) != 0;
    }
};

#endif /* OBJECT_HEADER_H */

