#ifndef FIXUP_H
#define FIXUP_H

#include <istream>
#include <vector>

#include "object_header.h"
#include "../error.h"

class Fixup {
    static uint8_t throwOnInvalidAddressFlags(std::istream &is) {
        uint8_t addr_flags;
        read_le(is, addr_flags);
        if ((addr_flags & 0x20) != 0) {
        	throw Error() << "Fixup lists not supported";
//        } else if ((addr_flags & 0xf) != 0x7) {/* 32-bit offset */
//        	throw Error() << "Unsupported fixup type in 0x" << std::hex << (int) addr_flags;
        }
        return addr_flags;
    }
    
    static uint8_t throwOnInvalidRelocFlags(std::istream &is) {
        uint8_t reloc_flags;
        read_le(is, reloc_flags);
        if ((reloc_flags & 0x3) != 0x0) {/* internal ref */
        	throw Error() << "Unsupported reloc type in 0x" << std::hex << (int) reloc_flags;
        }
        return reloc_flags;
    }
    
    static uint8_t throwOnInvalidObjectIndex(std::istream &is, std::vector<ObjectHeader> objects, uint32_t page_offset) {
        uint8_t obj_index;
        read_le(is, obj_index);
        if (obj_index < 1 || obj_index > objects.size ()) {
        	throw Error() << "Page at offset 0x" << std::hex << page_offset << ": unexpected object index " << std::dec << (int) obj_index;
        }
        return obj_index - 1;
    }

	static int16_t readUpToSourceOffset(std::istream &is, size_t &offset, uint8_t &addr_flags, uint8_t &reloc_flags) {
		addr_flags = throwOnInvalidAddressFlags(is);
		++offset;

		reloc_flags = throwOnInvalidRelocFlags(is);
		++offset;

		int16_t src_off;
		read_le(is, src_off);
		offset += sizeof(int16_t);
		return src_off;
	}

	static uint32_t readDestOffset(std::istream &is, size_t &offset, std::vector<ObjectHeader> objects, uint32_t page_offset, uint8_t addr_flags, uint8_t reloc_flags) {
		uint8_t obj_index = throwOnInvalidObjectIndex(is, objects, page_offset);
		++offset;

		uint32_t dst_off_32;
		if ((reloc_flags & 0x10) != 0) {/* 32-bit offset */
			read_le(is, dst_off_32);
			offset += 4;
		} else if ((addr_flags & 0xf) != 0x2) {/* 16-bit offset */
			uint16_t dst_off_16;
			read_le(is, dst_off_16);
			dst_off_32 = dst_off_16;
			offset += 2;
		} else {
			return obj_index + 1;
		}
		return objects[obj_index].base_address + dst_off_32;
	}
public:
    Fixup(std::istream &is, size_t &offset_, std::vector<ObjectHeader> objects, uint32_t page_offset, uint8_t addr_flags = 0, uint8_t reloc_flags = 0) :
    	offset(page_offset + readUpToSourceOffset(is, offset_, addr_flags, reloc_flags)),
		address(readDestOffset(is, offset_, objects, page_offset, addr_flags, reloc_flags)) {
    }

    const uint32_t offset;
    const uint32_t address;
};

#endif /* FIXUP_H */

