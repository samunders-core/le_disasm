#ifndef LIN_EX_H
#define LIN_EX_H

#include <set>
#include <vector>

#include "fixup.h"
#include "header.h"
#include "object_page_header.h"

struct LinearExecutable {
    Header header;
    std::vector<ObjectHeader> objects;
    std::vector<ObjectPageHeader> object_pages;
    std::vector<std::map<uint32_t/*offset*/, uint32_t/*address*/> > fixups;
    std::set<uint32_t> fixup_addresses;
    
    uint32_t entryPointAddress() {
    	return objects[header.eip_object_index].base_address + header.eip_offset;
    }

    size_t offsetOfPageInFile(size_t index) const {
    	if (index < 0 || object_pages.size() <= index) {
    		return 0;
    	}
    	const ObjectPageHeader &hdr = object_pages[index];
    	return (hdr.first_number + hdr.second_number - 1) * header.page_size + header.data_pages_offset;
    }

    template<typename T>
	void loadTable(std::istream &is, uint32_t count, std::vector<T> &ret) {
		ret.resize(count);
		for (uint32_t n = 0; n < count; ++n) {
			ret[n].readFrom(is);
		}
	}
    
    void loadObjectFixups(std::istream &is, std::vector<uint32_t> &fixup_record_offsets, size_t table_offset, size_t oi) {
        ObjectHeader &obj = objects[oi];
        std::cerr << "Loading fixups for object " << oi << std::endl;
        for (size_t n = obj.first_page_index; n < obj.first_page_index + obj.page_count; ++n) {
            size_t offset = table_offset + fixup_record_offsets[n];
            size_t end = offset + fixup_record_offsets[n + 1] - fixup_record_offsets[n];
            size_t page_offset = (n - obj.first_page_index) * header.page_size;
            for (is.seekg(offset); offset < end; ) {
            	std::cerr << "Loading fixup 0x" << offset << " at page " << std::dec << n << "/" << obj.page_count << ", offset 0x" << std::hex << page_offset << ": ";
                Fixup fixup(is, offset, objects, page_offset);
                fixups[oi][fixup.offset] = fixup.address;
                fixup_addresses.insert(fixup.address);
                std::cerr << "0x" << fixup.offset << " -> 0x" << fixup.address << std::endl;
            }
        }
    }
    
    void loadFixupTable(std::istream &is, std::vector<uint32_t> &fixup_record_offsets, size_t table_offset) {
        fixups.resize(objects.size());
        for (size_t oi = 0; oi < objects.size(); ++oi) {
            loadObjectFixups(is, fixup_record_offsets, table_offset, oi);
        }
    }
    
    LinearExecutable(std::istream &is, uint32_t header_offset = 0) : header(is, header_offset) {
        is.seekg(header_offset + header.object_table_offset);
        loadTable(is, header.object_count, objects);
        
        is.seekg(header_offset + header.object_page_table_offset);
        loadTable(is, header.page_count, object_pages);
        
        std::vector<uint32_t> fixup_record_offsets;
        is.seekg(header_offset + header.fixup_page_table_offset);
        fixup_record_offsets.resize(header.page_count + 1);
        for (size_t n = 0; n <= header.page_count; ++n) {
            read_le(is, fixup_record_offsets[n]);
        }
        
        loadFixupTable(is, fixup_record_offsets, header_offset + header.fixup_record_table_offset);
    }
};

#endif /* LIN_EX_H */

