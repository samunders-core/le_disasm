#ifndef HEADER_H
#define HEADER_H

#include "../error.h"
#include "../little_endian.h"

struct Header {
    /* "LE" signature comes before the header data */
	uint8_t byte_order; /* 02h */
	uint8_t word_order; /* 03h */
    uint32_t format_version; /* 04h */
    uint16_t cpu_type; /* 08h */
    uint16_t os_type; /* 0Ah */
    uint32_t module_version; /* 0Ch */
    uint32_t module_flags; /* 10h */
    uint32_t page_count; /* 14h */
    uint32_t eip_object_index; /* 18h */
    uint32_t eip_offset; /* 1Ch */
    uint32_t esp_object_index; /* 20h */
    uint32_t esp_offset; /* 24h */
    uint32_t page_size; /* 28h */
    uint32_t last_page_size; /* 2Ch */
    uint32_t fixup_section_size; /* 30h */
    uint32_t fixup_section_check_sum; /* 34h */
    uint32_t loader_section_size; /* 38h */
    uint32_t loader_section_check_sum; /* 3Ch */
    uint32_t object_table_offset; /* 40h */
    uint32_t object_count; /* 44h */
    uint32_t object_page_table_offset; /* 48h */
    uint32_t object_iterated_pages_offset; /* 4Ch */
    uint32_t resource_table_offset; /* 50h */
    uint32_t resource_entry_count; /* 54h */
    uint32_t resident_name_table_offset; /* 58h */
    uint32_t entry_table_offset; /* 5Ch */
    uint32_t module_directives_offset; /* 60h */
    uint32_t module_directives_count; /* 64h */
    uint32_t fixup_page_table_offset; /* 68h */
    uint32_t fixup_record_table_offset; /* 6Ch */
    uint32_t import_module_name_table_offset; /* 70h */
    uint32_t import_module_name_entry_count; /* 74h */
    uint32_t import_procedure_name_table_offset; /* 78h */
    uint32_t per_page_check_sum_table_offset; /* 7Ch */
    uint32_t data_pages_offset; /* 80h */
    uint32_t preload_pages_count; /* 84h */
    uint32_t non_resident_name_table_offset; /* 88h */
    uint32_t non_resident_name_entry_count; /* 8Ch */
    uint32_t non_resident_name_table_check_sum; /* 90h */
    uint32_t auto_data_segment_object_index; /* 94h */
    uint32_t debug_info_offset; /* 98h */
    uint32_t debug_info_size; /* 9Ch */
    uint32_t instance_pages_count; /* A0h */
    uint32_t instance_pages_demand_count; /* A4h */
    uint32_t heap_size; /* A8h */
    
    void throwOnInvalidSignature(std::istream &is, uint32_t &header_offset) {
        char id[3] = {"??"};
        is.seekg(0);
        is.read(id, 2);
        if (strcmp(id, "MZ") && strcmp(id, "LE") && strcmp(id, "LX")) {
            throw Error() << "Invalid MZ signature: " << id;
        } else if (!strcmp(id, "MZ")) {
            is.seekg(0x18);
            uint8_t byte;
            read_le(is, byte);
            if (byte < 0x40) {
            	throw Error() << "Not a LE executable";
            }
            is.seekg(0x3c);
            read_le(is, header_offset);
            is.seekg(header_offset);
            is.read(id, 2);
            if (strcmp(id, "LE")) {
            	throw Error() << "Invalid LE signature: " << id;
            }
        }
    }
    
    Header(std::istream &is, uint32_t &header_offset) {
        throwOnInvalidSignature(is, header_offset);
        read_le(is, byte_order);
        if (byte_order != 0) {
        	throw Error() << "Only LITTLE_ENDIAN byte order supported: " << byte_order;
        }
        read_le(is, word_order);
        if (word_order != 0) {
        	throw Error() << "Only LITTLE_ENDIAN word order supported: " << word_order;
        }
        read_le(is, format_version);
        if (format_version > 0) {
        	throw Error() << "Unknown LE format version: " << format_version;
        }
        read_le(is, cpu_type);
        read_le(is, os_type);
        read_le(is, module_version);
        read_le(is, module_flags);
        read_le(is, page_count);
        read_le(is, eip_object_index);
        read_le(is, eip_offset);
        read_le(is, esp_object_index);
        read_le(is, esp_offset);
        read_le(is, page_size);
        read_le(is, last_page_size);
        read_le(is, fixup_section_size);
        read_le(is, fixup_section_check_sum);
        read_le(is, loader_section_size);
        read_le(is, loader_section_check_sum);
        read_le(is, object_table_offset);
        read_le(is, object_count);
        read_le(is, object_page_table_offset);
        read_le(is, object_iterated_pages_offset);
        read_le(is, resource_table_offset);
        read_le(is, resource_entry_count);
        read_le(is, resident_name_table_offset);
        read_le(is, entry_table_offset);
        read_le(is, module_directives_offset);
        read_le(is, module_directives_count);
        read_le(is, fixup_page_table_offset);
        read_le(is, fixup_record_table_offset);
        read_le(is, import_module_name_table_offset);
        read_le(is, import_module_name_entry_count);
        read_le(is, import_procedure_name_table_offset);
        read_le(is, per_page_check_sum_table_offset);
        read_le(is, data_pages_offset);
        read_le(is, preload_pages_count);
        read_le(is, non_resident_name_table_offset);
        read_le(is, non_resident_name_entry_count);
        read_le(is, non_resident_name_table_check_sum);
        read_le(is, auto_data_segment_object_index);
        read_le(is, debug_info_offset);
        read_le(is, debug_info_size);
        read_le(is, instance_pages_count);
        read_le(is, instance_pages_demand_count);
        read_le(is, heap_size);
        --eip_object_index;
        --esp_object_index;
    }
};

#endif /* HEADER_H */

