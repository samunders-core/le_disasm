#ifndef SRC_LE_IMAGE_H_
#define SRC_LE_IMAGE_H_

#include <map>

#include "../error.h"
#include "image_object.h"
#include "lin_ex.h"

struct Image {
	std::vector<ImageObject> objects;

	const ImageObject &objectAt(uint32_t address) const {
		for (size_t n = 0; n < objects.size(); ++n) {
			const ImageObject &obj = objects[n];
			if (obj.base_address <= address and address < obj.base_address + obj.data.size()) {
				return obj;
			}
		}
		throw Error() << "BUG: address out of image range: 0x" << std::setfill('0') << std::setw(6) << std::hex << std::noshowbase << address;
	}

	void loadObjectData(std::istream &is, LinearExecutable &lx, std::vector<uint8_t> &data, Header &hdr, ObjectHeader &ohdr) {
		size_t data_off = 0, page_end = std::min<size_t>(ohdr.first_page_index + ohdr.page_count, hdr.page_count);
		for (size_t page_idx = ohdr.first_page_index; page_idx < page_end; ++page_idx) {
			size_t size = std::min<size_t>(ohdr.virtual_size - data_off, (page_idx + 1 < hdr.page_count) ? hdr.page_size : hdr.last_page_size);
			is.seekg(lx.offsetOfPageInFile(page_idx));
			if (!is.read((char *) &data.front() + data_off, size).good()) {
				throw Error() << "EOF";
			}
			data_off += size;
		}
	}

	void applyFixups(std::map<uint32_t/*offset*/, uint32_t/*address*/> &fixups, std::vector<uint8_t> &data) {
		for (std::map<uint32_t, uint32_t>::iterator itr = fixups.begin(); itr != fixups.end(); ++itr) {
			if (itr->first + 4 >= data.size()) {
				throw Error() << "Fixup points outside object boundaries";
			}
			void *ptr = &data.front() + itr->first;
			if (itr->second < 256) {
				write_le<uint16_t>(ptr, itr->second);
			} else {
				write_le<uint32_t>(ptr, itr->second);
			}
		}
	}

	Image(std::istream &is, LinearExecutable &lx) {
		std::vector<uint8_t> data;
		objects.resize(lx.objects.size());
		for (size_t oi = 0; oi < lx.objects.size(); ++oi) {
			ObjectHeader &ohdr = lx.objects[oi];
			data.clear();
			data.resize(ohdr.virtual_size);
			loadObjectData(is, lx, data, lx.header, ohdr);
			applyFixups(lx.fixups[oi], data);
			objects[oi].init(oi, ohdr.base_address, ohdr.isExecutable(), data);
		}
	}
};

#endif /* SRC_LE_IMAGE_H_ */
