#ifndef SRC_REGIONS_H_
#define SRC_REGIONS_H_

#include "le/object_header.h"
#include "region.h"

struct Regions {
	std::map<uint32_t, Region> regions;
	std::map<uint32_t, Type> labelTypes;

	Regions(std::vector<ObjectHeader> &objects) {
		for (size_t n = 0; n < objects.size(); ++n) {
			ObjectHeader &ohdr = objects[n];
			Type type = ohdr.isExecutable() ? UNKNOWN : DATA;
			printAddress(std::cerr, ohdr.base_address, "Creating Region(0x") << ", " << std::dec << ohdr.virtual_size << ", " << type << ")" << std::endl;
			regions[ohdr.base_address] = Region(ohdr.base_address,
					ohdr.virtual_size, type,
					ohdr.isDefaultObjectBitness32Bit() ?
							Region::DEFAULT_BITNESS_32BIT :
							Region::DEFAULT_BITNESS_16BIT);
			if (!ohdr.isExecutable()) {
				labelTypes[ohdr.base_address] = type;
			}	// else no automatic label for lowest .text address
		}
	}

	Region *regionContaining(uint32_t address) {
		std::map<uint32_t, Region>::iterator itr = regions.lower_bound(address);
		if (regions.end() != itr) {
			if (itr->first == address) {
				return &itr->second;
			} else if (regions.begin() == itr) {
				return NULL;
			}
		}
		if (regions.empty()) {
			return NULL;
		}
		--itr;
		return itr->second.contains_address(address) ? &itr->second : NULL;
	}

	void splitInsert(Region &parent, const Region &reg) {
		assert(parent.contains_address(reg.get_address()));
		assert(parent.contains_address(reg.get_end_address() - 1));

		FlagsRestorer _(std::cerr);
		Region next(reg.get_end_address(), parent.get_end_address() - reg.get_end_address(), parent.get_type(), parent.get_default_bitness());
		std::cerr << parent << " split to ";

		if (reg.get_address() != parent.get_address()) {
			parent.size = reg.get_address() - parent.get_address();
			regions[reg.get_address()] = reg;
			std::cerr << parent << ", " << reg;
		} else {
			parent = reg;
			std::cerr << parent;
		}

		if (next.size > 0) {
			regions[reg.get_end_address()] = next;
			std::cerr << ", " << next;
		}
		std::cerr << std::endl;

		check_merge_regions(reg.get_address());
	}

	Region *nextRegion(const Region &reg) {
		std::map<uint32_t, Region>::iterator itr = regions.upper_bound(reg.get_address());
		return regions.end() != itr ? &itr->second : NULL;
	}
private:
	Region *previousRegion(const Region &reg) {
		for (std::map<uint32_t, Region>::iterator itr = regions.lower_bound(reg.get_address()); regions.begin() != itr;) {
			--itr;
			return &itr->second;
		}
		return NULL;
	}

	void check_merge_regions(uint32_t address) {
		Region &reg = regions[address];
		Region *merged = attemptMerge(previousRegion(reg), &reg);
		attemptMerge(merged, nextRegion(*merged));
	}

	Region *attemptMerge(Region *prev, Region *next) {
		if (prev != NULL and next != NULL
				and prev->get_type() == next->get_type()
				and prev->get_end_address() == next->get_address()
				and prev->get_default_bitness() == next->get_default_bitness()) {
			std::cerr << "Combining " << *prev << " and " << *next << std::endl;
			prev->size += next->size;
			regions.erase(next->get_address());
			return prev;
		}
		return next;
	}
};

#endif /* SRC_REGIONS_H_ */
