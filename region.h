#ifndef SRC_REGION_H_
#define SRC_REGION_H_

#include "type.h"

struct Region {
	enum DefaultBitness {
		DEFAULT_BITNESS_32BIT,
		DEFAULT_BITNESS_16BIT
	};

	Region(uint32_t address_, uint32_t size_, Type type_, DefaultBitness bitness_ = DEFAULT_BITNESS_32BIT) {
		address = address_;
		size = size_;
		type = type_;
		bitness = bitness_;
	}

	Region(void) {
		this->address = 0;
		this->size = 0;
		this->type = UNKNOWN;
		this->bitness = DEFAULT_BITNESS_32BIT;
	}

	Region(const Region &other) {
		*this = other;
	}

	uint32_t get_address(void) const {
		return this->address;
	}

	size_t get_end_address(void) const {
		return (this->address + this->size);
	}

	Type get_type(void) const {
		return this->type;
	}

	bool contains_address(uint32_t addr) const {
		return (this->address <= addr and addr < this->address + this->size);
	}

	size_t get_size(void) const {
		return this->size;
	}

	DefaultBitness get_default_bitness(void) const {
		return this->bitness;
	}

	uint32_t address;
	uint32_t size;
	Type type;
	DefaultBitness bitness;
};

std::ostream &operator<<(std::ostream &os, Type type) {
	switch (type) {
	case UNKNOWN:
		return os << "unknown";
	case CODE:
		return os << "code";
	case DATA:
		return os << "data";
	case SWITCH:
		return os << "switch";
	default:
		return os << "(unknown " << type << ")";
	}
}

std::ostream &operator<<(std::ostream &os, const Region &reg) {	// %7s @ 0x%06x[%6d]
	FlagsRestorer _(os);
	return printAddress(os << std::setw(7) << reg.get_type(), reg.get_address(), " @ 0x") << "[" << std::setw(6) << std::setfill(' ') << std::dec << reg.get_size() << "]";
}

#endif /* SRC_REGION_H_ */
