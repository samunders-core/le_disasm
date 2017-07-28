#ifndef SRC_TYPE_H_
#define SRC_TYPE_H_

#include "flags_restorer.h"

std::ostream &printAddress(std::ostream &os, uint32_t address, const char *prefix = "0x") {
	FlagsRestorer _(os);
	return os << prefix << std::setfill('0') << std::setw(6) << std::hex << std::noshowbase << address;
}

enum Type {
	UNKNOWN,	// region
	CODE, 		// region
	DATA, 		// region, label
	SWITCH, 	// region, label
	JUMP, 		// label
	FUNCTION,	// label
	CASE,		// label
	FUNC_GUESS	// label; either callback or data in code segment
};

#endif /* SRC_TYPE_H_ */
