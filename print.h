#ifndef SRC_PRINT_H_
#define SRC_PRINT_H_

#include "analyzer.h"
#include "le/image.h"
#include "print_data.h"

static std::string replace_addresses_with_labels(const std::string &str, Image &img, LinearExecutable &lx, Analyzer &anal) {
	std::ostringstream oss;
	size_t n, start;
	uint32_t addr;
	std::string addr_str;
	std::string comment;
	char prefix_symbol;

	/* Many opcodes support displacement in indirect addressing modes.
	 * Example: mov    %edx,-0x10(%ebp) .
	 * Displacement constants are signed literals and should not be misinterpreted
	 * as unsigned fixup addresses.
	 */

	n = str.find ("0x");
	  if (n == std::string::npos)
	    return str;

	start = 0;

	do {
		prefix_symbol = *str.substr(n - sizeof(char), sizeof(char)).c_str();
		oss << str.substr(start, n - start);

		if (n + 2 >= str.length())
			break;

		n += 2;
		start = n;

		while (n < str.length() and isxdigit(str[n]))
			n++;

		addr_str = str.substr(start, n - start);
		addr = strtol(addr_str.c_str(), NULL, 16);
		std::map<uint32_t, Type>::const_iterator lab = anal.regions.labelTypes.find(addr);
		if (prefix_symbol != '-' /* && prefix_symbol != '$' */
				&& anal.regions.labelTypes.end() != lab) {
			printTypedAddress(oss, addr, lab->second);
		} else {
			printAddress(oss, addr);

			if (lx.fixup_addresses.find(addr) != lx.fixup_addresses.end()) {
				img.objectAt(addr);	// throws
				comment = " /* Warning: address points to a valid object/reloc, but no label found */";
			}
		}

		start = n;
		n = str.find("0x", start);
	} while (n != std::string::npos);

	if (start < str.length()) {
		oss << str.substr(start);
	}
	if (!comment.empty()) {
		oss << comment;
	}
	return oss.str();
}

static void print_instruction(Insn &inst, Image &img, LinearExecutable &lx, Analyzer &anal) {
	std::string str;
	std::string::size_type n;

	str = replace_addresses_with_labels(inst.text, img, lx, anal);

	n = str.find("(287 only)");
	if (n != std::string::npos) {
		std::cout << "\t\t/* " << str << " -- ignored */\n";
		return;
	}

	/* Work around buggy libopcodes */
	if (str == "lar    %cx,%ecx") {
		str = "lar    %ecx,%ecx";
	} else if (str == "lsl    %ax,%eax") {
		str = "lsl    %eax,%eax";
	} else if (str == "lea    0x000000(%eax,%eiz,1),%eax") {
		str = "lea    0x000000(%eax),%eax";
	} else if (str == "lea    0x000000(%edx,%eiz,1),%edx") {
		str = "lea    0x000000(%edx),%edx";	// https://www.technovelty.org/arch/the-quickest-way-to-do-nothing.html
	}
	std::cout << "\t\t" << str;

	if (str == "data16" or str == "data32") {
		std::cout << " ";
	} else {
		std::cout << "\n";
	}
}

static void printCodeTypeRegion(const Region &reg, const ImageObject &obj, LinearExecutable &lx, Image &img, Analyzer &anal) {
	DisInfo disasm(obj.bitness == ImageObject::DEFAULT_BITNESS_32BIT ? bfd_mach_i386_i386 : bfd_mach_i386_i8086);
	Insn inst;

	for (uint32_t addr = reg.get_address(); addr < reg.get_end_address();) {
		std::map<uint32_t, Type>::iterator type = anal.regions.labelTypes.find(addr);
		if (anal.regions.labelTypes.end() != type) {
//			if (CASE == type->second) {	// newline makes case not be part of function
				std::cout << std::endl;
//			}
			printLabel(addr, type->second) << std::endl;
		}

		disasm.disassemble(addr, obj.get_data_at(addr), reg.get_end_address() - addr, inst);
		if (anal.regions.labelTypes.end() == type && inst.size > 1) {	// hack for corrupted libraries
			type = anal.regions.labelTypes.find(addr + inst.size / 2);
			if (anal.regions.labelTypes.end() != type) {
				printLabel(addr + inst.size / 2, type->second) << "\t/* WARNING: instructions around this label are incorrect, generated just to workaround corrupted library */" << std::endl;
			}
		}
		print_instruction(inst, img, lx, anal);
		addr += inst.size;
	}
}


static void printSwitchTypeRegion(const Region &reg, const ImageObject &obj, LinearExecutable &lx, Image &img, Analyzer &anal) {
	uint32_t func_addr, addr = reg.get_address();

	/* TODO: limit by relocs */
	printLabel(addr, anal.regions.labelTypes[addr]) << std::endl;
	std::map<uint32_t, Type>::iterator next_label = anal.regions.labelTypes.upper_bound(addr);

	while (addr < reg.get_end_address()) {
		if (anal.regions.labelTypes.end() != next_label and addr == next_label->first) {
			printLabel(addr, next_label->second) << std::endl;
			next_label = anal.regions.labelTypes.upper_bound(addr);
		}

		func_addr = read_le<uint32_t>(obj.get_data_at(addr));

		if (func_addr != 0) {
			if (addr < func_addr) {
				anal.regions.labelTypes[func_addr] = CASE;
			}
			printTypedAddress(std::cout << "\t\t.long   ", func_addr, anal.regions.labelTypes[func_addr]) << std::endl;
		} else {
			std::cout << "\t\t.long   0\n";
		}
		addr += sizeof(uint32_t);
	}
	std::cout << std::endl;
}

static void print_region(const Region &reg, const ImageObject &obj, LinearExecutable &lx, Image &img, Analyzer &anal) {
	void (*printMethods[])(const Region &, const ImageObject &, LinearExecutable &, Image &, Analyzer &) = {NULL, printCodeTypeRegion, printDataTypeRegion, printSwitchTypeRegion};
	if (UNKNOWN < reg.get_type() && reg.get_type() < sizeof(printMethods)/sizeof(printMethods[0])) {
		(*printMethods[reg.get_type()])(reg, obj, lx, img, anal);
	}
	else {
		/* Emit unidentified region data for reference. Hex editors like wxHexEditor
		 * could be used to find and disassemble the rendered raw data that could
		 * help further improve le_disasm analyzer and actual reengineering projects.
		 */
		std::cout << "\n\t\t/* Skipped " << std::dec << reg.size << " bytes of "
				<< (obj.executable ? "executable " : "") << reg.type
				<< " type data at virtual address 0x" << std::setfill('0')
				<< std::setw(8) << std::hex << std::noshowbase
				<< (uint32_t) reg.address << ":";
		const uint8_t * data_pointer = obj.get_data_at(reg.address);
		for (uint8_t index = 0; index < reg.size && data_pointer; ++index) {
			if (index >= 16) {
				std::cout << "\n\t\t * ...";
				break;
			}
			if (index % 8 == 0) {
				std::cout << "\n\t\t *\t";
			}
			std::cout << std::setfill('0') << std::setw(2) << std::hex
					<< std::noshowbase << (uint32_t) data_pointer[index];
		}
		std::cout << "\n\t\t */" << std::endl;
	}
}

static void printChangedSectionType(const Region &reg, Type &section) {
	char sections[][6] = { "bug", ".text", ".data" };
	if (reg.get_type() == DATA) {
		if (section != DATA) {
			std::cout << std::endl << sections[section = DATA] << std::endl;
		}
	} else {
		if (section != CODE) {
			std::cout << std::endl << sections[section = CODE] << std::endl;
		}
	}
}

void print_code(LinearExecutable &lx, Image &img, Analyzer &anal) {
	const Region *prev = NULL;
	const Region *next;
	Type section = CODE;

	Regions &regions = anal.regions;

	std::cerr << "Region count: " << regions.regions.size() << std::endl;

	std::cout << ".code32" << std::endl;
	std::cout << ".text" << std::endl;
	std::cout << ".globl main" << std::endl;
	std::cout << "main:" << std::endl;
	printTypedAddress(std::cout << "\t\tjmp\t", lx.entryPointAddress(), FUNCTION) << std::endl;

	for (std::map<uint32_t, Region>::const_iterator itr = regions.regions.begin(); itr != regions.regions.end(); ++itr) {
		const Region &reg = itr->second;
		const ImageObject &obj = img.objectAt(reg.get_address());

		printChangedSectionType(reg, section);

		print_region(reg, obj, lx, img, anal);

		assert(prev == NULL || prev->get_end_address() <= reg.get_address());

		next = regions.nextRegion(reg);
		if (next == NULL or next->get_address() > reg.get_end_address()) {
			std::map<uint32_t, Type>::iterator type = anal.regions.labelTypes.find(reg.get_end_address());
			if (anal.regions.labelTypes.end() != type) {
				printLabel(reg.get_end_address(), type->second) << std::endl;
			}
		}

		prev = &reg;
	}
}

#endif /* SRC_PRINT_H_ */
