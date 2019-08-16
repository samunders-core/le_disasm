#ifndef SRC_DIS_INFO_H_
#define SRC_DIS_INFO_H_

#include <dis-asm.h>

extern "C" int print_insn_i386_att (bfd_vma pc, disassemble_info *info);

#include "insn.h"

class DisInfo : disassemble_info {
	static void callbackPrintAddress(bfd_vma address, disassemble_info *info) {
		info->fprintf_func(info->stream, "0x00%lx", address);
		((Insn *) info->stream)->memoryAddress = address;
	}
public:
	DisInfo(unsigned long machine = bfd_mach_i386_i386) {
		init_disassemble_info(this, NULL, &Insn::callbackResetTypeAndText);
		mach = machine;
		print_address_func = callbackPrintAddress;
	}

	void disassemble(uint32_t addr, const void *data, size_t length, Insn &insn) {
		buffer = (bfd_byte *) data;
		buffer_length = length;
		buffer_vma = addr;
		stream = &insn;

		insn.reset(mach == bfd_mach_i386_i8086 ? Insn::mode_16bit : Insn::mode_32bit);

		int size = print_insn_i386_att(addr, this);
		if (size < 0) {	// FIXME: dump arguments to error
			throw Error() << "Failed to disassemble instruction";
		}
		insn.setSize(size);
		if (size > 0) {
			insn.setTargetAndType(addr, data);
		}
	}

	void setMachineType(unsigned long machine) {
		if(machine != bfd_mach_i386_i386 && machine != bfd_mach_i386_i8086) {
			throw Error() << "Only 16-bit or 32-bit x86 machine types are supported";
		}

		mach = machine;
	}
};

#endif /* SRC_DIS_INFO_H_ */
