#ifndef LE_DISASM_ANALYZER_H_
#define LE_DISASM_ANALYZER_H_

#include <stdint.h>
#include <cassert>
#include <cctype>
#include <cstdlib>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>

#include "dis_info.h"
#include "le/image.h"
#include "le/lin_ex.h"
#include "regions.h"

struct Analyzer {
    Regions regions;
    std::deque<uint32_t> code_trace_queue;
    Image &image;
    DisInfo disasm;

    Analyzer(LinearExecutable &lx, Image &image_) : regions(image_.objects), image(image_) {}

    void add_code_trace_address(uint32_t addr, Type onlyFunctionOrJump, uint32_t refAddress = 0) {
        this->code_trace_queue.push_back(addr);
        regions.labelTypes[addr] = onlyFunctionOrJump;
        if (refAddress > 0) {
            printAddress(printAddress(std::cerr, refAddress) << " schedules ", addr) << std::endl;
        }
    }

    void trace_code(void) {
        uint32_t address;

        while (!this->code_trace_queue.empty()) {
            address = this->code_trace_queue.front();
            this->code_trace_queue.pop_front();
            this->trace_code_at_address(address);
        }
    }

    void trace_code_at_address(uint32_t start_addr) {
        Region *reg = regions.regionContaining(start_addr);
        if (reg == NULL) {
            printAddress(std::cerr, start_addr, "Warning: Tried to trace code at an unmapped address: 0x") << std::endl;
            return;
        }

        const ImageObject &obj = image.objectAt(start_addr);
        if (reg->type() == CODE || reg->type() == DATA) { /* already traced */
            if (reg->type() == CODE) {
                std::map<uint32_t, Type>::iterator label = regions.labelTypes.find(start_addr);
                if (regions.labelTypes.end() != label && label->second == FUNC_GUESS) {
                    Insn inst(std::addressof(obj));
                    disasm.disassemble(start_addr, obj.get_data_at(start_addr), reg->end_address() - start_addr, inst);
                    label->second = (strstr(inst.text, "push") == inst.text ||
                                     (strstr(inst.text, "sub") == inst.text && strstr(inst.text, ",%esp") != NULL))
                                        ? FUNCTION
                                        : JUMP;
                }
            }
            return;
        } else if (regions.labelTypes.end() == regions.labelTypes.find(start_addr)) {
            printAddress(std::cerr, start_addr, "Warning: Tracing code without label: 0x") << std::endl;
            // FIXME: generate label
        }

        Type type = CODE;
        uint32_t nopCount = 0;
        uint32_t addr = traceRegionUntilAnyJump(reg, start_addr, obj.get_data_at(0), type, nopCount);
        if (nopCount == (addr - start_addr)) {
            type = DATA;
        }
        if (DATA == type) {
            std::map<uint32_t, Type>::iterator label = regions.labelTypes.find(start_addr);
            if (regions.labelTypes.end() != label) {
                label->second = DATA;
            }
        }
        regions.splitInsert(*reg, Region(start_addr, addr - start_addr, type));
    }

    size_t traceRegionUntilAnyJump(Region *&tracedReg, uint32_t &startAddress, const void *offset, Type &type,
                                   uint32_t &nopCount) {
        uint32_t addr = startAddress;
        for (Insn inst(tracedReg->image_object_pointer()); addr < tracedReg->end_address();) {
            disassemble(addr, tracedReg, inst, (uint8_t *)offset + addr, type);
            for (addr += inst.size; Insn::JUMP == inst.type || Insn::RET == inst.type;) {
                return addr;
            }
            if (DATA != type) {
                char invalids[][6] = {"(bad)", "ss", "gs"};
                for (size_t i = 0; i < sizeof(invalids) / sizeof(invalids[0]); ++i) {
                    if (strstr(inst.text, invalids[i]) == inst.text) {
                        type = DATA;
                        break;
                    }
                }
                if (strstr(inst.text, "nop") == inst.text) {
                    ++nopCount;

                    /* Any FPU instruction-referenced fixup has to be data.
                     *
                     * Note that the FS segment override instruction prefix byte may be applied to disassembled
                     * instructions.
                     * E.g. 0x647Fxx converts to FS JG rel8, which should not be misinterpreted as an FPU instruction.
                     */
                } else if (DATA != type && *inst.text == 'f' && inst.memoryAddress > 0 &&
                           strncmp(inst.text, "fs ", strlen("fs ")) != 0) {
                    Region *reg = regions.regionContaining(inst.memoryAddress);
                    if (reg == NULL) {
                        continue;
                    } else if (reg->type() == UNKNOWN) {
                        if (strstr(inst.text, "t ") != NULL) {
                            regions.splitInsert(*reg, Region(inst.memoryAddress, 10, DATA));
                        } else if (strstr(inst.text, "l ") != NULL) {
                            regions.splitInsert(*reg, Region(inst.memoryAddress, 8, DATA));
                        } else {
                            throw Error() << "0x" << std::hex << addr - inst.size
                                          << ": unsupported FPU operand size in " << inst.text;
                        }
                        if (tracedReg == reg) {
                            tracedReg = regions.regionContaining(inst.memoryAddress + 10);
                        }
                    } else if (reg->type() != DATA) {
                        printAddress(std::cerr, inst.memoryAddress, "Warning: 0x") << " marked as data" << std::endl;
                    }
                    regions.labelTypes[inst.memoryAddress] = DATA;
                } else if (addr - inst.size == startAddress && strstr(inst.text, "mov    $") == inst.text) {
                    uint32_t dataAddress = strtol(&inst.text[strlen("mov    $")], NULL, 16);
                    if (regions.regionContaining(dataAddress) != NULL) {
                        const ImageObject &obj = image.objectAt(dataAddress);
                        if (strncmp("ABNORMAL TERMINATION", (const char *)(obj.get_data_at(dataAddress)),
                                    strlen("ABNORMAL TERMINATION")) == 0) {
                            printAddress(printAddress(std::cerr, startAddress) << ": ___abort signature found at ",
                                         dataAddress)
                                << std::endl;
                            regions.labelTypes[startAddress] = FUNCTION;  // eases further script-based transformation
                        }
                    }
                } else if (inst.bitness() == BITNESS_16BIT and inst.memoryAddress > 0) {
                    /* assume that ds and cs equal segment base in 16 bit mode */
                    uint32_t virtual_address = inst.base_address() + inst.memoryAddress;
                    Region *reg = regions.regionContaining(virtual_address);
                    if (reg and reg->type() == DATA) {
                        regions.labelTypes[virtual_address] = DATA;
                    }
                }
            }
        }
        return addr;
    }

    void disassemble(uint32_t addr, Region *&tracedReg, Insn &inst, const void *data_ptr, Type type) {
        uint32_t end_addr = tracedReg->end_address();
        for (disasm.disassemble(addr, data_ptr, end_addr - addr, inst); inst.memoryAddress == 0 || DATA == type;) {
            return;
        }
        if ((Insn::COND_JUMP == inst.type || Insn::JUMP == inst.type) && strstr(inst.text, "*") == NULL) {
            add_code_trace_address(inst.memoryAddress, JUMP, addr);
        } else if (Insn::CALL == inst.type) {
            add_code_trace_address(inst.memoryAddress, FUNCTION, addr);
        }
    }

    size_t addSwitchAddresses(std::map<uint32_t /*offset*/, uint32_t /*address*/> &fixups, size_t size,
                              const uint8_t *data_ptr, uint32_t offset) {
        size_t count = 0;
        for (size_t off = 0; off + 4 <= size; off += 4, ++count) {
            uint32_t addr = read_le<uint32_t>(data_ptr + off);
            if (addr != 0) {
                if (fixups.find(offset + off) == fixups.end()) {
                    break;
                }
                add_code_trace_address(addr, CASE);
            }
        }
        return count;
    }

    void traceRegionSwitches(LinearExecutable &lx, std::map<uint32_t /*offset*/, uint32_t /*address*/> &fixups,
                             Region &reg, uint32_t address) {
        const ImageObject &obj = image.objectAt(reg.address());
        if (!obj.is_executable()) {
            return;
        }
        size_t size = reg.end_address() - address;
        std::set<uint32_t>::iterator iter = lx.fixup_addresses.upper_bound(address);
        if (lx.fixup_addresses.end() != iter) {
            size = std::min<size_t>(size, *iter - address);
        }
        size_t count = addSwitchAddresses(fixups, size, obj.get_data_at(address), address - obj.base_address());
        if (count > 0) {
            regions.splitInsert(reg, Region(address, sizeof(uint32_t) * count, SWITCH));
            regions.labelTypes[address] = SWITCH;
            trace_code();  // TODO: is returning not enough?
        }
    }

    void traceSwitches(LinearExecutable &lx, std::map<uint32_t /*offset*/, uint32_t /*address*/> &fixups) {
        for (std::map<uint32_t, uint32_t>::const_iterator itr = fixups.begin(); itr != fixups.end(); ++itr) {
            Region *reg = regions.regionContaining(itr->second);
            if (reg == NULL) {
                printAddress(std::cerr, itr->second, "Warning: Removing reloc pointing to unmapped memory at 0x")
                    << std::endl;
                lx.fixup_addresses.erase(itr->second);
                continue;
            } else if (reg->type() == UNKNOWN) {
                traceRegionSwitches(lx, fixups, *reg, itr->second);
            }
        }
    }

    void traceSwitches(LinearExecutable &lx) {
        for (size_t n = 0; n < lx.objects.size(); ++n) {
            traceSwitches(lx, lx.fixups[n]);
        }
    }

    void addAddress(size_t &guess_count, uint32_t address) {
        Type &type = regions.labelTypes[address];
        if (FUNCTION != type and JUMP != type) {
            printAddress(std::cerr, address, "Guessing that 0x") << " is a function" << std::endl;
            ++guess_count;
            type = FUNC_GUESS;
        }
        add_code_trace_address(address, type);
    }

    void addAddressesFromUnknownRegions(size_t &guess_count,
                                        std::map<uint32_t /*offset*/, uint32_t /*address*/> &fixups) {
        for (std::map<uint32_t, uint32_t>::const_iterator itr = fixups.begin(); itr != fixups.end(); ++itr) {
            Region *reg = regions.regionContaining(itr->second);
            if (reg == NULL) {
                continue;
            } else if (reg->type() == UNKNOWN) {
                addAddress(guess_count, itr->second);
            } else if (reg->type() == DATA) {
                regions.labelTypes[itr->second] = DATA;
            }
        }
    }

    void trace_remaining_relocs(LinearExecutable &lx) {
        size_t guess_count = 0;
        for (size_t n = 0; n < image.objects.size(); ++n) {
            addAddressesFromUnknownRegions(guess_count, lx.fixups[n]);
        }
        std::cerr << std::dec << guess_count << " guess(es) to investigate" << std::endl;
    }

public:
    void run(LinearExecutable &lx) {
        uint32_t eip = lx.entryPointAddress();
        add_code_trace_address(eip, FUNCTION);  // TODO: name it "_start"
        printAddress(std::cerr, eip, "Tracing code directly accessible from the entry point at 0x") << std::endl;
        trace_code();

        std::cerr << "Tracing text relocs for switches..." << std::endl;
        traceSwitches(lx);

        std::cerr << "Tracing remaining relocs for functions and data..." << std::endl;
        trace_remaining_relocs(lx);
        trace_code();
    }
};

#endif /* LE_DISASM_ANALYZER_H_ */
