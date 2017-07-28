#ifndef SRC_INSN_H_
#define SRC_INSN_H_

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "error.h"
#include "little_endian.h"

class Insn {
	char string[128];
	static int count;

	int lowerCasedSpaceTrimmed(int ret, char *end) {
		for (text = &string[0]; text < &string[textLength] + ret && isspace(*text); ++text);
//		for (; end > text && isspace(*end); --end);
		for (char *i = text; i <= end; *i = tolower(*i), ++i);
		*(end + 1) = 0;
		textLength = end + 1 - text;
		return ret;
	}
public:
	static int callbackResetTypeAndText(void *stream, const char *fmt, ...) {
		va_list list;
		Insn * insn = (Insn *) stream;
		va_start(list, fmt);
		int ret = vsnprintf(&insn->string[insn->textLength], sizeof(insn->string) - 1 - insn->textLength, fmt, list);
		va_end(list);
		insn->type = MISC;
//		if (insn->count-- > 0) {
//			write(2, &insn->string[0], insn->textLength + ret);
//			write(2, "\n", 1);
//		}
		return insn->lowerCasedSpaceTrimmed(ret, &insn->string[insn->textLength] + ret - 1);
	}

	void reset() {
		memoryAddress = 0;
		textLength = 0;
	}

	void setSize(size_t size) {
		this->size = size;
	}

	void setTargetAndType(uint32_t addr, const void *data) {
		bool have_target = true;
		uint8_t data0 = ((uint8_t *) data)[0], data1 = 0;

		if (data0 == 0x2e) {
			if (size > 1) {
				data0 = ((uint8_t *) data)[1];
			}
			if (size > 2) {
				data1 = ((uint8_t *) data)[2];
			}
		} else if (size > 1) {
			data1 = ((uint8_t *) data)[1];
		}

		if (data0 == 0x0f) {
			if (data1 >= 0x80 and data1 < 0x90) {/* j.. near */
				type = COND_JUMP;
			}
		} else if (data0 == 0xe8) {/* call */
			type = CALL;
		} else if (data0 == 0xe9) {/* jmp near */
			type = JUMP;
		} else if (data0 == 0x67 and data1 == 0xe3) {/* 0x67 jmp short */
			type = JUMP;
		} else if (data0 == 0xc2) {/* retn */
			type = RET;
		} else if (data0 == 0xca) {/* lretn */
			type = RET;
		} else if (data0 == 0xeb) {/* jmp short */
			type = JUMP;
		} else if (data0 >= 0x70 and data0 < 0x80) {/* j.. short */
			type = COND_JUMP;
		} else if (data0 >= 0xe0 and data0 <= 0xe3) {/* loop */
			type = COND_JUMP;
		} else if (data0 == 0xe3) {/* jmp short */
			type = JUMP;
		} else if (data0 == 0xcf) {/* iret */
			type = RET;
		} else if (data0 == 0xc3) {/* ret */
			type = RET;
		} else if (data0 == 0xcb) {/* lret */
			type = RET;
		} else if (data0 == 0xff) {/* jmp near or call near indirect*/
			have_target = false;
			/* whatever... */
			type = (strstr(text, "jmp") != NULL) ? JUMP : CALL;
		}

		if (have_target and (type == COND_JUMP or type == JUMP or type == CALL)) {
			uint32_t address;
			if (size < 5) {
				address = addr + size + read_le<int8_t>((uint8_t *) data + size - sizeof(int8_t));
			} else {
				address = addr + size + read_le<int32_t>((uint8_t *) data + size - sizeof(int32_t));
			}
			if (memoryAddress != 0 && address != memoryAddress) {
				throw Error() << "0x" << std::hex << memoryAddress << "discarded for 0x" << address;
			}
			memoryAddress = address;
		} else if (memoryAddress == 0) {
			char * addrStr = strstr(text, "s:0x");
			if (NULL != addrStr) {
				memoryAddress = strtol(addrStr + 2, NULL, 16);
			}
		}
	}

	enum Type {
		MISC, COND_JUMP, JUMP, CALL, RET
	};

	Type type;
	char * text;
	size_t textLength;
	/** jump/call target or memory operand */
	uint32_t memoryAddress;
	size_t size;
};

int Insn::count = 10;

#endif /* SRC_INSN_H_ */
