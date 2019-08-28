#ifndef LE_DISASM_FLAGS_RESTORER_H_
#define LE_DISASM_FLAGS_RESTORER_H_

struct FlagsRestorer {
    FlagsRestorer(std::ios &str) : stream(str), flags(str.flags()) {}

    ~FlagsRestorer(void) { stream.flags(flags); }

protected:
    std::ios &stream;
    std::ios::fmtflags flags;
};

#endif /* LE_DISASM_FLAGS_RESTORER_H_ */
