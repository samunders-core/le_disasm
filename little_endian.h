#ifndef SRC_LITTLE_ENDIAN_H_
#define SRC_LITTLE_ENDIAN_H_

#include <istream>

#include "error.h"

template<typename T, size_t Bytes>
static void read_le(const void *memory, T &value) {
	value = T(0);
	uint8_t *p = (uint8_t *) memory;
	for (size_t n = 0; n < Bytes; ++n) {
		value |= (T) p[n] << (n * 8);
	}
}

template<typename T>
void read_le(std::istream &is, T &ret) {
	char buffer[sizeof(T)];
	for (is.read(buffer, sizeof(T)); !is.good(); ) {
		throw Error() << "EOF";
	}
	read_le<T, sizeof(T)>(buffer, ret);
}

template<typename T>
T read_le(const void *memory) {
	T ret;
	read_le<T, sizeof(T)>(memory, ret);
	return ret;
}

template<typename T, size_t Bytes>
static void write_le(const void *memory, T value) {
	uint8_t *p = (uint8_t *) memory;
	for (size_t n = 0; n < Bytes; ++n) {
		p[n] = value & 0xff;
		value >>= 8;
	}
}

template<typename T>
void write_le(const void *memory, T value) {
	write_le<T, sizeof(T)>(memory, value);
}

#endif /* SRC_LITTLE_ENDIAN_H_ */
