#ifndef SRC_LE_IMAGE_OBJECT_H_
#define SRC_LE_IMAGE_OBJECT_H_

#include <vector>

struct ImageObject {
	size_t index;
	uint32_t base_address;	// both available in LinearExecutable.objects
	bool executable;
	std::vector<uint8_t> data;

	void init(size_t index_, uint32_t base_address_, bool executable_, const std::vector<uint8_t> &data_) {
		index = index_;
		base_address = base_address_;
		executable = executable_;
		data = data_;
	}

	const uint8_t *get_data_at(uint32_t address) const {
		return (&data.front () + address - base_address);
	}
};

#endif /* SRC_LE_IMAGE_OBJECT_H_ */
