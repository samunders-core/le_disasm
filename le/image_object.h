#ifndef LE_DISASM_LE_IMAGE_OBJECT_H_
#define LE_DISASM_LE_IMAGE_OBJECT_H_

#include <vector>

#include "../type.h"

class ImageObject {
public:
    void init(size_t index, uint32_t base_address, bool executable, bool bitness, const std::vector<uint8_t> &data) {
        index_ = index;
        base_address_ = base_address;
        executable_ = executable;
        bitness_ = bitness ? BITNESS_32BIT : BITNESS_16BIT;
        data_ = data;
    }

    const uint8_t *const get_data_at(uint32_t address) const { return (&data_.front() + address - base_address_); }
    uint32_t base_address() const { return base_address_; }
    uint32_t size() const { return data_.size(); }
    Bitness bitness() const { return bitness_; }
    bool is_executable() const { return executable_; }
    size_t index() const { return index_; }

private:
    size_t index_;
    uint32_t base_address_;
    bool executable_;
    Bitness bitness_;
    std::vector<uint8_t> data_;
};

#endif /* LE_DISASM_LE_IMAGE_OBJECT_H_ */
