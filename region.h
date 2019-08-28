#ifndef LE_DISASM_REGION_H_
#define LE_DISASM_REGION_H_

#include "le/image_object.h"

class Region {
    const ImageObject *image_object_pointer_;
    uint32_t address_;
    uint32_t size_;
    Type type_;

public:
    Region(uint32_t address, uint32_t size, Type type, const ImageObject *image_object_pointer = NULL) {
        address_ = address;
        size_ = size;
        type_ = type;
        image_object_pointer_ = image_object_pointer;
    }

    Region(void) {
        address_ = 0;
        size_ = 0;
        type_ = UNKNOWN;
        image_object_pointer_ = NULL;
    }

    Region(const Region &other) { *this = other; }
    uint32_t address() const { return address_; }
    size_t end_address() const { return (address_ + size_); }
    Type type() const { return type_; }
    bool contains_address(uint32_t address) const { return (address_ <= address and address < address_ + size_); }
    size_t size() const { return size_; }
    void size(size_t size) { size_ = size; }
    Bitness bitness() const {
        assert(image_object_pointer_);
        return image_object_pointer_->bitness();
    }
    const ImageObject *image_object_pointer() { return image_object_pointer_; }
    void image_object_pointer(const ImageObject *image_object_pointer) { image_object_pointer_ = image_object_pointer; }
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

std::ostream &operator<<(std::ostream &os, const Region &reg) { /* %7s @ 0x%06x[%6d] */
    FlagsRestorer _(os);
    return printAddress(os << std::setw(7) << reg.type(), reg.address(), " @ 0x")
           << "[" << std::setw(6) << std::setfill(' ') << std::dec << reg.size() << "]";
}

#endif /* LE_DISASM_REGION_H_ */
