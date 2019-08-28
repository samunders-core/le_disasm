#ifndef LE_DISASM_REGIONS_H_
#define LE_DISASM_REGIONS_H_

#include "le/image.h"
#include "region.h"

struct Regions {
    std::map<uint32_t, Region> regions;
    std::map<uint32_t, Type> labelTypes;

    Regions(std::vector<ImageObject> &objects) {
        for (size_t n = 0; n < objects.size(); ++n) {
            ImageObject &obj = objects[n];
            Type type = obj.is_executable() ? UNKNOWN : DATA;
            printAddress(std::cerr, obj.base_address(), "Creating Region(0x") << ", " << std::dec << obj.size() << ", "
                                                                              << type << ")" << std::endl;
            regions[obj.base_address()] = Region(obj.base_address(), obj.size(), type, std::addressof(obj));
            if (type == DATA) {
                labelTypes[obj.base_address()] = type;
            }  // else no automatic label for lowest .text address
        }
    }

    Region *regionContaining(uint32_t address) {
        std::map<uint32_t, Region>::iterator itr = regions.lower_bound(address);
        if (regions.end() != itr) {
            if (itr->first == address) {
                return &itr->second;
            } else if (regions.begin() == itr) {
                return NULL;
            }
        }
        if (regions.empty()) {
            return NULL;
        }
        --itr;
        return itr->second.contains_address(address) ? &itr->second : NULL;
    }

    void splitInsert(Region &parent, const Region &target) {
        assert(parent.contains_address(target.address()));
        assert(parent.contains_address(target.end_address() - 1));

        Region reg = target;
        reg.image_object_pointer(parent.image_object_pointer());
        FlagsRestorer _(std::cerr);
        Region next(reg.end_address(), parent.end_address() - reg.end_address(), parent.type(),
                    parent.image_object_pointer());
        std::cerr << parent << " split to ";

        if (reg.address() != parent.address()) {
            parent.size(reg.address() - parent.address());
            regions[reg.address()] = reg;
            std::cerr << parent << ", " << reg;
        } else {
            parent = reg;
            std::cerr << parent;
        }

        if (next.size() > 0) {
            regions[reg.end_address()] = next;
            std::cerr << ", " << next;
        }
        std::cerr << std::endl;

        assert(reg.image_object_pointer());
        assert(next.image_object_pointer());
        assert(parent.image_object_pointer());
        check_merge_regions(reg.address());
    }

    Region *nextRegion(const Region &reg) {
        std::map<uint32_t, Region>::iterator itr = regions.upper_bound(reg.address());
        return regions.end() != itr ? &itr->second : NULL;
    }

private:
    Region *previousRegion(const Region &reg) {
        for (std::map<uint32_t, Region>::iterator itr = regions.lower_bound(reg.address()); regions.begin() != itr;) {
            --itr;
            return &itr->second;
        }
        return NULL;
    }

    void check_merge_regions(uint32_t address) {
        Region &reg = regions[address];
        Region *merged = attemptMerge(previousRegion(reg), &reg);
        attemptMerge(merged, nextRegion(*merged));
    }

    Region *attemptMerge(Region *prev, Region *next) {
        if (prev != NULL and next != NULL and prev->type() == next->type() and
            prev->end_address() == next->address() and prev->bitness() == next->bitness()) {
            std::cerr << "Combining " << *prev << " and " << *next << std::endl;
            prev->size(prev->size() + next->size());
            regions.erase(next->address());
            return prev;
        }
        return next;
    }
};

#endif /* LE_DISASM_REGIONS_H_ */
