#include "model/descriptor_cleaner.h"

void descriptor_cleaner_clean(const descriptor_cleaner_t c, const uint32_t desc) {
    if (!c.clean_descriptor) {
        return;
    }

    c.clean_descriptor(c.data, desc);
}
