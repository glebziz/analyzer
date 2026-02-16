#include "model/processor.h"

bool processor_call(const processor_t processor, packet_t *pkt) {
    return processor.process(processor.data, pkt);
}
