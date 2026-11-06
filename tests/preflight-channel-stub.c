#include "probe_icc_handler.h"
void probe_icc_handler_stage_a(void (*emit)(const char *fmt, ...)) {
    emit("CHANNEL_TEST %d\n", 42);
}
