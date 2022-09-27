#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 2

#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 4

typedef struct WireSyncReturnStruct {
  uint8_t *ptr;
  int32_t len;
  bool success;
} WireSyncReturnStruct;

typedef int64_t DartPort;

typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);

void wire_start_event_stream(int64_t port_);

void wire_start_rgba_stream(int64_t port_);

void free_WireSyncReturnStruct(struct WireSyncReturnStruct val);

void store_dart_post_cobject(DartPostCObjectFnType ptr);

static int64_t dummy_method_to_enforce_bundling(void) {
    int64_t dummy_var = 0;
    dummy_var ^= ((int64_t) (void*) wire_start_event_stream);
    dummy_var ^= ((int64_t) (void*) wire_start_rgba_stream);
    dummy_var ^= ((int64_t) (void*) free_WireSyncReturnStruct);
    dummy_var ^= ((int64_t) (void*) store_dart_post_cobject);
    return dummy_var;
}