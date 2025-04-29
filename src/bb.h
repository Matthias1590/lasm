#pragma once

#include <stdlib.h>
#include <stdint.h>
#include "util.h"

typedef struct {
	uint8_t *data;
	size_t size;
	size_t capacity;
} bb_t;

bb_t *bb_new(void);
void bb_free(bb_t *bb);
offset_t bb_add(bb_t *bb, const void *data, size_t size);
void bb_set(bb_t *bb, offset_t offset, const void *data, size_t size);
offset_t bb_add_str(bb_t *bb, const char *str);
offset_t bb_add_u8(bb_t *bb, uint8_t value);
offset_t bb_add_u16(bb_t *bb, uint16_t value);
offset_t bb_add_u32(bb_t *bb, uint32_t value);
offset_t bb_add_u64(bb_t *bb, uint64_t value);
void bb_zeroes(bb_t *bb, size_t count);
