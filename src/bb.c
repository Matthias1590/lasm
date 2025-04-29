#include "bb.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

bb_t *bb_new(void) {
	bb_t *bb = malloc(sizeof(bb_t));
	assert(bb != NULL);
	memset(bb, 0, sizeof(bb_t));
	return bb;
}

void bb_free(bb_t *bb) {
	free(bb->data);
	free(bb);
}

offset_t bb_add(bb_t *bb, const void *data, size_t size) {
	while (bb->size + size > bb->capacity) {
		bb->capacity = bb->capacity == 0 ? 1 : bb->capacity * 2;
		bb->data = realloc(bb->data, bb->capacity);
		assert(bb->data != NULL);
	}
	memcpy(bb->data + bb->size, data, size);
	bb->size += size;
	return bb->size - size;
}

void bb_set(bb_t *bb, offset_t offset, const void *data, size_t size) {
	assert(offset + size <= bb->size);
	memcpy(bb->data + offset, data, size);
}

offset_t bb_add_str(bb_t *bb, const char *str) {
	return bb_add(bb, str, strlen(str));
}

offset_t bb_add_u8(bb_t *bb, uint8_t value) {
	return bb_add(bb, &value, sizeof(value));
}

offset_t bb_add_u16(bb_t *bb, uint16_t value) {
	return bb_add(bb, &value, sizeof(value));
}

offset_t bb_add_u32(bb_t *bb, uint32_t value) {
	return bb_add(bb, &value, sizeof(value));
}

offset_t bb_add_u64(bb_t *bb, uint64_t value) {
	return bb_add(bb, &value, sizeof(value));
}

void bb_zeroes(bb_t *bb, size_t count) {
	for (size_t i = 0; i < count; i++) {
		bb_add_u8(bb, 0);
	}
}
