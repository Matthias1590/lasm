#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

typedef struct {
	uint8_t *data;
	size_t size;
	size_t capacity;
} bb_t;

void *bb_add(bb_t *bb, const void *data, size_t size) {
	while (bb->size + size > bb->capacity) {
		bb->capacity *= 2;
		bb->data = realloc(bb->data, bb->capacity);
		assert(bb->data != NULL);
	}
	memcpy(bb->data + bb->size, data, size);
	bb->size += size;
	return bb->data + bb->size - size;
}

bb_t *bb_new(void) {
	bb_t *bb = malloc(sizeof(bb_t));
	assert(bb != NULL);
	memset(bb, 0, sizeof(bb_t));
    bb->data = malloc(1);
    bb->capacity = 1;
	return bb;
}

int main(void) {
    bb_t *bb = bb_new();
    assert(bb != NULL);

    bb_add(bb, "hey", 3);
}
