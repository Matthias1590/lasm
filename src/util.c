#include "util.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

void *_heapify(void *data, size_t size) {
	void *ptr = malloc(size);
	assert(ptr != NULL);
	memcpy(ptr, data, size);
	return ptr;
}

char *read_file(const char *path) {
	FILE *f = fopen(path, "rb");
	assert(f != NULL);

	assert(fseek(f, 0, SEEK_END) == 0);

	long size = ftell(f);
	assert(size >= 0);

	assert(fseek(f, 0, SEEK_SET) == 0);

	char *buffer = malloc(size + 1);
	assert(buffer != NULL);

	size_t read_size = fread(buffer, 1, size, f);
	assert(read_size == (size_t)size);
	buffer[size] = '\0';

	assert(fclose(f) == 0);
	return buffer;
}

bool write_file(const char *path, const void *data, size_t size) {
	FILE *f = fopen(path, "wb");
	assert(f != NULL);

	size_t written_size = fwrite(data, 1, size, f);
	assert(written_size == size);

	assert(fclose(f) == 0);

	return true;
}
