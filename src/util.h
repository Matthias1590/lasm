#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

typedef uint64_t addr_t;
typedef uint64_t offset_t;

/// @brief Puts an object on the heap.
/// @param t The type of the object.
/// @param data The address of the object.
/// @return A pointer to the object on the heap.
#define heapify(t, data) (t *)_heapify(data, sizeof(t))

void *_heapify(void *data, size_t size);

/// @brief Reads an entire file.
/// @param path The path to the file.
/// @return Contents of the file as an owned string.
char *read_file(const char *path);

/// @brief Writes data to a file.
/// @param path The path to the file.
/// @param data The data to write.
/// @param size The size of the data.
/// @return True if the file was written successfully, false otherwise.
bool write_file(const char *path, const void *data, size_t size);
