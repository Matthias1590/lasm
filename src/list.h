#pragma once

#include <stdlib.h>

#define list_fields(t) \
	t *items; \
	size_t count; \
	size_t capacity;

/// @brief Frees a list.
/// @param l The list to free.
#define list_free(l) _list_free((void ***)&(l)->items, &(l)->count, &(l)->capacity)

void _list_free(void ***items, size_t *count, size_t *capacity);

/// @brief Pushes an item to a list.
/// @param l The list to push to.
/// @param item The item to push.
#define list_push(l, item) _list_push((void ***)&(l)->items, &(l)->count, &(l)->capacity, item)

void *_list_push(void ***items, size_t *count, size_t *capacity, void *item);

#define list_at(l, i) _list_at((void **)(l)->items, (l)->count, (i))

void *_list_at(void **items, size_t count, size_t i);
