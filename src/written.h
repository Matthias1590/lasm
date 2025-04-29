#pragma once

#define written_t(t) written_##t
#define typedef_written(t) \
	typedef struct { \
		t data; \
		bb_t *_bb; \
		offset_t _offset; \
	} written_t(t)

#define written_init(written, bb) \
    do { \
        (written)->_bb = (bb); \
        (written)->_offset = bb_add((bb), &(written)->data, sizeof((written)->data)); \
    } while (0)

#define written_update(written) \
    do { \
        bb_set((written)._bb, (written)._offset, &(written).data, sizeof((written).data)); \
    } while (0)
