#ifndef __TCB_H
#define __TCB_H

#include <errno.h>

#define TCB_MAGIC			0x0a00ff7fUL

#define IO_LOOP(LOOP_NAME, NAME, QUAL) \
static int LOOP_NAME(int fd, QUAL char *buffer, int count) \
{ \
	int offset, block; \
\
	offset = 0; \
	while (count > 0) { \
		block = NAME(fd, &buffer[offset], count); \
\
		if (block < 0) { \
			if (errno == EINTR) continue; \
			return block; \
		} \
		if (!block) return offset; \
\
		offset += block; \
		count -= block; \
	} \
\
	return offset; \
}

#endif
