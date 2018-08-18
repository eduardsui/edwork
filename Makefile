CC = gcc
RM = rm
CFLAGS = -pthread -O3 -D_FILE_OFFSET_BITS=64 -DEDFS_DEFAULT_HOST=\"discovery.gyrogears.com:4848\"
LIBS = -lfuse
BUILDFLAGS= -o edfs_mount

SRC = src/sha256.c src/xxhash.c src/base64.c src/parson.c src/edd25519.c src/avl.c src/chacha.c src/log.c src/sha3.c src/curve25519.c src/edwork.c src/edfs_core.c src/edfs_fuse.c
OBJS = $(SRC: .c=.o)

edfs: ${OBJS}
	${CC} ${BUILDFLAGS} ${CFLAGS} ${OBJS} ${LIBS}

%.o:
	${CC} ${CFLAGS} -c $<

.PHONY: clean
clean:
	@echo all cleaned up!