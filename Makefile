CC = gcc
RM = rm
CFLAGS = -pthread -O3 -D_FILE_OFFSET_BITS=64
LIBS = -lfuse
BUILDFLAGS= -o edfs_mount

SRC = sha256.c xxhash.c base64.c parson.c edd25519.c avl.c chacha.c log.c sha3.c edwork.c edfs_core.c edfs_fuse.c
OBJS = $(SRC: .c=.o)

edfs: ${OBJS}
	${CC} ${BUILDFLAGS} ${CFLAGS} ${OBJS} ${LIBS}

%.o:
	${CC} ${CFLAGS} -c $<

.PHONY: clean
clean:
	@echo all cleaned up!
