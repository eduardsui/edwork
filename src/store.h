#ifndef __STORE_H
#define __STORE_H

#include <stdlib.h>
#include <sys/stat.h>

#define STORE_MAX_CHUNK_SIZE    0x10000
#define STORE_CHUNKS_PER_FILE   20

struct store_data;

struct store_data *store_open(const char *path, int mode, unsigned int chunk);
FILE *store_handle(struct store_data *f);
int store_close(struct store_data *f);
int store_write(const void *buf, int size, struct store_data *f);
int store_read(void *buf, int size, struct store_data *f);
int store_seek(struct store_data *f, int offset);
int store_exists(const char *path, int chunk);
int store_size(const char *path, int chunk);
int store_unlink(const char *path, int chunk);
int store_stat(const char *path, int chunk, struct stat *attrib);

#endif

