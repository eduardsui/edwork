#ifndef __EDFS_H
#define __EDFS_H

#include <dirent.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>

#include "edwork.h"
#include "edfs_core.h"

#define EDFS_DIR_BUFFER     128

typedef struct _EDFS_FILE {
    struct filewritebuf *buf;
    struct edfs *edfs_context;
    edfs_ino_t ino;
    int64_t offset;
} EDFS_FILE;

typedef struct _EDFS_DIR {
    struct dirbuf *buf;
    struct edfs *edfs_context;
    edfs_ino_t ino;
    struct dirent dir_buffer[EDFS_DIR_BUFFER];
    int dir_buffer_offset;
    int dir_buffer_size;
    int64_t offset;
} EDFS_DIR;

EDFS_FILE *ed_fopen(struct edfs *edfs_context, const char *filename, const char *mode);
size_t ed_fread(void *ptr, size_t size, size_t nmemb, EDFS_FILE *f);
size_t ed_fwrite(const void *ptr, size_t size, size_t nmemb, EDFS_FILE *f);
int ed_flush(EDFS_FILE *f);
int ed_fseek(EDFS_FILE *f, int64_t offset, int64_t whence);
int64_t ed_ftell(EDFS_FILE *f);
int ed_fclose(EDFS_FILE *f);

EDFS_DIR *ed_opendir(struct edfs *edfs_context, const char *path);
struct dirent *ed_readdir(EDFS_DIR *dir);
int ed_closedir(EDFS_DIR *dir);

int ed_mkdir(struct edfs *edfs_context, const char *path, int mode);
int ed_rmdir(struct edfs *edfs_context, const char *path);
int ed_unlink(struct edfs *edfs_context, const char *path);

int ed_stat(struct edfs *edfs_context, const char *path, edfs_stat *buf);
int ed_chmod(struct edfs *edfs_context, const char *pathname, int mode);
int ed_utime(struct edfs *edfs_context, const char *filename, const struct utimbuf *times);

#endif // __EDFS_H
