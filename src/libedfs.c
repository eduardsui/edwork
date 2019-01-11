#include "edfs.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

EDFS_FILE *ed_fopen(struct edfs *edfs_context, const char *filename, const char *mode) {
    errno = 0;
    if ((!edfs_context) || (!mode) || (!mode[0])) {
        errno = EINVAL;
        return NULL;
    }
    uint64_t parent;
    const char *name = NULL;
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, filename, &parent, &name);
    int type = edfs_lookup_inode(edfs_context, inode, name);
    if (!type) {
        errno = ENOENT;
        return NULL;
    }
    if (type & S_IFDIR) {
        errno = EISDIR;
        return NULL;
    }

    struct filewritebuf *fbuf = NULL;
    int flags = 0;
    int do_truncate = 0;
    while (*mode) {
        switch (*mode) {
            case 'w':
                flags |= O_WRONLY | O_CREAT | O_TRUNC;
                do_truncate = 1;
                break;
            case 'r':
                flags |= O_RDONLY;
                break;
            case '+':
                do_truncate = 0;
                if (!flags) {
                    errno = EINVAL;
                    return NULL;
                }
                flags |= O_RDWR;
                break;
            case 'a':
                do_truncate = 0;
                flags |= O_WRONLY | O_CREAT | O_APPEND;
                break;
            case 'b':
                // ignore this flag, everything is binary with edfs
                break;
            default:
                // unknown mode
                errno = EINVAL;
                return NULL;
        }
        mode ++;
    }
    if (do_truncate)
        edfs_set_size(edfs_context, inode, 0);

    if (!flags)
        flags = O_RDONLY;
    int err = edfs_open(edfs_context, inode, flags, &fbuf);
    if (err) {
        errno = -err;
        return NULL;
    }
    EDFS_FILE *f = (EDFS_FILE *)malloc(sizeof(EDFS_FILE));
    if (!f) {
        errno = ENOMEM;
        return NULL;
    }
    memset(f, 0, sizeof(EDFS_FILE));
    f->edfs_context = edfs_context;
    f->buf = fbuf;
    f->ino = inode;
    if (flags & O_APPEND) {
        edfs_stat stbuf;
        if (!edfs_getattr(edfs_context, inode, &stbuf))
            f->offset = stbuf.st_size;
    }
    return f;
}

size_t ed_fread(void *ptr, size_t size, size_t nmemb, EDFS_FILE *f) {
    errno = 0;
    if (!f) {
        errno = EINVAL;
        return 0;
    }

    int err = edfs_read(f->edfs_context, f->ino, size * nmemb, f->offset, (char *)ptr, f->buf);
    if (err < 0) {
        errno = -err;
        return 0;
    }
    f->offset += err;
    return (size_t)err;
}

size_t ed_fwrite(const void *ptr, size_t size, size_t nmemb, EDFS_FILE *f) {
    errno = 0;
    if (!f) {
        errno = EINVAL;
        return 0;
    }
    int err = edfs_write(f->edfs_context, f->ino, (const char *)ptr, size * nmemb, f->offset, f->buf);
    if (err < 0) {
        errno = -err;
        return 0;
    }
    f->offset += err;
    return (size_t)err;
}

int ed_flush(EDFS_FILE *f) {
    errno = 0;
    if (!f) {
        errno = EINVAL;
        return -1;
    }
    edfs_flush(f->edfs_context, f->buf);
    return 0;
}

int ed_fseek(EDFS_FILE *f, int64_t offset, int64_t whence) {
    errno = 0;
    if (!f) {
        errno = EINVAL;
        return -1;
    }
    edfs_stat stbuf;
    switch (whence) {
        case SEEK_SET:
            f->offset = whence;
            break;
        case SEEK_CUR:
            f->offset += whence;
            break;
        case SEEK_END:
            if (edfs_getattr(f->edfs_context, f->ino, &stbuf)) {
                errno = EINVAL;
                return -1;
            }
            f->offset = stbuf.st_size - whence;
            break;
        default:
            errno = EINVAL;
            return -1;
    }
    return 0;
}

int64_t ed_ftell(EDFS_FILE *f) {
    errno = 0;
    if (!f) {
        errno = EINVAL;
        return -1;
    }
    return f->offset;
}

int ed_fclose(EDFS_FILE *f) {
    errno = 0;
    if (!f) {
        errno = EINVAL;
        return -1;
    }
    edfs_close(f->edfs_context, f->buf);
    free(f);
    return 0;
}

EDFS_DIR *ed_opendir(struct edfs *edfs_context, const char *path) {
    errno = 0;
    if ((!edfs_context) || (!path)) {
        errno = EINVAL;
        return NULL;
    }
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, path, NULL, NULL);
    struct dirbuf *dbuf = edfs_opendir(edfs_context, inode);
    if (!dbuf) {
        errno = ENOTDIR;
        return NULL;
    }
    EDFS_DIR *dir = (EDFS_DIR *)malloc(sizeof(EDFS_DIR));
    if (!dir) {
        errno = ENOMEM;
        return NULL;
    }
    memset(dir, 0, sizeof(EDFS_DIR));
    dir->edfs_context = edfs_context;
    dir->buf = dbuf;
    dir->ino = inode;
    return dir;
}

static unsigned int edfs_private_add_directory(const char *name, edfs_ino_t ino, int type, int64_t size, time_t created, time_t modified, time_t timestamp, void *userdata) {
    EDFS_DIR *dir = (EDFS_DIR *)userdata;
    if (dir->dir_buffer_size < EDFS_DIR_BUFFER) {
        struct dirent *dirdata = &dir->dir_buffer[dir->dir_buffer_size];
        memset(dirdata, 0, sizeof(struct dirent));
        dirdata->d_ino = ino;
#ifdef EXTENDED_READDIR
        dirdata->d_off = dir->offset + dir->dir_buffer_size;
        dirdata->d_type = type;
        dirdata->d_reclen = sizeof(struct dirent);
#endif
        strncpy(dirdata->d_name, name, sizeof(dirdata->d_name));
        dir->dir_buffer_size ++;
    }
    return 1;
}


struct dirent *ed_readdir(EDFS_DIR *dir) {
    errno = 0;
    if (!dir) {
        errno = EINVAL;
        return NULL;
    }

    if (dir->dir_buffer_offset < dir->dir_buffer_size)
        return &dir->dir_buffer[dir->dir_buffer_offset ++];

    dir->dir_buffer_offset = 0;
    dir->dir_buffer_size = 0;

    int err = edfs_readdir(dir->edfs_context, dir->ino, EDFS_DIR_BUFFER, dir->offset, dir->buf, edfs_private_add_directory, dir);
    if (err) {
        errno = -err;
        return NULL;
    }

    if (dir->dir_buffer_offset < dir->dir_buffer_size)
        return &dir->dir_buffer[dir->dir_buffer_offset ++];

    return NULL;
}

int ed_closedir(EDFS_DIR *dir) {
    errno = 0;
    if (!dir) {
        errno = EINVAL;
        return -1;
    }
    edfs_releasedir(dir->buf);
    free(dir);
}

int ed_mkdir(struct edfs *edfs_context, const char *path, int mode) {
    errno = 0;
    if (!edfs_context) {
        errno = EINVAL;
        return -1;
    }
    uint64_t parent = 0;
    const char *name = NULL;
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, path, &parent, &name);

    int err = edfs_mkdir(edfs_context, parent, name, (mode_t)mode);
    if (err) {
        errno = -err;
        return -1;
    }
    return 0;
}

int ed_rmdir(struct edfs *edfs_context, const char *path) {
    errno = 0;
    if (!edfs_context) {
        errno = EINVAL;
        return -1;
    }
    uint64_t parent = 0;
    const char *name = NULL;
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, path, &parent, &name);

    int err = edfs_rmdir_inode(edfs_context, parent, inode);
    if (err) {
        errno = -err;
        return -1;
    }
    return 0;
}

int ed_unlink(struct edfs *edfs_context, const char *path) {
    if (!edfs_context) {
        errno = EINVAL;
        return -1;
    }
    uint64_t parent = 0;
    const char *name = NULL;
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, path, &parent, &name);

    int err = edfs_unlink_inode(edfs_context, parent, inode);
    if (err) {
        errno = -err;
        return -1;
    }
    return 0;
}

int ed_stat(struct edfs *edfs_context, const char *path, edfs_stat *buf) {
    errno = 0;
    if (!edfs_context) {
        errno = EINVAL;
        return -1;
    }

    uint64_t parent = 0;
    const char *name = NULL;
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, path, &parent, &name);

    edfs_stat stbuf;
    int err = edfs_getattr(edfs_context, inode, buf);
    if (err) {
        errno = -err;
        return -1;
    }
    return 0;
}

int ed_chmod(struct edfs *edfs_context, const char *pathname, int mode) {
    errno = 0;
    if (!edfs_context) {
        errno = EINVAL;
        return -1;
    }

    uint64_t parent = 0;
    const char *name = NULL;
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, pathname, &parent, &name);

    edfs_stat attr;
    memset(&attr, 0, sizeof(edfs_stat));
    attr.st_mode = mode;

    int err = edfs_setattr(edfs_context, inode, &attr, EDFS_SET_ATTR_MODE);
    if (err) {
        errno = -err;
        return -1;
    }
    return -1;
}

int ed_utime(struct edfs *edfs_context, const char *filename, const struct utimbuf *times) {
    errno = 0;
    if (!edfs_context) {
        errno = EINVAL;
        return -1;
    }

    uint64_t parent = 0;
    const char *name = NULL;
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, filename, &parent, &name);

    edfs_stat attr;
    memset(&attr, 0, sizeof(edfs_stat));
    attr.st_mtime = times->modtime;

    int err = edfs_setattr(edfs_context, inode, &attr, EDFS_SET_ATTR_MTIME);
    if (err) {
        errno = -err;
        return -1;
    }
    return 0;
}
