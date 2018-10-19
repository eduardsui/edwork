#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#ifdef _WIN32
    #include <windows.h>
    #include <io.h>

    int ftruncate(int fd, unsigned int size) {
        HANDLE hfile;
        unsigned int curpos;

        if (fd < 0) {
            errno = EBADF;
            return -1;
        }

        hfile = (HANDLE) _get_osfhandle (fd);
        curpos = SetFilePointer (hfile, 0, NULL, FILE_CURRENT);
        if (curpos == ~0 || SetFilePointer (hfile, size, NULL, FILE_BEGIN) == ~0 || !SetEndOfFile (hfile)) {
            int error = GetLastError (); 
            switch (error) {
                case ERROR_INVALID_HANDLE:
                    errno = EBADF;
                    break;
                default:
                    errno = EIO;
                    break;
            }
            return -1;
        }
        return 0;
    }
#endif

#include "store.h"

struct store_data {
    FILE *f;
    unsigned int chunk;

    unsigned int header[STORE_CHUNKS_PER_FILE * 4];

    unsigned int offset;
    unsigned char buffer[STORE_MAX_CHUNK_SIZE];
    int buffer_size;

    unsigned char dataread;
    unsigned char modified;
};

struct store_data *store_open(const char *path, int mode, unsigned int chunk) {
    if (chunk >= STORE_CHUNKS_PER_FILE) {
        errno = ENOENT;
        return NULL;
    }

    int dataread = 0;
    FILE *f = fopen(path, mode ? "r+b" : "rb");
    if ((mode == 1) && (!f)) {
        f = fopen(path, "w+b");
        dataread = 1;
    }
    if (!f)
        return NULL;

    struct store_data *fdata = (struct store_data *)malloc(sizeof(struct store_data));
    if (fdata) {
        memset(fdata, 0, sizeof(struct store_data));
        fdata->f = f;
        fdata->dataread = dataread;
    }

    int size = fread(fdata->header, 1, sizeof(fdata->header), f);
    if (!mode) {
        if (size != sizeof(fdata->header)) {
            free(fdata);
            fclose(f);
            errno = EIO;
            return NULL;
        }

        if (!fdata->header[chunk * 4 + 1]) {
            free(fdata);
            fclose(f);
            errno = ENOENT;
            return NULL;
        }
    }
    if (size > 0) {
        int i;
        for (i = 0; i < STORE_CHUNKS_PER_FILE * 4; i ++)
            fdata->header[i] = ntohl(fdata->header[i]);
    }

    fdata->header[chunk * 4] = chunk;
    fdata->chunk = chunk;
    fdata->buffer_size = fdata->header[chunk * 4 + 2];

    return fdata;
}

FILE *store_handle(struct store_data *f) {
    if (f)
        return f->f;

    return NULL;
}

int private_store_unlink(struct store_data *f) {
    if (!f)
        return -1;

    int unlink_at_offset = f->header[f->chunk * 4 + 1];
    if (unlink_at_offset <= 0)
        return -1;

    int unlink_size = f->header[f->chunk * 4 + 2];

    fseek(f->f, 0, SEEK_END);
    int file_size = (int)ftell(f->f);

    int delta = file_size - (unlink_at_offset + unlink_size);
    if ((delta < 0) || (unlink_size <= 0))
        return -1;

    if (delta) {
        void *buf = malloc(delta);
        if (!buf)
            return -1;

        fseek(f->f, unlink_at_offset + unlink_size, SEEK_SET);
        if (fread(buf, 1, delta, f->f) != delta) {
            free(buf);
            return -1;
        }

        fseek(f->f, unlink_at_offset, SEEK_SET);
        if (fwrite(buf, 1, delta, f->f) != delta) {
            free(buf);
            return -1;
        }
        f->header[f->chunk * 4 + 1] = 0;
        f->header[f->chunk * 4 + 2] = 0;

        int i;
        for (i = 0; i < STORE_CHUNKS_PER_FILE; i += 4) {
            if (f->header[i + 1] > unlink_at_offset)
                f->header[i + 1] -= unlink_size;
        }
        free(buf);
        fflush(f->f);
    } else {
        f->header[f->chunk * 4 + 1] = 0;
        f->header[f->chunk * 4 + 2] = 0;
    }
    // last chunk
    ftruncate(fileno(f->f), file_size - unlink_size);
    return 0;
}

int store_close(struct store_data *f) {
    int err = 0;
    if (f) {
        if (f->modified) {
            int i;

            int offset = f->header[f->chunk * 4 + 1];

            int same_size = 0;
            if (f->header[f->chunk * 4 + 2] == f->buffer_size)
                same_size = 1;
            else
                private_store_unlink(f);

            for (i = 0; i < STORE_CHUNKS_PER_FILE * 4; i ++)
                f->header[i] = htonl(f->header[i]);


            int storage_offset;
            if (same_size) {
                storage_offset = offset;
            } else {
                fseek(f->f, 0, SEEK_END);
                storage_offset = (int)ftell(f->f);
            }
            fseek(f->f, 0, SEEK_SET);
            if (!storage_offset)
                storage_offset = sizeof(f->header);

            f->header[f->chunk * 4 + 1] = htonl(storage_offset);
            f->header[f->chunk * 4 + 2] = htonl(f->buffer_size);
            f->header[f->chunk * 4 + 3] = htonl(time(NULL));
            if (fwrite(f->header, 1, sizeof(f->header), f->f) == sizeof(f->header))
                err = 0;
            else
                err = -1;

            if (!err) {
                fseek(f->f, storage_offset, SEEK_SET);
                err = fwrite(f->buffer, 1, f->buffer_size, f->f);
                if (err != f->buffer_size)
                    err = -1;
            }
        }
        fclose(f->f);
        free(f);
    }
    return err;
}

int store_write(const void *buf, int size, struct store_data *f) {
    if (!f)
        return -1;
    if (size <= 0)
        return 0;

    // chunk to big
    if (f->offset + size > STORE_MAX_CHUNK_SIZE)
        return -1;

    if ((!f->dataread) && (f->header[f->chunk * 4 + 1])) {
        fseek(f->f, f->header[f->chunk * 4 + 1], SEEK_SET);
        int err = fread(f->buffer, 1, f->buffer_size, f->f);
        if (err != f->buffer_size) {
            errno = EIO;
            return -1;
        }
        f->dataread = 1;
    }

    memcpy(f->buffer + f->offset, buf, size);
    f->offset += size;
    if (f->buffer_size < f->offset)
        f->buffer_size = f->offset;

    f->modified = 1;

    return size;
}

int store_read(void *buf, int size, struct store_data *f) {
    if (!f)
        return -1;

    if (size > f->buffer_size - f->offset)
        size = f->buffer_size - f->offset;

    if ((size <= 0) || (!f->header[f->chunk * 4 + 1]))
        return 0;

    if (!f->dataread) {
        fseek(f->f, f->header[f->chunk * 4 + 1], SEEK_SET);
        int err = fread(f->buffer, 1, f->buffer_size, f->f);
        if (err != f->buffer_size) {
            errno = EIO;
            return -1;
        }
        f->dataread = 1;
    }
    memcpy(buf, f->buffer + f->offset, size);

    f->offset += size;

    return size;
}

int store_seek(struct store_data *f, int offset) {
    if ((!f) || (offset < 0) || (offset > f->header[f->chunk * 4 + 2]))
        return -1;

    f->offset = offset;
    return 0;
}

int store_exists(const char *path, int chunk) {
    int timestamp = 0;
    if ((chunk < 0) || (chunk >= STORE_MAX_CHUNK_SIZE))
        return 0;

    struct store_data *f = store_open(path, 0, chunk);
    if (!f)
        return 0;

    if (f->header[chunk * 4 + 1]) {
        timestamp = f->header[chunk * 4 + 3];
        if (!timestamp)
            timestamp = 1;
    }
    store_close(f);
    return timestamp;
}

int store_size(const char *path, int chunk) {
    int file_size = 0;
    if ((chunk < 0) || (chunk >= STORE_MAX_CHUNK_SIZE))
        return -1;

    struct store_data *f = store_open(path, 0, chunk);
    if (!f)
        return -1;

    if (f->header[chunk * 4 + 1])
        file_size = f->header[chunk * 4 + 2];
    store_close(f);
    return file_size;
}

int store_stat(const char *path, int chunk, struct stat *attrib) {
    int file_size = 0;
    if ((chunk < 0) || (chunk >= STORE_MAX_CHUNK_SIZE) || (!attrib))
        return -1;

    struct store_data *f = store_open(path, 0, chunk);
    if (!f)
        return -1;

    if (f->header[chunk * 4 + 1]) {
        memset(attrib, 0, sizeof(struct stat));
        attrib->st_size = f->header[chunk * 4 + 2];
        attrib->st_mtime = f->header[chunk * 4 + 3];
    }
    store_close(f);

    return 0;
}

int store_unlink(const char *path, int chunk) {
    if ((chunk < 0) || (chunk >= STORE_MAX_CHUNK_SIZE))
        return 0;

    struct store_data *f = store_open(path, 1, chunk);
    if (!f)
        return -1;

    private_store_unlink(f);
    int has_data = 0;
    int i;
    for (i = 0; i < STORE_CHUNKS_PER_FILE * 4; i += 4) {
        if (f->header[i + 1]) {
            if (f->header[i] == chunk) {
                f->header[i] = 0;
                f->header[i + 1] = 0;
                f->header[i + 2] = 0;
                f->header[i + 3] = 0;
            } else {
                f->header[i] = htonl(f->header[i]);
                f->header[i + 1] = htonl(f->header[i + 1]);
                f->header[i + 2] = htonl(f->header[i + 2]);
                f->header[i + 3] = htonl(f->header[i + 3]);
                has_data ++;
            }
        }
    }
    int err = 0;
    if (has_data) {
        fseek(f->f, 0, SEEK_SET);
        if (fwrite(f->header, 1, sizeof(f->header), f->f) != sizeof(f->header))
            err = -1;
    }
    store_close(f);

    // remove entire file
    if (!has_data)
        unlink(path);

    return err;
}
