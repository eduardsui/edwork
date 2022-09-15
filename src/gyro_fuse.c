#include "gyro_fuse.h"
#include <inttypes.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>

#include <wchar.h>
#include <windows.h>
#include <objbase.h>
#include <projectedfslib.h>

#include "khash.h"

#ifndef S_ISDIR
    #define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif

KHASH_MAP_INIT_INT64(guid, void *)
// using file couneter removing local content (if removed while opened => unexpected behaviour)
KHASH_MAP_INIT_INT(filecounter, int)

struct fuse_chan {
    wchar_t path[MAX_PATH + 1];
    struct fuse *fs;
};

struct dirinfo_data {
    wchar_t *name;
    PRJ_FILE_BASIC_INFO info;
};

struct fuse {
    PRJ_STARTVIRTUALIZING_OPTIONS options;
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT instanceHandle;
    PRJ_CALLBACKS callbacks;
    PRJ_NOTIFICATION_MAPPING notificationMappings[1];
    struct fuse_operations op;
    struct fuse_conn_info connection;
    struct fuse_chan *ch;
    void *user_data;
    char *path_utf8;
    char running;
    
    khash_t(guid) *guids;
    khash_t(filecounter) *files;

    HANDLE sem;
};

#define LARGE_TIME(src) ((unsigned __int64)src)*10000000 + 116444736000000000LL;

static uint64_t guid64(const GUID *guid) {
    char key[sizeof(GUID)];

    memset(key, 0, sizeof(key));
    memcpy(key, &guid->Data1, sizeof(guid->Data1));

    // endianess is not important (same machine)
    int len = sizeof(guid->Data1);
    memcpy(key + len, &guid->Data2, sizeof(guid->Data2));
    len += sizeof(guid->Data2);
    memcpy(key + len, &guid->Data3, sizeof(guid->Data3));
    len += sizeof(guid->Data3);
    memcpy(key + len, guid->Data4, sizeof(guid->Data4));
    len += sizeof(guid->Data4);

    uint64_t seed = 0;
    const uint64_t m = 0xc6a4a7935bd1e995LLU;
    const int r = 47;

    uint64_t h = seed ^ (len * m);

    const uint64_t* data = (const uint64_t*)key;
    const uint64_t* end = data + (len / 8);

    while (data != end) {
        uint64_t k = *data++;

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    const unsigned char* data2 = (const unsigned char*)data;

    switch (len & 7) {
        case 7: h ^= ((uint64_t)data2[6]) << 48;
        case 6: h ^= ((uint64_t)data2[5]) << 40;
        case 5: h ^= ((uint64_t)data2[4]) << 32;
        case 4: h ^= ((uint64_t)data2[3]) << 24;
        case 3: h ^= ((uint64_t)data2[2]) << 16;
        case 2: h ^= ((uint64_t)data2[1]) << 8;
        case 1: h ^= ((uint64_t)data2[0]);
            h *= m;
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h;
}

static unsigned int djb2_hash(const unsigned char *str) {
    unsigned int hash = 5381;
    int c;

    while ( (c = *str++) )
        hash = ((hash << 5) + hash) + c;

    return hash;
}

static void* guid_data(struct fuse* f, const GUID * EnumerationId) {
    if (!EnumerationId)
        return NULL;

    uint64_t hash = guid64(EnumerationId);

    void* data = NULL;

    WaitForSingleObject(f->sem, INFINITE);

    khint_t k = kh_get(guid, f->guids, hash);
    if ((k != kh_end(f->guids)) && (kh_exist(f->guids, k)))
        data = kh_val(f->guids, k);

    ReleaseSemaphore(f->sem, 1, NULL);

    return data;
}

static int guid_set_data(struct fuse* f, const GUID* EnumerationId, void *data) {
    if (!EnumerationId)
        return 0;

    uint64_t hash = guid64(EnumerationId);

    int absent;

    WaitForSingleObject(f->sem, INFINITE);

    khint_t k = kh_put(guid, f->guids, hash, &absent);
    kh_value(f->guids, k) = data;

    ReleaseSemaphore(f->sem, 1, NULL);

    return absent;
}

static void *guid_remove_key(struct fuse* f, const GUID* EnumerationId) {
    if (!EnumerationId)
        return NULL;

    uint64_t hash = guid64(EnumerationId);
    void* data = NULL;

    WaitForSingleObject(f->sem, INFINITE);

    khint_t k = kh_get(guid, f->guids, hash);
    if ((k != kh_end(f->guids)) && (kh_exist(f->guids, k))) {
        data = kh_val(f->guids, k);
        kh_del(guid, f->guids, k);
    }

    ReleaseSemaphore(f->sem, 1, NULL);

    return data;
}

static struct fuse_file_info *guid_file_info(struct fuse* f, const GUID* EnumerationId) {
    if (!EnumerationId)
        return NULL;

    struct fuse_file_info *finfo = (struct fuse_file_info *)guid_data(f, EnumerationId);
    if (!finfo) {
        finfo = (struct fuse_file_info*)malloc(sizeof(struct fuse_file_info));
        if (!finfo)
            return NULL;
        memset(finfo, 0, sizeof(struct fuse_file_info));
        guid_set_data(f, EnumerationId, finfo);
    }
    return finfo;
}


static void file_opened(struct fuse* f, const char *name) {
    if (!name)
        return;

    WaitForSingleObject(f->sem, INFINITE);

    unsigned int hash = djb2_hash((const unsigned char *)name);
    khint_t k = kh_get(filecounter, f->files, hash);
    if ((k != kh_end(f->files)) && (kh_exist(f->files, k))) {
        int val = kh_val(f->files, k);
        val ++;
        kh_value(f->files, k) = val;

        ReleaseSemaphore(f->sem, 1, NULL);

        return;
    }

    int absent;
    k = kh_put(filecounter, f->files, hash, &absent);
    kh_value(f->files, k) = 1;

    ReleaseSemaphore(f->sem, 1, NULL);
}

static int file_closed(struct fuse* f, const char *name) {
    if (!name)
        return 0;

    int val = 0;

    unsigned int hash = djb2_hash((const unsigned char *)name);

    WaitForSingleObject(f->sem, INFINITE);

    khint_t k = kh_get(filecounter, f->files, hash);
    if ((k != kh_end(f->files)) && (kh_exist(f->files, k))) {
        val = kh_val(f->files, k);
        val --;
        if (val <= 0)
            kh_del(filecounter, f->files, k);
        else
            kh_value(f->files, k) = val;

        if (val < 0)
            val = 0;
    }

    ReleaseSemaphore(f->sem, 1, NULL);

    return val;
}

static void guid_close(struct fuse* f, const GUID* EnumerationId) {
    if (!EnumerationId)
        return;

    struct fuse_file_info *finfo = (struct fuse_file_info *)guid_remove_key(f, EnumerationId);
    if (finfo) {
        struct dirinfo_data *dir_list_data = (struct dirinfo_data *)finfo->data;
        if (dir_list_data) {
            int i;
            for (i = 0; i < finfo->data_len; i ++) {
                wchar_t *dir = dir_list_data[i].name;
                free(dir);
            }
            free(finfo->data);
        }
        free(finfo);
    }
}

static char* toUTF8(const wchar_t* src) {
    if (!src)
        return NULL;

    int len = (int)wcslen(src);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char *buf = (char *)malloc((utf8_len + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf, utf8_len, NULL, NULL);
        buf[utf8_len] = 0;
    }
    return buf;
}

static char* toUTF8_path(const wchar_t* src) {
    if (!src)
        return NULL;

    int add_path = 0;
    if (src[0] != '/')
        add_path = 1;
    int len = (int)wcslen(src);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char* buf = (char*)malloc((utf8_len + add_path  + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf + add_path, utf8_len, NULL, NULL);
        if (add_path)
            buf[0] = '/';
        buf[utf8_len + add_path] = 0;
    }
    return buf;
}

static wchar_t* fromUTF8(const char* src) {
    if (!src)
        return NULL;

    int len = (int)strlen(src);
    int length = MultiByteToWideChar(CP_UTF8, 0, src, len, 0, 0);
    wchar_t* buf = (wchar_t *)malloc((length + 1) * sizeof(wchar_t));
    if (buf) {
        MultiByteToWideChar(CP_UTF8, 0, src, len, buf, length);
        buf[length] = 0;
    }
    return buf;
}

HRESULT StartDirEnumCallback_C(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int res = 0;
    if (f->op.opendir) {
        struct fuse_file_info* finfo = guid_file_info(f, EnumerationId);

        char *dir_name = toUTF8(CallbackData->FilePathName);
        res = f->op.opendir(((dir_name) && (dir_name[0])) ? dir_name : "/", finfo);
        free(dir_name);

        if (res < 0)
            res *= -1;
    }

    return HRESULT_FROM_WIN32(res);
}

HRESULT EndDirEnumCallback_C(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    struct fuse_file_info *finfo = (struct fuse_file_info *)guid_remove_key(f, EnumerationId);
    if (f->op.releasedir) {
        char *dir_name = toUTF8(CallbackData->FilePathName);
        f->op.releasedir(((dir_name) && (dir_name[0])) ? dir_name : "/", finfo);
        free(dir_name);
    }

    if (finfo)
        guid_close(f, EnumerationId);

    return S_OK;
}

static PRJ_FILE_STATE GetFileState(struct fuse* f, const wchar_t *directory, const wchar_t *destinationFileName) {
    wchar_t full_path[MAX_PATH * 3 + 3];

    if ((directory) && (directory[0]))
        _snwprintf(full_path, sizeof(full_path), L"%s/%s/%s", f->ch ? f->ch->path : L"", directory, destinationFileName ? destinationFileName : L"");
    else
        _snwprintf(full_path, sizeof(full_path), L"%s/%s", f->ch ? f->ch->path : L"", destinationFileName ? destinationFileName : L"");

    PRJ_FILE_STATE fileState;
    if (FAILED(PrjGetOnDiskFileState(full_path, &fileState)))
        fileState = 0;

    return fileState;
}

static int fuse_fill_dir(void* buf, const char* name, const struct stat* stbuf, off_t off) {
    struct fuse* f = (struct fuse*)((void**)buf)[0];
    PRJ_DIR_ENTRY_BUFFER_HANDLE DirEntryBufferHandle = (PRJ_DIR_ENTRY_BUFFER_HANDLE)((void**)buf)[1];
    PCWSTR SearchExpression = (PCWSTR)((void**)buf)[2];
    struct fuse_file_info* finfo = (struct fuse_file_info*)((void**)buf)[3];
    PRJ_FILE_BASIC_INFO info;
    struct stat stbuf2;
    char *path = (char *)((void**)buf)[4];

    if ((!finfo) || (!f) || (!DirEntryBufferHandle))
        return -EIO;

    if (off < finfo->offset)
        return 0;

    if ((!name) || ((name[0] == '.') && (name[1] == 0)) || ((name[0] == '.') && (name[1] == '.') && (name[2] == 0))) {
        finfo->session_offset ++;
        return 0;
    }
    memset(&info, 0, sizeof(PRJ_FILE_BASIC_INFO));

    if ((!stbuf) && (f->op.getattr) && (name) && (path) && (path[0])) {
        memset(&stbuf2, 0, sizeof(stbuf2));
        int len_name = (int)strlen(name);
        int len_path = (int)strlen(path);
        char *full_path = (char* )malloc(len_path + len_name + 2);
        if (full_path) {
            memcpy(full_path, path, len_path);
            if (path[len_path - 1] == '/') {
                memcpy(full_path + len_path, name, len_name);
                full_path[len_path + len_name] = 0;
            } else {
                memcpy(full_path + len_path + 1, name, len_name);
                full_path[len_path] = '/';
                full_path[len_path + len_name + 1] = 0;
            }
            if (!f->op.getattr(full_path, &stbuf2))
                stbuf = &stbuf2;
            free(full_path);
        }
    }
    if (stbuf) {
        if (S_ISDIR(stbuf->st_mode))
            info.IsDirectory = TRUE;
        info.CreationTime.QuadPart = LARGE_TIME(stbuf->st_ctime);
        info.ChangeTime.QuadPart = LARGE_TIME(stbuf->st_mtime);
        info.LastAccessTime.QuadPart = LARGE_TIME(stbuf->st_atime);
        info.LastWriteTime.QuadPart = LARGE_TIME(stbuf->st_mtime);
        info.FileSize = stbuf->st_size;

        if ((name) && (name[0] == '.'))
            info.FileAttributes = FILE_ATTRIBUTE_HIDDEN;
        else
            info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }

    wchar_t* dir = fromUTF8(name);

    if (PrjFileNameMatch(dir, SearchExpression)) {
        if ((!finfo->failed_buffer) && (PrjFillDirEntryBuffer(dir, &info, DirEntryBufferHandle) == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)))
            finfo->failed_buffer = 1;

        if (finfo->failed_buffer) {
            struct dirinfo_data *dir_list_data = (struct dirinfo_data *)finfo->data;
            if ((!dir_list_data) && (finfo->data_len >= finfo->data_allocated)) {
                dir_list_data = (struct dirinfo_data *)realloc(dir_list_data, sizeof(struct dirinfo_data) * (finfo->data_allocated + 0x100));
                if (!dir_list_data) {
                    free(dir);
                    return -ENOMEM;
                }
                finfo->data_allocated += 0x100;
                finfo->data = (void *)dir_list_data;
            }

            dir_list_data[finfo->data_len].info = info;
            dir_list_data[finfo->data_len].name = dir;
            finfo->data_len ++;
            // prevent free
            dir = NULL;
        }
    }
    finfo->session_offset ++;

    if (dir)
        free(dir);

    return 0;
}

HRESULT GetDirEnumCallback_C(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId, PCWSTR SearchExpression, PRJ_DIR_ENTRY_BUFFER_HANDLE DirEntryBufferHandle) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int res = ENOENT;
    if (f->op.readdir) {
        struct fuse_file_info* finfo = guid_file_info(f, EnumerationId);

        struct dirinfo_data *dir_list_data = (struct dirinfo_data *)finfo->data;
        if ((finfo->data_len) && (dir_list_data)) {
            int i;
            for (i = 0; i < finfo->data_len; i ++) {
                wchar_t *dir = dir_list_data[i].name;
                HRESULT hr = PrjFillDirEntryBuffer(dir, &dir_list_data[i].info, DirEntryBufferHandle);
                if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
                    break;

                free(dir);
            }
            if (i) {
                int j;
                for (j = 0; j < finfo->data_len - i; j ++)
                    dir_list_data[j] = dir_list_data[j + i];

                finfo->data_len -= i;
            }

            return S_OK;
        }

        // important to avoid unnecessary calls to readdir function
        if (finfo->offset)
            return S_OK;

        char *dir_name = toUTF8(CallbackData->FilePathName);

        void* data[5];
        data[0] = (void *)f;
        data[1] = (void *)DirEntryBufferHandle;
        data[2] = (void *)SearchExpression;
        data[3] = (void *)finfo;
        data[4] = (void *)(((dir_name) && (dir_name[0])) ? dir_name : "/");

        res = f->op.readdir((char *)data[4], data, fuse_fill_dir, finfo->offset, finfo);
        free(dir_name);

        finfo->offset = finfo->session_offset;

        if (res < 0)
            res *= -1;
    }
    return HRESULT_FROM_WIN32(res);
}

HRESULT GetPlaceholderInfoCallback_C(const PRJ_CALLBACK_DATA* CallbackData) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int res = 0;
    if (f->op.getattr) {
        struct stat st_buf;
        memset(&st_buf, 0, sizeof(st_buf));

        char* path = toUTF8_path(CallbackData->FilePathName);
        res = f->op.getattr(path, &st_buf);
        free(path);

        if (!res) {
            PRJ_PLACEHOLDER_INFO info;
            memset(&info, 0, sizeof(PRJ_PLACEHOLDER_INFO));

            info.FileBasicInfo.ChangeTime.QuadPart = LARGE_TIME(st_buf.st_mtime);
            info.FileBasicInfo.CreationTime.QuadPart = LARGE_TIME(st_buf.st_ctime);
            info.FileBasicInfo.LastAccessTime.QuadPart = LARGE_TIME(st_buf.st_atime);
            info.FileBasicInfo.LastWriteTime.QuadPart = LARGE_TIME(st_buf.st_mtime);
            info.FileBasicInfo.FileSize = st_buf.st_size;

            if (S_ISDIR(st_buf.st_mode))
                info.FileBasicInfo.IsDirectory = TRUE;

            info.FileBasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;

            PrjWritePlaceholderInfo(f->instanceHandle, CallbackData->FilePathName, &info, sizeof(info));
        }

        if (res < 0)
            res *= -1;
    }
    return HRESULT_FROM_WIN32(res);
}

HRESULT GetFileDataCallback_C(const PRJ_CALLBACK_DATA* CallbackData, UINT64 ByteOffset, UINT32 Length) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int res = ENOENT;

    struct stat st_buf;
    memset(&st_buf, 0, sizeof(st_buf));

    char *path = toUTF8_path(CallbackData->FilePathName);

    int err = 0;

    if ((!err) && (f->op.read)) {
        char *buffer = (char *)PrjAllocateAlignedBuffer(f->instanceHandle, Length);
        if (buffer) {
            struct fuse_file_info *finfo = guid_file_info(f, &CallbackData->FileId);
            off_t buffer_offset = 0;
            do {
                err = f->op.read(path, buffer + buffer_offset, Length - buffer_offset, (off_t)ByteOffset + buffer_offset, finfo);
                if (err > 0)
                    buffer_offset += err;
                if (buffer_offset >= Length)
                    break;
            } while (err > 0);

            PrjWriteFileData(f->instanceHandle, &CallbackData->DataStreamId, buffer, ByteOffset, buffer_offset);
            PrjFreeAlignedBuffer(buffer);
            if (err > 0)
                err = 0;
        }
    }

    free(path);

    res = err;

    if (res < 0)
        res *= -1;

    return HRESULT_FROM_WIN32(res);
}

static int fuse_sync_full_sync(struct fuse *f, char *path, PCWSTR DestinationFileName, struct fuse_file_info *finfo) {
    if (!f->op.write)
        return -EACCES;

    char full_path[4096];
    full_path[0] = 0;

    int err = 0;

    snprintf(full_path, sizeof(full_path), "%s/%s", f->path_utf8, path);

    FILE* local_file = fopen(full_path, "rb");
    if (!local_file)
        return -EACCES;

    char buffer[8192];
    off_t offset = 0;
    while (!feof(local_file)) {
        size_t bytes = fread(buffer, 1, sizeof(buffer), local_file);
        if (bytes <= 0) {
            if (bytes < 0)
                err = -EIO;
            break;
        }
        off_t written = 0;
        do {
            err = f->op.write(path, buffer + written, bytes - written, offset + written, finfo);
            if (err <= 0)
                break;

            written += err;
        } while (written < bytes);

        if (written != bytes)
            break;

        offset += written;
    }
    if (err > 0)
        err = 0;
    fclose(local_file);

    if (f->op.flush)
        f->op.flush(path, finfo);

    if (f->op.fsync)
        f->op.fsync(path, 0, finfo);

    if (f->op.truncate)
        f->op.truncate(path, offset);

    if (f->op.utimens) {
        struct stat st_buf;
        if (!stat(full_path, &st_buf)) {
            struct timespec tv[2];
            tv[0].tv_sec = st_buf.st_atime;
            tv[0].tv_nsec = 0;
            tv[1].tv_sec = st_buf.st_mtime;
            tv[1].tv_nsec = 0;
            f->op.utimens(path, tv);
        }
    }

    return err;
}

HRESULT NotificationCallback_C(const PRJ_CALLBACK_DATA *CallbackData, BOOLEAN IsDirectory, PRJ_NOTIFICATION NotificationType, PCWSTR DestinationFileName, PRJ_NOTIFICATION_PARAMETERS *NotificationParameters) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;


    int ret = EACCES;
    struct fuse_file_info *finfo;
    char* path = NULL;
    int err = 0;

    PRJ_UPDATE_FAILURE_CAUSES err_cause = PRJ_UPDATE_FAILURE_CAUSE_NONE;

    switch (NotificationType) {
        case PRJ_NOTIFICATION_FILE_OVERWRITTEN:
            PrjDeleteFile(f->instanceHandle, CallbackData->FilePathName, PRJ_UPDATE_ALLOW_DIRTY_DATA | PRJ_UPDATE_ALLOW_DIRTY_METADATA | PRJ_UPDATE_ALLOW_READ_ONLY | PRJ_UPDATE_ALLOW_TOMBSTONE, &err_cause);
            // no break here
        case PRJ_NOTIFICATION_FILE_OPENED:
            ret = 0;
            if (!IsDirectory) {
                if (f->op.open) {
                    finfo = guid_file_info(f, &CallbackData->FileId);
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.open(path, finfo);
                    if (!ret)
                        file_opened(f, path);
                }
            }
            break;
        case PRJ_NOTIFICATION_NEW_FILE_CREATED:
            if (IsDirectory) {
                if (f->op.mkdir) {
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.mkdir(path, 0755);
                }
            } else {
                if (f->op.create) {
                    finfo = guid_file_info(f, &CallbackData->FileId);
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.create(path, 0755, finfo);
                    if (!ret)
                        file_opened(f, path);
                }
            }
            break;
        case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_NO_MODIFICATION:
        case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED:            
        case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED:
            if (!IsDirectory) {
                path = toUTF8_path(CallbackData->FilePathName);
                finfo = guid_file_info(f, &CallbackData->FileId);
                if (NotificationType == PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED) {
                    if (GetFileState(f, NULL, CallbackData->FilePathName) & PRJ_FILE_STATE_FULL) {
                        if (f->op.write) {
                            err = fuse_sync_full_sync(f, path, CallbackData->FilePathName, finfo);
                        } else
                            err = EACCES;
                        PrjDeleteFile(f->instanceHandle, CallbackData->FilePathName, PRJ_UPDATE_ALLOW_DIRTY_DATA | PRJ_UPDATE_ALLOW_DIRTY_METADATA | PRJ_UPDATE_ALLOW_READ_ONLY | PRJ_UPDATE_ALLOW_TOMBSTONE, &err_cause);
                    }
                }
                if (f->op.release)
                    ret = f->op.release(path, finfo);

                if (!file_closed(f, path))
                    PrjDeleteFile(f->instanceHandle, CallbackData->FilePathName, PRJ_UPDATE_ALLOW_DIRTY_DATA | PRJ_UPDATE_ALLOW_DIRTY_METADATA | PRJ_UPDATE_ALLOW_READ_ONLY | PRJ_UPDATE_ALLOW_TOMBSTONE, &err_cause);

                if ((!ret) && (err))
                    ret = err;
                guid_close(f, &CallbackData->FileId);
            } else
                PrjDeleteFile(f->instanceHandle, CallbackData->FilePathName, PRJ_UPDATE_ALLOW_DIRTY_DATA | PRJ_UPDATE_ALLOW_DIRTY_METADATA | PRJ_UPDATE_ALLOW_READ_ONLY | PRJ_UPDATE_ALLOW_TOMBSTONE, &err_cause);

            // no break on delete to trigger the delete events
            if (NotificationType != PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED)
                break;
        case PRJ_NOTIFICATION_PRE_DELETE:
            if (IsDirectory) {
                if (f->op.rmdir) {
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.rmdir(path);
                }
            } else {
                if (f->op.unlink) {
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.unlink(path);
                }
            }
            break;
        case PRJ_NOTIFICATION_PRE_RENAME:
            if (f->op.rename) {
                path = toUTF8_path(CallbackData->FilePathName);
                char *path2 = toUTF8_path(DestinationFileName);
                ret = f->op.rename(path, path2, 0);
                free(path2);
            }
            break;
        case PRJ_NOTIFICATION_PRE_SET_HARDLINK:
            break;
        case PRJ_NOTIFICATION_FILE_RENAMED:
            err = 0;
            break;
        case PRJ_NOTIFICATION_HARDLINK_CREATED:
            break;
        case PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL:
            if (!IsDirectory) {
                finfo = guid_data(f, &CallbackData->FileId);
                if (finfo)
                    finfo->needs_sync = 1;
                ret = 0;
            }
            break;
    }
    if (ret < 0)
        ret *= -1;
    if (path)
        free(path);
    return HRESULT_FROM_WIN32(ret);
}

static int DeleteDirectory(const char *sPath) {
    HANDLE hFind;
    WIN32_FIND_DATA FindFileData;

    char DirPath[MAX_PATH];
    char FileName[MAX_PATH];

    strcpy(DirPath, sPath);
    strcat(DirPath,"\\*");
    strcpy(FileName,sPath);
    strcat(FileName,"\\");

    hFind = FindFirstFile(DirPath, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;

    strcpy(DirPath, FileName);
        
    int bSearch = 1;
    while (bSearch) {
        if (FindNextFile(hFind, &FindFileData)) {
            if ((!strcmp(FindFileData.cFileName, ".")) || (!strcmp(FindFileData.cFileName,"..")))
                continue;
            strcat(FileName, FindFileData.cFileName);
            if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!DeleteDirectory(FileName)) { 
                    FindClose(hFind); 
                    return 0;
                }
                RemoveDirectory(FileName);
                strcpy(FileName, DirPath);
            } else {
                if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                    _chmod(FileName, _S_IWRITE);
                if (!DeleteFile(FileName)) {
                    FindClose(hFind); 
                    return 0; 
                }                 
                strcpy(FileName, DirPath);
            }
        } else {
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                bSearch = 0;
            } else {
                FindClose(hFind); 
                return 0;
            }

        }
    }
    FindClose(hFind);
 
    return RemoveDirectory(sPath);
}

static int VirtualFS_stop(struct fuse* this_ref) {
    if (!this_ref)
        return -1;

    this_ref->running = 0;
    PrjStopVirtualizing(this_ref->instanceHandle);

    DeleteDirectory(this_ref->path_utf8);
    return 0;
}

int fuse_enable_service() {
    return system("powershell Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart");
}


struct fuse* fuse_new(struct fuse_chan *ch, void *args, const struct fuse_operations *op, size_t op_size, void *private_data) {
    struct fuse* this_ref = (struct fuse*)malloc(sizeof(struct fuse));
    if (!this_ref)
        return NULL;

    memset(this_ref, 0, sizeof(struct fuse));

    this_ref->notificationMappings[0].NotificationRoot = L"";
    this_ref->notificationMappings[0].NotificationBitMask = PRJ_NOTIFY_FILE_OPENED | PRJ_NOTIFY_NEW_FILE_CREATED | PRJ_NOTIFY_FILE_OVERWRITTEN | PRJ_NOTIFY_PRE_DELETE | PRJ_NOTIFY_PRE_RENAME | PRJ_NOTIFY_PRE_SET_HARDLINK | PRJ_NOTIFY_FILE_RENAMED | PRJ_NOTIFY_HARDLINK_CREATED | PRJ_NOTIFY_FILE_HANDLE_CLOSED_NO_MODIFICATION | PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED | PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_DELETED | PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL;

    // this_ref->options.PoolThreadCount = 1;
    // this_ref->options.ConcurrentThreadCount = 1;
    this_ref->options.NotificationMappings = this_ref->notificationMappings;
    this_ref->options.NotificationMappingsCount = 1;

    this_ref->callbacks.StartDirectoryEnumerationCallback = StartDirEnumCallback_C;
    this_ref->callbacks.EndDirectoryEnumerationCallback = EndDirEnumCallback_C;
    this_ref->callbacks.GetDirectoryEnumerationCallback = GetDirEnumCallback_C;
    this_ref->callbacks.GetPlaceholderInfoCallback = GetPlaceholderInfoCallback_C;
    this_ref->callbacks.GetFileDataCallback = GetFileDataCallback_C;
    this_ref->callbacks.NotificationCallback = NotificationCallback_C;

    if (op)
        this_ref->op = *op;

    if (this_ref->op.init) {
        struct fuse_config cfg = {0};
        this_ref->op.init(&this_ref->connection, &cfg);
    }
    this_ref->guids = kh_init(guid);
    this_ref->files = kh_init(filecounter);
    this_ref->user_data = private_data;

    if (ch) {
        ch->fs = this_ref;
        this_ref->path_utf8 = toUTF8(ch->path);
    }
    this_ref->ch = ch;
    this_ref->sem = CreateSemaphore(NULL, 1, 0xFFFF, NULL);
    return this_ref;
}

struct fuse_chan *fuse_mount(const char *mountpoint, void *args) {
    const char *def_mnt = "gyro";
    if (!mountpoint)
        mountpoint = def_mnt;

    struct fuse_chan *ch = (struct fuse_chan*)malloc(sizeof(struct fuse_chan));
    if (!ch)
        return NULL;

    MultiByteToWideChar(CP_UTF8, 0, mountpoint, (int)strlen(mountpoint), ch->path, MAX_PATH);

    GUID instanceId;
    CreateDirectoryA(mountpoint, NULL);
    if (FAILED(CoCreateGuid(&instanceId))) {
        free(ch);
        return NULL;
    }

    if (FAILED(PrjMarkDirectoryAsPlaceholder(ch->path, NULL, NULL, &instanceId))) {
        free(ch);
        return NULL;
    }

    return ch;
}

void fuse_unmount(const char *dir, struct fuse_chan *ch) {
    // not implemented
}

int fuse_set_signal_handlers(struct fuse *se) {
    if (!se)
        return -1;

    // not implemented

    return 0;
}

struct fuse *fuse_get_session(struct fuse *f) {
    return f;
}

void fuse_remove_signal_handlers(struct fuse *se) {
    // not implemented
}


int fuse_loop(struct fuse* f) {
    if ((!f) || (!f->ch))
        return -1;

    HRESULT hr = PrjStartVirtualizing(f->ch->path, &f->callbacks, f, &f->options, &f->instanceHandle);
    if (FAILED(hr))
        return -1;
    else
        f->running = 1;

    while (f->running == 1)
        Sleep(100);

    f->running = -1;
    return 0;
}

int fuse_loop_mt(struct fuse* f) {
    return fuse_loop(f);
}

void fuse_exit(struct fuse* f) {
    if ((f) && (f->running == 1)) {
        VirtualFS_stop(f);
        f->running = -1;
    }
}

void fuse_destroy(struct fuse* f) {
    if (f) {
        if (f->op.init)
            f->op.destroy(f->user_data);

        kh_destroy(guid, f->guids);
        kh_destroy(filecounter, f->files);
        free(f->path_utf8);

        CloseHandle(f->sem);
        free(f);
    }
}
