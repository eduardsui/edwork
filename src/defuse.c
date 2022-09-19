#pragma comment(lib, "CldApi")

#define _CRT_SECURE_NO_WARNINGS

#define _WIN32_WINNT    0x0A00

#include "defuse.h"

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <WinBase.h>
#include <Unknwn.h>
#include <cfapi.h>
#include <sddl.h>

#ifndef S_ISDIR
    #define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif
#define LARGE_TIME(src) ((unsigned __int64)src)*10000000 + 116444736000000000LL;

#define FIELD_SIZE( type, field ) ( sizeof( ( (type*)0 )->field ) )
#define CF_SIZE_OF_OP_PARAM( field )                                           \
    ( FIELD_OFFSET( CF_OPERATION_PARAMETERS, field ) +                         \
      FIELD_SIZE( CF_OPERATION_PARAMETERS, field ) )

struct fuse_chan {
    wchar_t path[MAX_PATH + 1];
    struct fuse *fs;
};

struct fuse {
    struct fuse_operations op;
    struct fuse_conn_info connection;
    struct fuse_chan* ch;
    void *user_data;
    char *path_utf8;
    CF_CONNECTION_KEY s_transferCallbackConnectionKey;
    char running;
};

static char *toUTF8(const wchar_t *src) {
    if (!src)
        return NULL;

    int len = (int)wcslen(src);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char* buf = (char*)malloc((utf8_len + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf, utf8_len, NULL, NULL);
        buf[utf8_len] = 0;
    }
    return buf;
}

static char *toUTF8_path(const wchar_t *src, int bytes_len) {
    if ((!src) || (!src[0]) || (bytes_len <= 0))
        return _strdup("/");

    int add_path = 0;
    if (src[0] != '/')
        add_path = 1;
    int len = bytes_len / 2;
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char *buf = (char *)malloc((utf8_len + add_path + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf + add_path, utf8_len, NULL, NULL);
        if (add_path)
            buf[0] = '/';
        buf[utf8_len + add_path] = 0;
    }
    return buf;
}

static wchar_t *fromUTF8(const char *src) {
    if (!src)
        src = "";

    int len = (int)strlen(src);
    int length = MultiByteToWideChar(CP_UTF8, 0, src, len, 0, 0);
    wchar_t* buf = (wchar_t*)malloc((length + 1) * sizeof(wchar_t));
    if (buf) {
        MultiByteToWideChar(CP_UTF8, 0, src, len, buf, length);
        buf[length] = 0;
    }
    return buf;
}

int fuse_is_read_only(struct fuse *f, const char *path) {
    int read_only = 0;

    if ((f) && (f->op.statfs)) {
        struct statvfs stbuf;

        if (!f->op.statfs(path, &stbuf)) {
            if ((!stbuf.f_bfree) || (!stbuf.f_bavail ) || (!stbuf.f_ffree) || (!stbuf.f_favail))
                read_only = 1;
        }
    }
    return read_only;
}

void CALLBACK OnFetchData(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse*)callbackInfo->CallbackContext;

    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opInfo.RequestKey = callbackInfo->RequestKey;

    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(TransferData);
    opParams.TransferData.CompletionStatus = STATUS_SUCCESS;
    opParams.TransferData.Offset.QuadPart = 0;
    opParams.TransferData.Length.QuadPart = 0;

    int open_err = 0;
    struct fuse_file_info finfo = { 0 };
    char *path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
    if (f->op.open)
        open_err = f->op.open(path, &finfo);

    char buf[8192];
    if (open_err) {
        opParams.TransferData.Buffer = buf;
        opParams.TransferData.Offset.QuadPart = callbackParameters->FetchData.RequiredFileOffset.QuadPart;
        opParams.TransferData.Length.QuadPart = callbackParameters->FetchData.RequiredLength.QuadPart;
        opParams.TransferData.CompletionStatus = STATUS_UNSUCCESSFUL;

        CfExecute(&opInfo, &opParams);
    } else {
        if (f->op.read) {
            __int64 size = (__int64)callbackParameters->FetchData.RequiredLength.QuadPart;
            __int64 offset = (__int64)callbackParameters->FetchData.RequiredFileOffset.QuadPart;

            LARGE_INTEGER ProviderProgressCompleted = { 0 };

            __int64 read_size = size;
            if (read_size > sizeof(buf))
                read_size = sizeof(buf);

            do {
                int err = f->op.read(path, buf, read_size, offset, &finfo);
                if (err < 0) {
                    opParams.TransferData.CompletionStatus = NTSTATUS_FROM_WIN32(EIO);
                    opParams.TransferData.Buffer = buf;
                    opParams.TransferData.Offset.QuadPart = callbackParameters->FetchData.RequiredFileOffset.QuadPart;//offset;
                    opParams.TransferData.Length.QuadPart = callbackParameters->FetchData.RequiredLength.QuadPart;//size;
                    CfExecute(&opInfo, &opParams);
                    break;
                } else {
                    opParams.TransferData.Buffer = buf;
                    opParams.TransferData.Offset.QuadPart = offset;
                    opParams.TransferData.Length.QuadPart = err;
                    opParams.TransferData.CompletionStatus = STATUS_SUCCESS;
                    
                    CfExecute(&opInfo, &opParams);

                    ProviderProgressCompleted.QuadPart += err;
                    CfReportProviderProgress(callbackInfo->ConnectionKey, callbackInfo->TransferKey, callbackParameters->FetchData.RequiredLength, ProviderProgressCompleted);


                    size -= err;
                    offset += err;

                    if (size < read_size)
                        read_size = size;
                }
            } while (size > 0);
        }

        if (f->op.release)
            f->op.release(path, &finfo);
    }

    free(path);
}

void CALLBACK OnFileOpen(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    // to do
}

static int is_modified(struct fuse *f, char *path, char *full_path) {
    struct stat st_buf = { 0 };

    FILE* local_file = NULL;
    
    int err = fopen_s(&local_file, full_path, "rb");
    if (!local_file)
        return 0;

    __int64 fuse_file_size = 0;
    int has_stat = 0;
    if ((f->op.getattr) && (!f->op.getattr(path, &st_buf))) {
        fuse_file_size = st_buf.st_size;
        has_stat = 1;
    }

    _fseeki64(local_file, 0, SEEK_END);
    __int64 fsize = _ftelli64(local_file);
    _fseeki64(local_file, 0, SEEK_SET);

    if ((fuse_file_size == fsize) && (has_stat)) {
        struct stat st_buf2 = { 0 };

        if (!stat(full_path, &st_buf2)) {
            if (st_buf.st_mtime == st_buf2.st_mtime) {
                // no change
                fclose(local_file);
                return 0;
            }
        }
    }

    fclose(local_file);
    return 1;
}

static int fuse_sync_full_sync(struct fuse *f, char *path, char *full_path) {
    struct fuse_file_info finfo = { 0 };

    if (!f->op.write)
        return -EACCES;

    int err = 0;
    struct stat st_buf = { 0 };

    FILE* local_file = NULL;
    
    err = fopen_s(&local_file, full_path, "rb");
    if (!local_file)
        return -EACCES;

    if (f->op.truncate) {
        __int64 fuse_file_size = 0;
        int has_stat = 0;
        if ((f->op.getattr) && (!f->op.getattr(path, &st_buf))) {
            fuse_file_size = st_buf.st_size;
            has_stat = 1;
        }

        _fseeki64(local_file, 0, SEEK_END);
        __int64 fsize = _ftelli64(local_file);
        _fseeki64(local_file, 0, SEEK_SET);

        if (fsize < fuse_file_size)
            f->op.truncate(path, fsize);
    }

    if (f->op.open) {
        err = f->op.open(path, &finfo);
        if (err) {
            fclose(local_file);
            return err;
        }
    }

    char buffer[8192];
    off_t offset = 0;
    while (!feof(local_file)) {
        size_t bytes = fread(buffer, 1, sizeof(buffer), local_file);
        if (bytes <= 0) {
            if (bytes < 0)
                err = -EIO;
            break;
        }
        buffer[bytes] = 0;

        off_t written = 0;
        do {
            err = f->op.write(path, buffer + written, bytes - written, offset + written, &finfo);
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
        f->op.flush(path, &finfo);

    if (f->op.fsync)
        f->op.fsync(path, 0, &finfo);

    if (f->op.utimens) {
        if (!stat(full_path, &st_buf)) {
            struct timespec tv[2];
            tv[0].tv_sec = st_buf.st_atime;
            tv[0].tv_nsec = 0;
            tv[1].tv_sec = st_buf.st_mtime;
            tv[1].tv_nsec = 0;
            f->op.utimens(path, tv);
        }
    }

    if (f->op.release)
        f->op.release(path, &finfo);

    return err;
}

void CALLBACK OnFileClose(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse*)callbackInfo->CallbackContext;

    HANDLE h;
    HRESULT hr = CfOpenFileWithOplock(callbackInfo->NormalizedPath, CF_OPEN_FILE_FLAG_EXCLUSIVE, &h);
    if (hr == S_OK) {
        LARGE_INTEGER start;
        LARGE_INTEGER len;
        start.QuadPart = 0;
        len.QuadPart = -1;
        hr = CfDehydratePlaceholder(h, start, len, CF_DEHYDRATE_FLAG_NONE, NULL);
        // not in sync
        if (hr == 0x80070179) {
            char *path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
            char *full_path = toUTF8(callbackInfo->NormalizedPath);
            if (!is_modified(f, path, full_path)) {
                CfCloseHandle(h);
                CfOpenFileWithOplock(callbackInfo->NormalizedPath, CF_OPEN_FILE_FLAG_EXCLUSIVE, &h);
                CfSetInSyncState(h, CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, NULL);
                CfCloseHandle(h);
                free(path);
                free(full_path);
                return;
            }
            CfOpenFileWithOplock(callbackInfo->NormalizedPath, CF_OPEN_FILE_FLAG_EXCLUSIVE, &h);
            if ((!(callbackParameters->CloseCompletion.Flags & CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED)) && (f->op.write)) {
                if (!fuse_is_read_only(f, path))
                    fuse_sync_full_sync(f, path, full_path);
            }
            free(full_path);
            free(path);
        }

        if (FAILED(hr)) {
            CfCloseHandle(h);

            // reopen file!
            CfOpenFileWithOplock(callbackInfo->NormalizedPath, CF_OPEN_FILE_FLAG_EXCLUSIVE, &h);
            CfSetInSyncState(h, CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, NULL);
            CfDehydratePlaceholder(h, start, len, CF_DEHYDRATE_FLAG_NONE, NULL);
        }

        CfCloseHandle(h);
    }
}

void CALLBACK OnFileDelete(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse *)callbackInfo->CallbackContext;
    int err = -1;

    char *path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
    if (!fuse_is_read_only(f, path)) {
        if (callbackParameters->Delete.Flags & CF_CALLBACK_DELETE_FLAG_IS_DIRECTORY) {
            if (f->op.rmdir)
                err = f->op.rmdir(path);
        } else {
            if (f->op.unlink)
                err = f->op.unlink(path);
        }
    }
    free(path);
    
    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_ACK_DELETE;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(AckDelete);
    opParams.AckDelete.CompletionStatus = err ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
    opParams.AckDelete.Flags = CF_OPERATION_ACK_DELETE_FLAG_NONE;

    CfExecute(&opInfo, &opParams);
}

void CALLBACK OnFileRename(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse*)callbackInfo->CallbackContext;
    int err = -1;
    char *path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
    char *path2;

    if ((f->op.rename) && (!fuse_is_read_only(f, path))) {
        path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
        path2 = toUTF8_path(callbackParameters->Rename.TargetPath, callbackParameters->Rename.TargetPath ? wcslen(callbackParameters->Rename.TargetPath) : 0);
        err = f->op.rename(path, path2, 0);
        free(path);
        free(path2);
    }

    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_ACK_RENAME;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(AckRename);
    opParams.AckRename.CompletionStatus = err ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
    opParams.AckRename.Flags = CF_OPERATION_ACK_RENAME_FLAG_NONE;

    CfExecute(&opInfo, &opParams);
}

static int fuse_fill_dir(void *buf, const char *name, const struct stat *stbuf, off_t off) {
    struct fuse *f = (struct fuse*)((void**)buf)[0];
    CF_PLACEHOLDER_CREATE_INFO **placeholders = (CF_PLACEHOLDER_CREATE_INFO **)((void **)buf)[1];
    unsigned int *placeholders_count = (unsigned int *)((void**)buf)[2];
    struct fuse_file_info* finfo = (struct fuse_file_info*)((void**)buf)[3];
    struct stat stbuf2;
    char* path = (char*)((void**)buf)[4];
    PCWSTR SearchExpression = (PCWSTR)((void**)buf)[5];

    if ((!finfo) || (!f))
        return -EIO;

    if (off < finfo->offset)
        return 0;

    int len_name = name ? (int)strlen(name) : 0;
    int len_path = path ? (int)strlen(path) : 0;
    char* full_path = (char*)malloc(len_path + len_name + 2);

    if (full_path) {
        memcpy(full_path, path, len_path);
        if (path[len_path - 1] == '/') {
            memcpy(full_path + len_path, name, len_name);
            full_path[len_path + len_name] = 0;
        } else {
            full_path[len_path] = '/';
            memcpy(full_path + len_path + 1, name, len_name);
            full_path[len_path + len_name + 1] = 0;
        }
    }

    if ((!stbuf) && (f->op.getattr) && (name) && (path) && (path[0])) {
        memset(&stbuf2, 0, sizeof(stbuf2));
        if ((!strcmp(name, ".")) || (!strcmp(name, ".."))) {
            if (!f->op.getattr(path, &stbuf2))
                stbuf = &stbuf2;
        } else {
            if (!f->op.getattr(full_path, &stbuf2))
                stbuf = &stbuf2;
        }
    }
    CF_PLACEHOLDER_CREATE_INFO *placeholders2 = (CF_PLACEHOLDER_CREATE_INFO *)realloc(*placeholders, sizeof(CF_PLACEHOLDER_CREATE_INFO) * ((*placeholders_count) + 1));
    if (!placeholders2)
        return -ENOMEM;

    *placeholders = placeholders2;

    CF_PLACEHOLDER_CREATE_INFO *placeholder = &placeholders2[*placeholders_count];
    (*placeholders_count) ++;

    memset(placeholder, 0, sizeof(CF_PLACEHOLDER_CREATE_INFO));

    wchar_t* wname = fromUTF8(full_path);
    placeholder->FileIdentity = wname;
    placeholder->FileIdentityLength = (DWORD)(wcslen(wname) * sizeof(wchar_t));
    placeholder->RelativeFileName = fromUTF8(name);

    // do not free wname nor placeholder->RelativeFileName here (it will be freed by OnFetchPlaceholders)

    placeholder->Flags = CF_PLACEHOLDER_CREATE_FLAG_NONE;
    if (stbuf) {
        if (S_ISDIR(stbuf->st_mode))
            placeholder->FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;

        placeholder->FsMetadata.BasicInfo.CreationTime.QuadPart = LARGE_TIME(stbuf->st_ctime);
        placeholder->FsMetadata.BasicInfo.ChangeTime.QuadPart = LARGE_TIME(stbuf->st_mtime);
        placeholder->FsMetadata.BasicInfo.LastAccessTime.QuadPart = LARGE_TIME(stbuf->st_atime);
        placeholder->FsMetadata.BasicInfo.LastWriteTime.QuadPart = LARGE_TIME(stbuf->st_mtime);
        placeholder->FsMetadata.FileSize.QuadPart = stbuf->st_size;

        if ((name) && (name[0] == '.'))
            placeholder->FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
        else
            placeholder->FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_NORMAL;
    }

    finfo->session_offset++;

    return 0;
}

void CALLBACK OnFetchPlaceholders(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opInfo.RequestKey = callbackInfo->RequestKey;

    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(TransferPlaceholders);
    opParams.TransferPlaceholders.CompletionStatus = STATUS_SUCCESS;
    struct fuse *f = (struct fuse*)callbackInfo->CallbackContext;

    CF_PLACEHOLDER_CREATE_INFO *placeholders = NULL;
    unsigned int placeholders_count = 0;

    if (f) {

        struct fuse_file_info fi = { 0 };
        int open_err = 0;
        char *path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);

        if (f->op.opendir) {
            open_err = f->op.opendir(path, &fi);
            if (open_err)
                opParams.TransferPlaceholders.CompletionStatus = STATUS_UNSUCCESSFUL;
        }

        if (!open_err) {
            if (f->op.readdir) {

                void* data[6];
                data[0] = (void*)f;
                data[1] = (void*)&placeholders;
                data[2] = (void*)&placeholders_count;
                data[3] = (void*)&fi;
                data[4] = (void*)path;
                data[5] = (void*)callbackParameters->FetchPlaceholders.Pattern;

                int err = f->op.readdir(path, data, fuse_fill_dir, fi.offset, &fi);
                if (err)
                    opParams.TransferPlaceholders.CompletionStatus = STATUS_UNSUCCESSFUL;

                opParams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;//CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION;
                opParams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = placeholders_count;
                opParams.TransferPlaceholders.PlaceholderCount = placeholders_count;
                opParams.TransferPlaceholders.PlaceholderArray = placeholders;
            }

            if ((f->op.releasedir) && (!open_err))
                f->op.releasedir(path, &fi);
        }

        free(path);
    }

    CfExecute(&opInfo, &opParams);

    unsigned int i;
    for (i = 0; i < placeholders_count; i++) {
        free((void *)placeholders[i].FileIdentity);
        free((void *)placeholders[i].RelativeFileName);
    }
    free(placeholders);
}

void CALLBACK OnValidateData(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    // to do
}

struct fuse_chan *fuse_mount(const char *dir, void* args) {
    const char* def_mnt = "defuse";
    if (!dir)
        dir = def_mnt;

    struct fuse_chan* ch = (struct fuse_chan *)malloc(sizeof(struct fuse_chan));
    if (!ch)
        return NULL;

    memset(ch, 0, sizeof(struct fuse_chan));

    CF_SYNC_REGISTRATION CfSyncRegistration = { 0 };
    CfSyncRegistration.StructSize = sizeof(CF_SYNC_REGISTRATION);
    CfSyncRegistration.ProviderName = L"edwork";
    CfSyncRegistration.ProviderVersion = L"1.0";
    CfSyncRegistration.ProviderId = (GUID){ 0x328cd0f9, 0x9f45, 0x4d22, { 0x90, 0x86, 0x73, 0x8a, 0xe5, 0x83, 0x5c, 0x20 } };

    CF_SYNC_POLICIES CfSyncPolicies = { 0 };
    CfSyncPolicies.StructSize = sizeof(CF_SYNC_POLICIES);
    CfSyncPolicies.HardLink = CF_HARDLINK_POLICY_NONE;
    CfSyncPolicies.Hydration.Primary = CF_HYDRATION_POLICY_PROGRESSIVE;
    CfSyncPolicies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED | CF_HYDRATION_POLICY_MODIFIER_AUTO_DEHYDRATION_ALLOWED;
    CfSyncPolicies.InSync = CF_INSYNC_POLICY_TRACK_FILE_LAST_WRITE_TIME | CF_INSYNC_POLICY_TRACK_DIRECTORY_LAST_WRITE_TIME;
    CfSyncPolicies.Population.Primary = CF_POPULATION_POLICY_FULL;
    CfSyncPolicies.Population.Modifier = CF_POPULATION_POLICY_MODIFIER_NONE;
    CfSyncPolicies.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_CREATE_UNRESTRICTED | CF_PLACEHOLDER_MANAGEMENT_POLICY_CONVERT_TO_UNRESTRICTED | CF_PLACEHOLDER_MANAGEMENT_POLICY_UPDATE_UNRESTRICTED;

    MultiByteToWideChar(CP_UTF8, 0, dir, (int)strlen(dir), ch->path, MAX_PATH);

    CreateDirectoryW(ch->path, NULL);

    HRESULT hr = CfRegisterSyncRoot(ch->path, &CfSyncRegistration, &CfSyncPolicies, CF_REGISTER_FLAG_NONE);
    if (FAILED(hr)) {
        CfUnregisterSyncRoot(ch->path);
        RemoveDirectoryW(ch->path);
        free(ch);
        return NULL;
    }

    return ch;
}

int fuse_loop(struct fuse *f) {
    CF_CALLBACK_REGISTRATION callbackTable[] = {
        { CF_CALLBACK_TYPE_FETCH_DATA, OnFetchData },
        { CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION, OnFileOpen },
        { CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION, OnFileClose },
        { CF_CALLBACK_TYPE_NOTIFY_DELETE, OnFileDelete },
        { CF_CALLBACK_TYPE_NOTIFY_RENAME, OnFileRename },
        { CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, OnFetchPlaceholders },
        { CF_CALLBACK_TYPE_VALIDATE_DATA, OnValidateData },
        CF_CALLBACK_REGISTRATION_END
    };

    if ((!f) || (!f->ch))
        return -1;

    HRESULT hr = CfConnectSyncRoot(f->ch->path, callbackTable, f, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &f->s_transferCallbackConnectionKey);

    if (FAILED(hr))
        return -1;
    else
        f->running = 1;

    while (f->running == 1)
        Sleep(100);

    f->running = -1;
    return 0;
}

int fuse_loop_mt(struct fuse *f) {
    return fuse_loop(f);
}

static int DeleteDirectory(const wchar_t *sPath) {
    HANDLE hFind;
    WIN32_FIND_DATAW FindFileData;

    wchar_t DirPath[4096];
    wchar_t FileName[4096];

    wcscpy(DirPath, sPath);
    wcscat(DirPath, L"\\*");
    wcscpy(FileName, sPath);
    wcscat(FileName, L"\\");

    hFind = FindFirstFileW(DirPath, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;

    wcscpy(DirPath, FileName);

    int bSearch = 1;
    while (bSearch) {
        if (FindNextFileW(hFind, &FindFileData)) {
            if ((!wcscmp(FindFileData.cFileName, L".")) || (!wcscmp(FindFileData.cFileName, L"..")))
                continue;
            wcscat(FileName, FindFileData.cFileName);
            if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!DeleteDirectory(FileName)) {
                    FindClose(hFind);
                    return 0;
                }
                RemoveDirectoryW(FileName);
                wcscpy(FileName, DirPath);
            } else {
                if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                    _wchmod(FileName, _S_IWRITE);
                if (!DeleteFileW(FileName)) {
                    FindClose(hFind);
                    return 0;
                }
                wcscpy(FileName, DirPath);
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

    return RemoveDirectoryW(sPath);
}

struct fuse *fuse_new(struct fuse_chan *ch, void *args, const struct fuse_operations *op, size_t op_size, void* private_data) {
    if (!ch)
        return NULL;

    struct fuse* this_ref = (struct fuse*)malloc(sizeof(struct fuse));
    if (!this_ref)
        return NULL;

    memset(this_ref, 0, sizeof(struct fuse));

    if (op)
        this_ref->op = *op;

    if (this_ref->op.init) {
        struct fuse_config cfg = { 0 };
        this_ref->op.init(&this_ref->connection, &cfg);
    }
    this_ref->user_data = private_data;

    if (ch) {
        ch->fs = this_ref;
        this_ref->path_utf8 = toUTF8(ch->path);
    }
    this_ref->ch = ch;
    return this_ref;
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

void fuse_exit(struct fuse *f) {
    if ((f) && (f->running == 1)) {
        CfDisconnectSyncRoot(f->s_transferCallbackConnectionKey);
        if (f->ch) {
            CfUnregisterSyncRoot(f->ch->path);
            DeleteDirectory(f->ch->path);
        }
        f->running = -1;
    }
}

int fuse_reload(struct fuse *f) {
    if ((!f) || (!f->ch))
        return -1;

    return 0;
}

void fuse_destroy(struct fuse *f) {
    if (f) {
        if (f->op.init)
            f->op.destroy(f->user_data);

        free(f->path_utf8);
        free(f);
    }
}