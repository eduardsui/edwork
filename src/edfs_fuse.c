#define FUSE_USE_VERSION 26
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <fuse.h>
#ifdef _WIN32
    #include <windows.h>
    #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
        #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
    #endif
    #include "ui/htmlwindow.h"
    #include "ui/edwork_settings_form.h"
#ifndef HAVE_TIMESPEC
    struct timespec {
        time_t tv_sec;
        long tv_nsec;
    };
#endif
#endif
#ifdef __APPLE__
    #include <unistd.h>
    #include <wordexp.h>
    #include "ui/htmlwindow.h"
    #include "ui/edwork_settings_form.h"
#endif

#include "log.h"
#include "edfs_core.h"

static struct edfs *edfs_context;
#if defined(_WIN32) || defined(__APPLE__)
static int server_pipe_is_valid = 1;
static int reload_keys = 0;
static int reopen_window = 0;
static void *gui_window = 0;
#endif
static struct fuse *fuse_session = NULL;

static int edfs_fuse_getattr(const char *path, edfs_stat *stbuf) {
    uint64_t inode = edfs_pathtoinode(edfs_context, path, NULL, NULL);
    return edfs_getattr(edfs_context, inode, stbuf);
}

static int edfs_fuse_truncate(const char *path, off_t offset) {
    if (!edfs_set_size(edfs_context, edfs_pathtoinode(edfs_context, path, NULL, NULL), offset))
        return -ENOENT;

    return 0;
}

static int edfs_fuse_utimens(const char *path, const struct timespec tv[2]) {
    uint64_t inode = edfs_pathtoinode(edfs_context, path, NULL, NULL);

    edfs_stat attr;
    memset(&attr, 0, sizeof(edfs_stat));

    attr.st_mtime = tv[1].tv_sec;

    if ((tv[1].tv_nsec < -1) || (!tv[1].tv_sec))
        return 0;

    if (tv[1].tv_nsec == -1)
        attr.st_mtime = time(NULL);

    return edfs_setattr(edfs_context, inode, &attr, EDFS_SET_ATTR_MTIME);
}

unsigned int add_directory(const char *name, edfs_ino_t ino, int type, int64_t size, time_t created, time_t modified, time_t timestamp, void *userdata) {
    void **data = (void **)userdata;
    fuse_fill_dir_t filler = (fuse_fill_dir_t)data[0];
    void *buf = data[1];

    edfs_stat stbuf;
    memset(&stbuf, 0, sizeof(edfs_stat));

    stbuf.st_ino = ino;
    stbuf.st_mode = type;
    stbuf.st_size = size;
    stbuf.st_ctime = created;
    stbuf.st_mtime = modified;
    stbuf.st_atime = timestamp / 1000000;

    filler(buf, name, &stbuf, 0);
    return 1;
}

static int edfs_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    uint64_t ino = edfs_pathtoinode(edfs_context, path, NULL, NULL);
    struct dirbuf *dirbuf = NULL;
    if ((fi) && (fi->fh))
        dirbuf = (struct dirbuf *)fi->fh;

    void *data[2];
    data[0] = (void *)filler;
    data[1] = buf;

    return edfs_readdir(edfs_context, ino, 0x7FFFFFFF, offset, dirbuf, add_directory, data);
}

static int edfs_fuse_open(const char *path, struct fuse_file_info *fi) {
    const char *nameptr = NULL;
    edfs_ino_t inode = edfs_pathtoinode(edfs_context, path, NULL, &nameptr);
    int type = edfs_lookup_inode(edfs_context, inode, nameptr);
    if (!type)
        return -ENOENT;
    if (type & S_IFDIR)
        return -EISDIR;

    struct filewritebuf *buf = NULL;

    int err = edfs_open(edfs_context, inode, fi->flags, &buf);
    if (err)
        return err;
    if (buf)
        fi->fh = (uint64_t)buf;
    return 0;
}

static int edfs_fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    edfs_ino_t ino = 0;
    struct filewritebuf *filebuf = NULL;
    if ((fi) && (fi->fh)) {
        filebuf = (struct filewritebuf *)fi->fh;
        ino = edfs_inode(filebuf);
    } else
        return -ENOENT;

    if (!ino)
        ino = edfs_pathtoinode(edfs_context, path, NULL, NULL);

	return edfs_read(edfs_context, ino, size, offset, buf, filebuf);
}

static int edfs_fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info * fi) {
    edfs_ino_t ino = 0;
    struct filewritebuf *filebuf = NULL;
    if ((fi) && (fi->fh)) {
        filebuf = (struct filewritebuf *)fi->fh;
        ino = edfs_inode(filebuf);
    }
    if (!ino)
        ino = edfs_pathtoinode(edfs_context, path, NULL, NULL);
    return edfs_write(edfs_context, ino, buf, size, offset, filebuf);
}

static int edfs_fuse_flush(const char *path, struct fuse_file_info *fi) {
    if (!fi)
        return 0;

    return edfs_flush(edfs_context, (struct filewritebuf *)fi->fh);
}

static int edfs_fuse_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    if (!fi)
        return 0;

    return edfs_fsync(edfs_context, datasync, (struct filewritebuf *)fi->fh);
}

static int edfs_fuse_unlink(const char *path) {
    uint64_t parent;
    uint64_t inode = edfs_pathtoinode(edfs_context, path, &parent, NULL);
    return edfs_unlink_inode(edfs_context, parent, inode);
}

static int edfs_fuse_rmdir(const char *path) {
    uint64_t parent;
    uint64_t inode = edfs_pathtoinode(edfs_context, path, &parent, NULL);
    return edfs_rmdir_inode(edfs_context, parent, inode);
}

static int edfs_fuse_mkdir(const char *path, mode_t mode) {
    uint64_t parent;
    const char *name = NULL;
    edfs_pathtoinode(edfs_context, path, &parent, &name);
    if (!name)
        return -EEXIST;
#ifdef _WIN32
    // on windows ignore mkdir error
    edfs_mkdir(edfs_context, parent, name, mode);
    return 0;
#else
    return edfs_mkdir(edfs_context, parent, name, mode);
#endif
}

static int edfs_fuse_mknod(const char *path, mode_t mode, dev_t dev) {
    uint64_t parent;
    const char *name = NULL;
    uint64_t inode = edfs_pathtoinode(edfs_context, path, &parent, &name);
    if (inode == 1)
        return -EEXIST;
    return edfs_mknod(edfs_context, parent, name, mode, NULL);
}

static int edfs_fuse_opendir(const char *path, struct fuse_file_info *fi) {
    const char *nameptr = NULL;
    uint64_t inode = edfs_pathtoinode(edfs_context, path, NULL, &nameptr);
    int type = edfs_lookup_inode(edfs_context, inode, nameptr);
    if (!type)
        return -ENOENT;

    if ((type & S_IFDIR) == 0)
        return -ENOTDIR;

    fi->fh = (uint64_t)edfs_opendir(edfs_context, inode);
    if (!fi->fh)
        return -ENOMEM;

    return 0;
}

static int edfs_fuse_releasedir(const char *path, struct fuse_file_info *fi) {
    if ((fi) && (fi->fh))
        edfs_releasedir((struct dirbuf *)fi->fh);
    return 0;
}

static int edfs_fuse_close(const char *path, struct fuse_file_info *fi) {
    if ((fi) && (fi->fh))
        edfs_close(edfs_context, (struct filewritebuf *)fi->fh);
    return 0;
}

static int edfs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    edfs_ino_t parent;
    const char *name = NULL;
    uint64_t inode = edfs_pathtoinode(edfs_context, path, &parent, &name);
    struct filewritebuf *buf = NULL;
    int err = edfs_create(edfs_context, parent, name, mode, &inode, &buf);
    if (err)
        return err;
    if (buf)
        fi->fh = (uint64_t)buf;
    return 0;
}

int edfs_fuse_chmod(const char *name, mode_t mode) {
    edfs_ino_t ino = edfs_pathtoinode(edfs_context, name, NULL, NULL);

    edfs_stat attr;
    memset(&attr, 0, sizeof(edfs_stat));
    attr.st_mode = mode;

    return edfs_setattr(edfs_context, ino, &attr, EDFS_SET_ATTR_MODE);
}

int edfs_fuse_chown(const char *name, uid_t user, gid_t group) {
    // not supported
    return 0;
}

#ifdef _WIN32
static int edfs_fuse_statfs(const char *path, struct statvfs *stbuf) {
    int read_only = edwork_readonly(edfs_context);

    stbuf->f_bsize = 4096;
    stbuf->f_frsize = 4096;
    stbuf->f_blocks = 0x10000000;
    stbuf->f_bfree = read_only ? 0 : (stbuf->f_blocks / 2);
    stbuf->f_bavail = read_only ? 0 : stbuf->f_bfree;
    stbuf->f_files = 0x10000000;
    stbuf->f_ffree = read_only ? 0 : (stbuf->f_files / 2);
    stbuf->f_favail = read_only ? 0 : stbuf->f_ffree;
    stbuf->f_namemax = 4096;
	return 0;
}
#endif

#ifdef _WIN32
int edfs_register_uri() {
    HKEY key;
    char edfs_path[MAX_PATH];
    char edfs_temp[MAX_PATH + 5];
    char *edfs_name = NULL;
    static const char protocol_description[] = "edwork protocol";
    
    if (!GetModuleFileNameA(NULL, edfs_path, MAX_PATH)) {
        log_warn("error in getting module name");
        return -1;
    }
    edfs_name = strrchr(edfs_path, '\\');
    if (edfs_name)
        edfs_name ++;
    else
        edfs_name = edfs_path;

    // re-create key (program moved ?)
    if (RegOpenKeyA(HKEY_CURRENT_USER, TEXT("Software\\Classes\\edwork\\"), &key) == ERROR_SUCCESS) {
        log_trace("protocol already registered");
        RegDeleteKeyA(key, NULL);
        RegCloseKey(key);
    }
    int error = RegCreateKeyA(HKEY_CURRENT_USER, TEXT("Software\\Classes\\edwork\\"), &key);
    if (error != ERROR_SUCCESS) {
        log_warn("cannot create registry key (error: %i)", error);
        return 0;
    }
    RegSetValueExA(key, NULL, 0, REG_SZ, (LPBYTE)protocol_description, strlen(protocol_description) + 1);
    RegSetValueExA(key, TEXT("URL Protocol"), 0, REG_SZ, (LPBYTE)"", 0);
    RegCloseKey(key);
    
    error = RegCreateKeyA(HKEY_CURRENT_USER, TEXT("Software\\Classes\\edwork\\DefaultIcon\\"), &key);
    if (error) {
        log_warn("cannot create registry key (error: %i)", error);
        return 0;
    }
    
    edfs_temp[0] = 0;
    snprintf(edfs_temp, sizeof(edfs_temp), "%s,1", edfs_name);
    RegSetValueExA(key, NULL, 0, REG_SZ, (LPBYTE)edfs_temp, strlen(edfs_temp) + 1);
    RegCloseKey(key);

    error = RegCreateKeyA(HKEY_CURRENT_USER, TEXT("Software\\Classes\\edwork\\shell\\open\\command\\"), &key);
    if (error) {
        log_warn("cannot create registry key (error: %i)", error);
        return 0;
    }
    edfs_temp[0] = 0;
    snprintf(edfs_temp, sizeof(edfs_temp), "\"%s\" \"-uri\" \"%%1\"", edfs_path);
    RegSetValueExA(key, NULL, 0, REG_SZ, (LPBYTE)edfs_temp, strlen(edfs_temp) + 1);
    RegCloseKey(key);

    edfs_name = strrchr(edfs_path, '\\');
    if (edfs_name) {
        edfs_name[0] = 0;
        chdir(edfs_path);
    }
    return 1;
}

int edfs_register_startup(int autostartup) {
    HKEY key;
    char edfs_path[MAX_PATH];
    
    if (!GetModuleFileNameA(NULL, edfs_path, MAX_PATH - 10)) {
        log_warn("error in getting module name");
        return -1;
    }

    strcat(edfs_path, " -autorun");
    // re-create key (program moved ?)
    if (RegOpenKeyA(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &key) != ERROR_SUCCESS) {
        log_warn("error setting autorun");
        return -1;
    }

    RegDeleteValueA (key, TEXT("edwork"));

    if (autostartup)
        RegSetValueExA(key, TEXT("edwork"), 0, REG_SZ, (LPBYTE)edfs_path, strlen(edfs_path) + 1);

    RegCloseKey(key);
    return 0;
}

int edfs_auto_startup() {
    HKEY key;
    if (RegOpenKeyA(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &key) != ERROR_SUCCESS) {
        log_warn("error reading autorun");
        return 0;
    }

    DWORD datalen;
    if (RegQueryValueExA(key, TEXT("edwork"), 0, NULL, NULL, &datalen) == ERROR_SUCCESS) {
        RegCloseKey(key);
        return datalen;
    }

    RegCloseKey(key);
    return 0;
}
#endif

void edfs_fuse_init(struct fuse_operations *edfs_fuse, const char *working_directory, const char *storage_key) {
    edfs_fuse->getattr      = edfs_fuse_getattr;
    edfs_fuse->readdir      = edfs_fuse_readdir;
    edfs_fuse->open         = edfs_fuse_open;
    edfs_fuse->read         = edfs_fuse_read;
    edfs_fuse->write        = edfs_fuse_write;
    edfs_fuse->flush        = edfs_fuse_flush;
    edfs_fuse->fsync        = edfs_fuse_fsync;
    edfs_fuse->create       = edfs_fuse_create;
    edfs_fuse->release      = edfs_fuse_close;
    edfs_fuse->releasedir   = edfs_fuse_releasedir;
    edfs_fuse->opendir      = edfs_fuse_opendir;
    edfs_fuse->mknod        = edfs_fuse_mknod;
    edfs_fuse->mkdir        = edfs_fuse_mkdir;
    edfs_fuse->rmdir        = edfs_fuse_rmdir;
    edfs_fuse->unlink       = edfs_fuse_unlink;
    edfs_fuse->truncate     = edfs_fuse_truncate;
    edfs_fuse->utimens      = edfs_fuse_utimens;
    edfs_fuse->chmod        = edfs_fuse_chmod;
    edfs_fuse->chown        = edfs_fuse_chown;
#ifdef _WIN32
    edfs_fuse->statfs       = edfs_fuse_statfs;

    edfs_register_uri();
#endif

    edfs_context = edfs_create_context(working_directory);
    if (storage_key)
        edfs_set_store_key(edfs_context, (const unsigned char *)storage_key, strlen(storage_key));
}

#if defined(_WIN32) || defined(__APPLE__)
void edfs_gui_load(void *window) {
    char buffer1[0x100];
    char buffer2[0x100];
    char buffer3[0x100];

    void *primary_key = edfs_get_primary_key(edfs_context);
    void *key = edfs_get_key(edfs_context);
    if (key) {
        ui_call(window, "clear_keys", NULL);
        const char *key_arguments[] = {"", "", "", "", NULL};
        while (key) {
            key_arguments[0] = edfs_key_id(key, buffer1);
            key_arguments[1] = edfs_public_key(key, buffer2);
            key_arguments[2] = edfs_private_key(key, buffer3);
            if (key == primary_key)
                key_arguments[3] = "true";
            else
                key_arguments[3] = "";

            ui_call(window, "add_key", key_arguments);

            key = edfs_next_key(key);
        }
    }
#ifdef _WIN32
    const char *arguments[] = {"true", NULL};
    if (edfs_auto_startup())
        ui_call(window, "set_autorun", arguments);
#endif
}

#ifdef _WIN32
int edfs_notify_edwork(char *uri) {
    HANDLE hpipe = CreateFileA("\\\\.\\pipe\\edwork", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hpipe == INVALID_HANDLE_VALUE) 
        return 0;

    DWORD dwMode = PIPE_READMODE_MESSAGE; 
    SetNamedPipeHandleState(hpipe, &dwMode, NULL, NULL);
    DWORD cbWritten;
    WriteFile(hpipe, uri, strlen(uri), &cbWritten, NULL);
    CloseHandle(hpipe);

    return 1;
}
#endif

void edfs_gui_callback(void *window) {
    char *foo = ui_call(window, "lastevent", NULL);
    char *use;

    uint64_t size = 0;
    uint64_t files = 0;
    uint64_t directories = 0;
    uint64_t index = 0;
    uint64_t timestamp = 0;
    if (foo) {
        switch (foo[0]) {
            case '@':
                if (edfs_chkey(edfs_context, foo + 1))
                    ui_message("Error", "Error switching key", 3);
                else
                    edfs_gui_load(window);
                break;
            case '-':
                if (ui_question("Warning", "Are you sure you want to delete this key?\nAccessing the data will not longer be possible.", 2)) {
                    if (edfs_rmkey(edfs_context, foo + 1))
                        ui_message("Error", "Error deleting key (key in use)", 3);
                    else
                        reload_keys = 2;
                }
                break;
            case '!':
                if (edfs_create_key(edfs_context))
                    ui_message("Error", "Error creating new key", 3);
                else
                    reload_keys = 2;
                break;
            case '*':
                edfs_storage_info(edfs_context, foo + 1, &size, &files, &directories, &index, &timestamp);

                char buf[0x1000];
                if ((index) && (timestamp)) {
                    time_t timestamp_32bit = (time_t)(timestamp / 1000000ULL);
                    struct tm *blocktimestamp = gmtime(&timestamp_32bit);
                    snprintf(buf, sizeof(buf), " %.3f GB in %" PRIu64 " files and %" PRIu64 " directories, blockchain has %" PRIu64 " blocks, last block was created on %s UTC", (double)size / (1024 * 1024 * 1024), files, directories, index, asctime(blocktimestamp));
                } else
                    snprintf(buf, sizeof(buf), " %.3f GB in %" PRIu64 " files and %" PRIu64 " directories", (double)size / (1024 * 1024 * 1024), files, directories);
                const char *arg[] = { foo + 1, buf, NULL };
                ui_call(window, "filesystem_usage", arg);
                break;
            case 'q':
                log_trace("edwork disconnect requested");
                if (server_pipe_is_valid)
                    server_pipe_is_valid = 0;

                if (fuse_session) {
                    fuse_exit(fuse_session);
                    fuse_session = NULL;
                    ui_window_close(gui_window);
                    gui_window = NULL;
                }
                break;
            case 'a':
#ifdef _WIN32
                if (foo[1] == '1')
                    edfs_register_startup(1);
                else
                    edfs_register_startup(0);
#endif
                break;
            case '?':
                use = ui_call(window, "getpeer", NULL);
                if (use) {
                    if (use[0]) {
                        log_trace("manually adding peer %s", use);
                        edfs_set_initial_friend(edfs_context, use);
                    }
                    ui_free_string(use);
                }
                break;
        }
        ui_free_string(foo);
    }
}

void edfs_tray_notify(void *menuwindow) {
    if (ui_window_count() <= 1) {
        gui_window = ui_window("edwork settings", edwork_settings_form);
        edfs_gui_load(gui_window);
    }
}

void edfs_gui_notify(void *userdata) {
    if (reload_keys) {
        if (gui_window)
            edfs_gui_load(gui_window);
        if (reload_keys != 2)
            ui_app_tray_icon("Open edwork settings", "New partition", "A new partition was added.", edfs_tray_notify);
        reload_keys = 0;
    }
    if (reopen_window) {
        if (ui_window_count() <= 1) {
            gui_window = ui_window("edwork settings", edwork_settings_form);
            edfs_gui_load(gui_window);
        }
        reopen_window = 0;
    }
}

int edfs_gui_thread(void *userdata) {
    ui_app_init(edfs_gui_callback);
    ui_app_tray_icon("Open edwork settings", NULL, NULL, edfs_tray_notify);
    if (!userdata) {
        gui_window = ui_window("edwork settings", edwork_settings_form);
        edfs_gui_load(gui_window);
    }
    ui_app_run_with_notify(edfs_gui_notify, NULL);
    ui_app_done();
    return 0;
}

int edfs_fuse_thread(void *userdata) {
    if (!userdata)
        return 0;
    int err;
#ifdef EDFS_MULTITHREADED
    err = fuse_loop_mt((struct fuse *)userdata);
#else
    err = fuse_loop((struct fuse *)userdata);
#endif
    ui_app_quit();
    return err;
}

thread_ptr_t edfs_fuse_loop(struct fuse *se) {
    return thread_create(edfs_fuse_thread, (void *)se, "edwork fuse", 8192 * 1024);
}

#ifdef _WIN32
HANDLE edfs_create_named_pipe() {
    HANDLE hpipe = CreateNamedPipeA("\\\\.\\pipe\\edwork", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE |  PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024 * 16, 1024 * 16, 0, NULL);
    if (hpipe == INVALID_HANDLE_VALUE) {
        log_error("error creating named pipe");
        return hpipe;
    }
    return hpipe;
}

int edfs_loop_named_pipe() {
    HANDLE server_pipe = edfs_create_named_pipe();
    if (server_pipe == INVALID_HANDLE_VALUE) {
        server_pipe_is_valid = 0;
        return 0;
    }
    if (ConnectNamedPipe(server_pipe, NULL)) {
        char buffer[0x100];
        DWORD bytes_read = 0;
        if ((ReadFile(server_pipe, buffer, sizeof(buffer) - 1, &bytes_read, NULL)) && (bytes_read > 0)) {
            buffer[bytes_read] = 0;
            if (bytes_read < 10) {
                log_debug("%s command received", buffer);
                if (!strcmp(buffer, "stop")) {
                    server_pipe_is_valid = 0;
                    if (fuse_session) {
                        fuse_exit(fuse_session);
                        fuse_session = NULL;
                    }
                } else
                if (!strcmp(buffer, "open")) {
                    reopen_window = 1;
                }
            } else {
                int err;
                if (bytes_read > 64)
                    err = edfs_use_key(edfs_context, buffer, NULL);
                else
                    err = edfs_use_key(edfs_context, NULL, buffer);
                if (err)
                    log_error("invalid key received via pipe");
                else
                    reload_keys = 1;
            }
        }
        CloseHandle(server_pipe); 
        return 1;
    }
    CloseHandle(server_pipe); 
    return 0;
}

int edfs_pipe_thread(void *userdata) {
    while (server_pipe_is_valid)
        edfs_loop_named_pipe();

    return 0;
}

thread_ptr_t edfs_pipe() {
    return thread_create(edfs_pipe_thread, (void *)edfs_context, "edwork pipe", 8192 * 1024);
}
#endif

thread_ptr_t edfs_gui(int gui_mode) {
    return thread_create(edfs_gui_thread, (void *)(intptr_t)(gui_mode == 2), "edwork gui", 8192 * 1024);
}


#ifdef _WIN32
void edfs_emulate_console() {
    AllocConsole();

    // Get STDOUT handle
    HANDLE ConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    int SystemOutput = _open_osfhandle((intptr_t)ConsoleOutput, _O_TEXT);
    FILE *COutputHandle = _fdopen(SystemOutput, "w");

    // Get STDERR handle
    HANDLE ConsoleError = GetStdHandle(STD_ERROR_HANDLE);
    int SystemError = _open_osfhandle((intptr_t)ConsoleOutput, _O_TEXT);
    FILE *CErrorHandle = _fdopen(SystemError, "w");

    // Get STDIN handle
    HANDLE ConsoleInput = GetStdHandle(STD_INPUT_HANDLE);
    int SystemInput = _open_osfhandle((intptr_t)ConsoleOutput, _O_TEXT);
    FILE *CInputHandle = _fdopen(SystemInput, "r");

    freopen_s(&CInputHandle, "CONIN$", "r", stdin);
    freopen_s(&COutputHandle, "CONOUT$", "w", stdout);
    freopen_s(&CErrorHandle, "CONOUT$", "w", stderr);
}
#endif

#ifdef __APPLE__
void edfs_quit(void *event_data, void *user_data) {
    // to do
}
#endif
#endif

static const char EDFS_BANNER[] =   " _______   ________  ___       __   ________  ________  ___  __       \n"
                                    "|\\  ___ \\ |\\   ___ \\|\\  \\     |\\  \\|\\   __  \\|\\   __  \\|\\  \\|\\  \\     \n"
                                    "\\ \\   __/|\\ \\  \\_|\\ \\ \\  \\    \\ \\  \\ \\  \\|\\  \\ \\  \\|\\  \\ \\  \\/  /|_   \n"
                                    " \\ \\  \\_|/_\\ \\  \\ \\\\ \\ \\  \\  __\\ \\  \\ \\  \\\\\\  \\ \\   _  _\\ \\   ___  \\  \n"
                                    "  \\ \\  \\_|\\ \\ \\  \\_\\\\ \\ \\  \\|\\__\\_\\  \\ \\  \\\\\\  \\ \\  \\\\  \\\\ \\  \\\\ \\  \\ \n"
                                    "   \\ \\_______\\ \\_______\\ \\____________\\ \\_______\\ \\__\\\\ _\\\\ \\__\\\\ \\__\\\n"
                                    "    \\|_______|\\|_______|\\|____________|\\|_______|\\|__|\\|__|\\|__| \\|__|\n";

int main(int argc, char *argv[]) {
#if defined(_WIN32) || defined(__APPLE__)
    char *dokan_argv[] = {"edwork", "-o", "volname=EDWORK Drive", "-o", "fsname=EdFS (edwork file system)", NULL};
    struct fuse_args args = FUSE_ARGS_INIT(5, dokan_argv);
#else
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
#endif
    FILE *fp = NULL;
    struct fuse_chan *ch;
    char *mountpoint = NULL;
    char *working_directory = NULL;
    char *storage_key = NULL;
    int err = -1;
    int port = EDWORK_PORT;
    int i;
    static struct fuse_operations edfs_fuse;
    int initial_friend_set = 0;
    int foreground = 1;
#ifdef __APPLE__
    wordexp_t pathexp;
    int gui = 0;
#endif

#ifdef _WIN32
    int gui = 0;
    // enable colors
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD fdwSaveOldMode;
    GetConsoleMode(hStdout, &fdwSaveOldMode);
    if (SetConsoleMode(hStdout, fdwSaveOldMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        log_set_colors(1);
#else
    log_set_colors(1);
#endif
    log_set_level(3);

    fprintf(stderr, "%s\n", EDFS_BANNER);

    // first look for working directory
    for (i = 1; i < argc; i++) {
        char *arg = argv[i];
        if ((arg) && (arg[0] == '-')) {
            if (!strcmp(arg, "-dir")) {
                if (i >= argc - 1) {
                    fprintf(stderr, "edfs: working directory name expected after -dir parameter. Try -help option.\n");
                    exit(-1);
                }
                i ++;
                working_directory = argv[i];
            } else
            if (!strcmp(arg, "-storagekey")) {
                if (i >= argc - 1) {
                    fprintf(stderr, "edfs: key expected after -storagekey parameter. Try -help option.\n");
                    exit(-1);
                }
                i ++;
                storage_key = argv[i];
            }
        }
    }

    edfs_fuse_init(&edfs_fuse, working_directory, storage_key);
    int uri_parameters = 0;
    int uri_sent = 0;
    for (i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (arg) {
            if (arg[0] == '-') {
                arg ++;
                if (!strcmp(arg, "port")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: port number expected after -port parameter. Try -help option.\n");
                        exit(-1);
                    }
                    i++;
                    port = atoi(argv[i]);
                } else
                if (!strcmp(arg, "loglevel")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: log level expected after -loglevel parameter. Try -help option.\n");
                        exit(-1);
                    }
                    i++;
                    if (!strcmp(argv[i], "trace"))
                        log_set_level(0);
                    else
                    if (!strcmp(argv[i], "debug"))
                        log_set_level(1);
                    else
                    if (!strcmp(argv[i], "info"))
                        log_set_level(2);
                    else
                    if (!strcmp(argv[i], "warning"))
                        log_set_level(3);
                    else
                    if (!strcmp(argv[i], "error"))
                        log_set_level(4);
                    else
                        log_set_level(atoi(argv[i]));
                } else
                if (!strcmp(arg, "logfile")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: log filename expected after -logfile parameter. Try -help option.\n");
                        exit(-1);
                    }
                    i++;
                    fp = fopen(argv[i], "wb");
                    if (fp)
                        log_set_fp(fp);
                    else {
                        fprintf(stderr, "cannot open log file %s", argv[i]);
                    }
                } else
                if (!strcmp(arg, "readonly")) {
                    edfs_set_readonly(edfs_context, 1);
                    log_info("mounting read-only file system");
                } else
                if (!strcmp(arg, "newkey")) {
                    if (edfs_create_key(edfs_context))
                        log_error("error creating new key pair");
                    else
                        log_info("key created");
                } else
                if (!strcmp(arg, "use")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: host[:ip] expected after use. Try -help option.\n");
                        exit(-1);
                    }
                    i++;
                    initial_friend_set = 1;
                    edfs_set_initial_friend(edfs_context, argv[i]);
                } else
                if (!strcmp(arg, "resync")) {
                    edfs_set_resync(edfs_context, 1);
                } else
                if (!strcmp(arg, "rebroadcast")) {
                    edfs_set_rebroadcast(edfs_context, 1);
                } else
                if (!strcmp(arg, "chunks")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: number of chunks expected after -chunks parameter. Try -help option.\n");
                        exit(-1);
                    }
                    i++;
                    edfs_set_forward_chunks(edfs_context, atoi(argv[i]));
                } else
                if (!strcmp(arg, "daemonize")) {
                    foreground = 0;
                } else
                if (!strcmp(arg, "proxy")) {
                    edfs_set_proxy(edfs_context, 1);
                } else
                if (!strcmp(arg, "shard")) {
                    if (i >= argc - 2) {
                        fprintf(stderr, "edfs: shard id and number of shards expected after -shard parameter. Try -help option.\n");
                        exit(-1);
                    }
                    edfs_set_shard(edfs_context, atoi(argv[i + 1]), atoi(argv[i + 2]));
                    i += 2;
                } else
#ifdef WITH_SCTP
                if (!strcmp(arg, "sctp")) {
                    edfs_set_force_sctp(edfs_context, 1);
                } else
#endif
                if (!strcmp(arg, "dir")) {
                    // already parsed this parameter
                    i ++;
                } else
                if (!strcmp(arg, "storagekey")) {
                    // already parsed this parameter
                    i ++;
                } else
                if (!strcmp(arg, "partition")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: partition id expected after -partition parameter. Try -help option.\n");
                        exit(-1);
                    }
                    i++;
                    edfs_set_partition_key(edfs_context, argv[i]);
                } else
                if (!strcmp(arg, "key")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: url-friendly, base64 encoding expected after -key parameter. Try -help option.\n");
                        exit(-1);
                    }
                    i++;
                    int err;
                    if (strlen(argv[i]) > 64)
                        err = edfs_use_key(edfs_context, argv[i], NULL);
                    else
                        err = edfs_use_key(edfs_context, NULL, argv[i]);
                    if (err) {
                        fprintf(stderr, "edfs: invalid key: %s\n", argv[i]);
                        exit(-1);
                    }
                } else
                if (!strcmp(arg, "uri")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: uri string expected after -uri parameter. Try -help option.\n");
                        exit(-1);
                    }
                    i++;
                    char *uri = argv[i];
                    int len = strlen(uri);
                    if ((len <= 7) || (memcmp(uri, "edwork:", 7))) {
                        fprintf(stderr, "edfs: invalid uri\n");
                        exit(-1);
                    }
                    uri += 7;
#ifdef _WIN32
                    uri_sent += edfs_notify_edwork(uri);
#endif
                    int err;
                    if (strlen(argv[i]) > 64)
                        err = edfs_use_key(edfs_context, uri, NULL);
                    else
                        err = edfs_use_key(edfs_context, NULL, uri);
                    if (err) {
                        fprintf(stderr, "edfs: invalid uri key\n");
                        exit(-1);
                    }
                    edfs_set_partition_key(edfs_context, uri);
                    uri_parameters += 2;
                } else
#if defined(_WIN32) || defined(__APPLE__)
                if (!strcmp(arg, "gui")) {
                    gui = 1;
                } else
#endif
#ifdef _WIN32
                if (!strcmp(arg, "autorun")) {
                    gui = 2;
                } else
                if (!strcmp(arg, "stop")) {
                    if (!edfs_notify_edwork(arg)) {
                        fprintf(stderr, "edfs: no other instance found.\n");
                        exit(-1);
                    } else {
                        fprintf(stdout, "edfs: sent stop request to service\n");
                        exit(0);
                    }
                } else
#endif
                if (!strcmp(arg, "help")) {
                    fprintf(stderr, "EdFS 0.1BETA, unlicensed 2018 by Eduard Suica\nUsage: %s [options] mount_point\n\nAvailable options are:\n"
                        "    -port port_number  listen on given port number\n"
                        "    -loglevel level    set log level, 0 to 5 or trace,debug,info,warning,error\n"
                        "    -logfile filename  set log filename\n"
                        "    -readonly          mount filesystem as read-only\n"
                        "    -newkey            generate a new key\n"
                        "    -key key           add given key (private or public), base64(url-friendly) encoded\n"
                        "    -partition id      mount given partition id\n"
                        "    -use host[:port]   use host:port as initial host\n"
                        "    -resync            request data resync\n"
                        "    -rebroadcast       force rebroadcast all local data\n"
                        "    -chunks n          set the number of forward chunks to be requested on read\n"
                        "    -daemonize         run as daemon/service\n"
                        "    -proxy             enable proxy mode (forward WANT requets)\n"
                        "    -shard id shards   set shard id, as id number of shard, eg.: -shards 1 2\n"
                        "    -dir directory     set the edfs working directory (default is ./edfs)\n"
                        "    -storagekey        set a storage key used for local encryption\n"
                        "    -uri               edfs uri (key)\n"
#if defined(_WIN32) || defined(__APPLE__)
                        "    -gui               open GUI\n"
#endif
#ifdef _WIN32
                        "    -autorun           open in autostart mode\n"
                        "    -stop              stop other instances of the application\n"
#endif
#ifdef WITH_SCTP
                        "    -sctp              force SCTP-only mode\n"
#endif
                        , argv[0]);
                    exit(0);
                } else {
                    fprintf(stderr, "edfs: unknown parameter %s\n", arg);
                    exit(-1);
                }
            } else {
                if (mountpoint) {
                    fprintf(stderr, "edfs: unknown parameter %s. Try -help option.\n", arg);
                    exit(-1);
                }
                mountpoint = arg;
            }
        }
    }
    if (uri_sent) {
        log_warn("application already running, forwarded uri parameters");
        exit(0);
    }
    if (!mountpoint) {
        fprintf(stderr, "EdFS 0.1BETA, unlicensed 2018 by Eduard Suica\nTo list all options, run with -help option\n");
#ifdef _WIN32
        mountpoint = "J";
#else
#ifdef __APPLE__
        wordexp("~/Desktop/edwork", &pathexp, 0);
        mountpoint = pathexp.we_wordv[0];
#else
        fprintf(stderr, "no mount point specified\n");
        exit(-1);
#endif
#endif
    }

#ifdef EDFS_DEFAULT_HOST
    if (!initial_friend_set)
        edfs_set_initial_friend(edfs_context, EDFS_DEFAULT_HOST);
#endif
    log_info("starting edfs on port %i, mount point [%s]", port, mountpoint);
    edfs_edwork_init(edfs_context, port);
    if ((ch = fuse_mount(mountpoint, &args)) != NULL) {
        struct fuse *se;

        se = fuse_new(ch, &args, &edfs_fuse, sizeof(edfs_fuse), NULL);
        if (se != NULL) {
            fuse_session = se;
            fuse_set_signal_handlers(fuse_get_session(se));
#ifdef _WIN32
            thread_ptr_t gui_thread;
            // on windows, if no parameters, detach console
            if ((!foreground) || (argc == (uri_parameters + 1)) || (gui == 2)) {
                // FreeConsole();
                if (!gui)
                    gui = 1;
            } else {
#ifdef _WIN32
                edfs_emulate_console();
#endif
            }
            HANDLE mutex = CreateMutexA(0, FALSE, "Local\\$edwork$");
            if (GetLastError() == ERROR_ALREADY_EXISTS) {
                log_error("edwork already running");
                edfs_notify_edwork("open");
                gui = 0;
            } else {
                if (gui)
                    gui_thread = edfs_gui(gui);
                thread_ptr_t pipe_thread = edfs_pipe();
#endif
#ifdef __APPLE__
                if (gui) {
                    // Cocoa loop must be in the main thread, so move fuse loop into another thread
                    thread_ptr_t fuse_thread = edfs_fuse_loop(se);
                    ui_set_event(UI_EVENT_LOOP_EXIT, edfs_quit, se);
                    ui_lock();
                    edfs_gui_thread(NULL);
                    ui_unlock();
                    if (fuse_session)
                        fuse_exit(se);
                    thread_join(fuse_thread);
                    thread_destroy(fuse_thread);
                } else
#endif
#ifdef EDFS_MULTITHREADED
                err = fuse_loop_mt(se);
#else
                err = fuse_loop(se);
#endif
#ifdef _WIN32
                if (server_pipe_is_valid)
                    server_pipe_is_valid = 0;
                // sometimes hangs
                // thread_join(pipe_thread);
                // thread_destroy(pipe_thread);
            }
            if (gui) {
                PostThreadMessage(GetThreadId(gui_thread), WM_QUIT, 0, 0);
                thread_join(gui_thread);
                thread_destroy(gui_thread);
            }
            if (mutex)
                CloseHandle(mutex);
#endif
            fuse_session = NULL;
            edfs_edwork_done(edfs_context);
            edfs_destroy_context(edfs_context);
            edfs_context = NULL;
            fuse_unmount(mountpoint, ch);
            fuse_destroy(se);
        } else {
            edfs_edwork_done(edfs_context);
            edfs_destroy_context(edfs_context);
            edfs_context = NULL;
        }
#ifdef __APPLE__
        rmdir(mountpoint);
#endif
    } else {
        edfs_edwork_done(edfs_context);
        edfs_destroy_context(edfs_context);
        edfs_context = NULL;
    }
    fuse_opt_free_args(&args);
    if (fp)
        fclose(fp);

    return err ? 1 : 0;
}

#ifdef _WIN32
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, char *pCmdLine, int nShowCmd) {
    return main(__argc, __argv);
}
#endif
