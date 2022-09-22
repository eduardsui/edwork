#define FUSE_USE_VERSION 26
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <inttypes.h>
#ifdef WITH_PJFS
    #include "defuse.h"
#else
    #include <fuse.h>
#endif
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
#else
    #include <unistd.h>
    #include <sys/types.h>
#endif
#ifdef __APPLE__
    #include <signal.h>
    #include "ui/htmlwindow.h"
    #include "ui/edwork_settings_form.h"
    
    struct apple_parameters {
        struct fuse_chan *ch;
        const char *mountpoint;
        struct fuse *se;
    };
#endif

#include "log.h"
#include "edfs_core.h"

static struct edfs *edfs_context;
static int server_pipe_is_valid = 1;
#if defined(_WIN32) || defined(__APPLE__)
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
BOOL WINAPI edfs_ctrl_console(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            fuse_exit(fuse_session);
            return FALSE;
        default:
            return FALSE;
    }
}

void edfs_emulate_console() {
    AllocConsole();

    // Get STDOUT handle
    HANDLE ConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    int SystemOutput = _open_osfhandle((intptr_t)ConsoleOutput, _O_TEXT);
    FILE *COutputHandle = _fdopen(SystemOutput, "w");

    // Get STDERR handle
    HANDLE ConsoleError = GetStdHandle(STD_ERROR_HANDLE);
    int SystemError = _open_osfhandle((intptr_t)ConsoleError, _O_TEXT);
    FILE *CErrorHandle = _fdopen(SystemError, "w");

    // Get STDIN handle
    HANDLE ConsoleInput = GetStdHandle(STD_INPUT_HANDLE);
    int SystemInput = _open_osfhandle((intptr_t)ConsoleInput, _O_TEXT);
    FILE *CInputHandle = _fdopen(SystemInput, "r");

    freopen_s(&CInputHandle, "CONIN$", "r", stdin);
    freopen_s(&COutputHandle, "CONOUT$", "w", stdout);
    freopen_s(&CErrorHandle, "CONOUT$", "w", stderr);

    SetConsoleCtrlHandler(edfs_ctrl_console, TRUE);
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
#ifndef EDFS_NO_JS
    int app_mode = edfs_app_mode(edfs_context);
    switch (app_mode) {
        case 1:
            strcat(edfs_path, " -app");
            break;
        case 2:
            strcat(edfs_path, " -debugapp");
            break;
    }
#endif
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

#ifdef WITH_SMARTCARD
    #if defined(_WIN32) || defined(__APPLE__)
        void edfs_tray_notify(void *menuwindow);

        void smartcard_status_changed(struct edwork_smartcard_context *smartcard_context) {
            switch (smartcard_context->status) {
                case 4:
                    ui_app_tray_icon("Smartcard user", smartcard_context->buf_name, "Added new signature.", edfs_tray_notify);
                    break;
                case 22:
                    ui_app_tray_icon("Smartcard user", smartcard_context->buf_name, "Removed signature.", edfs_tray_notify);
                    break;
            }
        }

        int smartcard_read_pin(struct edwork_smartcard_context *smartcard_context, const char *reader, char *pin, int *max_len) {
            int data_entered = ui_input("Enter PIN", reader, pin, *max_len, 1);
            if (data_entered) {
                *max_len = 0;
                *max_len = strlen(pin);
            }
            return data_entered;
        }
    #else
        int smartcard_read_pin(struct edwork_smartcard_context *smartcard_context, char *reader, char *pin, int *max_len) {
            printf("PIN for %s: ", reader);
            scanf("%20s", pin);
            if (max_len)
                *max_len = strlen(pin);
            if (*max_len)
                return 1;
            return 0;
        }
    #endif
#endif

int edfs_fuse_history(const char *path, uint64_t timestamp_limit, unsigned char **blockchainhash, uint64_t *generation, uint64_t *timestamp, int history_limit) {
    return edfs_history(edfs_context, edfs_pathtoinode(edfs_context, path, NULL, NULL), timestamp_limit, blockchainhash, generation, timestamp, history_limit);
}

char *edfs_fuse_signature(const char *path, int signature_index) {
    return edfs_get_signature(edfs_context, edfs_pathtoinode(edfs_context, path, NULL, NULL), signature_index);
}

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
#ifdef WITH_PJFS
    edfs_fuse->history      = edfs_fuse_history;
    edfs_fuse->signature    = edfs_fuse_signature;
#endif

    edfs_register_uri();
#endif

    edfs_context = edfs_create_context(working_directory);
    if (storage_key)
        edfs_set_store_key(edfs_context, (const unsigned char *)storage_key, strlen(storage_key));
#ifdef WITH_SMARTCARD
    #if defined(_WIN32) || defined(__APPLE__)
        edfs_set_smartcard_callback(edfs_context, smartcard_status_changed);
    #endif
    edfs_set_smartcard_pin_callback(edfs_context, smartcard_read_pin);
#endif
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
        const char *key_arguments[] = {"", "", "", "", "", NULL};
        while (key) {
            key_arguments[0] = edfs_key_id(key, buffer1);
            key_arguments[1] = edfs_public_key(key, buffer2);
            key_arguments[2] = edfs_private_key(key, buffer3);
            if (key == primary_key)
                key_arguments[3] = "true";
            else
                key_arguments[3] = "";
#ifndef EDFS_NO_JS
            if (((struct edfs_key_data *)key)->js)
                key_arguments[4] = "true";
            else
                key_arguments[4] = "";
#endif
            ui_call(window, "add_key", key_arguments);

            key = edfs_next_key(key);
        }
    }
#ifdef _WIN32
    const char *arguments[] = {"true", NULL};
    if (edfs_auto_startup())
        ui_call(window, "set_autorun", arguments);
#endif
#ifdef WITH_SMARTCARD
    struct edwork_smartcard_context *smartcard = edfs_get_smartcard_context(edfs_context);
    const char *smartcard_arguments[] = {"", NULL};
    if (smartcard)
        smartcard_arguments[0] = smartcard->buf_name;
    ui_call(window, "set_username", smartcard_arguments);
#endif
}

void edfs_gui_callback(void *window) {
#ifndef EDFS_NO_JS
    // JS UI event
    if (edfs_verify_window_event(edfs_context, window))
        return;
#endif
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
                if (edfs_chkey(edfs_context, foo + 1)) {
                    ui_message("Error", "Error switching key", 3);
                } else {
#ifdef WITH_PJFS
                    if (fuse_reload(fuse_session)) {
                        ui_message("Error", "Current partition is in use, cannot switch.", 3);
                        exit(-1);
                    }
#endif
                    edfs_gui_load(window);
                }
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
            case '$':
                edfs_remove_data(edfs_context, foo + 1);
                // no break, just re-print statistics
            case '*':
                edfs_storage_info(edfs_context, foo + 1, &size, &files, &directories, &index, &timestamp);

                char buf[0xF000];
                int buf_offset = 0;
                if ((index) && (timestamp)) {
                    time_t timestamp_32bit = (time_t)(timestamp / 1000000ULL);
                    struct tm *blocktimestamp = gmtime(&timestamp_32bit);
                    buf_offset = snprintf(buf, sizeof(buf), " <b>%.3fGB</b> in %" PRIu64 " files and %" PRIu64 " directories (<a href='javascript: window.edworkData = \"$%s\"; window.external.notify();\'>clean</a>), blockchain has %" PRIu64 " blocks, last block was created on %s UTC<br/><br/>Recent peers:", (double)size / (1024 * 1024 * 1024), files, directories, foo + 1, index, asctime(blocktimestamp));
                } else
                    buf_offset = snprintf(buf, sizeof(buf), " <b>%.3fGB</b> in %" PRIu64 " files and %" PRIu64 " directories (<a href='javascript: window.edworkData = \"$%s\"; window.external.notify();\'>clean</a>)<br/><br/>Recent peers:", (double)size / (1024 * 1024 * 1024), files, directories, foo + 1);

                if (buf_offset > 0)
                    edfs_peers_info(edfs_context, buf + buf_offset, sizeof(buf) - buf_offset, 1);
                const char *arg[] = { foo + 1, buf, NULL };
                ui_call(window, "filesystem_usage", arg);
                break;
            case 'q':
                log_trace("edwork disconnect requested");
                if (server_pipe_is_valid)
                    server_pipe_is_valid = 0;
#ifdef __APPLE__
                ui_app_quit();
#else
                if (fuse_session) {
                    fuse_exit(fuse_session);
                    fuse_session = NULL;
                    ui_window_close(gui_window);
                    gui_window = NULL;
                    // __APPLE__
                    // ui_unlock();
                    // fuse exit doesn't exit the fuse loop
                    // kill(getpid(), SIGTERM);
                }
#endif
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
#ifndef EDFS_NO_JS
            case 'j':
                {
                    struct edfs_key_data *key_data = (struct edfs_key_data *)edfs_find_key_opaque(edfs_context, foo + 1);
                    if (key_data) {
                        log_trace("launch application");
                        edfs_key_js_call(key_data, "edwork.events.onlaunch", NULL);
                    } else {
                        log_error("error launching application");
                    }
                }
                break;
#endif
            case '/':
#ifdef _WIN32
                edfs_emulate_console();
#endif
                break;
        }
        ui_free_string(foo);
    }
}

void edfs_tray_notify(void *menuwindow) {
#ifdef EDFS_NO_JS
    if (ui_window_count() <= 1) {
#else
    if (ui_window_count() <= edfs_app_window_count(edfs_context) + 1) {
#endif
        gui_window = ui_window("edwork settings", edwork_settings_form);
        edfs_gui_load(gui_window);
    } else
    if (gui_window) {
        ui_window_restore(gui_window);
        ui_window_top(gui_window);
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
#ifdef EDFS_NO_JS
        if (ui_window_count() <= 1) {
#else
        if (ui_window_count() <= edfs_app_window_count(edfs_context) + 1) {
#endif
            gui_window = ui_window("edwork settings", edwork_settings_form);
            edfs_gui_load(gui_window);
        } else
        if (gui_window) {
            ui_window_restore(gui_window);
            ui_window_top(gui_window);
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

#ifdef __APPLE__
int edfs_fuse_thread(void *userdata) {
    if (!userdata)
        return 0;
    struct apple_parameters *arg = (struct apple_parameters *)userdata;
    int err;
#ifdef EDFS_MULTITHREADED
    err = fuse_loop_mt(arg->se);
#else
    err = fuse_loop(arg->se);
#endif
    edfs_edwork_done(edfs_context);
    edfs_destroy_context(edfs_context);
    edfs_context = NULL;
    fuse_unmount(arg->mountpoint, arg->ch);
    fuse_destroy(arg->se);
    rmdir(arg->mountpoint);

    ui_app_quit();
    return err;
}

thread_ptr_t edfs_fuse_loop(void *arg) {
    return thread_create(edfs_fuse_thread, arg, "edwork fuse", 8192 * 1024);
}
#endif

thread_ptr_t edfs_gui(int gui_mode) {
    return thread_create(edfs_gui_thread, (void *)(intptr_t)(gui_mode == 2), "edwork gui", 8192 * 1024);
}

#ifdef __APPLE__
void edfs_quit(void *event_data, void *user_data) {
    struct apple_parameters *arg = (struct apple_parameters *)user_data;
    kill(getpid(), SIGTERM);
    rmdir(arg->mountpoint);
}
#endif

void edfs_window_close(void *window, void *user_data) {
    if (window == gui_window)
        gui_window = NULL;
#ifndef EDFS_NO_JS
    edfs_notify_window_close(edfs_context, window);
#endif
}
#endif

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

#else

int edfs_create_named_pipe() {
    static int pipe_created;
    char pipe_name[64];

    if (pipe_created)
        return 0;

    snprintf(pipe_name, sizeof(pipe_name), "/tmp/edwork_%i", getuid());
    unlink(pipe_name);
    if (mkfifo(pipe_name, 0666)) {
        log_error("error creating pipe %s, errno %i", pipe_name, errno);
        return -1;
    }
    pipe_created = 1;
    return 0;
}

int edfs_loop_named_pipe() {
    if (edfs_create_named_pipe()) {
        server_pipe_is_valid = 0;
        return 0;
    }
    char pipe_name[64];
    snprintf(pipe_name, sizeof(pipe_name), "/tmp/edwork_%i", getuid());

    FILE *f = fopen(pipe_name, "rb");
    if (f) {
        char buffer[0x100];
        int bytes_read = fread(buffer, 1, sizeof(buffer) - 1, f);
        if (bytes_read > 0) {
            buffer[bytes_read] = 0;
            if (bytes_read < 10) {
                log_debug("%s command received", buffer);
                if (!strcmp(buffer, "stop")) {
                    server_pipe_is_valid = 0;
                    if (fuse_session) {
                        fuse_exit(fuse_session);
                        fuse_session = NULL;
                    }
                }
#if defined(_WIN32) || defined(__APPLE__)
                else
                if (!strcmp(buffer, "open")) {
                    reopen_window = 1;
                }
#endif
            } else {
                int err;
                if (bytes_read > 64)
                    err = edfs_use_key(edfs_context, buffer, NULL);
                else
                    err = edfs_use_key(edfs_context, NULL, buffer);
                if (err)
                    log_error("invalid key received via pipe");
#if defined(_WIN32) || defined(__APPLE__)
                else
                    reload_keys = 1;
#endif
            }
        }
        fclose(f);
    }
    return 0;
}
#endif

int edfs_notify_edwork(const char *uri) {
#ifdef _WIN32
    if (!uri)
        return 0;

    HANDLE hpipe = CreateFileA("\\\\.\\pipe\\edwork", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hpipe == INVALID_HANDLE_VALUE) 
        return 0;

    DWORD dwMode = PIPE_READMODE_MESSAGE; 
    SetNamedPipeHandleState(hpipe, &dwMode, NULL, NULL);
    DWORD cbWritten;
    WriteFile(hpipe, uri, strlen(uri), &cbWritten, NULL);
    CloseHandle(hpipe);
#else
    // do not create fifo
    if (!uri)
        return 0;

    char pipe_name[64];
    snprintf(pipe_name, sizeof(pipe_name), "/tmp/edwork_%i", getuid());

    int err = 0;
    FILE *f = fopen(pipe_name, "wb");
    if (f) {
        int len = strlen(uri);
        if (fwrite(uri, 1, len, f) != len)
            err = 1;
        fclose(f);
        if (err)
            return 0;
    } else
        return 0;
#endif
    return 1;
}

int edfs_pipe_thread(void *userdata) {
    while (server_pipe_is_valid)
        edfs_loop_named_pipe();

    return 0;
}

thread_ptr_t edfs_pipe() {
    return thread_create(edfs_pipe_thread, (void *)edfs_context, "edwork pipe", 8192 * 1024);
}

static const char EDFS_BANNER[] =   " _______   ________  ___       __   ________  ________  ___  __       \n"
                                    "|\\  ___ \\ |\\   ___ \\|\\  \\     |\\  \\|\\   __  \\|\\   __  \\|\\  \\|\\  \\     \n"
                                    "\\ \\   __/|\\ \\  \\_|\\ \\ \\  \\    \\ \\  \\ \\  \\|\\  \\ \\  \\|\\  \\ \\  \\/  /|_   \n"
                                    " \\ \\  \\_|/_\\ \\  \\ \\\\ \\ \\  \\  __\\ \\  \\ \\  \\\\\\  \\ \\   _  _\\ \\   ___  \\  \n"
                                    "  \\ \\  \\_|\\ \\ \\  \\_\\\\ \\ \\  \\|\\__\\_\\  \\ \\  \\\\\\  \\ \\  \\\\  \\\\ \\  \\\\ \\  \\ \n"
                                    "   \\ \\_______\\ \\_______\\ \\____________\\ \\_______\\ \\__\\\\ _\\\\ \\__\\\\ \\__\\\n"
                                    "    \\|_______|\\|_______|\\|____________|\\|_______|\\|__|\\|__|\\|__| \\|__|\n";

int main(int argc, char *argv[]) {
#ifdef _WIN32
    #ifndef WITH_PJFS
        char *dokan_argv[] = {"edwork", "-o", "volname=EDWORK Drive", "-o", "fsname=EdFS (edwork file system)", NULL};
        struct fuse_args args = FUSE_ARGS_INIT(5, dokan_argv);
    #else
        void *args = NULL;
    #endif
#else
#ifdef __APPLE__
    char *osxfuse_argv[] = {"edwork", "-o", "volname=EDWORK Drive", "-o", "fsname=EdFS (edwork file system)", "-o", "local", NULL};
    struct fuse_args args = FUSE_ARGS_INIT(7, osxfuse_argv);
#else
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
#endif
#endif
    FILE *fp = NULL;
    struct fuse_chan *ch;
    const char *mountpoint = NULL;
    char *working_directory = NULL;
    char *storage_key = NULL;
    int err = -1;
    int port = EDWORK_PORT;
    int i;
    static struct fuse_operations edfs_fuse;
    int initial_friend_set = 0;
    int foreground = 1;
#ifdef __APPLE__
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
#if defined(_WIN32) || defined(__APPLE__)
                static char passwd[0x100];
                int data_entered = ui_input("Enter password", "Storage key", passwd, sizeof(passwd) - 1, 1);
                if ((data_entered) && (passwd[0]))
                    storage_key = passwd;
#else
                if (i >= argc - 1) {
                    fprintf(stderr, "edfs: key expected after -storagekey parameter. Try -help option.\n");
                    exit(-1);
                }
                i ++;
                storage_key = argv[i];
#endif
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
#if defined(_WIN32) || defined(__APPLE__)
                        ui_message("Error", "edfs: log level expected after -loglevel parameter. Try -help option.\n", 3);
#endif
                        exit(-1);
                    }
#ifdef _WIN32
                    edfs_emulate_console();
#endif
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
#if defined(_WIN32) || defined(__APPLE__)
                    uri_parameters ++;
#else
                    i ++;
#endif
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
                    uri_sent += edfs_notify_edwork(uri);
                    int err;
                    if (!uri_sent) {
                        if (strlen(argv[i]) > 64)
                            err = edfs_use_key(edfs_context, uri, NULL);
                        else
                            err = edfs_use_key(edfs_context, NULL, uri);
                        if (err) {
                            fprintf(stderr, "edfs: invalid uri key\n");
                            exit(-1);
                        }
                        edfs_set_partition_key(edfs_context, uri);
                    }
                    uri_parameters += 2;
                } else
#if defined(_WIN32) || defined(__APPLE__)
                if (!strcmp(arg, "gui")) {
                    gui = 1;
                } else
                if (!strcmp(arg, "autorun")) {
                    gui = 2;
                } else
#endif
                if (!strcmp(arg, "stop")) {
                    if (!edfs_notify_edwork(arg)) {
                        fprintf(stderr, "edfs: no other instance found.\n");
                        exit(-1);
                    } else {
                        fprintf(stdout, "edfs: sent stop request to service\n");
                        exit(0);
                    }
                } else
#ifndef EDFS_NO_JS
                if (!strcmp(arg, "app")) {
#if defined(_WIN32) || defined(__APPLE__)
                    uri_parameters ++;
#endif
                    edfs_set_app_mode(edfs_context, 1);
                } else
                if (!strcmp(arg, "debugapp")) {
#if defined(_WIN32) || defined(__APPLE__)
                    uri_parameters ++;
#endif
                    edfs_set_app_mode(edfs_context, 2);
                } else
#endif
                if (!strcmp(arg, "help")) {
#ifdef _WIN32
                    edfs_emulate_console();
#endif
                    fprintf(stderr, "EdFS 0.1BETA, unlicensed 2018-2022 by Eduard Suica\nUsage: %s [options] mount_point\n\nAvailable options are:\n"
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
#if defined(_WIN32) || defined(__APPLE__)
                        "    -storagekey        set a storage key used for local encryption\n"
#else
                        "    -storagekey key    set a storage key used for local encryption\n"
#endif
                        "    -uri               edfs uri (key)\n"
#if defined(_WIN32) || defined(__APPLE__)
                        "    -gui               open GUI\n"
                        "    -autorun           open in autostart mode\n"
#endif
                        "    -stop              stop other instances of the application\n"
#ifdef WITH_SCTP
                        "    -sctp              force SCTP-only mode\n"
#endif
#ifndef EDFS_NO_JS
                        "    -app               run partition application (.app.js)\n"
                        "    -debugapp          run local application\n"
#endif
                        , argv[0]);
                    exit(0);
                } else {
                    fprintf(stderr, "edfs: unknown parameter %s\n", arg);
#if defined(_WIN32) || defined(__APPLE__)
                    ui_message("Error", "Unknown parameter recieved.\nTry -help to see al the supported parameters.", 3);
#endif
                    exit(-1);
                }
            } else {
                if (mountpoint) {
                    fprintf(stderr, "edfs: unknown parameter %s. Try -help option.\n", arg);
#if defined(_WIN32) || defined(__APPLE__)
                    ui_message("Error", "Unknown parameter recieved.\nTry -help to see al the supported parameters.", 3);
#endif
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
        fprintf(stderr, "EdFS 0.1BETA, unlicensed 2018-2022 by Eduard Suica\nTo list all options, run with -help option\n");
#ifdef _WIN32
        #ifdef WITH_PJFS
            mountpoint = "edwork";
        #else
            mountpoint = "J";
        #endif
#else
#ifdef __APPLE__
        mountpoint = "/Volumes/edwork";
#else
        fprintf(stderr, "no mount point specified\n");
        exit(-1);
#endif
#endif
    }
    char *default_host = getenv("EDWORK_HOST");
    if ((default_host) && (default_host[1])) {
        edfs_set_initial_friend(edfs_context, EDFS_DEFAULT_HOST);
        initial_friend_set = 1;
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
                edfs_emulate_console();
            }
            HANDLE mutex = CreateMutexA(0, FALSE, "Local\\$edwork$");
            if (GetLastError() == ERROR_ALREADY_EXISTS) {
                log_error("edwork already running");
                edfs_notify_edwork("open");
                gui = 0;
            } else {
                if (gui) {
                    gui_thread = edfs_gui(gui);
                    ui_set_event(UI_EVENT_WINDOW_CLOSE, edfs_window_close, NULL);
                }
#endif
                thread_ptr_t pipe_thread = edfs_pipe();
#ifdef __APPLE__
                if ((!foreground) || (argc == (uri_parameters + 1))) {
                    if (!gui)
                        gui = 1;
                }
                if (gui) {
                    // Cocoa loop must be in the main thread, so move fuse loop into another thread
                    struct apple_parameters arg = { ch, mountpoint, se };
                    thread_ptr_t fuse_thread = edfs_fuse_loop(&arg);
                    ui_set_event(UI_EVENT_WINDOW_CLOSE, edfs_window_close, NULL);
                    ui_set_event(UI_EVENT_LOOP_EXIT, edfs_quit, &arg);
                    ui_lock();
                    if (gui == 2)
                        edfs_gui_thread((void *)1);
                    else
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
                if (server_pipe_is_valid)
                    server_pipe_is_valid = 0;
#ifdef _WIN32
            }
            if (gui) {
                PostThreadMessage(GetThreadId(gui_thread), WM_QUIT, 0, 0);
                thread_join(gui_thread);
                thread_destroy(gui_thread);
            }
            if (mutex)
                CloseHandle(mutex);
#endif
            // sometimes hangs (the thread may be in a blocking read operation)
            // thread_join(pipe_thread);
            // thread_destroy(pipe_thread);

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
#if defined(_WIN32) || defined(__APPLE__)
            ui_message("Error", "Error mounting partition (directory is already mapped to a partition?).", 3);
#endif
            fprintf(stderr, "%s\n", "Error mounting partition (directory is already mapped to a partition?).");
            err = -1;
        }
#ifdef __APPLE__
        rmdir(mountpoint);
#endif
    } else {
        edfs_edwork_done(edfs_context);
        edfs_destroy_context(edfs_context);
        edfs_context = NULL;
#if defined(_WIN32) || defined(__APPLE__)
        ui_message("Error", "Error mounting partition (read-only filesystem or mounting point already mapped).", 3);
#endif
        fprintf(stderr, "%s\n", "Error mounting partition (read-only filesystem or mounting point already mapped).");

        err = -1;
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
