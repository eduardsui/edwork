#ifdef _WIN32
    #include <windows.h>
    #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
        #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
    #endif
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifndef _WIN32
    #include <unistd.h>
#endif

#include "log.h"
#include "edwork.h"
#include "edfs_core.h"

static struct edfs *edfs_context;

unsigned int add_directory(const char *name, edfs_ino_t ino, int type, int64_t size, time_t created, time_t modified, time_t timestamp, void *userdata) {
    if (type & S_IFDIR) {
        if ((strcmp(name, ".")) && (strcmp(name, "..")))
            fprintf(stderr, "\x1b[35m%s\x1b[0m\n", name);
    } else
    if (type & S_IXUSR) {
        fprintf(stderr, "\x1b[32m%s\x1b[0m\n", name);
    } else {
        fprintf(stderr, "%s\n", name);
    }
    return 1;
}


static int edfs_console_ls(const char *path) {
    const char *nameptr = NULL;
    uint64_t inode = pathtoinode(path, NULL, &nameptr);
    int type = edfs_lookup_inode(edfs_context, inode, nameptr);
    if (!type) {
        fprintf(stderr, "edfs console: %s: No such file or directory\n", path);
        return -ENOENT;
    }

    if ((type & S_IFDIR) == 0) {
        fprintf(stderr, "edfs console: %s: Not a directory\n", path);
        return -ENOTDIR;
    }

    struct dirbuf *dbuf = edfs_opendir(edfs_context, inode);
    if (!dbuf) {
        fprintf(stderr, "edfs console: %s: Not enough memory\n", path);
        return -ENOMEM;
    }

    edfs_readdir(edfs_context, inode, 0x7FFFFFFF, 0, dbuf, add_directory, NULL);

    edfs_releasedir(dbuf);
    return 0;
}

static int edfs_console_download(const char *path, const char *name, edfs_ino_t inode) {
    int type = edfs_lookup_inode(edfs_context, inode, name);
    if (!type) {
        fprintf(stderr, "edfs console: %s: no such file\n", path);
        return -ENOENT;
    }

    if (type & S_IFDIR) {
        fprintf(stderr, "edfs console: %s: is a directory\n", path);
        return -EISDIR;
    }

    struct filewritebuf *buf = NULL;
    int err = edfs_open(edfs_context, inode, O_RDONLY, &buf);
    if (err) {
        fprintf(stderr, "edfs console: %s: error opening file\n", path);
        return err;
    }
    FILE *f = fopen(name, "wb");
    if (!f) {
        fprintf(stderr, "edfs console: %s: error opening local file\n", name);
        edfs_close(edfs_context, buf);
    }
    uint64_t offset = 0;
    char buffer[BLOCK_SIZE];
    int read_size;
    edfs_stat stbuf;
    int64_t file_size = 0;

    if (!edfs_getattr(edfs_context, inode, &stbuf)) {
        file_size = stbuf.st_size;
        while (offset < file_size) {
            read_size = edfs_read(edfs_context, inode, sizeof(buffer), offset, buffer, buf);
            if (read_size <= 0)
                break;

            offset += read_size;
            fprintf(stderr, "edfs console: %s: %i/%i bytes written\r", name, (int)offset, (int)file_size);

            if (fwrite(buffer, 1, read_size, f) != read_size) {
                fprintf(stderr, "edfs console: %s: error writing local file\n", name);
                break;
            }
        }
    }
    fclose(f);
    edfs_close(edfs_context, buf);
    if (offset < file_size) {
        fprintf(stderr, "\nedfs console: %s: error reading\n", path);
        unlink(name);
        return -EIO;
    } else
        fprintf(stderr, "\nedfs console: %s: done\n", name);
    return 0;
}

static int edfs_console_upload(const char *path, const char *fname) {
    FILE *f = fopen(fname, "rb");
    if (!f) {
        fprintf(stderr, "edfs console: %s: local file does not exists\n", fname);
        return -1;
    }

    int fname_start = strlen(fname) - 1;
    while ((fname_start >= 0) && (fname[fname_start] != '/') && (fname[fname_start] != '\\'))
        fname_start--;

    char full_path[4096];
    full_path[0] = 0;

    const char *name = fname;
    if (fname_start >= 0) {
        if ((fname[fname_start] == '/') || (fname[fname_start] != '\\'))
            fname_start++;
        name = fname + fname_start;
        snprintf(full_path, 4096, "%s%s", path, name);
    } else {
        if (strlen(path) == 1)
            snprintf(full_path, 4096, "%s%s", path, fname);
        else
            snprintf(full_path, 4096, "%s/%s", path, fname);
    }

    uint64_t parent;
    uint64_t inode = pathtoinode(full_path, &parent, &name);
    int type = edfs_lookup_inode(edfs_context, inode, name);
    if (type) {
        fclose(f);
        fprintf(stderr, "edfs console: %s: file already exists\n", full_path);
        return -1;
    }

    struct filewritebuf *buf = NULL;
    int err = edfs_create(edfs_context, parent, name, S_IFREG | 0644, &inode, &buf);
    if (err) {
        fprintf(stderr, "edfs console: %s: error creating file\n", name);
        fclose(f);
        return err;
    }
    char buffer[4096];
    uint64_t offset;
    do {
        int size = fread(buffer, 1, sizeof(buffer), f);
        if (size > 0)
            edfs_write(edfs_context, inode, buffer, size, offset, buf);
        else
            break;
        offset += size;
    } while (1);
    fclose(f);
    edfs_close(edfs_context, buf);
    edfs_set_size(edfs_context, inode, offset);
    fprintf(stderr, "\nedfs console: %s: done\n", name);
    return 0;
}

const char EDFS_BANNER[] =  " _______   ________  ___       __   ________  ________  ___  __       \n"
                            "|\\  ___ \\ |\\   ___ \\|\\  \\     |\\  \\|\\   __  \\|\\   __  \\|\\  \\|\\  \\     \n"
                            "\\ \\   __/|\\ \\  \\_|\\ \\ \\  \\    \\ \\  \\ \\  \\|\\  \\ \\  \\|\\  \\ \\  \\/  /|_   \n"
                            " \\ \\  \\_|/_\\ \\  \\ \\\\ \\ \\  \\  __\\ \\  \\ \\  \\\\\\  \\ \\   _  _\\ \\   ___  \\  \n"
                            "  \\ \\  \\_|\\ \\ \\  \\_\\\\ \\ \\  \\|\\__\\_\\  \\ \\  \\\\\\  \\ \\  \\\\  \\\\ \\  \\\\ \\  \\ \n"
                            "   \\ \\_______\\ \\_______\\ \\____________\\ \\_______\\ \\__\\\\ _\\\\ \\__\\\\ \\__\\\n"
                            "    \\|_______|\\|_______|\\|____________|\\|_______|\\|__|\\|__|\\|__| \\|__|\n";


int main(int argc, char *argv[]) {
#ifdef _WIN32
    // enable colors
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD fdwSaveOldMode;
    GetConsoleMode(hStdout, &fdwSaveOldMode);
    if (SetConsoleMode(hStdout, fdwSaveOldMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        log_set_colors(1);
#else
    log_set_colors(1);
#endif

    int err = -1;
    int port = EDWORK_PORT;
    int i;

    fprintf(stdout, "%s\n", EDFS_BANNER);

    edfs_context = edfs_create_context(NULL);
    edfs_init(edfs_context);

    if (!edfs_file_exists(edfs_signature_path(edfs_context))) {
        log_info("using default signature");
        char *signature = "{\n"\
        "    \"alg\": \"ED25519\",\n"\
        "    \"kty\": \"EDD25519\",\n"\
        "    \"k\": \"wG5RPGPCly9kNWs2_DZRMU8DtQGmXxRduafL9M-AMX-9H3n3V3udUagWE_HyDAMw5GOka8ppuzuO7pp_x5i5ew\",\n"\
        "    \"pk\": \"siy3GXOHnVySVUlHUDVGt7v6nMKWjy39Hy23M40Toos\"\n"\
        "}\n";
        FILE *f = fopen(edfs_signature_path(edfs_context), "w+b");
        if (f) {
            fwrite(signature, 1, strlen(signature), f);
            fclose(f);
#ifdef EDFS_DEFAULT_HOST
            edfs_set_initial_friend(edfs_context, EDFS_DEFAULT_HOST);
#endif
            edfs_set_resync(edfs_context, 1);
            log_warn("This is your first run of EdFS. Please wait 20 seconds for data to sync.");
        } else
            log_error("error writing signature: %i", errno);
    }

    log_set_level(5);

    for (i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (arg) {
            if (arg[0] == '-') {
                arg ++;
                if (!strcmp(arg, "port")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: port number expected after -port parameter\n");
                        exit(-1);
                    }
                    i++;
                    port = atoi(argv[i]);
                } else
                if (!strcmp(arg, "loglevel")) {
                    if (i >= argc - 1) {
                        fprintf(stderr, "edfs: log level expected after -loglevel parameter\n");
                        exit(-1);
                    }
                    i++;
                    log_set_level(atoi(argv[i]));
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
                        fprintf(stderr, "edfs: host[:ip] expected after use\n");
                        exit(-1);
                    }
                    i++;
                    edfs_set_initial_friend(edfs_context, argv[i]);
                    edfs_set_resync(edfs_context, 1);
                } else
                if (!strcmp(arg, "resync")) {
                    edfs_set_resync(edfs_context, 1);
                } else
                if (!strcmp(arg, "rebroadcast")) {
                    edfs_set_rebroadcast(edfs_context, 1);
                } else {
                    fprintf(stderr, "EdFS 0.1BETA, unlicensed 2018 by Eduard Suica\nUsage: %s [-port port_number][-loglevel 0 - 5][-readonly][-newkey][-use host[:port]][-resync][-rebroadcast] mount_point\n", argv[0]);
                    exit(-1);
                }
            }
        }
    }

    log_info("starting edfs on port %i", port);

    fprintf(stdout, "Welcome to edwork 0.1BETA console\nSupported commands are: ls, cd, get, put, rmdir, rm, open, exit\n");
    char buffer[0x100];
    edfs_edwork_init(edfs_context, port);
    char working_dir[4096];
    working_dir[0] = '/';
    working_dir[1] = 0;
    edfs_stat stbuf;
    char full_path[4096];
    const char *name = NULL;
    do {
        fprintf(stdout, "%s> ", working_dir);
        char *cmd = fgets(buffer, sizeof(buffer), stdin);
        if (!cmd)
            break;
        int idx = strlen(cmd) - 1;
        while (idx >= 0) {
            if ((cmd[idx] == '\r') || (cmd[idx] == '\n') || (cmd[idx] == ' ') || (cmd[idx] == '\t')) {
                cmd[idx] = 0;
                idx--;
            } else
                break;
        }
        if (cmd[0]) {
            char *parameters = strchr(cmd, ' ');
            if (parameters) {
                parameters[0] = 0;
                parameters ++;
            }
            if (!strcmp(cmd, "exit"))
                break;
            if (!strcmp(cmd, "ls")) {
                if ((parameters) && (parameters[0]))
                    edfs_console_ls(parameters);
                else
                    edfs_console_ls(working_dir);
                continue;
            }
            if (!strcmp(cmd, "rm")) {
                if ((!parameters) || (!parameters[0])) {
                    fprintf(stderr, "edfs console: %s: filename expected\n", cmd);
                    continue;
                }
                char *path = parameters;
                if ((parameters[0] != '/') && (parameters[0] != '\\')) {
                    if (strlen(working_dir) == 1) {
                        snprintf(full_path, 4096, "/%s", parameters);
                    } else
                        snprintf(full_path, 4096, "%s/%s", working_dir, parameters);
                    path = full_path;
                }
                uint64_t parent = 0;

                uint64_t inode = pathtoinode(path, &parent, NULL);
                if (inode > 1) {
                    int err = edfs_unlink_inode(edfs_context, parent, inode);
                    if (err < 0) {
                        if (err == -EISDIR)
                            fprintf(stderr, "edfs console: %s: is a directory(use rmdir instead)\n", path);
                        else
                        if (err == -ENOENT)
                            fprintf(stderr, "edfs console: %s: no such file\n", path);
                        else
                            fprintf(stderr, "edfs console: %s: cannot remove file\n", path);
                        continue;
                    }
                } else
                    fprintf(stderr, "edfs console: %s: no such file or directory\n", path);
                continue;
            }
            if (!strcmp(cmd, "rmdir")) {
                if ((!parameters) || (!parameters[0])) {
                    fprintf(stderr, "edfs console: %s: filename expected\n", cmd);
                    continue;
                }
                char *path = parameters;
                if ((parameters[0] != '/') && (parameters[0] != '\\')) {
                    if (strlen(working_dir) == 1) {
                        snprintf(full_path, 4096, "/%s", parameters);
                    } else
                        snprintf(full_path, 4096, "%s/%s", working_dir, parameters);
                    path = full_path;
                }
                uint64_t parent = 0;

                uint64_t inode = pathtoinode(path, &parent, NULL);
                if (inode > 1) {
                    int err = edfs_rmdir_inode(edfs_context, parent, inode);
                    if (err < 0) {
                        if (err == -ENOTDIR)
                            fprintf(stderr, "edfs console: %s: is not a directory(use rm instead)\n", path);
                        else
                        if (err == -ENOENT)
                            fprintf(stderr, "edfs console: %s: no such directory\n", path);
                        else
                            fprintf(stderr, "edfs console: %s: cannot remove non-empty directory\n", path);
                        continue;
                    }
                } else
                    fprintf(stderr, "edfs console: %s: no such file or directory\n", path);
                continue;
            }
            if (!strcmp(cmd, "mkdir")) {
                if ((!parameters) || (!parameters[0])) {
                    fprintf(stderr, "edfs console: %s: filename expected\n", cmd);
                    continue;
                }
                char *path = parameters;
                if ((parameters[0] != '/') && (parameters[0] != '\\')) {
                    if (strlen(working_dir) == 1) {
                        snprintf(full_path, 4096, "/%s", parameters);
                    } else
                        snprintf(full_path, 4096, "%s/%s", working_dir, parameters);
                    path = full_path;
                }
                uint64_t parent = 0;
                uint64_t inode = pathtoinode(path, &parent, &name);

                if (!edfs_getattr(edfs_context, inode, &stbuf)) {
                    fprintf(stderr, "edfs console: %s: file/directory exists\n", parameters);
                    continue;
                }
                if (inode > 1) {
                    int err = edfs_mkdir(edfs_context, parent, name, inode);
                    if (err < 0) {
                        fprintf(stderr, "edfs console: %s: cannot create directory\n", path);
                        continue;
                    }
                } else
                    fprintf(stderr, "edfs console: %s: no such file or directory\n", path);
                continue;
            }
            if (!strcmp(cmd, "cd")) {
                if ((!parameters) || (!parameters[0])) {
                    working_dir[0] = '/';
                    working_dir[1] = '/';
                    continue;
                }
                if (!strcmp(parameters, "."))
                    continue;
                if (!strcmp(parameters, "..")) {
                    int len = strlen(working_dir);
                    if (len == 1)
                        continue;
                    len --;
                    while (len >= 0) {
                        if ((working_dir[len] == '/') || (working_dir[len] == '\\')) {
                            if (len <= 1) {
                                working_dir[0] = '/';
                                working_dir[1] = 0;
                            } else
                                working_dir[len] = 0;
                            break;
                        }
                        len--;
                    }
                    continue;
                }
                if (parameters[0] == '/') {
                    if (edfs_getattr(edfs_context, pathtoinode(parameters, NULL, NULL), &stbuf)) {
                        fprintf(stderr, "edfs console: %s: No such file or directory\n", parameters);
                        continue;
                    }
                    if ((stbuf.st_mode & S_IFDIR) == 0) {
                        fprintf(stderr, "edfs console: %s: Not a directory\n", parameters);
                        continue;
                    }
                    memcpy(working_dir, parameters, strlen(parameters) + 1);
                } else {
                    if (strlen(working_dir) > 1)
                        snprintf(full_path, 4096, "%s/%s", working_dir, parameters);
                    else
                        snprintf(full_path, 4096, "/%s", parameters);
                    if (edfs_getattr(edfs_context, pathtoinode(full_path, NULL, NULL), &stbuf)) {
                        fprintf(stderr, "edfs console: %s: No such file or directory\n", full_path);
                        continue;
                    }
                    if ((stbuf.st_mode & S_IFDIR) == 0) {
                        fprintf(stderr, "edfs console: %s: Not a directory\n", full_path);
                        continue;
                    }
                    memcpy(working_dir, full_path, strlen(full_path) + 1);
                }
                continue;
            }
            if ((!strcmp(cmd, "get")) || (!strcmp(cmd, "open")))  {
                if ((!parameters) || (!parameters[0])) {
                    fprintf(stderr, "edfs console: %s: filename expected\n", cmd);
                    continue;
                }
                char *path = parameters;
                if ((parameters[0] != '/') && (parameters[0] != '\\')) {
                    if (strlen(working_dir) == 1) {
                        snprintf(full_path, 4096, "/%s", parameters);
                    } else
                        snprintf(full_path, 4096, "%s/%s", working_dir, parameters);
                    path = full_path;
                }
                uint64_t parent;
                uint64_t inode = pathtoinode(path, &parent, &name);
                if ((!edfs_console_download(path, name, inode)) && (!strcmp(cmd, "open"))) {
                    snprintf(full_path, 4096, "\"%s\"", name);
                    system(full_path);
                }
                continue;
            }
            if (!strcmp(cmd, "put")) {
                if ((!parameters) || (!parameters[0])) {
                    fprintf(stderr, "edfs console: %s: filename expected\n", cmd);
                    continue;
                }
                edfs_console_upload(working_dir, parameters);
                continue;
            }
            fprintf(stderr, "edfs console: %s: command not found\n", cmd);
        }
    } while (1);
    edfs_edwork_done(edfs_context);
    edfs_destroy_context(edfs_context);
    return 0;
}
