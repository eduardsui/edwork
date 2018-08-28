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
#endif

#include "log.h"
#include "edfs_core.h"

static struct edfs *edfs_context;

static int edfs_fuse_getattr(const char *path, edfs_stat *stbuf) {
    uint64_t inode = pathtoinode(path, NULL, NULL);
    return edfs_getattr(edfs_context, inode, stbuf);
}

static int edfs_fuse_truncate(const char *path, off_t offset) {
    if (!edfs_set_size(edfs_context, pathtoinode(path, NULL, NULL), offset))
        return -ENOENT;

    return 0;
}

static int edfs_fuse_utimens(const char *path, const struct timespec tv[2]) {
    uint64_t inode = pathtoinode(path, NULL, NULL);

    edfs_stat attr;
    memset(&attr, 0, sizeof(edfs_stat));

    attr.st_mtime = tv[1].tv_sec;

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
    uint64_t ino = pathtoinode(path, NULL, NULL);
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
    edfs_ino_t inode = pathtoinode(path, NULL, &nameptr);
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
        ino = pathtoinode(path, NULL, NULL);

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
        ino = pathtoinode(path, NULL, NULL);
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
    uint64_t inode = pathtoinode(path, &parent, NULL);
    return edfs_unlink_inode(edfs_context, parent, inode);
}

static int edfs_fuse_rmdir(const char *path) {
    uint64_t parent;
    uint64_t inode = pathtoinode(path, &parent, NULL);
    return edfs_rmdir_inode(edfs_context, parent, inode);
}

static int edfs_fuse_mkdir(const char *path, mode_t mode) {
    uint64_t parent;
    const char *name = NULL;
    pathtoinode(path, &parent, &name);
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
    uint64_t inode = pathtoinode(path, &parent, &name);
    if (inode == 1)
        return -EEXIST;
    return edfs_mknod(edfs_context, parent, name, mode, NULL);
}

static int edfs_fuse_opendir(const char *path, struct fuse_file_info *fi) {
    const char *nameptr = NULL;
    uint64_t inode = pathtoinode(path, NULL, &nameptr);
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
    uint64_t inode = pathtoinode(path, &parent, &name);
    struct filewritebuf *buf = NULL;
    int err = edfs_create(edfs_context, parent, name, mode, &inode, &buf);
    if (err)
        return err;
    if (buf)
        fi->fh = (uint64_t)buf;
    return 0;
}

int edfs_fuse_chmod(const char *name, mode_t mode) {
    edfs_ino_t ino = pathtoinode(name, NULL, NULL);

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

void edfs_fuse_init(struct fuse_operations *edfs_fuse) {
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
#endif


    edfs_context = edfs_create_context(NULL);
    edfs_init(edfs_context);
}

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
    int err = -1;
    int port = EDWORK_PORT;
    int i;
    static struct fuse_operations edfs_fuse;
    int initial_friend_set = 0;
    int foreground = 1;
#ifdef __APPLE__
    wordexp_t pathexp;
#endif

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

    fprintf(stderr, "%s\n", EDFS_BANNER);
    edfs_fuse_init(&edfs_fuse);

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
                if (!strcmp(arg, "genesis")) {
                    edfs_genesis_if_new(edfs_context);
                } else
                if (!strcmp(arg, "help")) {
                    fprintf(stderr, "EdFS 0.1BETA, unlicensed 2018 by Eduard Suica\nUsage: %s [options] mount_point\n\nAvailable options are:\n"
                        "    -port port_number  listen on given port number\n"
                        "    -loglevel 0 - 5    set log level\n"
                        "    -logfile filename  set log filename\n"
                        "    -readonly          mount filesystem as read-only\n"
                        "    -newkey            generate a new key\n"
                        "    -use host[:port]   use host:port as initial host\n"
                        "    -resync            request data resync\n"
                        "    -rebroadcast       force rebroadcast all local data\n"
                        "    -chunks n          set the number of forward chunks to be requested on read\n"
                        "    -daemonize         run as daemon/service\n"
                        "    -genesis           initialize blockchain if not created\n"
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
    if (!edfs_file_exists(edfs_signature_path(edfs_context))) {
        log_info("using default signature");
        const char *signature = "{\n"\
        "    \"alg\": \"ED25519\",\n"\
        "    \"kty\": \"EDD25519\",\n"\
        "    \"k\": \"wG5RPGPCly9kNWs2_DZRMU8DtQGmXxRduafL9M-AMX-9H3n3V3udUagWE_HyDAMw5GOka8ppuzuO7pp_x5i5ew\",\n"\
        "    \"pk\": \"siy3GXOHnVySVUlHUDVGt7v6nMKWjy39Hy23M40Toos\"\n"\
        "}\n";
        FILE *f = fopen(edfs_signature_path(edfs_context), "w+b");
        if (f) {
            fwrite(signature, 1, strlen(signature), f);
            fclose(f);
            edfs_set_resync(edfs_context, 1);
            log_warn("This is your first run of EdFS. Please wait 20 seconds for data to sync.");
        } else
            log_error("error writing signature: %i", errno);
    }

    if (!edfs_file_exists(edfs_signature_path(edfs_context))) {
        log_info("creating signature");
        edfs_create_key(edfs_context);
    }

    log_info("starting edfs on port %i, mount point [%s]", port, mountpoint);
    if ((ch = fuse_mount(mountpoint, &args)) != NULL) {
        struct fuse *se;

        se = fuse_new(ch, &args, &edfs_fuse, sizeof(edfs_fuse), NULL);
        if (se != NULL) {
            fuse_set_signal_handlers(fuse_get_session(se));
            edfs_edwork_init(edfs_context, port);
#ifdef EDFS_MULTITHREADED
            err = fuse_loop_mt(se);
#else
            err = fuse_loop(se);
#endif
            edfs_edwork_done(edfs_context);
            edfs_destroy_context(edfs_context);
            edfs_context = NULL;
            fuse_unmount(mountpoint, ch);
            fuse_destroy(se);
        }
#ifdef __APPLE__
        rmdir(mountpoint);
#endif
    }
    fuse_opt_free_args(&args);
    if (fp)
        fclose(fp);

    return err ? 1 : 0;
}
