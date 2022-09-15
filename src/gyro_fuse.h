#ifndef __gyro_fuse_h
#define __gyro_fuse_h

#include <inttypes.h>
#include <sys/stat.h>

#ifndef mode_t
    #define mode_t  int
#endif

#ifndef uid_t
    #define uid_t   int
#endif

#ifndef gid_t
    #define gid_t   int
#endif

#ifndef pid_t
    #define pid_t   int
#endif

struct fuse;
struct fuse_chan;

struct flock {
	off_t	l_start;
	off_t	l_len;
	pid_t	l_pid;
	short	l_type;
	short	l_whence;
};

struct fuse_conn_info {
    unsigned proto_major;
    unsigned proto_minor;
    unsigned max_write;
    unsigned max_read;
    unsigned max_readahead;
    unsigned capable;
    unsigned want;
    unsigned max_background;
    unsigned congestion_threshold;
    unsigned time_gran;
    unsigned reserved[22];
};

struct fuse_file_info {
	int flags;
	uint64_t fh;
    off_t session_offset;
    off_t offset;
    void *data;
    unsigned int data_len;
    unsigned int data_allocated;
    unsigned char failed_buffer;
    unsigned char needs_sync;
};

enum fuse_readdir_flags {
    FUSE_READDIR_PLUS = (1 << 0)
};

enum fuse_fill_dir_flags {
    FUSE_FILL_DIR_PLUS = (1 << 1)
};

struct fuse_config {
	int set_gid;
	unsigned int gid;
	int set_uid;
	unsigned int uid;
	int set_mode;
	unsigned int umask;
	double entry_timeout;
	double negative_timeout;
	double attr_timeout;
	int intr;
	int intr_signal;
	int remember;
	int hard_remove;
	int use_ino;
	int readdir_ino;
	int direct_io;
	int kernel_cache;
	int auto_cache;
	int no_rofd_flush;
	int ac_attr_timeout_set;
	double ac_attr_timeout;
	int nullpath_ok;
	int show_help;
	char * modules;
	int debug;
};

struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    unsigned long f_blocks;
    unsigned long f_bfree;
    unsigned long f_bavail;
    unsigned long f_files;
    unsigned long f_ffree;
    unsigned long f_favail;
    unsigned long f_fsid;
    unsigned long f_flag;
    unsigned long f_namemax;
};

typedef int (*fuse_fill_dir_t) (void * buf, const char * name, const struct stat* stbuf, off_t off);

struct fuse_operations {
    int (*getattr) (const char *, struct stat*);
    int (*readlink) (const char *, char *, size_t);
    int (*mknod) (const char *, mode_t, dev_t);
    int (*mkdir) (const char *, mode_t);
    int (*unlink) (const char *);
    int (*rmdir) (const char *);
    int (*symlink) (const char *, const char *);
    int (*rename) (const char *, const char *, unsigned int flags);
    int (*link) (const char *, const char *);
    int (*chmod) (const char *, mode_t);
    int (*chown) (const char *, uid_t, gid_t);
    int (*truncate) (const char *, off_t);
    int (*open) (const char *, struct fuse_file_info *);
    int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);
    int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *);
    int (*statfs) (const char *, struct statvfs*);
    int (*flush) (const char *, struct fuse_file_info *);
    int (*release) (const char *, struct fuse_file_info *);
    int (*fsync) (const char *, int, struct fuse_file_info *);
    int (*setxattr) (const char *, const char *, const char *, size_t, int);
    int (*getxattr) (const char *, const char *, char *, size_t);
    int (*listxattr) (const char *, char *, size_t);
    int (*removexattr) (const char *, const char *);
    int (*opendir) (const char *, struct fuse_file_info *);
    int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);
    int (*releasedir) (const char *, struct fuse_file_info *);
    int (*fsyncdir) (const char *, int, struct fuse_file_info *);
    void * (*init) (struct fuse_conn_info * conn, struct fuse_config* cfg);
    void (*destroy) (void * private_data);
    int (*access) (const char *, int);
    int (*create) (const char *, mode_t, struct fuse_file_info *);
    int (*lock) (const char *, struct fuse_file_info *, int cmd, struct flock *);
    int (*utimens) (const char *, const struct timespec tv[2]);
    int (*bmap) (const char *, size_t blocksize, uint64_t* idx);
    int (*ioctl) (const char *, unsigned int cmd, void * arg, struct fuse_file_info *, unsigned int flags, void *data);
    // int (*poll) (const char *, struct fuse_file_info *, struct fuse_pollhandle* ph, unsigned* reventsp);
    // int (*write_buf) (const char *, struct fuse_bufvec* buf, off_t off, struct fuse_file_info *);
    // int (*read_buf) (const char *, struct fuse_bufvec** bufp, size_t size, off_t off, struct fuse_file_info *);
    int (*flock) (const char *, struct fuse_file_info *, int op);
    int (*fallocate) (const char *, int, off_t, off_t, struct fuse_file_info *);
    off_t (*lseek) (const char *, off_t off, int whence, struct fuse_file_info *);
};

struct fuse_context {
    struct fuse* fuse;
    void * private_data;
    mode_t umask;
};

// not implemented
#define fuse_opt_free_args(x)

struct fuse* fuse_new(struct fuse_chan * ch, void * args, const struct fuse_operations* op, size_t op_size, void * private_data);

struct fuse_chan *fuse_mount(const char *dir, void *args);
void fuse_unmount(const char *dir, struct fuse_chan *ch);

int fuse_set_signal_handlers(struct fuse *se);
struct fuse *fuse_get_session(struct fuse *f);
void fuse_remove_signal_handlers(struct fuse *se);

int fuse_loop(struct fuse* f);
int fuse_loop_mt(struct fuse* f);
void fuse_exit(struct fuse* f);
void fuse_destroy(struct fuse* f);

// enable windows projected virtual file system
int fuse_enable_service();

#endif // __gyro_fuse_h
