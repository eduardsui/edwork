#ifndef __EDFS_CORE_H
#define __EDFS_CORE_H

#include <inttypes.h>
#include "edwork.h"

#ifdef _WIN32
    #ifndef _MODE_T_
        typedef unsigned short mode_t;
    #endif

    #ifndef S_ISDIR
        #define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
    #endif

    #ifndef S_ISREG
        #define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
    #endif

    #if !S_IXUSR
        #define S_IXUSR 00100
    #endif

#ifdef USE_STAT_PATCH
    struct stat64_win32 {
	    dev_t         st_dev;
	    uint64_t      st_ino;
	    mode_t        st_mode;
	    short          st_nlink;
	    unsigned int  st_uid;
	    unsigned int  st_gid;
	    dev_t st_rdev;
        short         dummy;
	    int64_t       st_size;
	    time_t st_atime;
        int dummy2;
	    time_t st_mtime;
        int dummy3;
	    time_t st_ctime;
        int dummy4;
    };
    #define edfs_stat struct stat64_win32
#else
    #define edfs_stat struct stat
#endif
#else
    #define edfs_stat struct stat
#endif

#define EDFS_HASHCASH_ASCII_STRING

#define USE_COMPRESSION 1
#define EDFS_DATA_BROADCAST_ENCRYPTED 1

#define KEY_HS256       1
#define KEY_EDD25519    2

#define MAX_PATH_LEN                8192
#define MAX_B64_HASH_LEN            16
#define MAX_INODE_DESCRIPTOR_SIZE   0x1FFF
#define BLOCK_SIZE                  57280
#define PROOF_OF_WORK_MAX_SIZE      0x1000

#define EDWORK_WANT_WORK_LEVEL      11
#define EDWORK_WANT_WORK_PREFIX     "edwork:1:11:"

#define EDWORK_LIST_WORK_LEVEL      14
#define EDWORK_LIST_WORK_PREFIX     "edwork:1:14:"

#define EDWORK_ROOT_WORK_LEVEL      EDWORK_LIST_WORK_LEVEL
#define EDWORK_ROOT_WORK_PREFIX     EDWORK_LIST_WORK_PREFIX

#define EDWORK_PING_INTERVAL        20
#define EDWORK_LIST_INTERVAL        600
#define EDWORK_INIT_INTERVAL        5
#define EDWORK_REBROADCAST_INTERVAL 3
#define EDWORK_NODE_WRITE_INTERVAL  600
#define EDWORK_NODES                2500
#define EDWORK_DATA_NODES           10
#define EDWORK_REBROADCAST          200
#define EDWORK_PORT                 4848
#define EDWORK_PACKET_SIZE          BLOCK_SIZE + 0x200
#define EDWORK_MAX_RETRY_TIMEOUT    4000
#define EDWORK_MAX_DIR_RETRY_TIMEOUT 2000

// new block every 2 minutes
#define EDFS_BLOCKCHAIN_NEW_BLOCK_TIMEOUT   120000000UL
// not lest than 10 seconds
#define EDFS_BLOCKCHAIN_MIN_TIMEOUT         10000000UL


#define EDFS_SET_ATTR_MODE	(1 << 0)
#define EDFS_SET_ATTR_UID	(1 << 1)
#define EDFS_SET_ATTR_GID	(1 << 2)
#define EDFS_SET_ATTR_SIZE	(1 << 3)
#define EDFS_SET_ATTR_ATIME	(1 << 4)
#define EDFS_SET_ATTR_MTIME	(1 << 5)
#define EDFS_SET_ATTR_CTIME	(1 << 6)

typedef uint64_t edfs_ino_t;

struct dirbuf;
struct filewritebuf;
struct edfs;

typedef unsigned int (*edfs_add_directory)(const char *name, edfs_ino_t ino, int type, int64_t size, time_t created, time_t modified, time_t timestamp, void *userdata);
typedef int (*edfs_schedule_callback)(struct edfs *edfs_context, uint64_t userdata_a, uint64_t userdata_b, void *data);

uint64_t edfs_pathtoinode(struct edfs *edfs_context, const char *path, uint64_t *parentinode, const char **nameptr);
int edfs_lookup_inode(struct edfs *edfs_context, edfs_ino_t inode, const char *ensure_name);
edfs_ino_t edfs_lookup(struct edfs *edfs_context, edfs_ino_t parent, const char *name, edfs_stat *stbuf);
int edfs_rmdir_inode(struct edfs *edfs_context, edfs_ino_t parent, edfs_ino_t inode);
int edfs_rmdir(struct edfs *edfs_context, edfs_ino_t parent, const char *name);
int edfs_unlink_inode(struct edfs *edfs_context, edfs_ino_t parent, edfs_ino_t inode);
int edfs_unlink(struct edfs *edfs_context, edfs_ino_t parent, const char *name);
int edfs_getattr(struct edfs *edfs_context, edfs_ino_t ino, edfs_stat *stbuf);
int edfs_releasedir(struct dirbuf *buf);
int edfs_close(struct edfs *edfs_context, struct filewritebuf *fbuf);
int edfs_set_size(struct edfs *edfs_context, uint64_t inode, int64_t new_size);
int edfs_mkdir(struct edfs *edfs_context, edfs_ino_t parent, const char *name, mode_t mode);
int edfs_mknod(struct edfs *edfs_context, edfs_ino_t parent, const char *name, mode_t mode, uint64_t *inode);
struct dirbuf *edfs_opendir(struct edfs *edfs_context, edfs_ino_t ino);
int edfs_fsync(struct edfs *edfs_context, int datasync, struct filewritebuf *fbuf);
int edfs_flush(struct edfs *edfs_context, struct filewritebuf *fbuf);
int edfs_open(struct edfs *edfs_context, edfs_ino_t ino, int flags, struct filewritebuf **fbuf);
int edfs_create(struct edfs *edfs_context, edfs_ino_t parent, const char *name, mode_t mode, uint64_t *inode, struct filewritebuf **buf);
edfs_ino_t edfs_inode(struct filewritebuf *filebuf);
int edfs_read(struct edfs *edfs_context, edfs_ino_t ino, size_t size, int64_t off, char *ptr, struct filewritebuf *filebuf);
int edfs_write(struct edfs *edfs_context, edfs_ino_t ino, const char *buf, size_t size, int64_t off, struct filewritebuf *fbuf);
int edfs_readdir(struct edfs *edfs_context, edfs_ino_t ino, size_t size, int64_t off, struct dirbuf *dbuf, edfs_add_directory add_directory, void *userdata);
int edfs_setattr(struct edfs *edfs_context, edfs_ino_t ino, edfs_stat *attr, int to_set);

int edfs_create_key(struct edfs *edfs_context);
int edfs_use_key(struct edfs *edfs_context, const char *public_key, const char *private_key);
void edfs_edwork_init(struct edfs *edfs_context, int port);
void edfs_edwork_done(struct edfs *edfs_context);
int edfs_file_exists(const char *name);

ssize_t edfs_read_simple_key(struct edfs *edfs_context, void *ptr, size_t size, FILE *stream);
ssize_t edfs_write_simple_key(struct edfs *edfs_context, const void *ptr, size_t size, FILE *stream);

void edfs_set_resync(struct edfs *edfs_context, int resync_val);
void edfs_set_rebroadcast(struct edfs *edfs_context, int rebroadcast_val);
void edfs_set_readonly(struct edfs *edfs_context, int readonly_val);
void edfs_set_initial_friend(struct edfs *edfs_context, const char *peer);
void edfs_set_forward_chunks(struct edfs *edfs_context, int forward_chunks);
void edfs_set_proxy(struct edfs *edfs_context, int proxy);
void edfs_set_shard(struct edfs *edfs_context, int shard_id, int shards);
void edfs_set_force_sctp(struct edfs *edfs_context, int force_sctp);
void edfs_set_store_key(struct edfs *edfs_context, const unsigned char *key, int len);
void edfs_set_partition_key(struct edfs *edfs_context, char *key_id);

int edfs_chkey(struct edfs *edfs_context, const char *key_id);
int edfs_rmkey(struct edfs *edfs_context, const char *key_id);
int edfs_storage_info(struct edfs *edfs_context, const char *key_id, uint64_t *size, uint64_t *files, uint64_t *directories);
int edfs_list_keys(struct edfs *edfs_context, char *buffer, int buffer_size);

void *edfs_get_key(struct edfs *edfs_context);
void *edfs_next_key(void *key);
void *edfs_get_primary_key(struct edfs *edfs_context);
char *edfs_key_id(void *key, char *buffer);
char *edfs_public_key(void *key, char *buffer);
char *edfs_private_key(void *key, char *buffer);

int edwork_readonly(struct edfs *edfs_context);

int edfs_proof_of_work(int bits, time_t timestamp, const unsigned char *resource, int resource_len, unsigned char *proof_str, int max_proof_len, unsigned char *proof_of_work);
int edfs_proof_of_work_verify(int bits, const unsigned char *proof_str, int proof_len, const unsigned char *subject, int subject_len, const unsigned char *prefix, int prefix_len);

int edfs_schedule(struct edfs *edfs_context, edfs_schedule_callback callback, uint64_t when, uint64_t expires, uint64_t userdata_a, uint64_t userdata_b, int run_now, int update, int idle, void *data);
int edfs_schedule_remove(struct edfs *edfs_context, edfs_schedule_callback callback, uint64_t userdata_a, uint64_t userdata_b);
int edfs_schedule_iterate(struct edfs *edfs_context, unsigned int *idle_ref);

struct edfs *edfs_create_context(const char *use_working_directory);
void edfs_destroy_context(struct edfs *edfs_context);

#endif
