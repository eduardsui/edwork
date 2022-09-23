#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64
#define THREAD_IMPLEMENTATION

// #define EDFS_USE_READ_QUEUE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#ifndef _WIN32
    #include <unistd.h>
    #include <fcntl.h>
#endif
#include <time.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "sha256.h"
#include "base64.h"
#include "base32.h"
#include "parson.h"
#include "xxhash.h"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include "edd25519.h"
#include "thread.h"
#include "miniz.c"
#include "edwork.h"
#include "log.h"
#include "tinydir.h"
#include "chacha.h"
#include "sha3.h"
#include "curve25519.h"
#include "edfs_core.h"
#include "avl.h"
#include "blockchain.h"
#include "sort.h"
#include "edfs_key_data.h"
#ifdef EDFS_EMULTATED_STORE
    #include "store.h"
#endif
#ifdef __APPLE__
    #include <CoreFoundation/CoreFoundation.h>
#endif
#include "doops.h"

#define BLOCK_SIZE_MAX          BLOCK_SIZE + 0x3000
#define EDFS_INO_CACHE_ADDR     20
#define BLOCKCHAIN_COMPLEXITY   22

#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...)            fprintf(stderr, __VA_ARGS__)
#define DEBUG_DUMP_HEX(buf, len)    {int _i_; for (_i_ = 0; _i_ < len; _i_++) { DEBUG_PRINT("%02X ", (unsigned int)(buf)[_i_]); } }
#define DEBUG_DUMP(buf, length)     fwrite(buf, 1, length, stderr);
#define DEBUG_DUMP_HEX_LABEL(title, buf, len)    {fprintf(stderr, "%s (%i): ", title, (int)len); DEBUG_DUMP_HEX(buf, len); fprintf(stderr, "\n");}
#else
#define DEBUG_PRINT(...)            { }
#define DEBUG_DUMP_HEX(buf, len)    { }
#define DEBUG_DUMP(buf, length)     { }
#define DEBUG_DUMP_HEX_LABEL(title, buf, len) { }
#endif

#ifdef _WIN32
    #include <windows.h>

    #if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
        #define DELTA_EPOCH_IN_MICROSECS  116444736000000000Ui64
    #else
        #define DELTA_EPOCH_IN_MICROSECS  116444736000000000ULL
    #endif
#ifndef HAVE_TIMEZONE
    struct timezone {
        int tz_minuteswest;
        int tz_dsttime;
    };
#endif

#ifdef EDFS_NO_DOOPS
    int gettimeofday(struct timeval *tv, struct timezone *tz) {
        FILETIME         ft;
        unsigned __int64 tmpres = 0;

        if (NULL != tv) {
            GetSystemTimeAsFileTime(&ft);

            tmpres  |= ft.dwHighDateTime;
            tmpres <<= 32;
            tmpres  |= ft.dwLowDateTime;

            tmpres     -= DELTA_EPOCH_IN_MICROSECS;
            tmpres     /= 10;

            tv->tv_sec  = (long)(tmpres / 1000000UL);
            tv->tv_usec = (long)(tmpres % 1000000UL);
        }

        if (NULL != tz) {
            tz->tz_minuteswest = _timezone / 60;
            tz->tz_dsttime     = _daylight;
        }
        return 0;
    }
#endif

    int truncate(const char *path, uint64_t length) {
        FILE *f = fopen(path, "w+b");
        if (f) {
            _chsize(fileno(f), length);
            fclose(f);
            return 0;
        }
        return -1;
    }

    #define EDFS_MKDIR(dir, mode)   mkdir(dir)
#else
    #include <sys/time.h>
    extern long timezone;

    #define EDFS_MKDIR(dir, mode)   mkdir(dir, mode)
#endif

#ifndef PRIu64
    #define PRIu64  "llu"
#endif

#ifndef S_ISLNK
    #define S_ISLNK(st_mode) 0
#endif

uint64_t switchorder(uint64_t input) {
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = input >> 56;
    data[1] = input >> 48;
    data[2] = input >> 40;
    data[3] = input >> 32;
    data[4] = input >> 24;
    data[5] = input >> 16;
    data[6] = input >> 8;
    data[7] = input >> 0;
    return rval;
}

#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : switchorder(x))
#endif

#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : switchorder(x))
#endif

#define edfs_min(x, y) ((x) < (y) ? (x) : (y))

static char const *default_working_directory = "./edfs";

struct vote_container {
    struct edfs_key_data *key_data;
    unsigned char subject[0xFF];
    int subject_size;
};

struct dirbuf {
    edfs_ino_t ino;
    void *userdata;
    struct edfs_key_data *key;
    size_t size;
    int64_t start;
};

struct edfs_hash_buffer {
    unsigned char buffer[BLOCK_SIZE];
    int read_size;
    int64_t chunk;
};

struct filewritebuf {
    edfs_ino_t ino;
    unsigned char *p;
    int64_t offset;
    int64_t file_size;

    uint64_t last_read_chunk;
    unsigned char *read_buffer;
    int read_buffer_size;
    uint64_t expires;

    uint64_t read_hash_cunk;
    unsigned char *read_hash_buffer;
    int read_hash_buffer_size;
    uint64_t read_hash_expires;

    int last_read_size;
    int size;
    int written_data;

    int check_hash;
    int in_read;

    struct edfs_hash_buffer *hash_buffer;
    struct edfs_key_data *key;
    int flags;

#ifdef EDFS_USE_READ_QUEUE
    unsigned char proof_cache[512];
    int proof_size;

    uint64_t request_timestamp;
    uint64_t requested_chunk;
    uint64_t timestamp;
    uint32_t requested_sig_hash;
    unsigned char is_sctp;
    unsigned char read_queued;
#endif
};

struct edwork_shard_io {
    uint64_t inode;
    uint64_t file_size;
    int try_update_hash;
    uint64_t start_chunk;
    uint64_t json_version;
    struct edfs_key_data *key;

    void *next;
};

struct edfs_x25519_key {
    unsigned char secret[32];
    unsigned char pk[32];
};

struct edfs_ino_cache {
    struct sockaddr_in clientaddr[EDFS_INO_CACHE_ADDR];
    uint64_t inode;
    int len;
    int offset;
    int clientaddr_size;
};

struct edfs_event {
    edfs_schedule_callback callback;
    uint64_t userdata_a;
    uint64_t userdata_b;
    uint64_t timeout;
    void *edfs_context;
    void *data;

    void *next;
};

#ifdef EDWORK_PEER_DISCOVERY_SERVICE
#define EDFS_MAX_PEER_DISCOVERY_ADDR_COUNT 10

struct edfs_peer_discovery_data {
    struct sockaddr addr[EDFS_MAX_PEER_DISCOVERY_ADDR_COUNT];
    unsigned short len;
};
#endif

struct edfs {
    int read_only_fs;
    int ping_received;

    int resync;
    int force_rebroadcast;
    char *host_and_port;
    time_t list_timestamp;
    uint64_t start_timestamp;

    char *edfs_directory;
    char *nodes_file;
    char *default_nodes;

    struct edwork_data *edwork;

    int events;
    thread_ptr_t network_thread;

    thread_mutex_t shard_lock;
    struct edwork_shard_io *shard_io;
    thread_ptr_t shard_thread;

    thread_mutex_t lock;
#ifdef EDFS_MULTITHREADED
    thread_mutex_t thread_lock;
#endif
    int network_done;
    int mutex_initialized;
    struct doops_loop loop;

    int port;

    struct edfs_key_data *key_data;
    struct edfs_key_data *primary_key;

    struct edfs_x25519_key key;
    struct edfs_x25519_key previous_key;

    avl_tree_t key_tree;
#ifdef EDWORK_PEER_DISCOVERY_SERVICE
    avl_tree_t peer_discovery;
    time_t disc_timestamp;
#endif

    int forward_chunks;

    int proxy;
    uint64_t proxy_timestamp;

    unsigned char storekey[32];
    int has_storekey;

    int shard_id;
    int shards;
#ifdef WITH_SCTP
    int force_sctp;
#endif
#ifdef WITH_CACHE_WARMUP
    uint64_t warmup_inode;
    uint64_t warmup_chunk;
    char warmup_key_dir[MAX_PATH_LEN];
    thread_ptr_t warmup_thread;
#endif
    uint64_t use_key_id;

#ifdef WITH_SMARTCARD
    struct edwork_smartcard_context smartcard_context;
#endif

#ifndef EDFS_NO_JS
    unsigned char app_mode;
#endif
};

#ifdef EDFS_MULTITHREADED
    #define EDFS_THREAD_LOCK(edfs_context)      if (edfs_context->mutex_initialized) thread_mutex_lock(&edfs_context->thread_lock);
    #define EDFS_THREAD_UNLOCK(edfs_context)    if (edfs_context->mutex_initialized) thread_mutex_unlock(&edfs_context->thread_lock);
#else
    #define EDFS_THREAD_LOCK(edfs_context)
    #define EDFS_THREAD_UNLOCK(edfs_context)
#endif


int sign(struct edfs *edfs_context, struct edfs_key_data *key, const char *str, int len, unsigned char *hash, int *info_key_type);
int edfs_flush_chunk(struct edfs *edfs_context, edfs_ino_t ino, struct filewritebuf *fi);
unsigned int edwork_resync(struct edfs *edfs_context, struct edfs_key_data *key, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket);
unsigned int edwork_resync_desc(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket);
unsigned int edwork_resync_dir_desc(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket);
int edwork_encrypt(struct edfs *edfs_context, struct edfs_key_data *key, const unsigned char *buffer, int size, unsigned char *out, const unsigned char *dest_i_am, const unsigned char *src_i_am, const unsigned char *shared_secret);
void edfs_block_save(struct edfs *edfs_context, struct edfs_key_data *key, struct block *chain);
void edfs_update_proof_inode(struct edfs_key_data *key, uint64_t ino);
int edfs_lookup_blockchain(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t inode, uint64_t block_timestamp_limit, unsigned char *blockchainhash, uint64_t *generation, uint64_t *timestamp);
size_t base64_encode_no_padding(const unsigned char *in, int in_size, unsigned char *out, int out_size);
int edfs_update_hash(struct edfs *edfs_context, struct edfs_key_data *key, const char *path, int64_t chunk, const unsigned char *buf, int size, struct edfs_hash_buffer *hash_buffer);
int edfs_update_chain(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t ino, int64_t file_size, unsigned char *hash, uint64_t *hash_chunks);
int edwork_load_key(struct edfs *edfs_context, const char *filename);
void edfs_broadcast_top(struct edfs *edfs_context, struct edfs_key_data *key, void *use_clientaddr, int clientaddr_len);
struct edfs_key_data *edfs_find_key(uint64_t keyid, void *userdata);
int edfs_init(struct edfs *edfs_context);
static void recursive_mkdir(const char *dir);
void edfs_warm_cache(struct edfs *edfs_context, const char *working_directory, edfs_ino_t ino, uint64_t chunk, uint64_t max_chunks);
void edfs_request_cache_warming(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, uint64_t chunk);
int edfs_check_descriptors(struct edfs *edfs_context, uint64_t userdata_a, uint64_t userdata_b, void *data);
int edfs_blockchain_request(struct edfs *edfs_context, uint64_t userdata_a, uint64_t userdata_b, void *data);
#ifndef EDFS_NO_JS
char *edfs_lazy_read_file(struct edfs *edfs_context, struct edfs_key_data *key, const char *filename, int *file_size, uint64_t offset, int max_size);
static void edfs_reload_app(struct edfs *edfs_context, struct edfs_key_data *key);
#endif

uint64_t microseconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000000 + (uint64_t)(tv.tv_usec);
}

static int ino_compare(void *a1, void *a2) {
    if (a1 < a2)
        return -1;

    if (a1 > a2)
        return 1;

    return 0;
}

void avl_ino_destructor(void *key) {
    // nothing
}

void avl_ino_key_data_destructor(void *key, void *data) {
    free(data);
}

void avl_no_destructor(void *key, void *data) {
    // nothing
}

int edfs_proof_of_work(int bits, time_t timestamp, const unsigned char *resource, int resource_len, unsigned char *proof_str, int max_proof_len, unsigned char *proof_of_work) {
    sha3_context ctx;
    const unsigned char *hash;
    static unsigned char ref_hash[8];

    if ((bits < 0) || (bits > 64))
        return 0;

    proof_str[0] = 0;

    char in[16];
    char out[32];
    edwork_random_bytes((unsigned char *)in, 16);

    int len = base64_encode_no_padding((const BYTE *)&in, 16, (BYTE *)out, 32);
    out[len] = 0;

#ifdef USE_HASHCASH_FORMAT
        char now_buf[20];
    #ifdef HAVE_GMTIME_R
        struct tm gmtm;
        gmtime_r(&timestamp, &gmtm);
        strftime(now_buf, sizeof(now_buf), "%Y%m%d%H%M%S", &gmtm);
    #else
        strftime(now_buf, sizeof(now_buf), "%Y%m%d%H%M%S", gmtime(&timestamp));
    #endif
    int proof_len = snprintf((char *)proof_str, max_proof_len, "edwork:1:%i:%s:%.*s::%s:", bits, now_buf, resource_len, (const char *)resource, out);
#else
    int proof_len = snprintf((char *)proof_str, max_proof_len, "edwork:1:%i:%i:%.*s::%s:", bits, (int)timestamp, resource_len, (const char *)resource, out);
#endif

    if (proof_len >= max_proof_len - 10)
        return 0;

    uint64_t counter = 0;
    unsigned char *ptr = proof_str + proof_len;

    int bytes = bits / 8;
    int mbits = bits % 8;

    if (mbits)
        mbits = 8 - mbits;

    // seems faster to just increment count instead of randomizing it
    while (1) {
        sha3_Init256(&ctx);

        uint64_t counter_be = htonll(counter);
#ifdef EDFS_HASHCASH_ASCII_STRING
        const BYTE *counter_ptr = (const BYTE *)&counter_be;
        int offset = 0;
        do {
            if (counter_ptr[offset])
                break;
            offset ++;
        } while (offset < 7);

        len = base64_encode_no_padding(counter_ptr + offset, 8 - offset, (BYTE *)ptr, max_proof_len - proof_len);
        sha3_Update(&ctx, proof_str, proof_len + len);
#else
        len = 8;
        sha3_Update(&ctx, proof_str, proof_len);
        sha3_Update(&ctx, (unsigned char *)&counter_be, 8);
#endif

        hash = (const unsigned char *)sha3_Finalize(&ctx);

        if (!memcmp(hash, ref_hash, bytes)) {
            if ((!mbits) || ((hash[bytes] >> mbits) == (ref_hash[bytes] >> mbits))) {
                if (proof_of_work)
                    memcpy(proof_of_work, hash, 32);
#ifndef EDFS_HASHCASH_ASCII_STRING
                memcpy(proof_str + proof_len, &counter_be, 8);
#endif
                proof_str[proof_len + len] = 0;
                return proof_len + len;
            }
        }
        counter++;

        // not found
        if (counter == 0)
            return 0;
    }
    return 0;
}

int edfs_proof_of_work_verify(int bits, const unsigned char *proof_str, int proof_len, const unsigned char *verify_str, int verify_len, const unsigned char *prefix, int prefix_len) {
    sha3_context ctx;
    const unsigned char *hash;
    static unsigned char ref_hash[8];

    if ((bits < 0) || (bits > 64)) {
        log_debug("unsupproted bit count");
        return 0;
    }

    if (proof_len < 10)
        return 0;

    if ((prefix) && (prefix_len)) {
        if (prefix_len > proof_len) {
            log_debug("proof too small");
            return 0;
        }

        // header prefix mismatch
        if (memcmp(proof_str, prefix, prefix_len)) {
            log_debug("header mismatch");
            return 0;
        }
    }
    int bytes = bits / 8;
    int mbits = bits % 8;

    int i;
    int parameter = 0;
    int timestamp = 0;
    for (i = 0; i < proof_len; i++) {
        if (proof_str[i] == ':') {
            parameter ++;
            if (parameter == 3) {
                if ((proof_len - i - 1) <= 2)
                    return 0;
                timestamp = atoi((const char *)proof_str + i + 1);
            } else
            if (parameter == 4) {
                if ((proof_len - i - 1) < verify_len) {
                    log_debug("verify buffer too small");
                    return 0;
                }
                if (memcmp(proof_str + i + 1, verify_str, verify_len)) {
                    log_debug("subject verify failed");
                    return 0;
                }
// #ifndef EDFS_HASHCASH_ASCII_STRING
                break;
// #endif
            }
        }
// #ifdef EDFS_HASHCASH_ASCII_STRING
//         else
//         if (!proof_str[i]) {
//             log_debug("binary proof of work encountered");
//             return 0;
//         }
// #endif
    }

    if (parameter < 4) {
        log_debug("invalid proof string");
        return 0;
    }

    if (!timestamp) {
        log_debug("timestamp missing");
        return 0;
    }

    if (mbits)
        mbits = 8 - mbits;

    sha3_Init256(&ctx);
    sha3_Update(&ctx, proof_str, proof_len);
    hash = (const unsigned char *)sha3_Finalize(&ctx);

    if ((memcmp(hash, ref_hash, bytes)) || ((mbits) && ((hash[bytes] >> mbits) != (ref_hash[bytes] >> mbits)))) {
        log_debug("puzzle verify failed");
        return 0;
    }

    return timestamp;
}

int edfs_file_lock(struct edfs *edfs_context, FILE *f, int exclusive_lock) {
    if (!f)
        return -1;
#ifdef _WIN32
    HANDLE f2 = (HANDLE)_get_osfhandle(fileno(f));
    if (!f2)
        return -1;

    OVERLAPPED sOverlapped;
    memset(&sOverlapped, 0, sizeof(OVERLAPPED));
    sOverlapped.Offset = 0;
    sOverlapped.OffsetHigh = 0;

    if (LockFileEx(f2, exclusive_lock ? LOCKFILE_EXCLUSIVE_LOCK : 0, 0, MAXDWORD, MAXDWORD, &sOverlapped))
        return 0;

    return -1;
#else
    // return flockfile(f);
    struct flock lock;
    memset (&lock, 0, sizeof(lock));
    lock.l_type = exclusive_lock ? F_WRLCK : F_RDLCK;
    return fcntl(fileno(f), F_SETLKW, &lock);
#endif
}

int edfs_file_unlock(struct edfs *edfs_context, FILE *f) {
    if (!f)
        return -1;
#ifdef _WIN32
    HANDLE f2 = (HANDLE)_get_osfhandle(fileno(f));
    if (!f2)
        return -1;

    OVERLAPPED sOverlapped;
    memset(&sOverlapped, 0, sizeof(OVERLAPPED));
    sOverlapped.Offset = 0;
    sOverlapped.OffsetHigh = 0;

    if (!UnlockFileEx(f2, 0, MAXDWORD, MAXDWORD, &sOverlapped))
        return -1;
    return 0;
#else
    // return funlockfile(f);
    struct flock lock;
    memset (&lock, 0, sizeof(lock));
    lock.l_type = F_UNLCK;
    return fcntl(fileno(f), F_SETLKW, &lock);
#endif
}

void edfs_notify_write(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int write) {
    thread_mutex_lock(&key->notify_write_lock);
    intptr_t write_count = (intptr_t)avl_remove(&key->notify_write, (void *)(uintptr_t)inode);
    if (write)
        write_count ++;
    else
        write_count --;
    if (write_count > 0)
        avl_insert(&key->notify_write, (void *)(uintptr_t)inode, (void *)write_count);
    thread_mutex_unlock(&key->notify_write_lock);
}

intptr_t edfs_is_write(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode) {
    thread_mutex_lock(&key->notify_write_lock);
    intptr_t write_count = (intptr_t)avl_search(&key->notify_write, (void *)(uintptr_t)inode);
    thread_mutex_unlock(&key->notify_write_lock);
    return write_count;
}

intptr_t edfs_may_write_block(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode) {
    thread_mutex_lock(&key->notify_write_lock);
    intptr_t write_count = (intptr_t)avl_search(&key->notify_write, (void *)(uintptr_t)inode);
    if (!write_count) {
        thread_mutex_unlock(&key->notify_write_lock);
        return 1;
    }
    intptr_t allow_data = (intptr_t)avl_search(&key->allow_data, (void *)(uintptr_t)inode);
    thread_mutex_unlock(&key->notify_write_lock);
    return allow_data;
}

void edfs_notify_allow_write_block(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int allow) {
    thread_mutex_lock(&key->notify_write_lock);
    if (allow)
        avl_insert(&key->allow_data, (void *)(uintptr_t)inode, (void *)1);
    else
        avl_remove(&key->allow_data, (void *)(uintptr_t)inode);
    thread_mutex_unlock(&key->notify_write_lock);
}

void edfs_notify_io(struct edfs *edfs_context, struct edfs_key_data *key, const char type[4], const unsigned char *buffer, int buffer_size, const unsigned char *append_data, int append_len, unsigned char ack, int do_sign, uint64_t ino, int proof_of_work, int loose_encrypt, void *use_clientaddr, int clientaddr_len, unsigned char *proof_of_work_cache, int *proof_of_work_size_cache) {
    if (edfs_context->network_done)
        return;
    if (!edfs_context->edwork) {
        log_warn("edwork context not yet initialized");
        return;
    }

    unsigned char ioblock_buffer[EDWORK_PACKET_SIZE];
    int ioblock_size = 0;
    if ((buffer) && (buffer_size > 0) && (append_len >= 0) && (buffer_size + append_len < EDWORK_PACKET_SIZE)) {
        int offset = 0;
        if (do_sign)
            offset = 64;

        memcpy(ioblock_buffer + offset, buffer, buffer_size);
        if (append_len > 0) {
            memcpy(ioblock_buffer + offset + buffer_size, append_data, append_len);
            buffer_size += append_len;
        }
        if (do_sign) {
            memcpy(ioblock_buffer + offset + buffer_size, type, 4);
            int signature_size = sign(edfs_context, key, (const char *)ioblock_buffer + offset, buffer_size + 4, ioblock_buffer, NULL);
            if (signature_size < 0) {
                log_error("error signing block");
                return;
            }
            buffer_size += offset;
        }
        if (loose_encrypt) {
            unsigned char buf2[BLOCK_SIZE_MAX];
            int size2 = edwork_encrypt(edfs_context, key, ioblock_buffer, buffer_size, buf2, NULL, edwork_who_i_am(edfs_context->edwork), NULL);
            memcpy(ioblock_buffer, buf2, size2);
            buffer_size = size2;
        }
        if (proof_of_work > 0) {
            if ((proof_of_work_cache) && (proof_of_work_size_cache) && (*proof_of_work_size_cache > 0)) {
                memcpy(ioblock_buffer + buffer_size, proof_of_work_cache, *proof_of_work_size_cache);
                buffer_size += *proof_of_work_size_cache;
            } else {
                sha3_context ctx;
                unsigned char out[64];

                sha3_Init256(&ctx);
                sha3_Update(&ctx, ioblock_buffer + offset, buffer_size);
                sha3_Update(&ctx, edwork_who_i_am(edfs_context->edwork), 32);
                int encode_len = base64_encode_no_padding((const unsigned char *)sha3_Finalize(&ctx), 32, out, 64);

                int proof_of_work_size = edfs_proof_of_work(proof_of_work, time(NULL), out, encode_len, ioblock_buffer + buffer_size, EDWORK_PACKET_SIZE - buffer_size, NULL);
                if ((proof_of_work_cache) && (proof_of_work_size_cache)) {
                    memcpy(proof_of_work_cache, ioblock_buffer + buffer_size, proof_of_work_size);
                    *proof_of_work_size_cache = proof_of_work_size;
                }
                buffer_size += proof_of_work_size;
            }
        }
        ioblock_size = buffer_size;
    } else {
        ioblock_size = 0;
    }

    switch (ack) {
        case 3:
            edwork_broadcast_client(edfs_context->edwork, key, type, ioblock_buffer, ioblock_size, 0, EDWORK_DATA_NODES, ino, use_clientaddr, clientaddr_len);
            break;
        case 2:
            edwork_broadcast_client(edfs_context->edwork, key, type, ioblock_buffer, ioblock_size, 1, EDWORK_NODES, ino, use_clientaddr, clientaddr_len);
            break;
        default:
            edwork_broadcast_client(edfs_context->edwork, key, type, ioblock_buffer, ioblock_size, ack ? EDWORK_NODES : 0, EDWORK_NODES, ino, use_clientaddr, clientaddr_len);
            break;
    }
    return;
}

#ifdef EDWORK_PEER_DISCOVERY_SERVICE
int edfs_add_to_peer_discovery(struct edfs_peer_discovery_data *peers, void *clientaddr, int clientaddrlen) {
    if ((!peers) || (!clientaddr) || (!clientaddrlen))
        return 0;
    int i;
    int found = 0;
    for (i = 0; i < peers->len; i++) {
        if (!memcmp(peers->addr, clientaddr, clientaddrlen))
            found = 1;
    }
    if (!found) {
        if (peers->len < EDFS_MAX_PEER_DISCOVERY_ADDR_COUNT) {
            memcpy(&peers->addr[peers->len], clientaddr, clientaddrlen);
            peers->len ++;
        } else {
            memmove(&peers->addr[0], &peers->addr[1], (EDFS_MAX_PEER_DISCOVERY_ADDR_COUNT - 1) * sizeof(struct sockaddr));
            memset(&peers->addr[peers->len - 1], 0, sizeof(struct sockaddr));
            memcpy(&peers->addr[peers->len - 1], clientaddr, clientaddrlen);
        }
        return 1;
    }
    return 0;
}

int edfs_get_peer_list(struct edfs_peer_discovery_data *peers, unsigned char *buf, int *buf_size) {
    if (!peers)
        return -1;

    int records = 0;
    unsigned int i;
    for (i = 0; i < peers->len; i++) {
        if (*buf_size < 7)
            break;
        records ++;
        *buf ++ = 6;
        memcpy(buf, &((struct sockaddr_in *)&peers->addr[i])->sin_addr, 4);
        buf += 4;
        memcpy(buf, &((struct sockaddr_in *)&peers->addr[i])->sin_port, 2);
        buf += 2;
        *buf_size -= 7;
    }
    *buf_size = records * 7;
    return records;
}

void edwork_broadcast_discovery_key(struct edfs *edfs_context, struct edfs_key_data *key) {
    unsigned char key_hash[32];
    if (key) {
        sha256(key->pubkey, key->pub_len, key_hash);
        hmac_sha256((const BYTE *)"key id", 6, (const BYTE *)key_hash, 32, NULL, 0, (BYTE *)key_hash);
        edfs_notify_io(edfs_context, NULL, "disc", key_hash, 32, NULL, 0, 0, 0, 0, EDWORK_LIST_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
        edfs_context->disc_timestamp = time(NULL);
    }
}

void edwork_broadcast_discovery(struct edfs *edfs_context) {
    unsigned char key_hash[32];
    struct edfs_key_data *key = edfs_context->key_data;
    while (key) {
        sha256(key->pubkey, key->pub_len, key_hash);
        hmac_sha256((const BYTE *)"key id", 6, (const BYTE *)key_hash, 32, NULL, 0, (BYTE *)key_hash);
        edfs_notify_io(edfs_context, NULL, "disc", key_hash, 32, NULL, 0, 0, 0, 0, EDWORK_LIST_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
        key = (struct edfs_key_data *)key->next_key;
    }

    edfs_context->disc_timestamp = time(NULL);
}
#endif

char *adjustpath(struct edfs_key_data *key_data, char *fullpath, const char *name) {
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", key_data->working_directory, name);
    return fullpath;
}

char *adjustpath2(struct edfs_key_data *key_data, char *fullpath, const char *name, uint64_t chunk) {
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", key_data->working_directory, name);
    // ensure directory exists
    EDFS_MKDIR(fullpath, 0755);
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s/%" PRIu64, key_data->working_directory, name, chunk);
    return fullpath;
}

char *adjustpath3(struct edfs_key_data *key_data, char *fullpath, const char *name, uint64_t chunk) {
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", key_data->working_directory, name);
    // ensure directory exists
    EDFS_MKDIR(fullpath, 0755);
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s/hash.%" PRIu64, key_data->working_directory, name, chunk);
    return fullpath;
}

char *store_adjustpath2(struct edfs_key_data *key_data, char *fullpath, const char *name, uint64_t chunk) {
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", key_data->working_directory, name);
    // ensure directory exists
    EDFS_MKDIR(fullpath, 0755);
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s/%04" PRIx64, key_data->working_directory, name, chunk);
    return fullpath;
}

#ifdef __APPLE__
const char *normalizedname(const char *name, int name_len, char *normalized_filename, int normalized_size) {
    normalized_filename[0] = 0;
    if (name_len > normalized_size - 1)
        name_len = normalized_size - 1;
    CFStringRef cfStringRef = CFStringCreateWithBytes(kCFAllocatorDefault, (const unsigned char *)name, name_len, kCFStringEncodingUTF8, FALSE);
    if (!cfStringRef)
        cfStringRef = CFStringCreateWithBytes(kCFAllocatorDefault, (const unsigned char *)name, name_len, kCFStringEncodingWindowsLatin1, FALSE);
    if (cfStringRef) {
        CFMutableStringRef cfMutable = CFStringCreateMutableCopy(NULL, 0, cfStringRef);
        CFStringNormalize(cfMutable, kCFStringNormalizationFormC);
        if (!CFStringGetCString(cfMutable, normalized_filename, normalized_size - 1, kCFStringEncodingUTF8)) {
            memcpy(normalized_filename, name, name_len);
            normalized_filename[name_len] = 0;
        }
        CFRelease(cfStringRef);
        CFRelease(cfMutable);
    } else {
        memcpy(normalized_filename, name, name_len);
        normalized_filename[name_len] = 0;
    }
    return normalized_filename;
}
#endif

uint64_t computeinode2(struct edfs_key_data *key, uint64_t parent_inode, const char *name, int name_len) {
    unsigned char hash[32];
    uint64_t inode;

#ifndef EDFS_SKIP_DEFAULT_KEY
    // default key ?
    if ((!parent_inode) && (key)) {
        static unsigned char default_key_id[8] = { 0x37, 0x9E, 0xA2, 0x49, 0xAC, 0xD1, 0x21, 0xB7 };
        if (!memcmp(&key->key_id_xxh64_be, default_key_id, sizeof(uint64_t))) {
            key = NULL;
            if ((!name) || (!name_len))
                return 1;
        }
    }
#endif

    parent_inode = htonll(parent_inode);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    if ((key) && (!parent_inode))
        sha256_update(&ctx, (const BYTE *)&key->key_id_xxh64_be, sizeof(uint64_t));
    sha256_update(&ctx, (const BYTE *)&parent_inode, sizeof(parent_inode));
#ifdef __APPLE__
    if (name) {
        char normalized_filename[MAX_PATH_LEN];
        normalizedname(name, name_len, normalized_filename, sizeof(normalized_filename));
        sha256_update(&ctx, (const BYTE *)normalized_filename, strlen(normalized_filename));
    }
#else
    if (name)
        sha256_update(&ctx, (const BYTE *)name, name_len);
#endif
    sha256_final(&ctx, hash);

    inode = XXH64(hash, 32, 0);
    return ntohll(inode);
}

uint64_t computeinode(struct edfs_key_data *key, uint64_t parent_inode, const char *name) {
    return computeinode2(key, parent_inode, name, strlen(name));
}

const char *computename(uint64_t inode, char *out) {
    inode = htonll(inode);
#ifdef EDFS_CASE_INSENSITIVE_ENCODING
    size_t len = base32_encode((const BYTE *)&inode, sizeof(uint64_t), (BYTE *)out, MAX_B64_HASH_LEN);
#else
    size_t len = base64_encode_no_padding((const BYTE *)&inode, sizeof(uint64_t), (BYTE *)out, MAX_B64_HASH_LEN);
#endif
    out[len] = 0;
    return (const char *)out;
}

const char *computeblockname(uint64_t inode, char *out) {
#ifdef EDFS_BASE64_BLOCKNAME
    return computename(inode, out);
#else
    inode = htonll(inode);
    size_t len = base32_encode((const BYTE *)&inode, sizeof(uint64_t), (BYTE *)out, MAX_B64_HASH_LEN);
    out[len] = 0;
    return (const char *)out;
#endif
}

size_t base64_decode_no_padding(const unsigned char *in, unsigned char *out, int max_len) {
    int in_len = strlen((const char *)in);
    int decoded_size = base64_decode(in_len, (char *)in, max_len, out);
    if (decoded_size < 0)
        decoded_size = 0;
    return decoded_size;
}

size_t base64_encode_no_padding(const unsigned char *in, int in_size, unsigned char *out, int out_size) {
    int encode_size = base64_encode(in_size, in, out_size, (char *)out);
    if (encode_size < 0)
        encode_size = 0;
    return encode_size;
}

int read_signature(struct edfs *edfs_context, const char *sig, unsigned char *sigdata, int verify, int *key_type, unsigned char *pubdata) {
    JSON_Value *root_value = NULL;
    if ((edfs_context) && (edfs_context->has_storekey)) {
        char keybuf[MAX_KEY_SIZE * 2];
        FILE *f = fopen(sig, "rb");
        if (f) {
            ssize_t key_size = edfs_read_simple_key(edfs_context, keybuf, sizeof(keybuf) - 1, f);
            fclose(f);
            if (key_size > 0) {
                keybuf[key_size] = 0;
                root_value = json_parse_string(keybuf);
            }
        }
    } else
        root_value = json_parse_file(sig);
    if (key_type)
        *key_type = 0;
    if (!root_value)
        return 0;

    if (json_value_get_type(root_value) != JSONObject) {
        json_value_free(root_value);
        return 0;
    }
    int len = 0;
    JSON_Object *root_object = json_value_get_object(root_value);

    const char *algorithm = json_object_get_string(root_object, "alg");
    if (!algorithm) {
        json_value_free(root_value);
        return 0;
    }
    if (!strcmp(algorithm, "HS256")) {
        const char *kty = json_object_get_string(root_object, "kty");
        if ((kty) && (strcmp(kty, "oct"))) {
            json_value_free(root_value);
            return 0;
        }

        const char *k = json_object_get_string(root_object, "k");
        if ((!k) || (!k[0])) {
            json_value_free(root_value);
            return 0;
        }

        int key_len = strlen(k);
        if (key_len > MAX_KEY_SIZE / 2) {
            json_value_free(root_value);
            return 0;
        }
        len = base64_decode_no_padding((const BYTE *)k, (BYTE *)sigdata, MAX_KEY_SIZE);
        if (len < 0)
            len = 0;
        else
        if (key_type)
            *key_type = KEY_HS256;
    } else
    if (!strcmp(algorithm, "ED25519")) {
        const char *kty = json_object_get_string(root_object, "kty");
        if ((kty) && (strcmp(kty, "EDD25519"))) {
            json_value_free(root_value);
            return 0;
        }

        const char *k;
        if (verify)
            k = json_object_get_string(root_object, "pk");
        else
            k = json_object_get_string(root_object, "k");
        if ((!k) || (!k[0])) {
            json_value_free(root_value);
            return 0;
        }

        int key_len = strlen(k);
        if (key_len > MAX_KEY_SIZE / 2) {
            json_value_free(root_value);
            return 0;
        }
        len = base64_decode_no_padding((const BYTE *)k, (BYTE *)sigdata, MAX_KEY_SIZE);
        if (len < 0)
            len = 0;
        else
        if (key_type) {
            *key_type = KEY_EDD25519;
            if (pubdata) {
                k = json_object_get_string(root_object, "pk");
                if ((!k) || (!k[0])) {
                    json_value_free(root_value);
                    return 0;
                }
                key_len = strlen(k);
                if (key_len > MAX_KEY_SIZE / 2) {
                    json_value_free(root_value);
                    return 0;
                }
                base64_decode_no_padding((const BYTE *)k, (BYTE *)pubdata, MAX_KEY_SIZE * 4);
            }
        }
    }

    json_value_free(root_value);
    return len;
}

int sign(struct edfs *edfs_context, struct edfs_key_data *key, const char *str, int len, unsigned char *hash, int *info_key_type) {
    if (info_key_type)
        *info_key_type = 0;
    if (!key->key_loaded) {
        EDFS_THREAD_LOCK(edfs_context);
        key->sig_len = read_signature(edfs_context, key->signature, key->sigkey, 0, &key->sign_key_type, key->pubkey);
        EDFS_THREAD_UNLOCK(edfs_context);
    }
    if (!key->sig_len)
        return 0;
    switch (key->sign_key_type) {
        case KEY_HS256:
            if (info_key_type)
                *info_key_type = key->sign_key_type;
            hmac_sha256((const BYTE *)key->sigkey, key->sig_len, (const BYTE *)str, len, NULL, 0, (BYTE *)hash);
            key->signature_size = 32;
            key->key_loaded = 1;
            break;
        case KEY_EDD25519:
            if (info_key_type)
                *info_key_type = key->sign_key_type;
            ed25519_sign(hash, (const unsigned char *)str, len, key->pubkey, key->sigkey);
            key->signature_size = 64;
            key->key_loaded = 1;
            break;
    }
    return key->signature_size;
}

int verify(struct edfs *edfs_context, struct edfs_key_data *key, const char *str, int len, const unsigned char *hash, int hash_size) {
    unsigned char hash2[32];

    if (!key->pub_loaded) {
        EDFS_THREAD_LOCK(edfs_context);
        key->pub_len = read_signature(edfs_context, key->signature, key->pubkey, 1, &key->key_type, NULL);
        if (key->pub_len)
            key->pub_loaded = 1;
        EDFS_THREAD_UNLOCK(edfs_context);
    }

    if (!key->pub_len) {
        log_error("verify error (no signature found)");
        return 0;
    }
    if (len < 0) {
        log_error("verify error (invalid message length)");
        return 0;
    }
    switch (key->key_type) {
        case KEY_HS256:
            if (hash_size < 32) {
                log_error("verify error (invalid public key)");
                return 0;
            }
            key->pub_loaded = 1;
            hmac_sha256((const BYTE *)key->pubkey, key->pub_len, (const BYTE *)str, len, NULL, 0, (BYTE *)hash2);
            if (!memcmp(hash2, hash, 32))
                return 1;
            log_warn("verify failed");
            return 0;
            break;
        case KEY_EDD25519:
            if ((hash_size != 64) || (key->pub_len != 32)) {
                log_error("verify error (invalid hash or public key) %i/%i", hash_size, key->pub_len);
                return 0;
            }
            key->pub_loaded = 1;
            if (ed25519_verify(hash, (const unsigned char *)str, len, key->pubkey))
                return 1;
            log_error("verification failed for %i bytes", len);
            return 0;
            break;
    }
    log_error("unsupported key type (%i)", (int)key->key_type);
    return 0;
}

void derive_storage_key(struct edfs *edfs_context, struct edfs_key_data *used_key, uint64_t inode, int64_t chunk, unsigned char key[32], unsigned char ivector[32]) {
    if (!used_key->pub_loaded) {
        EDFS_THREAD_LOCK(edfs_context);
        used_key->pub_len = read_signature(edfs_context, used_key->signature, used_key->pubkey, 1, &used_key->key_type, NULL);
        if (used_key->pub_len > 0)
            used_key->pub_loaded = 1;
        EDFS_THREAD_UNLOCK(edfs_context);
    }

    if (inode) {
        unsigned char hash[32];
        uint64_t inode_be = htonll(inode);
        uint64_t chunk_be = htonll(chunk);

        hmac_sha256((const BYTE *)edfs_context->storekey, 32, (const BYTE *)&chunk_be, sizeof(chunk_be), (const BYTE *)&inode_be, sizeof(inode_be), (BYTE *)hash);

        hmac_sha256((const BYTE *)used_key->pubkey, used_key->pub_len, (const BYTE *)"EDFS STORAGEKEY:", 16, (const BYTE *)hash, 32, (BYTE *)key);
        hmac_sha256((const BYTE *)used_key->pubkey, used_key->pub_len, (const BYTE *)"EDFS STORAGE VECTOR:", 20, (const BYTE *)hash, 32, (BYTE *)ivector);
    } else {
        hmac_sha256((const BYTE *)used_key->pubkey, used_key->pub_len, (const BYTE *)"EDFS STORAGEKEY:", 16, (const BYTE *)edfs_context->storekey, 32, (BYTE *)key);
        hmac_sha256((const BYTE *)used_key->pubkey, used_key->pub_len, (const BYTE *)"EDFS STORAGE VECTOR:", 20, (const BYTE *)edfs_context->storekey, 32, (BYTE *)ivector);
    }
}

void derive_simple_key(struct edfs *edfs_context, unsigned char key[32], unsigned char ivector[32]) {
    hmac_sha256((const BYTE *)edfs_context->storekey, 32, (const BYTE *)"storekey", 8, NULL, 0, (BYTE *)key);
    hmac_sha256((const BYTE *)edfs_context->storekey, 32, (const BYTE *)"store vector", 12, NULL, 0, (BYTE *)ivector);
}

ssize_t fread_with_key(struct edfs *edfs_context, struct edfs_key_data *used_key, uint64_t inode, int64_t chunk, void *ptr, size_t size, size_t nmemb, FILE *stream, int signature_prefix) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size > 0) && (nmemb > 0)) {
        ssize_t err;
        if ((signature_prefix) && (nmemb >= 64)) {
            err = fread(ptr, 1, 64, stream);
            if ((err != 64) || (nmemb == 64))
                return err;

            nmemb -= 64;
            ptr = (unsigned char *)ptr + 64;
        }
        unsigned char *out = (unsigned char *)malloc(size * nmemb);
        if (!out)
            return -1;
        err = fread(out, size, nmemb, stream);
        if (err <= 0) {
            free(out);
            return err;
        }

        struct chacha_ctx ctx;
        unsigned char key[32];
        unsigned char ivector[32];

        derive_storage_key(edfs_context, used_key, inode, chunk, key, ivector);

        chacha_keysetup(&ctx, key, 256);
        chacha_ivsetup(&ctx, ivector, NULL);

        chacha_encrypt_bytes(&ctx, (const unsigned char *)out, (unsigned char *)ptr, err);
        free(out);
        return err;
    }
    return fread(ptr, size, nmemb, stream);
}

ssize_t edfs_read_simple_key(struct edfs *edfs_context, void *ptr, size_t size, FILE *stream) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size > 0)) {
        unsigned char *out = (unsigned char *)malloc(size);
        if (!out)
            return -1;
        ssize_t err = fread(out, 1, size, stream);
        if (err <= 0) {
            free(out);
            return err;
        }

        struct chacha_ctx ctx;
        unsigned char key[32];
        unsigned char ivector[32];

        derive_simple_key(edfs_context, key, ivector);

        chacha_keysetup(&ctx, key, 256);
        chacha_ivsetup(&ctx, ivector, NULL);

        chacha_encrypt_bytes(&ctx, (const unsigned char *)out, (unsigned char *)ptr, err);
        free(out);

        return err;
    }
    return fread(ptr, 1, size, stream);
}

#ifdef EDFS_EMULATED_STORE
ssize_t store_write_with_key(struct edfs *edfs_context, struct edfs_key_data *used_key, uint64_t inode, int64_t chunk, const void *ptr, size_t size, size_t nmemb, struct store_data *stream) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size > 0) && (nmemb > 0)) {
        struct chacha_ctx ctx;
        unsigned char key[32];
        unsigned char ivector[32];
        unsigned char *out = (unsigned char *)malloc(size * nmemb);
        if (!out)
            return -1;

        derive_storage_key(edfs_context, used_key, 0, 0, key, ivector);

        chacha_keysetup(&ctx, key, 256);
        chacha_ivsetup(&ctx, ivector, NULL);

        chacha_encrypt_bytes(&ctx, (unsigned char *)ptr, out, size * nmemb);

        ssize_t err = store_write(out, size * nmemb, stream);
        free(out);
        return err;
    }
    return store_write(ptr, size * nmemb, stream);
}

ssize_t store_write_block_with_key(struct edfs *edfs_context, struct edfs_key_data *key, const void *ptr, size_t size, size_t nmemb, struct store_data *stream) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size * nmemb >= 64)) {
        ssize_t written = store_write(ptr, 64, stream);
        if (written != 64)
            return written;
        ssize_t written_data = store_write_with_key(edfs_context, key, 0, 0, (const unsigned char *)ptr + 64, 1, (nmemb * size) - 64, stream);
        if (written_data < 0)
            return written_data;

        return written + written_data;
    }
    return store_write(ptr, size * nmemb, stream);
}

ssize_t store_read_with_key(struct edfs *edfs_context, struct edfs_key_data *used_key, void *ptr, size_t size, size_t nmemb, struct store_data *stream, int signature_prefix) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size > 0) && (nmemb > 0)) {
        ssize_t err;
        if ((signature_prefix) && (nmemb >= 64)) {
            err = store_read(ptr, 64, stream);
            if ((err != 64) || (nmemb == 64))
                return err;

            nmemb -= 64;
            ptr = (unsigned char *)ptr + 64;
        }
        unsigned char *out = (unsigned char *)malloc(size * nmemb);
        if (!out)
            return -1;
        err = store_read(out, size * nmemb, stream);
        if (err <= 0) {
            free(out);
            return err;
        }

        struct chacha_ctx ctx;
        unsigned char key[32];
        unsigned char ivector[32];

        derive_storage_key(edfs_context, used_key, 0, 0, key, ivector);

        chacha_keysetup(&ctx, key, 256);
        chacha_ivsetup(&ctx, ivector, NULL);

        chacha_encrypt_bytes(&ctx, (const unsigned char *)out, (unsigned char *)ptr, err);
        free(out);
        return err;
    }
    return store_read(ptr, size * nmemb, stream);
}

int store_read_signature(struct edfs *edfs_context, struct edfs_key_data *key, unsigned char *data, int len, struct store_data *f, unsigned char *signature, int signature_prefix) {
    if (signature) {
        int read_size = store_read(signature, 64, f);
        if (read_size != 64) {
            errno = EIO;
            return -EIO;
        }
        signature_prefix = 0;
    }
    return store_read_with_key(edfs_context, key, data, 1, len, f, signature_prefix);
}

int store_read_compressed(struct edfs *edfs_context, struct edfs_key_data *key, unsigned char *data, int len, struct store_data *f, unsigned char *signature, int signature_prefix) {
    unsigned char compressed_buffer[BLOCK_SIZE_MAX];
    int bytes_read = store_read_signature(edfs_context, key, compressed_buffer, BLOCK_SIZE_MAX, f, signature, signature_prefix);
    if (bytes_read > 0) {
        mz_ulong max_len = len;
        if (uncompress(data, &max_len, compressed_buffer, bytes_read) == Z_OK)
            return max_len;
        errno = EIO;
        return -EIO;
    }
    return bytes_read;
}

int edfs_read_store(struct edfs *edfs_context, struct edfs_key_data *key, const char *base_path, uint64_t chunk, unsigned char *data, int len, int check_signature, int compression, int *filesize, uint32_t signature_hash, int signature_prefix) {
    struct store_data *f;
    char fullpath[MAX_PATH_LEN];
    unsigned char sig_buf[BLOCK_SIZE_MAX];
    unsigned char hash[64];
    unsigned char *sig_ptr = NULL;
    int sig_bytes_read = 0;

    if (filesize)
        *filesize = 0;

    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%04" PRIx64, base_path, chunk / STORE_CHUNKS_PER_FILE);
    f = store_open(fullpath, 0, chunk % STORE_CHUNKS_PER_FILE);
    if (!f)
        return -errno;

    edfs_file_lock(edfs_context, store_handle(f), 0);
    int bytes_read;
    if ((compression) || ((check_signature) && ((len < BLOCK_SIZE) && (len > 0)))) {
        if (compression) {
            sig_bytes_read = store_read_compressed(edfs_context, key, sig_buf, BLOCK_SIZE_MAX, f, check_signature ? hash : NULL, signature_prefix);
        } else {
            sig_bytes_read = store_read_signature(edfs_context, key, sig_buf, BLOCK_SIZE_MAX, f, check_signature ? hash : NULL, signature_prefix);
        }
        sig_ptr = sig_buf;
        if (sig_bytes_read <= 0) {
            bytes_read = sig_bytes_read;
        } else {
            bytes_read = edfs_min(len, sig_bytes_read);
            memcpy(data, sig_buf, bytes_read);
        }
    } else {
        bytes_read = store_read_signature(edfs_context, key, data, len, f, check_signature ? hash : NULL, signature_prefix);
        sig_ptr = data;
        sig_bytes_read = bytes_read;
    }
    if ((bytes_read < 0) || (sig_bytes_read < 0)) {
        int err = -errno;
        edfs_file_unlock(edfs_context, store_handle(f));
        store_close(f);
        return err;
    }
    edfs_file_unlock(edfs_context, store_handle(f));
    store_close(f);

    if (check_signature) {
        if (verify(edfs_context, key, (const char *)sig_ptr, sig_bytes_read, hash, sizeof(hash))) {
            if (signature_hash) {
                if (XXH32(hash, sizeof(hash), 0) != signature_hash) {
                    log_warn("different chunk version received");
                    return -EIO;
                }
            }
            return bytes_read;
        }
        log_error("signature verify failed (%s)", fullpath);
        return -EIO;
    }

    if (filesize)
        *filesize = sig_bytes_read;

    return bytes_read;
}
#endif

ssize_t fwrite_with_key(struct edfs *edfs_context, struct edfs_key_data *used_key, uint64_t inode, int64_t chunk, const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size > 0) && (nmemb > 0)) {
        struct chacha_ctx ctx;
        unsigned char key[32];
        unsigned char ivector[32];
        unsigned char *out = (unsigned char *)malloc(size * nmemb);
        if (!out)
            return -1;

        derive_storage_key(edfs_context, used_key, inode, chunk, key, ivector);

        chacha_keysetup(&ctx, key, 256);
        chacha_ivsetup(&ctx, ivector, NULL);

        chacha_encrypt_bytes(&ctx, (unsigned char *)ptr, out, size * nmemb);

        ssize_t err = fwrite(out, size, nmemb, stream);
        free(out);
        return err;
    }
    return fwrite(ptr, size, nmemb, stream);
}

ssize_t edfs_write_simple_key(struct edfs *edfs_context, const void *ptr, size_t size, FILE *stream) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size > 0)) {
        struct chacha_ctx ctx;
        unsigned char key[32];
        unsigned char ivector[32];
        unsigned char *out = (unsigned char *)malloc(size);
        if (!out)
            return -1;

        derive_simple_key(edfs_context, key, ivector);

        chacha_keysetup(&ctx, key, 256);
        chacha_ivsetup(&ctx, ivector, NULL);

        chacha_encrypt_bytes(&ctx, (unsigned char *)ptr, out, size);

        ssize_t err = fwrite(out, 1, size, stream);
        free(out);
        return err;
    }
    return fwrite(ptr, 1, size, stream);
}

ssize_t fwrite_block_with_key(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size * nmemb >= 64)) {
        ssize_t written = fwrite(ptr, 1, 64, stream);
        if (written != 64)
            return written;
        ssize_t written_data = fwrite_with_key(edfs_context, key, inode, chunk, (const unsigned char *)ptr + 64, 1, (nmemb * size) - 64, stream);
        if (written_data < 0)
            return written_data;

        return written + written_data;
    }
    return fwrite(ptr, size, nmemb, stream);
}

ssize_t fread_block_with_key(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if ((edfs_context) && (edfs_context->has_storekey) && (size * nmemb >= 64)) {
        ssize_t sig_size = fread(ptr, 1, 64, stream);
        if (sig_size != 64)
            return sig_size;
        ssize_t read_data = fread_with_key(edfs_context, key, inode, chunk, (unsigned char *)ptr + 64, 1, (nmemb * size) - 64, stream, 0);
        if (read_data < 0)
            return read_data;

        return sig_size + read_data;
    }
    return fread(ptr, size, nmemb, stream);
}


int fwrite_signature(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, const unsigned char *data, int len, FILE *f, unsigned char *signature, int signature_size) {
    if ((signature) && (signature_size > 0)) {
        // static => initialized with 0
        static unsigned char dummy_buffer[64];

        if (fwrite(signature, 1, signature_size, f) != signature_size)
            return -1;

        if (signature_size < 64) {
            if (fwrite(dummy_buffer, 1, 64 - signature_size, f) != 64 - signature_size)
                return -1;
        }
    }
    return fwrite_with_key(edfs_context, key, inode, chunk, data, 1, len, f);
}

int fwrite_compressed(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, const unsigned char *data, int len, FILE *f, unsigned char *signature, int signature_size, unsigned char *compressed_buffer, mz_ulong *max_len) {
    if (compress(compressed_buffer, max_len, data, len) == Z_OK) {
        int written = fwrite_signature(edfs_context, key, inode, chunk, compressed_buffer, *max_len, f, signature, signature_size);
        if (written > 0)
            written = len;
        return written;
    }
    return -EIO;
}

int fread_signature(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, unsigned char *data, int len, FILE *f, unsigned char *signature, int signature_prefix) {
    if (signature) {
        int read_size = fread(signature, 1, 64, f);
        if (read_size != 64) {
            errno = EIO;
            return -EIO;
        }
        signature_prefix = 0;
    }
    return fread_with_key(edfs_context, key, inode, chunk, data, 1, len, f, signature_prefix);
}

int fread_compressed(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, unsigned char *data, int len, FILE *f, unsigned char *signature, int signature_prefix) {
    unsigned char compressed_buffer[BLOCK_SIZE_MAX];
    int bytes_read = fread_signature(edfs_context, key, inode, chunk, compressed_buffer, BLOCK_SIZE_MAX, f, signature, signature_prefix);
    if (bytes_read > 0) {
        mz_ulong max_len = len;
        if (uncompress(data, &max_len, compressed_buffer, bytes_read) == Z_OK)
            return max_len;
        errno = EIO;
        return -EIO;
    }
    return bytes_read;
}

int edfs_write_file(struct edfs *edfs_context, struct edfs_key_data *key, const char *base_path, const char *name, const unsigned char *data, int len, const char *suffix, int do_sign, unsigned char *compressed_buffer, mz_ulong *max_len, unsigned char signature[64], int *sig_size, int signature_prefix, uint64_t inode, int64_t chunk) {
    FILE *f;
    char fullpath[MAX_PATH_LEN];
    const char *fname;
    unsigned char hash[64];
    int hash_size = 0;
    if ((base_path) && (base_path[0])) {
        fullpath[0] = 0;
        if ((suffix) && (suffix[0]))
            snprintf(fullpath, MAX_PATH_LEN, "%s/%s%s", base_path, name, suffix);
        else
            snprintf(fullpath, MAX_PATH_LEN, "%s/%s", base_path, name);
        fname = fullpath;
    } else
        fname = name;

    f = fopen(fname, "wb");
    if (!f)
        return -errno;

    edfs_file_lock(edfs_context, f, 1);
    int written_signature = 0;
    if (do_sign) {
        hash_size = sign(edfs_context, key, (const char *)data, len, hash, NULL);
        if (!hash_size) {
            edfs_file_unlock(edfs_context, f);
            fclose(f);
            return -EIO;
        }
        if (signature) {
            memcpy(signature, hash, hash_size);
            if (hash_size == 32)
                memset(signature + 32, 0, 32);
        }
        if (sig_size)
            *sig_size = hash_size;
    } else
    if ((signature_prefix) && (len >= 64) && (edfs_context->has_storekey)) {
        // write signature
        written_signature = fwrite(data, 1, 64, f);
        data += 64;
        len -= 64;
    }

    int written;
    if ((compressed_buffer) && (max_len))
        written = fwrite_compressed(edfs_context, key, inode, chunk, data, len, f, hash, hash_size, compressed_buffer, max_len);
    else
        written = fwrite_signature(edfs_context, key, inode, chunk, data, len, f, hash, hash_size);

    if (written < 0) {
        int err = -errno;
        edfs_file_unlock(edfs_context, f);
        fclose(f);
        return err;
    }
    edfs_file_unlock(edfs_context, f);
    fclose(f);
    return written + written_signature;
}

int edfs_scheduled_event(struct doops_loop *loop) {
    struct edfs_event *updated_event = (struct edfs_event *)loop_event_data(loop);
    if (!updated_event)
        return 1;
    // expired ?
    if ((updated_event->timeout) && (updated_event->timeout <= microseconds())) {
        ((struct edfs *)updated_event->edfs_context)->events --;
        free(updated_event);
        return 1;
    }

    if (updated_event->callback((struct edfs *)updated_event->edfs_context, updated_event->userdata_a, updated_event->userdata_b, updated_event->data)) {
        ((struct edfs *)updated_event->edfs_context)->events --;
        free(updated_event);
        return 1;
    }

    return 0;
}

static int edfs_schedule_foreach_data(struct doops_loop *loop, void *foreachdata) {
    struct edfs_event *udata = (struct edfs_event *)loop_event_data(loop);
    struct edfs_event *search = (struct edfs_event *)foreachdata;
    // return value > 1 will cause the foreach loop to stop
    if ((udata) && (search) && (udata->callback == search->callback) && (udata->userdata_a == search->userdata_a) && (udata->userdata_b == search->userdata_b) && (udata->data == search->data)) {
        free(udata);
        return 2;
    }
    return 0;
}

int edfs_schedule(struct edfs *edfs_context, edfs_schedule_callback callback, uint64_t when, uint64_t expires, uint64_t userdata_a, uint64_t userdata_b, int run_now, int update, void *data) {
    if ((!callback) || (!edfs_context))
        return 0;

    log_trace("scheduling event");
    struct edfs_event *updated_event = (struct edfs_event *)malloc(sizeof(struct edfs_event));
    if (!updated_event) {
        log_error("error creating event");
        return 0;
    }
    updated_event->edfs_context = edfs_context;

    updated_event->callback = callback;
    updated_event->userdata_a = userdata_a;
    updated_event->userdata_b = userdata_b;
    updated_event->data = data;

    if (update) {
        if (loop_foreach(&edfs_context->loop, edfs_schedule_foreach_data, updated_event) == 1)
            edfs_context->events --;
    }

    if (expires)
        updated_event->timeout = microseconds() + expires;
    else
        updated_event->timeout = 0;
    if (run_now)
        loop_add(&edfs_context->loop, edfs_scheduled_event, - (when / 1000), updated_event);
    else
        loop_add(&edfs_context->loop, edfs_scheduled_event, when / 1000, updated_event);
    edfs_context->events ++;
    log_trace("scheduling done");
    return 1;
}

static int edfs_schedule_foreach(struct doops_loop *loop, void *foreachdata) {
    struct edfs_event *udata = (struct edfs_event *)loop_event_data(loop);
    struct edfs_event *search = (struct edfs_event *)foreachdata;
    // return value > 1 will cause the foreach loop to stop
    if ((udata) && (search) && (udata->callback == search->callback) && (udata->userdata_a == search->userdata_a) && (udata->userdata_b == search->userdata_b)) {
        free(udata);
        return 2;
    }
    return 0;
}

int edfs_schedule_remove(struct edfs *edfs_context, edfs_schedule_callback callback, uint64_t userdata_a, uint64_t userdata_b) {
    if ((!callback) || (!edfs_context))
        return 0;

    struct edfs_event look_for;
    look_for.callback = callback;
    look_for.userdata_a = userdata_a;
    look_for.userdata_b = userdata_b;

    if (loop_foreach(&edfs_context->loop, edfs_schedule_foreach, &look_for) == 1)
        edfs_context->events --;
    return 0;
}

int edfs_unlink_file(struct edfs *edfs_context, const char *base_path, const char *name) {
    char fullpath[MAX_PATH_LEN];
    const char *fname;

    if ((base_path) && (base_path[0])) {
        fullpath[0] = 0;
        snprintf(fullpath, MAX_PATH_LEN, "%s/%s", base_path, name);
        fname = fullpath;
    } else
        fname = name;

    return unlink(fname);
}

int edfs_read_file(struct edfs *edfs_context, struct edfs_key_data *key, const char *base_path, const char *name, unsigned char *data, int len, const char *suffix, int as_text_file, int check_signature, int compression, int *filesize, uint32_t signature_hash, int signature_prefix, uint64_t inode, int64_t chunk) {
    FILE *f;
    char fullpath[MAX_PATH_LEN];
    unsigned char sig_buf[BLOCK_SIZE_MAX];
    unsigned char hash[64];
    unsigned char *sig_ptr = NULL;
    int sig_bytes_read = 0;
    const char *fname;
    if (filesize)
        *filesize = 0;

    if ((base_path) && (base_path[0])) {
        fullpath[0] = 0;
        if ((suffix) && (suffix[0]))
            snprintf(fullpath, MAX_PATH_LEN, "%s/%s%s", base_path, name, suffix);
        else
            snprintf(fullpath, MAX_PATH_LEN, "%s/%s", base_path, name);
        fname = fullpath;
    } else
        fname = name;

    f = fopen(fname, "rb");
    if (!f)
        return -errno;

    if (as_text_file)
        len--;

    edfs_file_lock(edfs_context, f, 0);
    int bytes_read;
    if ((compression) || ((check_signature) && ((len < BLOCK_SIZE) && (len > 0)))) {
        if (compression) {
            sig_bytes_read = fread_compressed(edfs_context, key, inode, chunk, sig_buf, BLOCK_SIZE_MAX, f, check_signature ? hash : NULL, signature_prefix);
        } else {
            sig_bytes_read = fread_signature(edfs_context, key, inode, chunk, sig_buf, BLOCK_SIZE_MAX, f, check_signature ? hash : NULL, signature_prefix);
        }
        sig_ptr = sig_buf;
        if (sig_bytes_read <= 0) {
            bytes_read = sig_bytes_read;
        } else {
            bytes_read = edfs_min(len, sig_bytes_read);
            memcpy(data, sig_buf, bytes_read);
        }
    } else {
        bytes_read = fread_signature(edfs_context, key, inode, chunk, data, len, f, check_signature ? hash : NULL, signature_prefix);
        sig_ptr = data;
        sig_bytes_read = bytes_read;
    }
    if ((bytes_read < 0) || (sig_bytes_read < 0)) {
        int err = -errno;
        edfs_file_unlock(edfs_context, f);
        fclose(f);
        return err;
    }
    edfs_file_unlock(edfs_context, f);
    fclose(f);
    if (as_text_file)
        data[bytes_read] = 0;
    if (check_signature) {
        if (verify(edfs_context, key, (const char *)sig_ptr, sig_bytes_read, hash, sizeof(hash))) {
            if (signature_hash) {
                uint32_t computed_hash = XXH32(hash, sizeof(hash), 0);
                if (computed_hash != signature_hash) {
                    log_warn("different chunk version received %x <=> %x", signature_hash, computed_hash);
                    return -EIO;
                }
            }
            return bytes_read;
        }
        log_error("signature verify failed (%s)", fname);
        return -EIO;
    }

    if (filesize)
        *filesize = sig_bytes_read;

    return bytes_read;
}

int verify_file(struct edfs *edfs_context, struct edfs_key_data *key, const char *base_path, const char *name) {
    unsigned char data[BLOCK_SIZE];
    if (edfs_read_file(edfs_context, key, base_path, name, data, BLOCK_SIZE, NULL, 0, 1, 0, NULL, 0, 0, 0, 0) <= 0)
        return 0;
    return 1;
}

uint64_t unpacked_ino(const char *data) {
    uint64_t ino = 0;
    if ((data) && (data[0])) {
        unsigned char buf[MAX_B64_HASH_LEN];
#ifdef EDFS_CASE_INSENSITIVE_ENCODING
        if (base32_decode((const BYTE *)data, (BYTE *)buf, MAX_B64_HASH_LEN) == 8)
            ino = ntohll((*(uint64_t *)buf));
#else
        if (base64_decode_no_padding((const BYTE *)data, (BYTE *)buf, MAX_B64_HASH_LEN) == 8)
            ino = ntohll((*(uint64_t *)buf));
#endif
    }
    return ino;
}

#ifdef WITH_SMARTCARD
static void smartcard_remove_signature(JSON_Array *signatures, const char *remove_identity) {
    if ((!remove_identity) || (!signatures))
        return;

    size_t array_count = json_array_get_count(signatures);
    if (array_count > 0) {
        size_t i = 0;
        while (i < array_count) {
            JSON_Object *signature_root_object = json_array_get_object(signatures, i);
            if (signature_root_object) {
                const char *identity = json_object_get_string(signature_root_object, "identity");
                if ((identity) && (!strcmp(remove_identity, identity)) && (json_array_remove(signatures, i) == JSONSuccess)) {
                    array_count --;
                    continue;
                }
            }
            i ++;
        }
    }
}

static void smartcard_sign_json(struct edfs *edfs_context, JSON_Object *root_object, const unsigned char *last_hash, int hash_size) {
    unsigned char temp_buf[64];
    if (edwork_smartcard_valid(&edfs_context->smartcard_context)) {
        unsigned char smartcard_signature[2048];
        if ((!last_hash) || (!hash_size)) {
            const char *iohash_mime = json_object_get_string(root_object, "iostamp");
            if (iohash_mime) {
                int mime_len = strlen(iohash_mime);
                if (mime_len > 43)
                    mime_len = 43;
                int len = base64_decode_no_padding((const BYTE *)iohash_mime, (BYTE *)temp_buf, 32);
                if (len < 32)
                    return;
                last_hash = temp_buf;
                hash_size = 32;
            } else {
                return;
            }
        }
        log_info("smartcard signing for %s", edfs_context->smartcard_context.buf_name);
        int smartcard_signature_size = edwork_smartcard_sign(&edfs_context->smartcard_context, last_hash, hash_size, smartcard_signature, sizeof(smartcard_signature));
        if (smartcard_signature_size > 0) {
            char signature_json_buffer[4096];
            int signature_json_len = base64_encode_no_padding((const BYTE *)smartcard_signature, smartcard_signature_size, (BYTE *)signature_json_buffer, sizeof(signature_json_buffer) - 1);
            if (signature_json_len < 0)
                signature_json_len = 0;
            signature_json_buffer[signature_json_len] = 0;
            JSON_Array *signatures = json_object_get_array(root_object, "signatures");
            if (!signatures) {
                JSON_Value *value = json_value_init_array();
                signatures = json_value_get_array(value);
                json_object_set_value(root_object, "signatures", value);
            }

            JSON_Value *value = json_value_init_object();
            json_array_append_value(signatures, value);
            JSON_Object *root_object2 = json_value_get_object(value);
            json_object_set_value(root_object, "signatures", value);

            json_object_set_string(root_object2, "stamp", json_object_get_string(root_object, "iostamp"));
            json_object_set_string(root_object2, "owner", edfs_context->smartcard_context.buf_name);
            json_object_set_string(root_object2, "signature", signature_json_buffer);
            json_object_set_number(root_object2, "timestamp", microseconds());

            signature_json_len = base64_encode_no_padding((const BYTE *)edfs_context->smartcard_context.public_key, edfs_context->smartcard_context.public_key_len, (BYTE *)signature_json_buffer, sizeof(signature_json_buffer) - 1);
            if (signature_json_len < 0)
                signature_json_len = 0;
            signature_json_buffer[signature_json_len] = 0;

            // remove old signatures
            smartcard_remove_signature(signatures, signature_json_buffer);

            json_object_set_string(root_object2, "identity", signature_json_buffer);
        } else
            log_warn("error signing for identity %s", edfs_context->smartcard_context.buf_name);
    } else
    if ((last_hash) && (hash_size == 32)) {
        const char *iohash_mime = json_object_get_string(root_object, "iostamp");
        if (iohash_mime) {
            int mime_len = strlen(iohash_mime);
            if (mime_len > 43)
                mime_len = 43;
            int len = base64_decode_no_padding((const BYTE *)iohash_mime, (BYTE *)temp_buf, 32);
            if ((len < 32) || (memcmp(last_hash, temp_buf, 32)))
                json_object_remove(root_object, "signature");
        } else
            json_object_remove(root_object, "signature");
    }
}
#endif

void write_json(struct edfs *edfs_context, struct edfs_key_data *key, const char *base_path, const char *name, int64_t size, uint64_t inode, uint64_t parent, int type, unsigned char *last_hash, time_t created, time_t modified, uint64_t timestamp, uint64_t generation) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;
    unsigned char sigdata[64];
    char b64name[MAX_B64_HASH_LEN];
    char b64parent[MAX_B64_HASH_LEN];

    computename(inode, b64name);
    computename(parent, b64parent);

    json_object_set_string(root_object, "name", name);
    json_object_set_string(root_object, "inode", b64name);
    json_object_set_string(root_object, "parent", b64parent);
    json_object_set_number(root_object, "type", type);
    json_object_set_number(root_object, "size", size);
    time_t now = time(NULL);
    if (!created)
        created = now;
    if (!modified)
        modified = now;
    if (!timestamp)
        timestamp = microseconds();
    json_object_set_number(root_object, "timestamp", microseconds());
    json_object_set_number(root_object, "created", created);
    json_object_set_number(root_object, "modified", modified);
    if (last_hash) {
        char buffer[64];
        int len = base64_encode_no_padding((const BYTE *)last_hash, 32, (BYTE *)buffer, 64);
        if (len < 0)
            len = 0;
        buffer[len] = 0;

        json_object_set_string(root_object, "iostamp", buffer);
#ifdef WITH_SMARTCARD
        smartcard_sign_json(edfs_context, root_object, last_hash, 32);
#endif
    }
    json_object_set_number(root_object, "version", generation);
    serialized_string = json_serialize_to_string_pretty(root_value);
    int sig_size = sign(edfs_context, key, serialized_string, strlen(serialized_string), sigdata, NULL);
    if (!sig_size) {
        json_value_free(root_value);
        return;
    }
    int string_len = strlen(serialized_string);
    unsigned char signature[64];
    edfs_write_file(edfs_context, key, base_path, b64name, (const unsigned char *)serialized_string, string_len, ".json", 1, NULL, NULL, signature, NULL, 0, 0, 0);

    // do not broadcast root object
    if ((parent != 0) && (key)) {
        edfs_notify_io(edfs_context, key, "desc", signature, 64, (const unsigned char *)serialized_string, string_len, 1, 0, inode, 0, 0, NULL, 0, NULL, NULL);
        edfs_update_proof_inode(key, inode);
    }

    json_free_serialized_string(serialized_string);
    json_value_free(root_value);
}

JSON_Value *read_json(struct edfs *edfs_context, struct edfs_key_data *key, const char *base_path, uint64_t inode) {
    char data[MAX_INODE_DESCRIPTOR_SIZE];

    char b64name[MAX_B64_HASH_LEN];
    computename(inode, b64name);

    int data_size = edfs_read_file(edfs_context, key, base_path, b64name, (unsigned char *)data, MAX_INODE_DESCRIPTOR_SIZE - 1, ".json", 1, 1, 0, NULL, 0, 0, 0, 0);
    if (data_size <= 0) {
        log_trace("invalid file %s/%s.json", base_path, b64name);
        return 0;
    }
    // signature is ok, proceed to processing
    JSON_Value *root_value = json_parse_string(data);
    if ((!root_value) || (json_value_get_type(root_value) != JSONObject)) {
        if (root_value)
            json_value_free(root_value);
        log_error("invlaid root object in JSON file");
        return 0;
    }
    return root_value;
}

int write_json2(struct edfs *edfs_context, struct edfs_key_data *key, const char *base_path, uint64_t inode, JSON_Value *root_value) {
    char b64name[MAX_B64_HASH_LEN];
    computename(inode, b64name);
    int written = 0;

    char *serialized_string = json_serialize_to_string_pretty(root_value);
    if (!serialized_string)
        return 0;

    int string_len = strlen(serialized_string);
    unsigned char signature[64];
    if (edfs_write_file(edfs_context, key, key->working_directory, b64name, (const unsigned char *)serialized_string, string_len , ".json", 1, NULL, NULL, signature, NULL, 0, 0, 0) == string_len) {
        written = string_len;

        JSON_Object *root_object = json_value_get_object(root_value);
        if (root_object) {
            edfs_notify_io(edfs_context, key, "desc", signature, 64, (const unsigned char *)serialized_string, string_len, 1, 0, inode, 0, 0, NULL, 0, NULL, NULL);
            edfs_update_proof_inode(key, inode);
        }
    } else
        log_warn("error writing file %s", b64name);

    json_free_serialized_string(serialized_string);
    return written;
}

#ifndef EDFS_NO_JS
static void edfs_reload_app(struct edfs *edfs_context, struct edfs_key_data *key) {
    // do not load app for first block
    if ((!key) || (!key->chain) || (!key->chain->index) || (!edfs_context) || (!edfs_context->app_mode))
        return;

    key->reload_js = 0;
    char *code_js = NULL;
    
    switch (edfs_context->app_mode) {
        case 1:
            code_js = edfs_lazy_read_file(edfs_context, key, ".app.js", NULL, 0, 0);
            break;
        case 2:
            {
                char fullpath[MAX_PATH_LEN];
                snprintf(fullpath, MAX_PATH_LEN, "%s/%s", key->js_working_directory, ".app.js");
                FILE *f = fopen(fullpath, "rb");
                if (f) {
                    if (!fseek(f, 0L, SEEK_END)) {
                        int size = ftell(f);
                        if (size > 0) {
                            if (!fseek(f, 0L, SEEK_SET)) {
                                code_js = (char *)malloc(size + 1);
                                if (fread(code_js, 1, size, f) == size) {
                                    code_js[size] = 0;
                                } else {
                                    free(code_js);
                                    code_js = NULL;
                                }
                            }
                        }
                        fclose(f);
                    }
                }
            }
            break;
        default:
            log_error("unknown application mode %i", (int)edfs_context->app_mode);
            break;
    }
    if (code_js) {
        uint64_t new_hash = XXH64(code_js, strlen(code_js), 0);
        if (key->app_version != new_hash) {
            key->app_version = new_hash;
            if (edfs_context->app_mode == 1)
                log_trace("loading partition application");
            else
                log_trace("loading local application");
            edfs_key_data_reset_js(key);
            edfs_key_data_load_js(key, code_js);
        }
        free(code_js);
    } else
    if (key->js) {
        edfs_key_data_reset_js(key);
        key->app_version = 0;
        log_warn("removed js application");
    }
}
#endif

char *edfs_smartcard_get_signature(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int signature_index) {
    char *buffer = NULL;
    JSON_Value *root_value = read_json(edfs_context, key, key->working_directory, inode);
    if (!root_value) {
        log_trace("invalid JSON file");
        return buffer;
    }
    JSON_Object *root_object = json_value_get_object(root_value);

    JSON_Array *array_data  = json_object_get_array(root_object, "signatures");
    size_t array_count      = json_array_get_count(array_data);
    const char *iostamp     = json_object_get_string(root_object, "iostamp");
    int sig_index           = 0;
    if (signature_index < 0)
        signature_index = 0;
    if ((array_data) && (array_count > 0) && (iostamp)) {
        size_t i;
        for (i = 0; i < array_count; i ++) {
            JSON_Object *signature_root_object   = json_array_get_object(array_data, i);
            if (signature_root_object) {
                const char *owner           = json_object_get_string(signature_root_object, "owner");
                const char *signature       = json_object_get_string(signature_root_object, "signature");
                const char *identity        = json_object_get_string(signature_root_object, "identity");
                const char *stamp           = json_object_get_string(signature_root_object, "stamp");

                if ((iostamp) && (signature) && (identity) && (stamp) && (!strcmp(iostamp, stamp))) {
                    if (sig_index == signature_index) {
                        int id_len = strlen(identity);
                        int len = strlen(iostamp) + strlen(signature) + id_len + 4096;
                        if (owner)
                            len += strlen(owner);
                        buffer = (char *)malloc(len);
                        if (buffer) {
                            buffer[0] = 0;
                            if (id_len > 128) {
                                snprintf(buffer, len,
                                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                    "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
                                    "  <SignedInfo>\n"
                                    "    <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n"
                                    "    <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha256\"/>\n"
                                    "    <Reference URI=\"#object\">\n"
                                    "      <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha256\"/>\n"
                                    "      <DigestValue>%s</DigestValue>\n"
                                    "    </Reference>\n"
                                    "  </SignedInfo>\n"
                                    "  <SignatureValue>%s</SignatureValue>\n"
                                    "  <KeyInfo>\n"
                                    "    <KeyValue>\n"
                                    "      <RSAKeyValue><Modulus>%s</Modulus><Exponent>%s</Exponent></RSAKeyValue>\n"
                                    "    </KeyValue>\n"
                                    "  </KeyInfo>\n"
                                    "  <Object Id=\"object\"><![CDATA[%s]]></Object>\n"
                                    "</Signature>\n"
                                , iostamp, signature, identity, "AQAB", owner);
                            } else {
                                JSON_Value *root_value2 = json_value_init_object();
                                JSON_Object *root_object2 = json_value_get_object(root_value2);
                                json_object_set_string(root_object2, "owner", owner);
                                json_object_set_string(root_object2, "stamp", iostamp);
                                json_object_set_string(root_object2, "signature", signature);
                                json_object_set_string(root_object2, "identity", identity);
                                json_object_set_number(root_object2, "timestamp", json_object_get_number(signature_root_object, "timestamp"));
                                char *serialized_string = json_serialize_to_string_pretty(root_value2);
                                if (serialized_string) {
                                    snprintf(buffer, len, "%s", serialized_string);
                                    json_free_serialized_string(serialized_string);
                                }
                                json_value_free(root_value2);
                            }
                        }
                        break;
                    }
                    sig_index ++;
                }
            }
        }
    }
    json_value_free(root_value);
    return buffer;
}

uint64_t edfs_root_inode(struct edfs_key_data *key) {
    uint64_t root = 1;
    if (key)
        root = computeinode2(key, 0, NULL, 0);

    return root;
}

int read_file_json(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, uint64_t *parent, int64_t *size, uint64_t *timestamp, edfs_add_directory add_directory, struct dirbuf *b, char *namebuf, int len_namebuf, time_t *created, time_t *modified, uint64_t *generation, unsigned char *iohash, int *has_signature) {
    JSON_Value *root_value = read_json(edfs_context, key, key->working_directory, inode);
    if (!root_value) {
        if (inode == edfs_root_inode(key)) {
            // first time root
            // char fullpath[MAX_PATH_LEN];
            // char b64name[MAX_B64_HASH_LEN];
            // EDFS_MKDIR(adjustpath(edfs_context, fullpath, computename(1, b64name)), 0755);
            write_json(edfs_context, key, key->working_directory, ".", 0, inode, 0, S_IFDIR | 0755, NULL, 0, 0, 0, 0);
            root_value = read_json(edfs_context, key, key->working_directory, inode);
        }
        if (!root_value) {
            log_trace("invalid JSON file");
            return 0;
        }
    }
    JSON_Object *root_object = json_value_get_object(root_value);

    if (generation)
        *generation = (uint64_t)json_object_get_number(root_object, "version");

    int type = (int)json_object_get_number(root_object, "type");
    if ((int)json_object_get_number(root_object, "deleted")) {
        // ignore type for deleted objects
        type = 0;
    }

    if (parent) {
        const char *parent_str = json_object_get_string(root_object, "parent");
        *parent = unpacked_ino(parent_str);
    }

    if ((add_directory) || ((namebuf) && (len_namebuf > 0))) {
        const char *name = json_object_get_string(root_object, "name");
        if ((name) && (name[0])) {
            // ignore deleted objects
            if ((add_directory) && (type)) {
                if ((!parent) || (b->ino == *parent)) {
#ifndef EDFS_NO_JS
                    if (edfs_key_js_call_args(key, "edwork.events.onreaddir", "s__", name, inode, parent ? *parent : (uint64_t)0) != 1)
#endif
                    b->size += add_directory(name, inode, type, (int64_t)json_object_get_number(root_object, "size"), (time_t)json_object_get_number(root_object, "created"), (time_t)json_object_get_number(root_object, "modified"), (time_t)(json_object_get_number(root_object, "timestamp") / 1000000), b->userdata);
                }
            }
            if ((namebuf) && (len_namebuf)) {
                int name_len = strlen(name);
                if (name_len > len_namebuf - 1)
                    name_len = len_namebuf - 1;
                memcpy(namebuf, name, name_len);
                namebuf[name_len] = 0;
            }
        }
    }
    if (has_signature)
        *has_signature = 0;

    if (size)
        *size = (int64_t)json_object_get_number(root_object, "size");
    if (timestamp)
        *timestamp = (uint64_t)json_object_get_number(root_object, "timestamp");
    if (created)
        *created = (time_t)json_object_get_number(root_object, "created");
    if (modified)
        *modified = (time_t)json_object_get_number(root_object, "modified");

    if (iohash) {
        const char *iohash_mime = json_object_get_string(root_object, "iostamp");
        if (iohash_mime) {
            int mime_len = strlen(iohash_mime);
            if (mime_len > 43)
                mime_len = 43;
            int len = base64_decode_no_padding((const BYTE *)iohash_mime, (BYTE *)iohash, 32);
            if (len <= 0)
                memset(iohash, 0, 32);
        } else
            memset(iohash, 0, 32);
    }
    if (has_signature) {
        JSON_Array *signatures = json_object_get_array(root_object, "signatures");
        if ((signatures) && (json_array_get_count(signatures) > 0))
            *has_signature = 1;
    }

    json_value_free(root_value);
    return type;
}

int edfs_update_json(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, const char **keys_value) {
    if ((!keys_value) || (!keys_value[0]))
        return 0;

    JSON_Value *root_value = read_json(edfs_context, key, key->working_directory, inode);
    if (!root_value)
        return 0;

    JSON_Object *root_object = json_value_get_object(root_value);

#ifndef EDFS_NO_JS
    int reload_app = 0;
#endif
    do {
        const char *json_key = *(keys_value++);
        const char *json_value = *(keys_value++);

        if (!strcmp(json_key, "iostamp")) {
            char buffer[64];
            int len = base64_encode_no_padding((const BYTE *)json_value, 32, (BYTE *)buffer, 64);
            if (len < 0)
                len = 0;
            buffer[len] = 0;
            json_object_set_string(root_object, json_key, buffer);
#ifndef EDFS_NO_JS
            // reload .app.js ?
            const char *name = json_object_get_string(root_object, "name");
            if ((name) && (!strcmp(name, ".app.js")))
                reload_app = 1;
#endif
        } else {
            json_object_set_string(root_object, json_key, json_value);
        }
    } while (*keys_value);
    json_object_set_number(root_object, "version", json_object_get_number(root_object, "version") + 1);
    json_object_set_number(root_object, "timestamp", microseconds());
#ifdef WITH_SMARTCARD
    smartcard_sign_json(edfs_context, root_object, NULL, 0);
#endif
    write_json2(edfs_context, key, key->working_directory, inode, root_value);
    json_value_free(root_value);

#ifndef EDFS_NO_JS
    if (reload_app)
        edfs_reload_app(edfs_context, key);
#endif
    return 1;
}

int edfs_update_json_number(struct edfs *edfs_context, struct edfs_key_data *used_key, uint64_t inode, const char *key, double value) {
    if ((!key) || (!key[0]))
        return 0;

    JSON_Value *root_value = read_json(edfs_context, used_key, used_key->working_directory, inode);
    if (!root_value)
        return 0;

    JSON_Object *root_object = json_value_get_object(root_value);

    double old_value = json_object_get_number(root_object, key);
    if (old_value != value) {
        json_object_set_number(root_object, key, value);
        json_object_set_number(root_object, "version", json_object_get_number(root_object, "version") + 1);
        json_object_set_number(root_object, "timestamp", microseconds());
        write_json2(edfs_context, used_key, used_key->working_directory, inode, root_value);
    }
    json_value_free(root_value);

    return 1;
}

int edfs_update_json_number_if_less(struct edfs *edfs_context, struct edfs_key_data *used_key, uint64_t inode, const char *key, double value) {
    if ((!key) || (!key[0]))
        return 0;

    JSON_Value *root_value = read_json(edfs_context, used_key, used_key->working_directory, inode);
    if (!root_value)
        return 0;

    JSON_Object *root_object = json_value_get_object(root_value);

    double old_value = json_object_get_number(root_object, key);
    if (old_value < value) {
        json_object_set_number(root_object, key, value);
        json_object_set_number(root_object, "version", json_object_get_number(root_object, "version") + 1);
        json_object_set_number(root_object, "timestamp", microseconds());
        write_json2(edfs_context, used_key, used_key->working_directory, inode, root_value);
    }
    json_value_free(root_value);

    return 1;
}

void truncate_inode(struct edfs *edfs_context, struct edfs_key_data *key, const char *b64name, int64_t new_size, int64_t old_size) {
    int64_t start_offset = new_size / BLOCK_SIZE;
    int64_t end_offset = old_size / BLOCK_SIZE;
    char blockname[MAX_PATH_LEN];
    if ((!USE_COMPRESSION) && (new_size % BLOCK_SIZE)) {
        snprintf(blockname, MAX_PATH_LEN, "%s/%s/%" PRIu64, key->working_directory, b64name, (uint64_t)start_offset);
        log_info("truncating block %s", blockname);
        if (truncate(blockname, new_size % BLOCK_SIZE))
            log_error("error truncating block %s", blockname);
        start_offset++;
    }
    while (start_offset <= end_offset) {
        snprintf(blockname, MAX_PATH_LEN, "%s/%s/%" PRIu64, key->working_directory, b64name, (uint64_t)start_offset);
        log_info("dropping block %s", blockname);
        if (unlink(blockname))
            log_error("error dropping block %s", blockname);
        start_offset++;
    }
}

int update_file_json(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, edfs_stat *attr, int to_set, edfs_stat *new_attr) {
    edfs_ino_t parent;
    int64_t size;
    uint64_t timestamp;
    time_t modified;
    time_t created;
    uint64_t generation;
    unsigned char hash[32];
    // silently drop request
    if (!attr) {
        log_error("null setattr received");
        return 1;
    }
    char name[MAX_PATH_LEN];
    name[0] = 0;
    int type = read_file_json(edfs_context, key, inode, &parent, &size, &timestamp, NULL, NULL, name, MAX_PATH_LEN, &created, &modified, &generation, hash, NULL);
    if ((!type) || (name[0] == 0))
        return 0;

    char b64name[MAX_B64_HASH_LEN];
    computename(inode, b64name);

    if ((to_set & EDFS_SET_ATTR_SIZE) && (type & S_IFREG)) {
        truncate_inode(edfs_context, key, b64name, attr->st_size, size);
        size = attr->st_size;
    }

    // type change (not allwoed)
    if (to_set & EDFS_SET_ATTR_MODE) {
        if ((type & S_IFDIR) && ((attr->st_mode & S_IFDIR) == 0))
            return 0;
        if (((type & S_IFDIR) == 0) && (attr->st_mode & S_IFDIR))
            return 0;
        type = attr->st_mode;
    }
    if (to_set & EDFS_SET_ATTR_MTIME)
        modified = attr->st_mtime;

    write_json(edfs_context, key, key->working_directory, name, size, inode, parent, type, hash, created, modified, 0, generation + 1);
    if (new_attr) {
        new_attr->st_mode = type;
        if (type & S_IFDIR) {
            new_attr->st_nlink = 2;
        } else {
            new_attr->st_nlink = 1;
            new_attr->st_size = size;
        }

        new_attr->st_atime = timestamp / 1000000;
        new_attr->st_mtime = modified;
        new_attr->st_ctime = created;
    }
    return 1;
}

int makesyncnode(struct edfs *edfs_context, struct edfs_key_data *key, const char *parentb64name, const char *b64name, const char *name) {
    char fullpath[MAX_PATH_LEN];

    // if directory exists, silently ignore it
    // EDFS_MKDIR(adjustpath(edfs_context, fullpath, b64name), 0755);

    // silently try to make parent node (if not available)
    EDFS_MKDIR(adjustpath(key, fullpath, parentb64name), 0755);

    unsigned char hash[32];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)&name, strlen(name));
    sha256_update(&ctx, (const BYTE *)&parentb64name, strlen(parentb64name));
    sha256_final(&ctx, hash);

    return edfs_write_file(edfs_context, key, fullpath, b64name, (const unsigned char *)hash, 32, NULL, 1, NULL, NULL, NULL, NULL, 0, 0, 0);
}

int pathhash(struct edfs *edfs_context, struct edfs_key_data *key, const char *path, unsigned char *hash) {
    tinydir_dir dir;
    int r = -1;
    SHA256_CTX ctx;
    char buf[0x100];

    sha256_init(&ctx);

    if (!tinydir_open_sorted(&dir, path)) {
        r = 0;
        int  i = 0;
        while ((!r) && (i < dir.n_files)) {
            tinydir_file file;
            tinydir_readfile_n(&dir, &file, i++);
            if (!file.is_dir) {
                snprintf(buf, sizeof(buf), "%s/%s", path, file.name);
                if (verify_file(edfs_context, key, path, file.name))
                    sha256_update(&ctx, (const BYTE *)file.name, strlen(file.name));
            }
            tinydir_next(&dir);
        }
        tinydir_close(&dir);
    }
    sha256_final(&ctx, hash);
    return r;
}

int makenode(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent, const char *name, int attr, edfs_ino_t *inode_ref) {
    char fullpath[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    char parentb64name[MAX_B64_HASH_LEN];
    unsigned char old_hash[32];
    unsigned char new_hash[32];

    uint64_t inode = computeinode(key, parent, name);
    if (inode_ref)
        *inode_ref = inode;

    int type = read_file_json(edfs_context, key, parent, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, old_hash, NULL);
    if (!type)
        return -EPERM;

#ifndef EDFS_NO_JS
    if (edfs_key_js_call_args(key, "edwork.events.oncreate", "_s", parent, name) == 1) {
        log_warn("access denied by JS function");
        return -EPERM;
    }
#endif

    computename(inode, b64name);

    if (attr & S_IFDIR)
        attr |= 0755;
    else
        attr |= 0644;

    uint64_t version = (uint64_t)0;

    // increment version for previously deleted object, if any
    read_file_json(edfs_context, key, inode, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, &version, NULL, NULL);

    write_json(edfs_context, key, key->working_directory, name, 0, inode, parent, attr, NULL, 0, 0, 0, version);

    adjustpath(key, fullpath, computename(parent, parentb64name));

    // ensure parent directory exists
    EDFS_MKDIR(fullpath, 0755);

    unsigned char hash[40];
    SHA256_CTX ctx;

    uint64_t now = htonll(microseconds());
    memcpy(hash, &now, sizeof(uint64_t));

    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)&name, strlen(name));
    sha256_update(&ctx, (const BYTE *)&parentb64name, strlen(parentb64name));
    sha256_final(&ctx, hash + 8);

    int err = edfs_write_file(edfs_context, key, fullpath, b64name, (const unsigned char *)hash, 40, NULL, 1, NULL, NULL, NULL, NULL, 0, 0, 0);
    if (err > 0) {
        pathhash(edfs_context, key, fullpath, new_hash);
        const char *update_data[] = {"iostamp", (const char *)new_hash, NULL, NULL};
        edfs_update_json(edfs_context, key, parent, update_data);
    }
    return err;
}

int edfs_setattr(struct edfs *edfs_context, edfs_ino_t ino, edfs_stat *attr, int to_set) {
    struct edfs_key_data *key = edfs_context->primary_key;
    if (!key)
        return -ENOENT;

    if ((edfs_context->read_only_fs) || (key->read_only))
        return -EROFS;

    if (update_file_json(edfs_context, key, ino, attr, to_set, NULL))
        return 0;
    return -ENOENT;
}

int edfs_getattr_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, edfs_stat *stbuf) {
    int64_t size = 0;
    uint64_t timestamp = 0;
    time_t modified = 0;
    time_t created = 0;

    if (!key)
        return -ENOENT;

    int type = read_file_json(edfs_context, key, ino, NULL, &size, &timestamp, NULL, NULL, NULL, 0, &created, &modified, NULL, NULL, NULL);
    if (!type)
        return -ENOENT;

    memset(stbuf, 0, sizeof(edfs_stat));
    stbuf->st_ino = ino;
    stbuf->st_mode = type;
    if (type & S_IFDIR) {
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_nlink = 1;
        stbuf->st_size = size;
    }

    stbuf->st_atime = timestamp / 1000000;
    stbuf->st_mtime = modified;
    stbuf->st_ctime = created;

    return 0;
}

int edfs_getattr(struct edfs *edfs_context, edfs_ino_t ino, edfs_stat *stbuf) {
    if ((!edfs_context->mutex_initialized) && (!edfs_context->primary_key))
        usleep(10000000);

    return edfs_getattr_key(edfs_context, edfs_context ? edfs_context->primary_key : NULL, ino, stbuf);
}

int edfs_lookup_inode_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t inode, const char *ensure_name) {
    char namebuf[MAX_PATH_LEN];
    int signature = 0;

    if (!key)
        return 0;

    int type = read_file_json(edfs_context, key, inode, NULL, NULL, NULL, NULL, NULL, ensure_name ? namebuf : NULL, ensure_name ? sizeof(namebuf) : 0, NULL, NULL, NULL, NULL, &signature);
    if ((type) && (ensure_name) && (strncmp(namebuf, ensure_name, sizeof(namebuf)))) {
#ifdef __APPLE__
        char normalized_filename[MAX_PATH_LEN];
        normalizedname(ensure_name, strlen(ensure_name), normalized_filename, sizeof(normalized_filename));
        // is valid (just needs normalization)
        if (!strncmp(namebuf, normalized_filename, MAX_PATH_LEN))
            return type;
#endif
        log_error("%s collides with %s", ensure_name, namebuf);
        return 0;
    }
    if ((signature) && (log_get_level() <= LOG_INFO)) {
        char *sig = NULL;
        int signature_index = 0;
        do {
            sig = edfs_smartcard_get_signature(edfs_context, key, inode, signature_index ++);
            if (sig) {
                log_info("%s has signature #%i\n%s", ensure_name, signature_index, sig);
                free(sig);
            }
        } while (sig);
    }
    return type;
}

int edfs_lookup_inode(struct edfs *edfs_context, edfs_ino_t inode, const char *ensure_name) {
    return edfs_lookup_inode_key(edfs_context, edfs_context ? edfs_context->primary_key : NULL, inode, ensure_name);
}

edfs_ino_t edfs_lookup(struct edfs *edfs_context, edfs_ino_t parent, const char *name, edfs_stat *stbuf) {
    int64_t size = 0;
    uint64_t timestamp = 0;
    time_t modified = 0;
    time_t created = 0;

    struct edfs_key_data *key = edfs_context->primary_key;
    if (!key)
        return 0;

    uint64_t inode = computeinode(key, parent, name);
    int type = read_file_json(edfs_context, key, inode, NULL, &size, &timestamp, NULL, NULL, NULL, 0, &created, &modified, NULL, NULL, NULL);
    if (!type)
        return 0;

#ifndef EDFS_NO_JS
    if (edfs_key_js_call_args(key, "edwork.events.onlookup", "__", inode, parent) == 1) {
        log_warn("access denied by JS function");
        return -EACCES;
    }
#endif

    if (stbuf) {
        memset(stbuf, 0, sizeof(edfs_stat));
        stbuf->st_mode = type;
        if (type & S_IFDIR) {
            stbuf->st_nlink = 2;
        } else {
            stbuf->st_nlink = 1;
            stbuf->st_size = size;
        }

        stbuf->st_atime = timestamp / 1000000;
        stbuf->st_mtime = modified;
        stbuf->st_ctime = created;
    }
    return inode;
}

void edfs_warm_cache(struct edfs *edfs_context, const char *working_directory, edfs_ino_t ino, uint64_t chunk, uint64_t max_chunks) {
    char b64name[MAX_B64_HASH_LEN];
    char name[MAX_PATH_LEN];

    computename(ino, b64name);

    max_chunks += chunk;
    do {
        if (edfs_context->network_done)
            break;

        snprintf(name, MAX_PATH_LEN, "%s/%s/%" PRIu64, working_directory, b64name, chunk);

        FILE *f = fopen(name, "rb");
        if (!f)
            break;

        fclose(f);

        chunk ++;
    } while (chunk < max_chunks);
}

#ifdef WITH_CACHE_WARMUP
void edfs_request_cache_warming(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, uint64_t chunk) {
    if ((!edfs_context) || (!key))
        return;

    edfs_context->warmup_chunk = chunk;
    if (edfs_context->warmup_inode != ino) {
        strncpy(edfs_context->warmup_key_dir, key->working_directory, MAX_PATH_LEN);
        edfs_context->warmup_inode = ino;
    }
}
#endif

int edfs_reply_chunk(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, uint64_t chunk, unsigned char *buf, int size, uint32_t chunk_hash) {
    if (size <= 0)
        return -1;

    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];
    char name[MAX_PATH_LEN];

    snprintf(name, MAX_PATH_LEN, "%s/%" PRIu64, adjustpath(key, fullpath, computename(ino, b64name)), (uint64_t)chunk);

    FILE *f = fopen(name, "rb");
    if (!f)
        return -errno;

    edfs_file_lock(edfs_context, f, 0);
    int err = fread_block_with_key(edfs_context, key, ino, chunk, buf, 1, size, f);
    edfs_file_unlock(edfs_context, f);
    fclose(f);

    if (chunk_hash) {
        if ((err > 0) && (err < 64))
            err = 0;
        if ((err > 0) && (XXH32(buf, 64, 0) != chunk_hash)) {
            log_warn("chunk has different hash than requested");
            err = 0;
        }
    }

    return err;
}

int edfs_reply_hash(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, uint64_t chunk, unsigned char *buf, int size, uint32_t file_hash) {
    if (size <= 0)
        return -1;

    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];
    char name[MAX_PATH_LEN];

    snprintf(name, MAX_PATH_LEN, "%s/hash.%" PRIu64, adjustpath(key, fullpath, computename(ino, b64name)), (uint64_t)chunk);

    FILE *f = fopen(name, "rb");
    if (!f)
        return -errno;

    edfs_file_lock(edfs_context, f, 0);
    int err = fread_block_with_key(edfs_context, key, 0, 0, buf, 1, size, f);
    edfs_file_unlock(edfs_context, f);
    fclose(f);

    if ((err > 0) && (err < 64))
        return 0;

    if ((err > 0) && (file_hash)) {
        unsigned char hash[32];
        unsigned char computed_hash[32];
        int64_t file_size = 0;
        if ((!read_file_json(edfs_context, key, ino, NULL, &file_size, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash, NULL)) || (XXH32(hash, 32, 0) != file_hash)) {
            log_warn("descriptor has different hash than requested");
            err = 0;
        }

        if ((!edfs_update_chain(edfs_context, key, ino, file_size, computed_hash, NULL)) || (memcmp(computed_hash, hash, 32))) {
            log_warn("computed hash differs from descriptor hash");
            err = 0;
        }
    }
    return err;
}

int chunk_exists(const char *path, uint64_t chunk) {
    char name[MAX_PATH_LEN];
    name[0] = 0;
#ifdef EDFS_EMULATED_STORE
    snprintf(name, MAX_PATH_LEN, "%s/%04" PRIx64, path, chunk / STORE_CHUNKS_PER_FILE);
    return store_exists(name, chunk % STORE_CHUNKS_PER_FILE);
#else
    snprintf(name, MAX_PATH_LEN, "%s/%" PRIu64, path, (uint64_t)chunk);

    struct stat statbuf;
    return (stat(name, &statbuf) == 0);
#endif
}

int chunk_exists2(struct edfs_key_data *key, uint64_t inode, uint64_t chunk) {
    char fullpath[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
#ifdef EDFS_EMULATED_STORE
    store_adjustpath2(key, fullpath, computename(inode, b64name), chunk / STORE_CHUNKS_PER_FILE);
    return store_exists(fullpath, chunk % STORE_CHUNKS_PER_FILE);
#else
    adjustpath2(key, fullpath, computename(inode, b64name), chunk);

    struct stat statbuf;
    return (stat(fullpath, &statbuf) == 0);
#endif
}

int request_data(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, uint64_t chunk, int encrypted, int use_cached_addr, unsigned char *proof_cache, int *proof_size, uint32_t chunk_hash) {
    unsigned char additional_data[20];
    *(uint64_t *)additional_data = htonll(ino);
    *(uint64_t *)(additional_data + 8)= htonll(chunk);
    *(uint32_t *)(additional_data + 16)= htonl(chunk_hash);

    struct sockaddr_in *use_clientaddr = NULL;
    int clientaddr_size = 0;
#ifdef WITH_SCTP
    int is_sctp = edfs_context->force_sctp;
#else
    int is_sctp = 0;
#endif
    struct sockaddr_in addrbuffer;
    if (use_cached_addr) {
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&key->ino_cache_lock);
        struct edfs_ino_cache *avl_cache = (struct edfs_ino_cache *)avl_search(&key->ino_cache, (void *)(uintptr_t)ino);
        // at least 2 nodes
        if ((avl_cache) && (avl_cache->len >= 1)) {
            if ((avl_cache->len >= 2) || (edwork_random() % 20 != 0)) {
                unsigned int to_client;
                if (use_cached_addr > 1)
                    to_client = use_cached_addr - 2;
                else
                    to_client = (unsigned int)edwork_random();

                memcpy(&addrbuffer, &avl_cache->clientaddr[to_client % avl_cache->len], avl_cache->clientaddr_size);
                use_clientaddr = &addrbuffer;
                clientaddr_size = avl_cache->clientaddr_size;
#ifdef WITH_SCTP
                if (!edfs_context->force_sctp)
                    is_sctp = edwork_is_sctp(edfs_context->edwork, use_clientaddr);
#endif
            }
        }
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&key->ino_cache_lock);
    }

    if (encrypted)
        edfs_notify_io(edfs_context, key, "wan4", additional_data, sizeof(additional_data), edfs_context->key.pk, 32, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
    else
    // 25% encrypted packages to avoid some problems with firewalls
    if (edwork_random() % 4)
        edfs_notify_io(edfs_context, key, "want", additional_data, sizeof(additional_data), NULL, 0, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
    else
        edfs_notify_io(edfs_context, key, "wan3", additional_data, sizeof(additional_data), NULL, 0, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);

    return is_sctp;
}

int request_data_sctp(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, uint64_t chunk, int use_cached_addr, unsigned char *proof_cache, int *proof_size, uint32_t chunk_hash, const char *path, int timeout, int *proof_type) {
#ifdef WITH_SCTP
    unsigned char additional_data[62];
#else
    unsigned char additional_data[20];
#endif
    *(uint64_t *)additional_data = htonll(ino);
    *(uint64_t *)(additional_data + 8) = htonll(chunk);
    *(uint32_t *)(additional_data + 16) = htonl(chunk_hash);

    struct sockaddr_in *use_clientaddr = NULL;
    int clientaddr_size = 0;
#ifdef WITH_SCTP
    int is_sctp = edfs_context->force_sctp;
#else
    int is_sctp = 0;
#endif
    struct sockaddr_in addrbuffer;
    if (edfs_context->mutex_initialized)
        thread_mutex_lock(&key->ino_cache_lock);
    struct edfs_ino_cache *avl_cache = (struct edfs_ino_cache *)avl_search(&key->ino_cache, (void *)(uintptr_t)ino);
    // at least 2 nodes
    if ((avl_cache) && (avl_cache->len >= 1)) {
        if (use_cached_addr) {
            if ((avl_cache->len >= 2) || (edwork_random() % 20 != 0)) {
                memcpy(&addrbuffer, &avl_cache->clientaddr[edwork_random() % avl_cache->len], avl_cache->clientaddr_size);
                use_clientaddr = &addrbuffer;
                clientaddr_size = avl_cache->clientaddr_size;
#ifdef WITH_SCTP
                if (!edfs_context->force_sctp)
                    is_sctp = edwork_is_sctp(edfs_context->edwork, use_clientaddr);
#endif
            }
        }
    }
    if (edfs_context->mutex_initialized)
        thread_mutex_unlock(&key->ino_cache_lock);

#ifdef WITH_SCTP
    if ((is_sctp) && (use_clientaddr) && (clientaddr_size)) {
        // up to 5 forward chunks
        int forward_chunks = 5;
        *(uint16_t *)(additional_data + 20) = htons(forward_chunks);
        int i = 0;
        int forward_chunk_index = chunk + 10;
        int loop_count = 0;

        for (i = 0; i < forward_chunks; i++) {
            int exists = chunk_exists(path, forward_chunk_index);
            while (exists) {
                loop_count ++;
                if (loop_count > 50)
                    goto loop_out;
                forward_chunk_index += 10;
                exists = chunk_exists(path, forward_chunk_index);
            }
            *(uint64_t *)(additional_data + 22 + i * sizeof(uint64_t)) = htonll(forward_chunk_index);
            if ((!exists) && (loop_count <= 50))
                forward_chunk_index += 10;
        }
loop_out:
        if ((proof_type) && (*proof_type != 2)) {
            if (proof_size)
                *proof_size = 0;
            *proof_type = 2;
        }
        edfs_notify_io(edfs_context, key, "wan5", additional_data, 22 + i * sizeof(uint64_t), edfs_context->key.pk, 32, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
        uint64_t start = microseconds();
        uint64_t last_sent = start;
        thread_set_high_priority();
        while ((!chunk_exists(path, chunk)) && (microseconds() - start < timeout)) {
            usleep(1000);
            if (microseconds() - last_sent >= 200000) {
                edfs_notify_io(edfs_context, key, "wan5", additional_data, 22 + i * sizeof(uint64_t), edfs_context->key.pk, 32, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
                last_sent = microseconds();
            }
            thread_yield();
        }
    } else {
        if ((proof_type) && (*proof_type != 1)) {
            if (proof_size)
                *proof_size = 0;
            *proof_type = 1;
        }
        edfs_notify_io(edfs_context, key, "wan4", additional_data, 20, edfs_context->key.pk, 32, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
    }
#else
    edfs_notify_io(edfs_context, key, "wan4", additional_data, 20, edfs_context->key.pk, 32, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
#endif
    return is_sctp;
}

void edfs_make_key(struct edfs *edfs_context) {
    unsigned char random_bytes[32];
    memcpy(&edfs_context->previous_key, &edfs_context->key, sizeof(struct edfs_x25519_key));
    edwork_random_bytes(random_bytes, 32);
    sha256(random_bytes, 32, edfs_context->key.secret);

    edfs_context->key.secret[0] &= 248;
    edfs_context->key.secret[31] &= 127;
    edfs_context->key.secret[31] |= 64;

    curve25519(edfs_context->key.pk, edfs_context->key.secret, NULL);
}

int edfs_file_exists(const char *name) {
    struct stat statbuf;
    return (stat(name, &statbuf) == 0);
}

uint32_t edfs_get_hash(struct edfs *edfs_context, struct edfs_key_data *key, const char *path, edfs_ino_t ino, uint64_t chunk, struct filewritebuf *filebuf) {
    uint32_t hash = 0;
    char hash_file[0x100];
    unsigned char buffer[BLOCK_SIZE];
    hash_file[0] = 0;

    int chunks_per_file = BLOCK_SIZE / sizeof(uint32_t);
    uint64_t hash_chunk = chunk / chunks_per_file;
    unsigned int chunk_offset = chunk % chunks_per_file;

    unsigned int offset = chunk_offset * sizeof(uint32_t);

    if ((filebuf) && (filebuf->read_hash_buffer) && (filebuf->read_hash_buffer_size) && (filebuf->read_hash_cunk == hash_chunk) && (filebuf->read_hash_expires >= microseconds()) && (filebuf->read_hash_buffer_size >= offset + sizeof(uint32_t))) {
        memcpy(&hash, filebuf->read_hash_buffer + offset, sizeof(uint32_t));
    } else {
        snprintf(hash_file, sizeof(hash_file), "hash.%" PRIu64, hash_chunk);
        int read_size = edfs_read_file(edfs_context, key, path, hash_file, buffer, BLOCK_SIZE, NULL, 0, 1, 0, NULL, 0, 0, 0, 0);
        if (read_size < 0)
            read_size = 0;
        if (read_size < offset + sizeof(uint32_t))
            return 0;

        memcpy(&hash, buffer + offset, sizeof(uint32_t));

        if (filebuf) {
            free(filebuf->read_hash_buffer);
            filebuf->read_hash_buffer = (unsigned char *)malloc(read_size);
            if (filebuf->read_hash_buffer) {
                memcpy(filebuf->read_hash_buffer, buffer, read_size);
                filebuf->read_hash_buffer_size = read_size;
                filebuf->read_hash_cunk = hash_chunk;
                filebuf->read_hash_expires = microseconds() + 1000000;
            }
        }
    }

    return ntohl(hash);
}

int edfs_get_hash2(struct edfs *edfs_context, struct edfs_key_data *key, const char *path, edfs_ino_t ino, uint64_t chunk, uint32_t *buffer, unsigned int *chunk_offset_ptr) {
    char hash_file[0x100];
    hash_file[0] = 0;

    int chunks_per_file = BLOCK_SIZE / sizeof(uint32_t);
    uint64_t hash_chunk = chunk / chunks_per_file;
    unsigned int chunk_offset = chunk % chunks_per_file;
    if (chunk_offset_ptr)
        *chunk_offset_ptr = chunk_offset;

    snprintf(hash_file, sizeof(hash_file), "hash.%" PRIu64, hash_chunk);
    int read_size = edfs_read_file(edfs_context, key, path, hash_file, (unsigned char *)buffer, BLOCK_SIZE, NULL, 0, 1, 0, NULL, 0, 0, 0, 0);
    if (read_size < 0)
        read_size = 0;

    return read_size / sizeof(uint32_t);
}

#ifdef EDFS_USE_READ_QUEUE
int edfs_data_request(struct edfs *edfs_context, uint64_t inode, uint64_t not_used, void *data) {
    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    struct filewritebuf *filebuf = (struct filewritebuf *)data;
    if ((!filebuf) || (!filebuf->key) || (filebuf->read_queued == 2) || (!filebuf->file_size)) {
        filebuf->read_queued = 0;
        return 1;
    }

    adjustpath(filebuf->key, fullpath, computename(filebuf->ino, b64name));

    if (chunk_exists(fullpath, filebuf->requested_chunk)) {
        filebuf->proof_size = 0;
        return 0;
    }

    uint64_t wait_count = filebuf->is_sctp ? 50000 : 20000;
    if (microseconds() - filebuf->timestamp >= wait_count) {
        if ((filebuf->request_timestamp) && (microseconds() - filebuf->request_timestamp > 1000000ULL)) {
            filebuf->is_sctp = request_data(edfs_context, filebuf->key, filebuf->ino, filebuf->requested_chunk, 1, 0, NULL, NULL, filebuf->requested_sig_hash);
            filebuf->request_timestamp = microseconds();
        } else
            filebuf->is_sctp = request_data(edfs_context, filebuf->key, filebuf->ino, filebuf->requested_chunk, 1, 1, filebuf->proof_cache, &filebuf->proof_size, filebuf->requested_sig_hash);
            // filebuf->is_sctp = request_data_sctp(edfs_context, filebuf->key, filebuf->ino, filebuf->requested_chunk, 1, filebuf->proof_cache, &filebuf->proof_size, filebuf->requested_sig_hash, fullpath, EDWORK_SCTP_TTL / 2 * 1000);
        filebuf->timestamp = microseconds();
    }
    return 0;
}
#endif

int broadcast_edfs_read_file(struct edfs *edfs_context, struct edfs_key_data *key, const char *path, const char *name, unsigned char *buf, int size, edfs_ino_t ino, uint64_t chunk, struct filewritebuf *filebuf) {
    int i = 0;
    uint64_t start = microseconds();
    uint64_t last_key_timestamp = start;
    uint64_t forward_chunk = chunk + 10;
    uint64_t last_file_chunk = filebuf->file_size / BLOCK_SIZE;
    uint32_t sig_hash = 0;
    int forward_chunks_requested = 0;
    unsigned char proof_cache[1024];
    int proof_size = 0;

    if (!filebuf->file_size)
        return 0;
    if ((filebuf->file_size % BLOCK_SIZE == 0) && (last_file_chunk))
        last_file_chunk--;

    if (chunk > last_file_chunk)
        return 0;

    // if ((filebuf->check_hash) && ((filebuf->flags & 3) == O_RDONLY) && (edfs_is_write(edfs_context, key, ino)))
    //     filebuf->check_hash = 0;

    int may_notify_write_block = 0;
    if (filebuf->check_hash) {
        if ((filebuf->written_data) && (filebuf->hash_buffer) && (filebuf->hash_buffer->read_size)) {
            char b64name[MAX_B64_HASH_LEN];
            char fullpath[MAX_PATH_LEN];
            adjustpath(key, fullpath, computename(ino, b64name));
            edfs_update_hash(edfs_context, key, fullpath, -1, NULL, 0, filebuf->hash_buffer);
            free(filebuf->read_hash_buffer);
            filebuf->read_hash_buffer = NULL;
            filebuf->read_hash_buffer_size = 0;
            filebuf->read_hash_cunk = 0;
            may_notify_write_block = 1;
        }
        sig_hash = edfs_get_hash(edfs_context, key, path, ino, chunk, ((filebuf->flags & 3) == O_RDONLY) ? filebuf : NULL);
    }
    int use_addr_cache = 1;
    int do_forward = 1;
    int is_sctp = 0;
    int reset_cache_tree = 0;
    int proof_type = 0;

    uint64_t proof_timestamp = microseconds();
#ifdef EDFS_USE_READ_QUEUE
    if (filebuf->requested_chunk != chunk) {
        filebuf->request_timestamp = microseconds();
        filebuf->requested_chunk = chunk;
        filebuf->proof_size = 0;
        filebuf->timestamp = 0;
    }
    filebuf->requested_sig_hash = sig_hash;
#endif
    do {
        int read_size = -1;
        // avoid I/O lock
        if (chunk_exists(path, chunk)) {
            int filesize;
            if (!filebuf->read_buffer)
                filebuf->read_buffer = (unsigned char *)malloc(BLOCK_SIZE);

            if ((filebuf->read_buffer) && (size < BLOCK_SIZE) && ((filebuf->flags & 3) == O_RDONLY)) {
#ifdef EDFS_EMULTATED_STORE
                read_size = edfs_read_store(edfs_context, key, path, chunk, (unsigned char *)filebuf->read_buffer, (int)BLOCK_SIZE, 1, USE_COMPRESSION, &filesize, filebuf->written_data ? 0 : sig_hash, 0);
#else
                read_size = edfs_read_file(edfs_context, key, path, name, (unsigned char *)filebuf->read_buffer, (int)BLOCK_SIZE, NULL, 0, 1, USE_COMPRESSION, &filesize, filebuf->written_data ? 0 : sig_hash, 0, ino, chunk);
#endif
                if (read_size > 0) {
                    filebuf->read_buffer_size = read_size;
                    if (size > read_size) {
                        memcpy(buf, filebuf->read_buffer, read_size);
                    } else {
                        memcpy(buf, filebuf->read_buffer, size);
                        read_size = size;
                    }
                    filebuf->expires = microseconds() + 500000;
                } else
                    filebuf->read_buffer_size = 0;
            } else {
#ifdef EDFS_EMULTATED_STORE
                read_size = edfs_read_store(edfs_context, key, path, chunk, (unsigned char *)buf, (int)size, 1, USE_COMPRESSION, &filesize, filebuf->written_data ? 0 : sig_hash, 0);
#else
                read_size = edfs_read_file(edfs_context, key, path, name, (unsigned char *)buf, (int)size, NULL, 0, 1, USE_COMPRESSION, &filesize, filebuf->written_data ? 0 : sig_hash, 0, ino, chunk);
#endif
                filebuf->read_buffer_size = 0;
            }
            if (read_size < 0) {
                if (edfs_is_write(edfs_context, key, ino)) {
                    // make hash buffer expired
                    filebuf->expires = 0;
                    if ((filebuf->check_hash) && (sig_hash))
                        sig_hash = edfs_get_hash(edfs_context, key, path, ino, chunk, ((filebuf->flags & 3) == O_RDONLY) ? filebuf : NULL);
                    log_warn("invalid chunk %s/%s (file is opened)", path, name);
                } else {
                    log_warn("deleting invalid chunk %s/%s", path, name);
#ifdef EDFS_EMULTATED_STORE
                    store_unlink(path, chunk % STORE_CHUNKS_PER_FILE);
#else
                    edfs_unlink_file(edfs_context, path, name);
#endif
                }
            }
#ifdef EDFS_REMOVE_INCOMPLETE_CHUNKS
            if ((read_size > 0) && (read_size < size) && (chunk < filebuf->last_read_chunk)) {
                // incomplete chunk, remove it
                if (filesize < BLOCK_SIZE) {
#ifdef EDFS_EMULTATED_STORE
                    store_unlink(path, chunk % STORE_CHUNKS_PER_FILE);
#else
                    edfs_unlink_file(edfs_context, path, name);
#endif
                }
                read_size = -2;
            }
#endif
        }
        if (read_size < 0) {
            if (may_notify_write_block == 1) {
                edfs_notify_allow_write_block(edfs_context, key, ino, 1);
                may_notify_write_block = 2;
            }

            if (microseconds() - start >= EDWORK_MAX_RETRY_TIMEOUT * 1000) {
                log_error("read timed out");
                if (is_sctp) {
                    if ((microseconds() - last_key_timestamp >= 1500000)) {
                        EDFS_THREAD_LOCK(edfs_context);
                        edfs_make_key(edfs_context);
                        EDFS_THREAD_UNLOCK(edfs_context);
                        last_key_timestamp = microseconds();
                    }
                }
                break;
            }
            if (!is_sctp) {
                if ((microseconds() - last_key_timestamp >= 2000000)) {
                    // new key every 2 seconds
                    EDFS_THREAD_LOCK(edfs_context);
                    edfs_make_key(edfs_context);
                    EDFS_THREAD_UNLOCK(edfs_context);
                    last_key_timestamp = microseconds();
                }
            }
            if ((microseconds() - start >= 1000000) && (!reset_cache_tree)) {
                use_addr_cache = 0;
                is_sctp = 0;
                reset_cache_tree = 1;
                // reset inode cache tree
                if (edfs_context->mutex_initialized)
                    thread_mutex_lock(&key->ino_cache_lock);
                avl_remove(&key->ino_cache, (void *)(uintptr_t)ino);
                if (edfs_context->mutex_initialized)
                    thread_mutex_unlock(&key->ino_cache_lock);

                // try to ignore signature
                // if ((filebuf->check_hash) && ((filebuf->flags & 3) == O_RDONLY) && (edfs_is_write(edfs_context, key, ino))) {
                //     filebuf->check_hash = 0;
                //     sig_hash = 0;
                // }
            }
            if (((is_sctp) && (microseconds() - proof_timestamp >= 500000)) || ((!is_sctp) && (microseconds() - proof_timestamp >= 200000))) {
                // new proof every 500ms (SCTP), 200ms (UDP)
#ifdef EDFS_USE_READ_QUEUE
                filebuf->proof_size = 0;
#else
                proof_size = 0;
#endif
                proof_timestamp = microseconds();
            }
            // end of file, no more queries
            // this is made to avoid an unnecessary edwork query
            if ((filebuf) && (filebuf->file_size > 0)) {
                if (chunk > last_file_chunk) {
                    if (may_notify_write_block == 2)
                        edfs_notify_allow_write_block(edfs_context, key, ino, 0);
                    return read_size;
                }
            }
#ifdef EDFS_USE_READ_QUEUE
            if (!filebuf->read_queued) {
                filebuf->read_queued = 1;
                edfs_schedule(edfs_context, edfs_data_request, 2000, 0, ino, last_file_chunk, 1, 0, filebuf);
            }
            uint64_t wait_count = (EDWORK_SCTP_TTL / 2) * 1000;
#else
            is_sctp = request_data_sctp(edfs_context, key, ino, chunk, use_addr_cache, proof_cache, &proof_size, sig_hash, path, EDWORK_SCTP_TTL / 2 * 1000, &proof_type);
            if (is_sctp)
                do_forward = 0;
            log_trace("requesting chunk %s:%" PRIu64 " (sctp: %i)", path, chunk, is_sctp);
#ifdef WITH_SCTP
            uint64_t wait_count = is_sctp ? (EDWORK_SCTP_TTL / 2) * 1000 : 50000;
#else
            uint64_t wait_count = 50000;
#endif
#ifndef EDFS_NO_FORWARD_WAIT
            if (do_forward) {
                uint64_t start = microseconds();
                if (forward_chunks_requested < edfs_context->forward_chunks) {
                    while (chunk_exists(path, forward_chunk)) {
                        forward_chunk ++;
                        if (forward_chunk - chunk > 30) {
                            do_forward = 0;
                            forward_chunk = last_file_chunk + 1;
                            break;
                        }
                    }
                    if (forward_chunk <= last_file_chunk) {
                        int i;
                        // wait 10 ms before requesting another chunk
                        int exists = 0;
                        for (i = 0; i < 10; i++) {
                            usleep(1000);
                            exists = chunk_exists(path, chunk);
                            if (exists)
                                break;
                        }
                        if (!exists) {
                            forward_chunks_requested ++;
                            request_data(edfs_context, key, ino, forward_chunk ++, 1, 1, NULL, NULL, 0);
                            uint64_t delta = (microseconds() - start);
                            if ((delta >= wait_count) || (delta < 2000))
                                continue;

                            wait_count = delta;
                        }
                    }
                }
            }
#endif
#endif
            uint64_t start = microseconds();
            while ((!chunk_exists(path, chunk)) && (microseconds() - start < wait_count)) {
                usleep(1000);
                thread_yield();
            }
        } else {
#ifdef EDFS_USE_READ_QUEUE
            if (!chunk_exists(path, chunk + 1)) {
                filebuf->requested_chunk = chunk + 1;
                filebuf->timestamp = 0;
                filebuf->request_timestamp = microseconds();
                filebuf->proof_size = 0;
                filebuf->requested_sig_hash = 0;
            }
#endif
#ifdef EDFS_FORWARD_REQUEST
            if ((!chunk_exists(path, forward_chunk)) && (forward_chunk <= last_file_chunk))
                request_data(edfs_context, key, ino, forward_chunk, 1, 1, NULL, NULL, 0);
#endif
            if ((filebuf) && (read_size > 0)) {
                filebuf->last_read_chunk = chunk;
                filebuf->last_read_size = read_size;
            }
#ifdef WITH_CACHE_WARMUP
            edfs_request_cache_warming(edfs_context, filebuf->key, ino, chunk + 5);
#endif
            if (may_notify_write_block == 2)
                edfs_notify_allow_write_block(edfs_context, key, ino, 0);
            return read_size;
        }
        i++;
    } while (!edfs_context->network_done);
    if (may_notify_write_block == 2)
        edfs_notify_allow_write_block(edfs_context, key, ino, 0);
    return -EIO;
}

int read_chunk(struct edfs *edfs_context, struct edfs_key_data *key, const char *path, int64_t chunk, char *buf, size_t size, edfs_ino_t ino, int64_t offset, struct filewritebuf *filebuf) {
    if ((chunk == filebuf->last_read_chunk) && (offset < filebuf->read_buffer_size) && (filebuf->read_buffer) && (filebuf->expires > microseconds())) {
        int read_size = filebuf->read_buffer_size - offset;
        if (size < read_size)
            read_size = size;
        memcpy(buf, filebuf->read_buffer + offset, read_size);
        return read_size;
    } else {
        filebuf->read_buffer_size = 0;
    }

    if (offset > 0) {
        int max_size = BLOCK_SIZE - offset;
        if (size > max_size)
            size = max_size;
    }

    if (offset + size > filebuf->file_size)
        size = filebuf->file_size - offset;

    if (size <= 0)
        return 0;

    if (size > BLOCK_SIZE)
        size = BLOCK_SIZE;

    char name[MAX_PATH_LEN];
    snprintf(name, MAX_PATH_LEN, "%" PRIu64, (uint64_t)chunk);
    if (!offset) {
        int err = broadcast_edfs_read_file(edfs_context, key, path, name, (unsigned char *)buf, size, ino, chunk, filebuf);
        if (err == -ENOENT)
            return 0;
        return err;
    }

    unsigned char block_data[BLOCK_SIZE];
    int read_size = broadcast_edfs_read_file(edfs_context, key, path, name, block_data, (int)offset + size, ino, chunk, filebuf);
    if (read_size < 0) {
        if (read_size == -ENOENT)
            return 0;
        return read_size;
    }

    if (read_size <= offset)
        return 0;

    if (size + offset > read_size)
        size = read_size - offset;

    memcpy(buf, block_data + offset, size);
    return size;
}

uint64_t edfs_get_max_chunk(int64_t file_size) {
    uint64_t file_chunks = file_size / BLOCK_SIZE;

    if (file_size % BLOCK_SIZE)
        file_chunks ++;

    int chunks_per_hash = BLOCK_SIZE / sizeof(uint32_t);
    uint64_t max_chunk = file_chunks / chunks_per_hash;

    if (file_chunks % chunks_per_hash)
        max_chunk ++;

    return max_chunk;
}

int edfs_update_chain(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t ino, int64_t file_size, unsigned char *hash, uint64_t *hash_chunks) {
    char fullpath[MAX_PATH_LEN];
    char fullpath2[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    unsigned char signature_data[64];
    uint64_t i;

    uint64_t max_chunk = edfs_get_max_chunk(file_size);

    if (hash_chunks)
        *hash_chunks = max_chunk;

    adjustpath(key, fullpath, computename(ino, b64name));

    SHA256_CTX ctx;
    sha256_init(&ctx);
    for (i = 0; i < max_chunk; i++) {
        fullpath2[0] = 0;
        snprintf(fullpath2, MAX_PATH_LEN, "%s/hash.%" PRIu64, fullpath, i);
        FILE *f = fopen(fullpath2, "rb");
        if (!f) {
            log_warn("error reading %s", fullpath2);
            return 0;
        }
        edfs_file_lock(edfs_context, f, 0);
        if (fread(signature_data, 1, 64, f) != 64) {
            edfs_file_unlock(edfs_context, f);
            fclose(f);
            log_error("error reading signature in %s", fullpath2);
            return 0;
        }
        edfs_file_unlock(edfs_context, f);
        fclose(f);
        sha256_update(&ctx, (const BYTE *)signature_data, 64);
    }
    sha256_final(&ctx, hash);
    return 1;
}

int edfs_readdir(struct edfs *edfs_context, edfs_ino_t ino, size_t size, int64_t off, struct dirbuf *dbuf, edfs_add_directory add_directory, void *userdata) {
    edfs_ino_t parent = 0;
    uint64_t timestamp = 0;
    time_t modified = 0;
    time_t created = 0;

    if (!dbuf)
        return -EIO;

    char b64name[MAX_B64_HASH_LEN];
    int type = read_file_json(edfs_context, dbuf->key, ino, &parent, NULL, &timestamp, NULL, NULL, NULL, 0, &created, &modified, NULL, NULL, NULL);
    if (type & S_IFDIR) {
        struct dirbuf dirbuf_container;
        computename(ino, b64name);
        char fullpath[MAX_PATH_LEN];
        adjustpath(dbuf->key, fullpath, b64name);

        struct dirbuf *b = dbuf;
        if (!b) {
            b = &dirbuf_container;
            memset(b, 0, sizeof(struct dirbuf));
        }
        b->userdata = userdata;

        if ((add_directory) && (!off)) {
            b->size += add_directory(".", ino, type, 0, created, modified, timestamp / 1000000, userdata);
            if (parent)
                b->size += add_directory("..", parent, type, 0, created, modified, timestamp / 1000000, userdata);
        }
        int64_t index = 0;
        int64_t start_at = b->start;

        if (b->size < off + size) {
            tinydir_dir dir;
            if (tinydir_open(&dir, fullpath))
                return 0;

            while (dir.has_next) {
                tinydir_file file;
                tinydir_readfile(&dir, &file);
                index ++;
                if ((start_at < index) && (!file.is_dir)) {
                    uint64_t parent_inode = 0;
                    read_file_json(edfs_context, b->key, unpacked_ino(file.name), &parent_inode, NULL, NULL, add_directory, b, NULL, 0, NULL, NULL, NULL, NULL, NULL);
                    if (b->size >= off + size)
                        break;
                }
                tinydir_next(&dir);
            }
            if (b->start < index)
                b->start = index;

            tinydir_close(&dir);
        }
    } else {
        return -ENOTDIR;
    }
    return 0;
}

int edfs_releasedir(struct dirbuf *buf) {
    if (buf) {
        if (buf->key)
            buf->key->opened_files --;
#ifndef EDFS_NO_JS
        edfs_key_js_call_args(buf->key, "edwork.events.onrelease", "_bf", buf->ino, (int)1, (double)0);
#endif
        free(buf);
    }
    return 0;
}

int edfs_request_hash_if_needed(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino) {
    unsigned char hash[32];
    unsigned char computed_hash[32];
    int64_t size = 0;
    int type = read_file_json(edfs_context, key, ino, NULL, &size, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash, NULL);
    if ((!type) || (!size))
        return 0;

    if ((edfs_update_chain(edfs_context, key, ino, size, computed_hash, NULL)) && (!memcmp(hash, computed_hash, 32))) {
        log_trace("hash is up-to-date");
        return 0;
    }

    unsigned char additional_data[20];
    *(uint64_t *)additional_data = htonll(ino);
    uint64_t max_chunks = edfs_get_max_chunk(size);
    *(uint64_t *)(additional_data + 16) = htonl(XXH32(hash, 32, 0));

    uint64_t i = 0;
    for (i = 0; i < max_chunks; i++) {
        *(uint64_t *)(additional_data + 8)= htonll(i);
        edfs_notify_io(edfs_context, key, "hash", additional_data, sizeof(additional_data), edfs_context->key.pk, 32, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
    }
    return 1;
}

int edfs_open_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, int flags, struct filewritebuf **fbuf) {
    int64_t size = 0;
    static unsigned char null_hash[32];
    unsigned char hash[32];
    unsigned char computed_hash[32];
    unsigned char blockchainhash[32];
    uint64_t blockchain_timestamp = 0;
    uint64_t blockchain_generation = 0;
    uint64_t blockchain_limit = 0;

    if (!key)
        return -EACCES;

    int type = read_file_json(edfs_context, key, ino, NULL, &size, &blockchain_limit, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash, NULL);
    if (!type)
        return -EACCES;
    if (type & S_IFDIR)
        return -EISDIR;

#ifndef EDFS_NO_JS
    if (edfs_key_js_call_args(key, "edwork.events.onopen", "_bb", ino, (int)(((flags & 3) == O_RDONLY) == 1), (int)0) == 1) {
        log_warn("access denied by JS function");
        return -EACCES;
    }
#endif
    int found_in_blockchain = edfs_lookup_blockchain(edfs_context, key, ino, blockchain_limit, blockchainhash, &blockchain_generation, &blockchain_timestamp);

    if (fbuf) {
        if (((edfs_context->read_only_fs) || (key->read_only)) && ((flags & 3) != O_RDONLY))
            return -EROFS;

        if (((flags & 3) != O_RDONLY) && (edfs_is_write(edfs_context, key, ino)))
            return -EBUSY;
#ifdef WITH_CACHE_WARMUP
        edfs_request_cache_warming(edfs_context, key, ino, 0);
#endif
        int check_hash = 0;
        int blockchain_error = 0;
        int send_want = 1;
        unsigned char additional_data[20];
        *(uint64_t *)additional_data = htonll(ino);

        if ((found_in_blockchain) && (memcmp(blockchainhash, hash, 32))) {
            log_warn("blockchain hash error, falling back to descriptor check");
            found_in_blockchain = 0;
            blockchain_error = 1;
        }

        if ((size > 0) && (memcmp(hash, null_hash, 32)) && (!edfs_is_write(edfs_context, key, ino))) {
            *(uint64_t *)(additional_data + 16) = htonl(XXH32(hash, 32, 0));
            // file hash hash
            int valid_hash = 0;
            uint64_t max_chunks = edfs_get_max_chunk(size);
            uint64_t i;
            uint64_t start = microseconds();
            thread_mutex_lock(&key->ino_cache_lock);
            void *hash_error = (struct edfs_ino_cache *)avl_search(&key->ino_checksum_mismatch, (void *)(uintptr_t)ino);
            thread_mutex_unlock(&key->ino_cache_lock);
            do {
                if (blockchain_error)
                    blockchain_error = 0;

                if (edfs_update_chain(edfs_context, key, ino, size, computed_hash, &max_chunks)) {
                    if (!memcmp(hash, computed_hash, 32)) {
                        valid_hash = 1;
                        break;
                    }
                    if ((found_in_blockchain) && (!memcmp(blockchainhash, computed_hash, 32))) {
                        valid_hash = 1;
                        break;
                    }
                }

                if (send_want) {
                    edfs_notify_io(edfs_context, key, "wand", additional_data, 8, NULL, 0, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
                    send_want = 0;
                }
                for (i = 0; i < max_chunks; i++) {
                    *(uint64_t *)(additional_data + 8)= htonll(i);
                    edfs_notify_io(edfs_context, key, "hash", additional_data, sizeof(additional_data), edfs_context->key.pk, 32, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
                }

                if (microseconds() - start >= EDWORK_MAX_RETRY_TIMEOUT * 1000) {
                    log_error("hash read timed out");
                    if (!hash_error) {
                        thread_mutex_lock(&key->ino_cache_lock);
                        avl_insert(&key->ino_checksum_mismatch, (void *)(uintptr_t)ino, (void *)1);
                        thread_mutex_unlock(&key->ino_cache_lock);
                    }
                    break;
                }
                if ((hash_error) && ((flags & 3) == O_RDONLY)) {
                    log_warn("file hash still mismatched, using last known version (not waiting for timeout)");
                    break;
                }
                if (edfs_context->network_done)
                    break;
#ifdef _WIN32
                Sleep(50);
#else
                usleep(50000);
#endif
                read_file_json(edfs_context, key, ino, NULL, &size, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash, NULL);

                thread_yield();
            } while (!valid_hash);

            if (valid_hash) {
                check_hash = 1;
                log_trace("hash is valid");
                if (hash_error) {
                    thread_mutex_lock(&key->ino_cache_lock);
                    avl_remove(&key->ino_checksum_mismatch, (void *)(uintptr_t)ino);
                    thread_mutex_unlock(&key->ino_cache_lock);
                }
            } else {
                log_warn("invalid file hash");
                // if no valid hash available, allow read-only access
                if ((flags & 3) != O_RDONLY)
                    return -EIO;
            }
        }

        *fbuf = (struct filewritebuf *)malloc(sizeof(struct filewritebuf));
        if (*fbuf) {
            memset(*fbuf, 0, sizeof(struct filewritebuf));
            (*fbuf)->ino = ino;
            (*fbuf)->file_size = size;
            (*fbuf)->check_hash = check_hash;
            (*fbuf)->key = key;
            key->opened_files ++;
            (*fbuf)->flags = flags;
        }
    }
    return 0;
}

int edfs_open(struct edfs *edfs_context, edfs_ino_t ino, int flags, struct filewritebuf **fbuf) {
    return edfs_open_key(edfs_context, edfs_context ? edfs_context->primary_key : NULL, ino, flags, fbuf);
}

int edfs_create_with_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent, const char *name, mode_t mode, uint64_t *inode, struct filewritebuf **buf) {
    if (edfs_context->read_only_fs)
        return -EROFS;

    if (!key)
        return -EACCES;

    if (key->read_only)
        return -EROFS;

    int err = makenode(edfs_context, key, parent, name, S_IFREG | 0644, inode);
    if (err <  0)
        return -EACCES;

    if (buf) {
        *buf = (struct filewritebuf *)malloc(sizeof(struct filewritebuf));
        if (*buf) {
            memset(*buf, 0, sizeof(struct filewritebuf));
            (*buf)->ino = *inode;
            (*buf)->key = key;
            key->opened_files ++;
            (*buf)->flags = O_WRONLY;
        }
    }
    return 0;
}

int edfs_create(struct edfs *edfs_context, edfs_ino_t parent, const char *name, mode_t mode, uint64_t *inode, struct filewritebuf **buf) {
    return edfs_create_with_key(edfs_context, edfs_context->primary_key, parent, name, mode, inode, buf);
}

edfs_ino_t edfs_inode(struct filewritebuf *filebuf) {
    if (filebuf)
        return filebuf->ino;
    return 0;
}

int edfs_read(struct edfs *edfs_context, edfs_ino_t ino, size_t size, int64_t off, char *ptr, struct filewritebuf *filebuf) {
    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    if (!filebuf)
        return -EIO;

    ++ filebuf->in_read;
    edfs_flush_chunk(edfs_context, ino, filebuf);


    int64_t chunk = off / BLOCK_SIZE;
    int64_t offset = off % BLOCK_SIZE;
    size_t bytes_read = 0;

    adjustpath(filebuf->key, fullpath, computename(ino, b64name));

    char *buf = ptr;
    while (size > 0) {
        int read_bytes = read_chunk(edfs_context, filebuf->key, fullpath, chunk, buf, size, ino, offset, filebuf);
        if (read_bytes <= 0) {
            if ((bytes_read != 0) || (read_bytes == 0))
                break;
            log_error("read chunk in %s, errno %i", fullpath, (int)-read_bytes);
            if (filebuf)
                -- filebuf->in_read;
            return read_bytes;
        }
        bytes_read += read_bytes;
        buf += read_bytes;
        size -= read_bytes;
        offset = 0;
        chunk++;
    }
    -- filebuf->in_read;
    return bytes_read;
}

int edfs_set_size_key(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t new_size) {
    edfs_update_json_number(edfs_context, key, inode, "size", (double)new_size);
    return 1;
}

int edfs_set_size(struct edfs *edfs_context, uint64_t inode, int64_t new_size) {
    struct edfs_key_data *key = edfs_context->primary_key;
    if ((!key) || (key->read_only) || (edfs_context->read_only_fs))
        return -EROFS;

    edfs_set_size_key(edfs_context, key, inode, new_size);
    return 1;
}


int64_t get_size_json(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode) {
    int64_t size;

    int type = read_file_json(edfs_context, key, inode, NULL, &size, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL);
    if (!type)
        return 0;

    return size;
}

uint64_t get_version_plus_one_json(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode) {
    uint64_t version = 0;

    int type = read_file_json(edfs_context, key, inode, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, &version, NULL, NULL);
    if (!type)
        return 0;

    return version + 1;
}

int get_deleted_json(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode) {

    int type = read_file_json(edfs_context, key, inode, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL);
    if (!type)
        return 1;

    return 0;
}

int edfs_update_hash(struct edfs *edfs_context, struct edfs_key_data *key, const char *path, int64_t chunk, const unsigned char *buf, int size, struct edfs_hash_buffer *hash_buffer) {
    char hash_file[0x100];
    unsigned char buffer_container[BLOCK_SIZE];
    unsigned char *buffer = buffer_container;
    hash_file[0] = 0;

    int chunks_per_file = BLOCK_SIZE / sizeof(uint32_t);
    uint64_t hash_chunk = chunk / chunks_per_file;

    // ensure directory exists
    EDFS_MKDIR(path, 0755);
    if (hash_buffer) {
        buffer = hash_buffer->buffer;
        if (((chunk < 0) || (hash_buffer->chunk != hash_chunk)) && (hash_buffer->read_size)) {
            snprintf(hash_file, sizeof(hash_file), "hash.%" PRIu64, hash_buffer->chunk);
            edfs_write_file(edfs_context, key, path, hash_file, buffer, hash_buffer->read_size, NULL, 1, NULL, NULL, NULL, NULL, 0, 0, 0);
            hash_buffer->chunk = hash_chunk;
            hash_buffer->read_size = 0;
        }
    }
    if (chunk < 0)
        return 1;

    uint32_t hash = htonl(XXH32(buf, size, 0));

    unsigned int chunk_offset = chunk % chunks_per_file;

    snprintf(hash_file, sizeof(hash_file), "hash.%" PRIu64, hash_chunk);
    int read_size;
    if (hash_buffer) {
        read_size = hash_buffer->read_size;
        if (!read_size) {
            read_size = edfs_read_file(edfs_context, key, path, hash_file, buffer, BLOCK_SIZE, NULL, 0, 1, 0, NULL, 0, 0, 0, 0);
            if (read_size < 0)
                read_size = 0;
        }
    } else {
        read_size = edfs_read_file(edfs_context, key, path, hash_file, buffer, BLOCK_SIZE, NULL, 0, 1, 0, NULL, 0, 0, 0, 0);
        if (read_size < 0)
            read_size = 0;
    }
    unsigned int offset = chunk_offset * sizeof(uint32_t);
    if (read_size < offset + sizeof(uint32_t)) {
        if (read_size < offset)
            memset(buffer + read_size, 0, offset - read_size);
        read_size = offset + sizeof(uint32_t);
    }
    memcpy(buffer + offset, &hash, sizeof(uint32_t));
    if (hash_buffer)
        hash_buffer->read_size = read_size;
    else
        edfs_write_file(edfs_context, key, path, hash_file, buffer, read_size, NULL, 1, NULL, NULL, NULL, NULL, 0, 0, 0);
    return 0;
}

int edfs_try_make_hash(struct edfs *edfs_context, struct edfs_key_data *key, const char *path, uint64_t file_size) {
    if (!file_size)
        return 1;

    uint64_t last_file_chunk = file_size / BLOCK_SIZE;
    if ((last_file_chunk % BLOCK_SIZE == 0) && (last_file_chunk))
        last_file_chunk --;

    uint64_t chunk;
    struct edfs_hash_buffer hash_buffer;
    memset(&hash_buffer, 0, sizeof(hash_buffer));
    for (chunk = 0; chunk <= last_file_chunk; chunk ++) {
        unsigned char signature[64];
        char chunk_file[MAX_PATH_LEN];
        snprintf(chunk_file, MAX_PATH_LEN, "%" PRIu64, (uint64_t)chunk);
        int read_size = edfs_read_file(edfs_context, key, path, chunk_file, signature, 64, NULL, 0, 0, 0, NULL, 0, 1, 0, 0);
        if (read_size != 64)
            return 0;
        edfs_update_hash(edfs_context, key, path, chunk, signature, 64, &hash_buffer);
    }
    // flush to disk
    edfs_update_hash(edfs_context, key, path, -1, NULL, 0, &hash_buffer);
    return 1;
}

int make_chunk(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, const char *path, int64_t chunk, const char *buf, size_t size, int64_t offset, int64_t *filesize, struct edfs_hash_buffer *hash_buffer, int64_t file_offset) {
    int block_written;
    int written_bytes;

    if (offset > 0) {
        int max_size = BLOCK_SIZE - offset;
        if (size > max_size)
            size = max_size;
    }

    if (size <= 0) {
        log_error("invalid size %i", size);
        return 0;
    }

    if (size > BLOCK_SIZE)
        size = BLOCK_SIZE;

    char name[MAX_PATH_LEN];
    snprintf(name, MAX_PATH_LEN, "%" PRIu64, (uint64_t)chunk);
    unsigned char old_data[BLOCK_SIZE];
    unsigned char additional_data[96];
    unsigned char compressed_buffer[BLOCK_SIZE_MAX];
    mz_ulong max_len = sizeof(compressed_buffer);

    int read_data = edfs_read_file(edfs_context, key, path, name, old_data, BLOCK_SIZE, NULL, 0, 1, USE_COMPRESSION, NULL, 0, 0, ino, chunk);

    if (read_data > 0) {
        if (!(*filesize))
            read_data = 0;
        else
        if (*filesize - file_offset < BLOCK_SIZE) {
            int last_chunk_size = (int)(*filesize % BLOCK_SIZE);
            if ((last_chunk_size > 0) && (read_data > last_chunk_size))
                read_data = last_chunk_size;
        }
    }
    const unsigned char *ptr;

    *(uint64_t *)additional_data = htonll(ino);
    *(uint64_t *)(additional_data + 8) = htonll(chunk);
    *(uint64_t *)(additional_data + 16) = htonll(microseconds());
    *(uint64_t *)(additional_data + 24) = htonll(size);

    if (read_data > 0) {
        if ((read_data >= offset + size) && (!memcmp(old_data + offset, buf, size))) {
            // writing the same data into a truncated cunk?
            if (*filesize < offset + size)
                *filesize = offset + size;
            return size;
        }

        int to_write = offset + size;
        if (to_write > BLOCK_SIZE)
            to_write = BLOCK_SIZE;
        if ((offset) || (size < read_data)) {
            // set to 0, to avoid potential information leak
            memset(old_data + read_data, 0, BLOCK_SIZE - read_data);

            if (offset + size > BLOCK_SIZE)
                size = BLOCK_SIZE - offset;

            memcpy(old_data + offset, buf, size);
            ptr = (const unsigned char *)old_data;
            if (to_write < read_data)
                to_write = read_data;
        } else
            ptr = (const unsigned char *)buf;

        block_written = edfs_write_file(edfs_context, key, path, name, (const unsigned char *)ptr, (int)to_write, NULL, 1, compressed_buffer, USE_COMPRESSION ? &max_len : NULL, additional_data + 32, NULL, 0, ino, chunk);
        if (block_written < 0)
            return block_written;
        if (block_written == to_write) {
            if (*filesize == 0) {
                *filesize = to_write;
            } else {
                int delta = offset + size;
                if (delta > read_data)
                    *filesize += delta - read_data;
            }
#ifdef EDFS_FORCE_BROADCAST
            if (to_write == BLOCK_SIZE) {
                if (USE_COMPRESSION) {
                    *(uint64_t *)(additional_data + 24) = htonll(max_len);
                    edfs_notify_io(edfs_context, key, "data", additional_data, sizeof(additional_data), (const unsigned char *)compressed_buffer, max_len, 3, 1, ino, 0, EDFS_DATA_BROADCAST_ENCRYPTED, NULL, 0, NULL, NULL);
                } else
                    edfs_notify_io(edfs_context, key, "data", additional_data, sizeof(additional_data), (const unsigned char *)ptr, to_write, 3, 1, ino, 0, EDFS_DATA_BROADCAST_ENCRYPTED, NULL, 0, NULL, NULL);
            }
#endif
            edfs_update_hash(edfs_context, key, path, chunk, additional_data + 32, 64, hash_buffer);
            return size;
        }
        return -EIO;
    } else
    if ((offset) && (offset < BLOCK_SIZE)) {
        memset(old_data, 0, offset);
        int available = BLOCK_SIZE - offset;
        if (size > available)
            size = available;
        memcpy(old_data + offset, buf, size);

        written_bytes = edfs_write_file(edfs_context, key, path, name, (const unsigned char *)old_data, (int)offset + size, NULL, 1, compressed_buffer, USE_COMPRESSION ? &max_len : NULL, additional_data + 32, NULL, 0, ino, chunk);
        if ((written_bytes > 0) && (offset)) {
            // increment file size by offset (null padded)
            *filesize += offset;
            written_bytes -= offset;
        }
    } else
    if (offset) {
        return -EBUSY;
    } else
        written_bytes = edfs_write_file(edfs_context, key, path, name, (const unsigned char *)buf, (int)size, NULL, 1, compressed_buffer, USE_COMPRESSION ? &max_len : NULL, additional_data + 32, NULL, 0, ino, chunk);
    if (written_bytes > 0) {
        *filesize += written_bytes;
#ifdef EDFS_FORCE_BROADCAST
        if (written_bytes == BLOCK_SIZE) {
            if (USE_COMPRESSION) {
                *(uint64_t *)(additional_data + 24) = htonll(max_len);
                edfs_notify_io(edfs_context, key, "data", additional_data, sizeof(additional_data), (const unsigned char *)compressed_buffer, max_len, 3, 1, ino, 0, EDFS_DATA_BROADCAST_ENCRYPTED, NULL, 0, NULL, NULL);
            } else
                edfs_notify_io(edfs_context, key, "data", additional_data, sizeof(additional_data), (const unsigned char *)buf, size, 3, 1, ino, 0, EDFS_DATA_BROADCAST_ENCRYPTED, NULL, 0, NULL, NULL);
        }
#endif
        edfs_update_hash(edfs_context, key, path, chunk, additional_data + 32, 64, hash_buffer);
    }
    return written_bytes;
}

int edfs_check_block_hash(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, const unsigned char *data, size_t size) {
    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    if ((!data) || (size < 64))
        return 0;

    adjustpath(key, fullpath, computename(inode, b64name));
    uint32_t hash = edfs_get_hash(edfs_context, key, fullpath, inode, chunk, NULL);
    if ((!hash) || (hash == XXH32(data, 64, 0)))
        return 1;
    log_warn("invalid signature hash %x", hash);
    return 0;
}

int edfs_write_block(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, const unsigned char *data, size_t size, time_t timestamp) {
    char fullpath[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    struct stat attrib;

#ifdef EDFS_EMULATED_STORE
    store_adjustpath2(key, fullpath, computename(inode, b64name), chunk / STORE_CHUNKS_PER_FILE);
    if (!store_stat(fullpath, chunk % STORE_CHUNKS_PER_FILE, &attrib)) {
        if (!edfs_may_write_block(edfs_context, key, inode)) {
            log_warn("refused to update file block because file is open for write");
            return -1;
        }
        if (timestamp) {
            // at least 3 seconds after creation
            if (attrib.st_ctime - attrib.st_mtime >= 3) {
                if ((attrib.st_mtime > timestamp) && (attrib.st_size >= size)) {
                    log_info("file block %s is newer than received", fullpath);
                    return -1;
                }

                if ((attrib.st_mtime == timestamp) && (attrib.st_size == size)) {
                    log_info("file block %s seems the same (%i bytes)", fullpath, size);
                    return -1;
                }
            }
        }
        if (!edfs_check_block_hash(edfs_context, key, inode, chunk, data, size)) {
            log_warn("refused to update file block: hash mismatch");
            return -1;
        }
    }
    struct store_data *f = store_open(fullpath, 1, chunk % STORE_CHUNKS_PER_FILE);
    if (!f) {
        log_error("error opening block file %s", fullpath);
        return -1;
    }

    edfs_file_lock(edfs_context, store_handle(f), 1);
    unsigned char signature[64];
    if (size >= 64) {
        if (store_read(signature, 64, f) == 64) {
            if (!memcmp(signature, data, 64)) {
                log_debug("file block is exactly the same, not rewriting");
                edfs_file_unlock(edfs_context, store_handle(f));
                store_close(f);
                return -1;
            }
        }
        store_seek(f, 0);
    }
    int written = store_write_block_with_key(edfs_context, key, data, 1, size, f);
    if (written < 0)
        log_error("error writing %i bytes to file %s (errno: %i)", size, fullpath, errno);

    edfs_file_unlock(edfs_context, store_handle(f));
    store_close(f);
#else
    adjustpath2(key, fullpath, computename(inode, b64name), chunk);
    if (!stat(fullpath, &attrib)) {
        if (!edfs_may_write_block(edfs_context, key, inode)) {
            log_warn("refused to update file block because file is open for write");
            return -1;
        }
        if (timestamp) {
            // at least 3 seconds after creation
            if (attrib.st_ctime - attrib.st_mtime >= 3) {
                if ((attrib.st_mtime > timestamp) && (attrib.st_size >= size)) {
                    log_info("file block %s is newer than received", fullpath);
                    return -1;
                }

                if ((attrib.st_mtime == timestamp) && (attrib.st_size == size)) {
                    log_info("file block %s seems the same (%i bytes)", fullpath, size);
                    return -1;
                }
            }
        }
        if (!edfs_check_block_hash(edfs_context, key, inode, chunk, data, size)) {
            log_warn("refused to update file block: hash mismatch");
            return -1;
        }
    }

    FILE *f = fopen(fullpath, "w+b");
    if (!f) {
        log_error("error opening block file %s", fullpath);
        return -1;
    }

    edfs_file_lock(edfs_context, f, 1);
    unsigned char signature[64];
    if (size >= 64) {
        if (fread(signature, 1, 64, f) == 64) {
            if (!memcmp(signature, data, 64)) {
                log_debug("file block is exactly the same, not rewriting");
                edfs_file_unlock(edfs_context, f);
                fclose(f);
                return -1;
            }
        }
        fseek(f, 0, SEEK_SET);
    }
    int written = fwrite_block_with_key(edfs_context, key, inode, chunk, data, 1, size, f);
    if (written < 0)
        log_error("error writing %i bytes to file %s (errno: %i)", size, fullpath, errno);

    edfs_file_unlock(edfs_context, f);
    fclose(f);
#endif

    return written;
}

int edfs_write_hash_block(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, int64_t chunk, const unsigned char *data, size_t size, time_t timestamp) {
    char fullpath[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    adjustpath3(key, fullpath, computename(inode, b64name), chunk);

    struct stat attrib;
    if (!stat(fullpath, &attrib)) {
        if (!edfs_may_write_block(edfs_context, key, inode)) {
            log_warn("refused to update hash because file is open for write");
            return -1;
        }
        if (timestamp) {
            // at least 3 seconds after creation
            if (attrib.st_ctime - attrib.st_mtime >= 3) {
                if ((attrib.st_mtime > timestamp) && (attrib.st_size >= size)) {
                    log_info("hash block %s is newer than received", fullpath);
                    return -1;
                }

                if ((attrib.st_mtime == timestamp) && (attrib.st_size == size)) {
                    log_info("hash block %s seems the same (%i bytes)", fullpath, size);
                    return -1;
                }
            }
        }
    }

    FILE *f = fopen(fullpath, "w+b");
    if (!f) {
        log_error("error opening hash file %s", fullpath);
        return -1;
    }

    edfs_file_lock(edfs_context, f, 1);
    unsigned char signature[64];
    if (size >= 64) {
        if (fread(signature, 1, 64, f) == 64) {
            if (!memcmp(signature, data, 64)) {
                log_debug("hash block is exactly the same, not rewriting");
                edfs_file_unlock(edfs_context, f);
                fclose(f);
                return -1;
            }
        }
        fseek(f, 0, SEEK_SET);
    }
    int written = fwrite_block_with_key(edfs_context, key, 0, 0, data, 1, size, f);
    if (written < 0)
        log_error("error writing %i bytes to file %s (errno: %i)", fullpath, errno);

    edfs_file_unlock(edfs_context, f);
    fclose(f);

    return written;
}

int edfs_write_chunk(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino, const char *buf, size_t size, int64_t off, int64_t *initial_filesize, int set_size, struct edfs_hash_buffer *hash_buffer) {
    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    adjustpath(key, fullpath, computename(ino, b64name));

    int64_t chunk = off / BLOCK_SIZE;
    int64_t offset = off % BLOCK_SIZE;
    size_t bytes_written = 0;
    // ensure directory exists
    EDFS_MKDIR(fullpath, 0755);

    int64_t filesize = *initial_filesize;
    while (size > 0) {
        int written = make_chunk(edfs_context, key, ino, fullpath, chunk, buf, size, offset, &filesize, hash_buffer, off);
        if (written <= 0) {
            if (filesize != *initial_filesize) {
                if (set_size)
                    edfs_set_size_key(edfs_context, key, ino, filesize);
                else
                    *initial_filesize = filesize;
            }
            log_error("write error in %s, errno %i", fullpath, (int)-written);
            return written;
        }
        bytes_written += written;
        buf += written;
        size -= written;
        offset = 0;
        chunk++;
    }
    if (filesize != *initial_filesize) {
        if (set_size)
            edfs_set_size_key(edfs_context, key, ino, filesize);
        else
            *initial_filesize = filesize;
    }

    return bytes_written;
}

int edfs_flush_chunk(struct edfs *edfs_context, edfs_ino_t ino, struct filewritebuf *fbuf) {
    if ((fbuf) && (fbuf->size)) {
        int size = fbuf->size;
        const char *p = (const char *)fbuf->p;
        int err = 0;
        int64_t offset = fbuf->offset - fbuf->size;
        int64_t initial_filesize = get_size_json(edfs_context, fbuf->key, ino);
        int64_t filesize = initial_filesize;
        fbuf->file_size = filesize;
        while (size > 0) {
            if (!fbuf->hash_buffer) {
                fbuf->hash_buffer = (struct edfs_hash_buffer *)malloc(sizeof(struct edfs_hash_buffer));
                if (fbuf->hash_buffer) {
                    fbuf->hash_buffer->read_size = 0;
                    fbuf->hash_buffer->chunk = 0;
                }
            }
            err = edfs_write_chunk(edfs_context, fbuf->key, ino, (const char *)p, edfs_min(BLOCK_SIZE, size), offset, &filesize, 0, fbuf->hash_buffer);
            if (err <= 0)
                break;

            p += err;
            size -= err;
            offset += err;
        }

        if (offset > initial_filesize) {
             edfs_set_size_key(edfs_context, fbuf->key, ino, filesize);
             fbuf->file_size = filesize;
        }
        free(fbuf->p);
        fbuf->p = NULL;
        free(fbuf->read_buffer);
        fbuf->read_buffer = NULL;
        free(fbuf->read_hash_buffer);
        fbuf->read_hash_buffer = NULL;
        fbuf->read_buffer_size = 0;
        fbuf->read_hash_buffer_size = 0;
        fbuf->read_hash_cunk = 0;
        fbuf->size = 0;
        fbuf->offset = 0;

        if (err < 0)
            return err;

        return err;
    }
    return 0;
}

int edfs_write_cache(struct edfs *edfs_context, edfs_ino_t ino, const char *buf, size_t size, int64_t off, struct filewritebuf *fbuf) {
    if (fbuf) {
        if (!fbuf->written_data) {
            fbuf->written_data = 1;
            edfs_notify_write(edfs_context, fbuf->key, ino, 1);
        }
        if (fbuf->offset != off) {
            int err = edfs_flush_chunk(edfs_context, ino, fbuf);
            if (err < 0)
                return err;
        }
        fbuf->p = (unsigned char *)realloc(fbuf->p, fbuf->size + size);
        if (!fbuf->p)
            return -ENOMEM;
        memcpy(fbuf->p + fbuf->size, buf, size);
        fbuf->size += size;
        fbuf->offset = off + size;
        if (fbuf->size >= BLOCK_SIZE * 10) {
            int err = edfs_flush_chunk(edfs_context, ino, fbuf);
            if (err < 0)
                return err;
        }
        return size;
    }
    return -EIO;
}

int edfs_write(struct edfs *edfs_context, edfs_ino_t ino, const char *buf, size_t size, int64_t off, struct filewritebuf *fbuf) {
    if (edfs_context->read_only_fs)
        return -EROFS;

    if (size <= 0)
        return 0;
    return edfs_write_cache(edfs_context, ino, buf, size, off, fbuf);
}

int edfs_close(struct edfs *edfs_context, struct filewritebuf *fbuf) {
    if (fbuf) {
        while (fbuf->in_read) {
            log_trace("waiting for read operation");
#ifdef _WIN32
            Sleep(5);
#else
            usleep(5000);
#endif
        }
#ifdef EDFS_USE_READ_QUEUE
        if (fbuf->read_queued == 1) {
            fbuf->read_queued = 2;
            while (fbuf->read_queued) {
                log_trace("waiting for read queue");
#ifdef _WIN32
                Sleep(5);
#else
                usleep(5000);
#endif
            }
        }
#endif

        edfs_flush_chunk(edfs_context, fbuf->ino, fbuf);
        if (fbuf->written_data) {
            uint64_t max_size = fbuf->offset; 
            unsigned char hash[32];
            // flush to disk
            char b64name[MAX_B64_HASH_LEN];
            char fullpath[MAX_PATH_LEN];
            adjustpath(fbuf->key, fullpath, computename(fbuf->ino, b64name));
            if (fbuf->hash_buffer)
                edfs_update_hash(edfs_context, fbuf->key, fullpath, -1, NULL, 0, fbuf->hash_buffer);
            if (edfs_update_chain(edfs_context, fbuf->key, fbuf->ino, fbuf->file_size, hash, NULL)) {
                const char *update_data[] = {"iostamp", (const char *)hash, NULL, NULL};
                edfs_update_json(edfs_context, fbuf->key, fbuf->ino, update_data);
            } else
                log_error("error updating chain");
            if (max_size < fbuf->file_size)
                max_size = fbuf->file_size;
            if (max_size > 0)
                edfs_update_json_number_if_less(edfs_context, fbuf->key, fbuf->ino, "size", max_size);
            edfs_notify_write(edfs_context, fbuf->key, fbuf->ino, 0);
        }
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&fbuf->key->ino_cache_lock);
        void *ino_cache = avl_remove(&fbuf->key->ino_cache, (void *)(uintptr_t)fbuf->ino);
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&fbuf->key->ino_cache_lock);

#ifndef EDFS_NO_JS
        edfs_key_js_call_args(fbuf->key, "edwork.events.onrelease", "_bf", fbuf->ino, (int)0, (double)fbuf->written_data);
#endif
        if (fbuf->key)
            fbuf->key->opened_files --;
        free(ino_cache);
        free(fbuf->p);
        free(fbuf->read_buffer);
        free(fbuf->read_hash_buffer);
        free(fbuf->hash_buffer);
        free(fbuf);

    }
    return 0;
}

int edfs_mkdir_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent, const char *name, mode_t mode) {
    if (edfs_context->read_only_fs)
        return -EROFS;

    if (!key)
        return -EACCES;

    if (key->read_only)
        return -EROFS;

    uint64_t inode;
    return makenode(edfs_context, key, parent, name, S_IFDIR | 0755, &inode);
}

int edfs_mkdir(struct edfs *edfs_context, edfs_ino_t parent, const char *name, mode_t mode) {
    return edfs_mkdir_key(edfs_context, edfs_context->primary_key, parent, name, mode);
}

int edfs_lookup_blockchain(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t inode, uint64_t block_timestamp_limit, unsigned char *blockchainhash, uint64_t *generation, uint64_t *timestamp) {
    if (timestamp)
        *timestamp = 0;
    if (generation)
        *generation = 0;

    struct block *blockchain = key->chain;
    int i;
    int record_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + 32;
    uint64_t inode_be = htonll(inode);
    while ((blockchain) && ((blockchain->timestamp + EDFS_BLOCKCHAIN_NEW_BLOCK_TIMEOUT) >= block_timestamp_limit)) {
        int len = blockchain->data_len - 72;
        if (len >= record_size) {
            unsigned char *ptr = blockchain->data;
            for (i = 0; i < len; i += record_size) {
                if (*(uint64_t *)ptr == inode_be) {
                    if (generation) {
                        memcpy(generation, ptr + sizeof(uint64_t), sizeof(uint64_t));
                        *generation = ntohll(*generation);
                    }
                    if (timestamp) {
                        memcpy(timestamp, ptr + sizeof(uint64_t) + sizeof(uint64_t), sizeof(uint64_t));
                        *timestamp = ntohll(*timestamp);
                    }
                    if (blockchainhash)
                        memcpy(blockchainhash, ptr + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t), 32);
                    log_debug("got data from blockchain");
                    return 1;
                }
                ptr += record_size;
            }
        }
        blockchain = (struct block *)blockchain->previous_block;
    }
    return 0;
}

int edfs_history(struct edfs *edfs_context, edfs_ino_t inode, uint64_t block_timestamp_limit, unsigned char **blockchainhash, uint64_t *generation, uint64_t *timestamp, int history_limit) {
    if ((!edfs_context) || (!edfs_context->primary_key))
        return -1;

    struct edfs_key_data *key = edfs_context->primary_key;
    struct block *blockchain = key->chain;
    int i;
    int records = 0;
    int record_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + 32;
    uint64_t inode_be = htonll(inode);
    while ((blockchain) && ((blockchain->timestamp + EDFS_BLOCKCHAIN_NEW_BLOCK_TIMEOUT) >= block_timestamp_limit)) {
        int len = blockchain->data_len - 72;
        if (len >= record_size) {
            unsigned char *ptr = blockchain->data;
            for (i = 0; i < len; i += record_size) {
                if (*(uint64_t *)ptr == inode_be) {
                    if (history_limit > 0) {
                        if (generation) {
                            memcpy(&generation[records], ptr + sizeof(uint64_t), sizeof(uint64_t));
                            generation[records] = ntohll(generation[records]);
                        }
                        if (timestamp) {
                            memcpy(&timestamp[records], ptr + sizeof(uint64_t) + sizeof(uint64_t), sizeof(uint64_t));
                            timestamp[records] = ntohll(timestamp[records]);
                        }
                        if (blockchainhash)
                            memcpy(blockchainhash[records], ptr + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t), 32);
                    }
                    log_debug("got data from blockchain");
                    records ++;
                    if ((history_limit > 0) && (records >= history_limit))
                        return records;
                }
                ptr += record_size;
            }
        }
        blockchain = (struct block *)blockchain->previous_block;
    }
    return records;
}

char *edfs_get_signature(struct edfs *edfs_context, uint64_t inode, int signature_index) {
    if ((!edfs_context) || (!edfs_context->primary_key))
        return NULL;

    return edfs_smartcard_get_signature(edfs_context, edfs_context->primary_key, inode, signature_index);
}

struct dirbuf *edfs_opendir_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t ino) {
    unsigned char hash[32];
    unsigned char blockchainhash[32];
    static unsigned char null_hash[32];
    uint64_t blockchain_timestamp = 0;
    uint64_t blockchain_generation = 0;
    uint64_t blockchain_limit = 0;
    uint64_t parent = 0;

    if (!key)
        return NULL;

    int type = read_file_json(edfs_context, key, ino, &parent, NULL, &blockchain_limit, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash, NULL);
    int found_in_blockchain = edfs_lookup_blockchain(edfs_context, key, ino, blockchain_limit, blockchainhash, &blockchain_generation, &blockchain_timestamp);
    if ((type & S_IFDIR) == 0)
        return NULL;
#ifndef EDFS_NO_JS
    if (edfs_key_js_call_args(key, "edwork.events.onopen", "_bb", ino, (int)1, (int)1) == 1) {
        log_warn("access denied by JS function");
        return NULL;
    }
#endif
    struct dirbuf *buf = (struct dirbuf *)malloc(sizeof(struct dirbuf));
    if (buf) {
        char path[MAX_PATH_LEN];
        char b64name[MAX_B64_HASH_LEN];
        unsigned char computed_hash[32];
        uint64_t network_inode = htonll(ino);
        int blockchain_error = 0;
        if (found_in_blockchain) {
            if (memcmp(blockchainhash, hash, 32)) {
                log_warn("blockchain hash error, falling back to descriptor check");
                found_in_blockchain = 0;
                blockchain_error = 1;
            } else
                log_trace("directory hash ok (blockchain)");
        }
        if ((!found_in_blockchain) && ((blockchain_error) || (memcmp(hash, null_hash, 32)))) {
            snprintf(path, sizeof(path), "%s/%s", key->working_directory, computename(ino, b64name));
            unsigned char proof_cache[1024];
            int proof_size = 0;
            thread_mutex_lock(&key->ino_cache_lock);
            void *hash_error = (struct edfs_ino_cache *)avl_search(&key->ino_checksum_mismatch, (void *)(uintptr_t)ino);
            thread_mutex_unlock(&key->ino_cache_lock);
            uint64_t start = microseconds();
            do {
                pathhash(edfs_context, key, path, computed_hash);
                if (blockchain_error) {
                    blockchain_error = 0;
                } else {
                    if (!memcmp(hash, computed_hash, 32)) {
                        log_trace("directory hash ok");
                        if (hash_error) {
                            thread_mutex_lock(&key->ino_cache_lock);
                            avl_remove(&key->ino_checksum_mismatch, (void *)(uintptr_t)ino);
                            thread_mutex_unlock(&key->ino_cache_lock);
                        }
                        break;
                    }
                }
                edfs_notify_io(edfs_context, key, "roo2", (const unsigned char *)&network_inode, sizeof(uint64_t), NULL, 0, 0, 0, 0, EDWORK_ROOT_WORK_LEVEL, 0, NULL, 0, proof_cache, &proof_size);
                if (hash_error) {
                    log_warn("directory hash still mismatched, using last known version (not waiting for timeout)");
                    break;
                }
#ifdef _WIN32
                Sleep(50);
#else
                usleep(50000);
#endif
                if (microseconds() - start >= EDWORK_MAX_DIR_RETRY_TIMEOUT * 1000) {
                    log_warn("directory read timeout, using last known version");
                    thread_mutex_lock(&key->ino_cache_lock);
                    avl_insert(&key->ino_checksum_mismatch, (void *)(uintptr_t)ino, (void *)1);
                    thread_mutex_unlock(&key->ino_cache_lock);
                    break;
                }
                if (!read_file_json(edfs_context, key, ino, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash, NULL)) {
                    log_warn("directory does not exists anymore");
                    thread_mutex_lock(&key->ino_cache_lock);
                    avl_insert(&key->ino_checksum_mismatch, (void *)(uintptr_t)ino, (void *)1);
                    thread_mutex_unlock(&key->ino_cache_lock);
                    break;
                }
            } while (!edfs_context->network_done);
        }

        memset(buf, 0, sizeof(struct dirbuf));
        buf->ino = ino;
        buf->key = key;
        key->opened_files ++;
    }
    return buf;
}

struct dirbuf *edfs_opendir(struct edfs *edfs_context, edfs_ino_t ino) {
    return edfs_opendir_key(edfs_context, edfs_context ? edfs_context->primary_key : NULL, ino);
}

int recursive_rmdir(const char *path) {
    tinydir_dir dir;
    size_t path_len = strlen(path);
    int r = -1;

    if (!tinydir_open_sorted(&dir, path)) {
        r = 0;
        int  i = 0;
        while ((!r) && (i < dir.n_files)) {
            tinydir_file file;
            tinydir_readfile_n(&dir, &file, i++);
            int r2 = -1;
            char *buf;
            size_t len;

            if (!strcmp(file.name, ".") || !strcmp(file.name, ".."))
                 continue;

            len = path_len + strlen(file.name) + 2;
            buf = (char *)malloc(len);

            if (buf) {
                struct stat statbuf;
                snprintf(buf, len, "%s/%s", path, file.name);
                if (!stat(buf, &statbuf)) {
                    if (!S_ISLNK(statbuf.st_mode)) {
                        if (S_ISDIR(statbuf.st_mode))
                            r2 = recursive_rmdir(buf);
                        else
                            r2 = unlink(buf);
                    }
                }
                free(buf);
            }
            r = r2;
            tinydir_next(&dir);
        }
        tinydir_close(&dir);
    }

    if (!r)
        r = rmdir(path);
    return r;
}

int recursive_dir_size(const char *path, uint64_t *size, uint64_t *files, uint64_t *directories) {
    tinydir_dir dir;
    size_t path_len = strlen(path);
    int r = -1;

    if (!tinydir_open(&dir, path)) {
        r = 0;
        if (directories)
            (*directories) ++;
        while (dir.has_next) {
            tinydir_file file;
            tinydir_readfile(&dir, &file);
            int r2 = -1;
            char *buf;
            size_t len;

            if ((strcmp(file.name, ".")) && (strcmp(file.name, ".."))) {
                len = path_len + strlen(file.name) + 2;
                buf = (char *)malloc(len);

                if (buf) {
                    struct stat statbuf;
                    snprintf(buf, len, "%s/%s", path, file.name);
                    if (!stat(buf, &statbuf)) {
                        if (!S_ISLNK(statbuf.st_mode)) {
                            if (S_ISDIR(statbuf.st_mode)) {
                                r2 = recursive_dir_size(buf, size, files, directories);
                                if (size)
                                    (*size) += statbuf.st_size;
                            } else {
                                if (files)
                                    (*files) ++;
                                if (size)
                                    (*size) += statbuf.st_size;
                            }
                        }
                    }
                    free(buf);
                }
                r = r2;
            }
            tinydir_next(&dir);
        }
        tinydir_close(&dir);
    }
    return r;
}

void rehash_parent(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent) {
    char parentb64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", key->working_directory, computename(parent, parentb64name));

    unsigned char new_hash[32];
    pathhash(edfs_context, key, fullpath, new_hash);
    const char *update_data[] = {"iostamp", (const char *)new_hash, NULL, NULL};
    edfs_update_json(edfs_context, key, parent, update_data);
}

int remove_node(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent, edfs_ino_t inode, int recursive, uint64_t generation, int is_broadcast) {
    char fullpath[MAX_PATH_LEN];
    char noderef[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    char parentb64name[MAX_B64_HASH_LEN];
    adjustpath(key, fullpath, computename(inode, b64name));
    if (recursive)
        recursive_rmdir(fullpath);
    else
        rmdir(fullpath);

#ifdef EDFS_USE_HARD_DELETE
    strcat(fullpath, ".json");
    unlink(fullpath);
#else
    if (!is_broadcast)
        edfs_update_json_number(edfs_context, key, inode, "deleted", 1);
#endif
    if (parent != 0) {
        noderef[0] = 0;
        snprintf(noderef, MAX_PATH_LEN, "%s/%s", computename(parent, parentb64name), b64name);
        unlink(adjustpath(key, fullpath, noderef));
        if (!is_broadcast)
            rehash_parent(edfs_context, key, parent);
    }

#ifdef EDFS_USE_HARD_DELETE
    // generate some noise for signing
    unsigned char hash[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)&parent, sizeof(parent));
    uint64_t random8bytes = edwork_random();
    sha256_update(&ctx, (const BYTE *)&random8bytes, sizeof(uint64_t));
    sha256_update(&ctx, (const BYTE *)&generation, sizeof(uint64_t));
    sha256_final(&ctx, hash);

    *(uint64_t *)hash = htonll(inode);
    *(uint64_t *)(hash + 8) = htonll(microseconds());
    log_info("broadcasting DEL request for %s (generation %" PRIu64 ")", b64name, generation);
    *(uint64_t *)(hash + 16) = htonll(generation);

    edfs_notify_io(edfs_context, key, "del\x00", hash, 32, NULL, 0, 1, 1, inode, 0, 0, NULL, 0, NULL, NULL);
#endif
    return 1;
}

int edfs_rmdir_inode_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent, edfs_ino_t inode) {
    if ((!key) || (key->read_only) || (edfs_context->read_only_fs))
        return -EROFS;

    uint64_t generation;
    int type = read_file_json(edfs_context, key, inode, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, &generation, NULL, NULL);
    if (!type)
        return -ENOENT;
    if (type & S_IFDIR) {
#ifndef EDFS_NO_JS
        if (edfs_key_js_call_args(key, "edwork.events.ondelete", "__s", inode, parent, "directory") == 1) {
            log_warn("access denied by JS function");
            return 0;
        }
#endif
        if (!remove_node(edfs_context, key, parent, inode, 0, generation, 0))
            return -errno;
        else
            return 0;
    }
    return -ENOTDIR;
}

int edfs_rmdir_inode(struct edfs *edfs_context, edfs_ino_t parent, edfs_ino_t inode) {
    return edfs_rmdir_inode_key(edfs_context, edfs_context->primary_key, parent, inode);
}

int edfs_rmdir_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent, const char *name) {
    return edfs_rmdir_inode_key(edfs_context, key, parent, computeinode(edfs_context->primary_key, parent, name));
}

int edfs_rmdir(struct edfs *edfs_context, edfs_ino_t parent, const char *name) {
    return edfs_rmdir_key(edfs_context, edfs_context->primary_key, parent, name);
}

int edfs_unlink_inode_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent, edfs_ino_t inode) {
    if ((!key) || (key->read_only) || (edfs_context->read_only_fs))
        return -EROFS;

    uint64_t generation;
    int type = read_file_json(edfs_context, key, inode, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, &generation, NULL, NULL);
    if (!type)
        return -ENOENT;
    if (type & S_IFDIR) {
        return -EISDIR;
    } else {
#ifndef EDFS_NO_JS
        if (edfs_key_js_call_args(key, "edwork.events.ondelete", "__s", inode, parent, "file") == 1) {
            log_warn("access denied by JS function");
            return 0;
        }
#endif
        if (!remove_node(edfs_context, key, parent, inode, 1, generation, 0))
            return -errno;
    }

    return 0;
}

int edfs_unlink_inode(struct edfs *edfs_context, edfs_ino_t parent, edfs_ino_t inode) {
    return edfs_unlink_inode_key(edfs_context, edfs_context->primary_key, parent, inode);
}

int edfs_unlink_key(struct edfs *edfs_context, struct edfs_key_data *key, edfs_ino_t parent, const char *name) {
    return edfs_unlink_inode_key(edfs_context, key, parent, computeinode(edfs_context->primary_key, parent, name));
}

int edfs_unlink(struct edfs *edfs_context, edfs_ino_t parent, const char *name) {
    return edfs_unlink_key(edfs_context, edfs_context->primary_key, parent, name);
}

int edfs_flush(struct edfs *edfs_context, struct filewritebuf *fbuf) {
    if (fbuf)
        edfs_flush_chunk(edfs_context, fbuf->ino, fbuf);
    return 0;
}

int edfs_fsync(struct edfs *edfs_context, int datasync, struct filewritebuf *fbuf) {
    if (fbuf)
        edfs_flush_chunk(edfs_context, fbuf->ino, fbuf);
    return 0;
}

int edfs_mknod(struct edfs *edfs_context, edfs_ino_t parent, const char *name, mode_t mode, uint64_t *inode) {
    if (edfs_context->read_only_fs)
        return -EROFS;

    if (edfs_context->read_only_fs)
        return -EROFS;

    struct edfs_key_data *key = edfs_context->primary_key;
    if ((!key) || (key->read_only))
        return -EROFS;

    if ((mode & S_IFREG) == 0)
        return -EACCES;


    return makenode(edfs_context, key, parent, name, S_IFREG | 0644, inode);
}

int edfs_genesis_if_new(struct edfs *edfs_context, struct edfs_key_data *key) {
    if ((!key) || (key->chain))
        return 0;

    log_info("please wait while initializing first block");
    key->chain = block_new(NULL, edwork_who_i_am(edfs_context->edwork), 32);
    block_mine(key->chain, BLOCKCHAIN_COMPLEXITY);
    edfs_block_save(edfs_context, key, key->chain);
    key->top_broadcast_timestamp = 0;
    log_info("done");
    edfs_broadcast_top(edfs_context, key, NULL, 0);
    return 1;
}

int edfs_create_key(struct edfs *edfs_context) {
    unsigned char seed[32];
    unsigned char public_key[32];
    unsigned char private_key[64];
    char b64buffer[128];
    int err = ed25519_create_seed(seed);
    if (err)
        return err;

    ed25519_create_keypair(public_key, private_key, seed);

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "alg", "ED25519");
    json_object_set_string(root_object, "kty", "EDD25519");

    b64buffer[0] = 0;
    size_t len = base64_encode_no_padding((const BYTE *)private_key, 64, (BYTE *)b64buffer, sizeof(b64buffer) - 1);
    if (len > 0) {
        b64buffer[len] = 0;
        json_object_set_string(root_object, "k", b64buffer);
    }

    b64buffer[0] = 0;
    len = base64_encode_no_padding((const BYTE *)public_key, 32, (BYTE *)b64buffer, sizeof(b64buffer) - 1);
    if (len > 0) {
        b64buffer[len] = 0;
        json_object_set_string(root_object, "pk", b64buffer);
    }

    unsigned char hash[32];
    sha256(public_key, 32, hash);
    uint64_t key_id = htonll(XXH64(hash, 32, 0));

    b64buffer[0] = 0;
    len = base32_encode((const BYTE *)&key_id, sizeof(uint64_t), (BYTE *)b64buffer, sizeof(b64buffer) - 1);
    b64buffer[len] = 0;

    char fullpath[MAX_PATH_LEN];
    fullpath[0] = 0;
    snprintf(fullpath, sizeof(fullpath), "%s/%s", edfs_context->edfs_directory, b64buffer);

    recursive_mkdir(fullpath);

    fullpath[0] = 0;
    snprintf(fullpath, sizeof(fullpath), "%s/%s/signature.json", edfs_context->edfs_directory, b64buffer);

    if (edfs_context->has_storekey) {
        char *serialized_string = json_serialize_to_string_pretty(root_value);
        FILE *f = fopen(fullpath, "wb");
        if (f) {
            edfs_write_simple_key(edfs_context, serialized_string, strlen(serialized_string), f);
            fclose(f);
        }
        json_free_serialized_string(serialized_string);
    } else
        json_serialize_to_file_pretty(root_value, fullpath);
    json_value_free(root_value);

    if ((edwork_load_key(edfs_context, b64buffer)) && (edfs_context->key_data)) {
        edfs_genesis_if_new(edfs_context, edfs_context->key_data);
        edfs_context->primary_key = edfs_context->key_data;
        edfs_settings_set_number(edfs_context, "edfs.primary_key", XXH32(edfs_context->primary_key->key_id, sizeof(edfs_context->primary_key->key_id), 0));
#ifdef EDWORK_PEER_DISCOVERY_SERVICE
        edwork_broadcast_discovery_key(edfs_context, edfs_context->key_data);
#endif
    }

    return 0;
}

int edfs_use_key(struct edfs *edfs_context, const char *private_key, const char *public_key) {
    if (((!public_key) && (!private_key)) || (!edfs_context))
        return -1;

    char b64buffer[128];
    char public_key_b64[64];
    unsigned char public_key_buffer[64];
    unsigned char keydata[128];
    size_t len;

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "alg", "ED25519");
    json_object_set_string(root_object, "kty", "EDD25519");

    if (private_key) {
        json_object_set_string(root_object, "k", private_key);

        if (!public_key) {
            len = base64_decode_no_padding((const BYTE *)private_key, (BYTE *)keydata, 128);
            if (len != 64) {
                log_error("invalid key");
                json_value_free(root_value);
                return -1;
            }

            keydata[0] &= 248;
            keydata[31] &= 63;
            keydata[31] |= 64;

            ed25519_get_pubkey(public_key_buffer, keydata);

            len = base64_encode_no_padding((const unsigned char *)public_key_buffer, 32, (unsigned char *)public_key_b64, 64);
            public_key_b64[len] = 0;
            public_key = public_key_b64;
        }
    }
    json_object_set_string(root_object, "pk", public_key);

    if (base64_decode_no_padding((const BYTE *)public_key, (BYTE *)keydata, MAX_KEY_SIZE) != 32) {
        log_error("invalid key");
        return -1;
    }

    unsigned char hash[32];
    sha256(keydata, 32, hash);
    uint64_t key_id = htonll(XXH64(hash, 32, 0));

    b64buffer[0] = 0;
    len = base32_encode((const BYTE *)&key_id, sizeof(uint64_t), (BYTE *)b64buffer, sizeof(b64buffer) - 1);
    b64buffer[len] = 0;

    char fullpath[MAX_PATH_LEN];
    fullpath[0] = 0;
    snprintf(fullpath, sizeof(fullpath), "%s/%s", edfs_context->edfs_directory, b64buffer);

    recursive_mkdir(fullpath);

    fullpath[0] = 0;
    snprintf(fullpath, sizeof(fullpath), "%s/%s/signature.json", edfs_context->edfs_directory, b64buffer);

    if (edfs_context->has_storekey) {
        char *serialized_string = json_serialize_to_string_pretty(root_value);
        FILE *f = fopen(fullpath, "wb");
        if (f) {
            edfs_write_simple_key(edfs_context, serialized_string, strlen(serialized_string), f);
            fclose(f);
        }
        json_free_serialized_string(serialized_string);
    } else
        json_serialize_to_file_pretty(root_value, fullpath);

    json_value_free(root_value);
    int key_loaded = edwork_load_key(edfs_context, b64buffer);
    if (key_loaded) {
        // for upgraded key, do nothing
        if (key_loaded == 2)
            return 0;
#ifdef EDWORK_PEER_DISCOVERY_SERVICE
        edwork_broadcast_discovery_key(edfs_context, edfs_context->key_data);
#endif
        edfs_schedule(edfs_context, edfs_check_descriptors, 10000000, 0, 0, 0, 0, 0, edfs_context->key_data);
        edfs_context->key_data->hblk_scheduled = 1;
        edfs_schedule(edfs_context, edfs_blockchain_request, 50000, 0, 0, 0, 0, 0, edfs_context->key_data);
        edfs_context->key_data->block_timestamp = time(NULL) + 20;
    } else
        return -1;

    if (!edfs_context->primary_key)
        edfs_context->primary_key = edfs_context->key_data;

    return 0;
}

void *edfs_find_key_opaque(struct edfs *edfs_context, const char *key_id) {
    if ((!edfs_context) || (!key_id))
        return NULL;

    uint64_t use_key_id = 0;
    if (strlen(key_id) > 32) {
        unsigned char public_key[MAX_KEY_SIZE];
        size_t len = base64_decode_no_padding((const BYTE *)key_id, public_key, MAX_KEY_SIZE);
        if (len >= 32) {
            if (len == 64) {
                public_key[0] &= 248;
                public_key[31] &= 63;
                public_key[31] |= 64;

                ed25519_get_pubkey(public_key, public_key);
            }
            unsigned char hash[32];
            sha256(public_key, 32, hash);
            use_key_id = htonll(XXH64(hash, 32, 0));
        }
    } else
        base32_decode((const BYTE *)key_id, (BYTE *)&use_key_id, sizeof(uint64_t));

    struct edfs_key_data *key = edfs_context->key_data;
    while (key) {
        if (key->key_id_xxh64_be == use_key_id)
            return key;
        key = (struct edfs_key_data *)key->next_key;
    }

    return NULL;
}

int edfs_chkey(struct edfs *edfs_context, const char *key_id) {
    struct edfs_key_data *key = (struct edfs_key_data *)edfs_find_key_opaque(edfs_context, key_id);
    if (!key)
        return -1;

    edfs_context->primary_key = key;
#ifdef EDWORK_PEER_DISCOVERY_SERVICE
    edwork_broadcast_discovery_key(edfs_context, key);
#endif
    edfs_settings_set_number(edfs_context, "edfs.primary_key", XXH32(key->key_id, sizeof(key->key_id), 0));
    return 0;
}

int edfs_rmkey(struct edfs *edfs_context, const char *key_id) {
    // do not remove key while block sync is performed
    if ((!edfs_context) || (!key_id) || (edfs_context->events))
        return -1;

    uint64_t use_key_id = 0;
    if (strlen(key_id) > 32) {
        unsigned char public_key[MAX_KEY_SIZE];
        size_t len = base64_decode_no_padding((const BYTE *)key_id, public_key, MAX_KEY_SIZE);
        if (len >= 32) {
            if (len == 64) {
                public_key[0] &= 248;
                public_key[31] &= 63;
                public_key[31] |= 64;

                ed25519_get_pubkey(public_key, public_key);
            }
            unsigned char hash[32];
            sha256(public_key, 32, hash);
            use_key_id = htonll(XXH64(hash, 32, 0));
        }
    } else
        base32_decode((const BYTE *)key_id, (BYTE *)&use_key_id, sizeof(uint64_t));

    struct edfs_key_data *key = edfs_context->key_data;
    struct edfs_key_data *prev_key = NULL;
    while (key) {
        if (key->key_id_xxh64_be == use_key_id) {
            if (edfs_context->primary_key == key) {
                log_error("cannot delete primary key");
                return -1;
            }
            if ((key->opened_files > 0) || (key->mining_flag)) {
                log_error("key is in use");
                return -1;
            }
            avl_remove(&edfs_context->key_tree, (void *)(uintptr_t)key->key_id_xxh64_be);
            if (prev_key)
                prev_key->next_key = key->next_key;
            else
                edfs_context->key_data = (struct edfs_key_data *)key->next_key;

            edfs_key_data_deinit(key);
            free(key);

            char fullpath[MAX_PATH_LEN];
            fullpath[0] = 0;
            snprintf(fullpath, MAX_PATH_LEN, "%s/%s", edfs_context->edfs_directory, key_id);
            recursive_rmdir(fullpath);

            return 0;
        }
        prev_key = key;
        key = (struct edfs_key_data *)key->next_key;
    }
    return -1;
}

int edfs_storage_info(struct edfs *edfs_context, const char *key_id, uint64_t *size, uint64_t *files, uint64_t *directories, uint64_t *top_block, uint64_t *timestamp) {
    struct edfs_key_data *key = (struct edfs_key_data *)edfs_find_key_opaque(edfs_context, key_id);
    if (!key)
        return -1;

    char fullpath[MAX_PATH_LEN];
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", edfs_context->edfs_directory, key_id);
    if (top_block) {
        *top_block = 0;
        if (key->chain)
            *top_block = key->chain->index;
    }
    if (timestamp) {
        *timestamp = 0;
        if (key->chain)
            *timestamp = key->chain->timestamp;
    }
    return recursive_dir_size(fullpath, size, files, directories);
}

static int edfs_data_dir_remove(struct edfs *edfs_context, struct edfs_key_data *key, const char *path) {
    tinydir_dir dir;
    size_t path_len = strlen(path);

    if (!tinydir_open_sorted(&dir, path)) {
        int i;
        for (i = 0; i < dir.n_files; i++) {
            tinydir_file file;
            tinydir_readfile_n(&dir, &file, i);

            char *buf;
            size_t len;

            if ((strcmp(file.name, ".")) && (strcmp(file.name, "..")) && (file.is_dir)) {
                len = path_len + strlen(file.name) + 2;
                buf = (char *)malloc(len);

                if (buf) {
                    snprintf(buf, len, "%s/%s", path, file.name);
                    unsigned char data[MAX_INODE_DESCRIPTOR_SIZE];
                    int edfs_inode_is_dir = 0;
                    int data_size = edfs_read_file(edfs_context, key, path, file.name, (unsigned char *)data, MAX_INODE_DESCRIPTOR_SIZE - 1, ".json", 1, 1, 0, NULL, 0, 0, 0, 0);
                    if (data_size > 0) {
                        JSON_Value *root_value = json_parse_string((const char *)data);
                        if (json_value_get_type(root_value) == JSONObject) {
                            JSON_Object *root_object = json_value_get_object(root_value);
                            edfs_inode_is_dir = ((int)json_object_get_number(root_object, "type")) & S_IFDIR;
                            if ((int)json_object_get_number(root_object, "deleted"))
                                edfs_inode_is_dir = 0;
                        }
                        json_value_free(root_value);
                    }
                    if (!edfs_inode_is_dir)
                        recursive_rmdir(buf);
                    free(buf);
                }
            }
        }
        tinydir_close(&dir);
    } else
        return -1;
    return 0;
}

int edfs_remove_data(struct edfs *edfs_context, const char *key_id) {
    struct edfs_key_data *key = (struct edfs_key_data *)edfs_find_key_opaque(edfs_context, key_id);
    if (!key)
        return -1;

    char fullpath[MAX_PATH_LEN];
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s/inode", edfs_context->edfs_directory, key_id);

    return edfs_data_dir_remove(edfs_context, key, fullpath);
}

int edfs_peers_info(struct edfs *edfs_context, char *buffer, int buffer_size, int html) {
    return edwork_debug_node_list(edfs_context->edwork, buffer, buffer_size, (unsigned int)0, time(NULL) - EDWORK_LAST_SEEN_TIMEOUT, html);
}

int edfs_list_keys(struct edfs *edfs_context, char *buffer, int buffer_size) {
    if (!edfs_context)
        return -1;

    struct edfs_key_data *key = edfs_context->key_data;
    char *ptr = buffer;
    int ptr_size = buffer_size;
    while ((key) && (ptr) && (ptr_size > 12)) {
        int encode_len = base32_encode((const unsigned char *)&key->key_id_xxh64_be, sizeof(uint64_t), (unsigned char *)ptr, ptr_size);
        ptr[encode_len] = '\n';
        ptr[encode_len + 1] = 0;
        ptr += encode_len + 1;
        ptr_size -= encode_len + 1;
        key = (struct edfs_key_data *)key->next_key;
    }
    return key ? 1 : 0;
}

void *edfs_get_key(struct edfs *edfs_context) {
   if (!edfs_context)
       return NULL;

   return edfs_context->key_data;
 }

void *edfs_next_key(void *key) {
   if (!key)
       return NULL;

   return ((struct edfs_key_data *)key)->next_key;
 }

void *edfs_get_primary_key(struct edfs *edfs_context) {
   if (!edfs_context)
       return NULL;

   return edfs_context->primary_key;
}

char *edfs_key_id(void *key, char *buffer) {
    if ((!key) || (!buffer))
        return NULL;

    buffer[0] = 0;
    int encode_len = base32_encode((const unsigned char *)&((struct edfs_key_data *)key)->key_id_xxh64_be, sizeof(uint64_t), (unsigned char *)buffer, 16);
    buffer[encode_len] = 0;

    return buffer;
}

char *edfs_public_key(void *key, char *buffer) {
    if ((!key) || (!buffer))
        return NULL;

    buffer[0] = 0;
    if (((struct edfs_key_data *)key)->pub_len > 0) {
        int encode_len = base64_encode_no_padding(((struct edfs_key_data *)key)->pubkey, ((struct edfs_key_data *)key)->pub_len, (unsigned char *)buffer, 128);
        buffer[encode_len] = 0;
    }

    return buffer;
}

char *edfs_private_key(void *key, char *buffer) {
    if ((!key) || (!buffer))
        return NULL;

    buffer[0] = 0;
    if (((struct edfs_key_data *)key)->sig_len > 0) {
        int encode_len = base64_encode_no_padding(((struct edfs_key_data *)key)->sigkey, ((struct edfs_key_data *)key)->sig_len, (unsigned char *)buffer, 128);
        buffer[encode_len] = 0;
    }

    return buffer;
}

char *edfs_who_i_am(struct edfs *edfs_context, char *buffer, unsigned char as_base64) {
    if ((!edfs_context) || (!buffer))
        return NULL;

    if (as_base64) {
        int encode_len = base64_encode_no_padding(edwork_who_i_am(edfs_context->edwork), 32, (unsigned char *)buffer, 64);
        buffer[encode_len] = 0;
    } else {
        memcpy(buffer, edwork_who_i_am(edfs_context->edwork), 32);
    }

    return buffer;
}

int edfs_blockchain_request(struct edfs *edfs_context, uint64_t userdata_a, uint64_t userdata_b, void *data) {
    struct edfs_key_data *key = (struct edfs_key_data *)data;
    if (!key)
        return 1;
    if (key->chain) {
        if ((userdata_b) && (microseconds() - userdata_b <= 1000000)) {
            uint64_t requested_block = 0;
            edfs_notify_io(edfs_context, key, "hblk", (const unsigned char *)&requested_block, sizeof(uint64_t), NULL, 0, 0, 0, 0, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
        }
        uint64_t requested_block = htonll(key->chain->index + 2 - userdata_a);
        edfs_notify_io(edfs_context, key, "hblk", (const unsigned char *)&requested_block, sizeof(uint64_t), NULL, 0, 0, 0, 0, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);

        if ((key->block_timestamp) && (time(NULL) - key->block_timestamp >= 20)) {
            key->hblk_scheduled = 0;
            return 1;
        }
    } else {
        uint64_t requested_block = htonll(1);
        edfs_notify_io(edfs_context, key, "hblk", (const unsigned char *)&requested_block, sizeof(uint64_t), NULL, 0, 0, 0, 0, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
    }
    return 0;
}

int edfs_shard_data_request(struct edfs *edfs_context, uint64_t inode, uint64_t chunk, void *data) {
    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    struct edfs_key_data *key = (struct edfs_key_data *)data;
    if (!key)
        return 1;

    adjustpath(key, fullpath, computename(inode, b64name));

    if (chunk_exists(fullpath, chunk))
        return 1;

    // file was deleted
    if (get_deleted_json(edfs_context, key, inode))
        return 1;
#ifdef WITH_SCTP
    request_data_sctp(edfs_context, key, inode, chunk, edwork_random() % 10, NULL, NULL, 0, fullpath, 0, NULL);
#else
    request_data(edfs_context, key, inode, chunk, 1, edwork_random() % 10, NULL, NULL, 0);
#endif
    return 0;
}

void edfs_ensure_data(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, uint64_t file_size, int try_update_hash, uint64_t start_chunk, uint64_t json_version) {
    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];
    char chunk_path[MAX_PATH_LEN];
    unsigned char sig_buffer[64];

    log_trace("ensure data");

    if ((!try_update_hash) && (json_version)) {
        uint64_t version = (uint64_t)(uintptr_t)avl_search(&key->ino_sync_file, (void *)(uintptr_t)inode);
        // already up to date
        if ((version) && (version == json_version)) {
            log_trace("data up to date");
            return;
        }
        edfs_request_hash_if_needed(edfs_context, key, inode);
    }
    adjustpath(key, fullpath, computename(inode, b64name));

    if (!file_size)
        file_size = get_size_json(edfs_context, key, inode);

    if (!file_size) {
        log_trace("file size is 0");
        return;
    }

    uint64_t chunk = start_chunk;

    uint32_t hash_buffer[BLOCK_SIZE / sizeof(uint32_t)];
    unsigned int chunk_offset = 0;
    int has_hash = edfs_get_hash2(edfs_context, key, fullpath, inode, chunk, hash_buffer, &chunk_offset);
    while (chunk_exists(fullpath, chunk)) {
        uint32_t signature_hash = 0;
        if (has_hash > 0) {
            if (chunk_offset >= has_hash)
                has_hash = edfs_get_hash2(edfs_context, key, fullpath, inode, chunk, hash_buffer, &chunk_offset);

            if ((has_hash) && (chunk_offset < has_hash)) {
                signature_hash = ntohl(hash_buffer[chunk_offset]);
                chunk_offset ++;
                has_hash --;
            } else
                has_hash = 0;
        }
        if (signature_hash) {
            snprintf(chunk_path, MAX_PATH_LEN, "%" PRIu64, chunk);
            if (edfs_read_file(edfs_context, key, fullpath, chunk_path, sig_buffer, 64, NULL, 0, 0, 0, NULL, signature_hash, 1, inode, chunk) != 64) {
                log_debug("error reading local chunk %s:%" PRIu64, fullpath, chunk);
                break;
            } else
            if (XXH32(sig_buffer, sizeof(sig_buffer), 0) != signature_hash) {
                edfs_request_hash_if_needed(edfs_context, key, inode);
                log_debug("modified chunk %s:%" PRIu64, fullpath, chunk);
                break;
            }
        }
        chunk ++;
    }

    uint64_t last_file_chunk = file_size / BLOCK_SIZE;
    if ((last_file_chunk % BLOCK_SIZE == 0) && (last_file_chunk))
        last_file_chunk --;
    if (chunk <= last_file_chunk) {
        log_trace("requesting shard chunk %s:%" PRIu64 "/%" PRIu64, fullpath, chunk, last_file_chunk);
        if (edwork_random() % 100 == 0) {
            EDFS_THREAD_LOCK(edfs_context);
            edfs_make_key(edfs_context);
            EDFS_THREAD_UNLOCK(edfs_context);
        }
        if (try_update_hash) {
            edfs_schedule(edfs_context, edfs_shard_data_request, 250000, 7ULL * 24ULL * 3600000000ULL, inode, chunk, 1, 1, key);
        } else {
            // use cached addresses for 90% of requests, 10% are broadcasts
            request_data(edfs_context, key, inode, chunk, 1, edwork_random() % 10, NULL, NULL, 0);
        }
    } else {
        if (try_update_hash) {
            edfs_try_make_hash(edfs_context, key, fullpath, file_size);
            edfs_request_hash_if_needed(edfs_context, key, inode);
        }

        void *avl_data;
        if (json_version)
            avl_data = (void *)(uintptr_t)json_version;
        else
            avl_data = (void *)(uintptr_t)get_version_plus_one_json(edfs_context, key, inode);
        avl_remove(&key->ino_sync_file, (void *)(uintptr_t)inode);
        avl_insert(&key->ino_sync_file, (void *)(uintptr_t)inode, (void *)avl_data);

    }
    log_trace("ensure data done");
}

void edfs_queue_ensure_data(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, uint64_t file_size, int try_update_hash, uint64_t start_chunk, uint64_t json_version) {
    struct edwork_shard_io *io = (struct edwork_shard_io *)malloc(sizeof(struct edwork_shard_io));
    if (!io)
        return;

    io->inode = inode;
    io->file_size = file_size;
    io->try_update_hash = try_update_hash;
    io->start_chunk = start_chunk;
    io->json_version = json_version;
    io->key = key;
    io->next = NULL;

    thread_mutex_lock(&edfs_context->shard_lock);
    if (edfs_context->shard_io) {
        struct edwork_shard_io *last = edfs_context->shard_io;
        while (last) {
            if (!last->next) {
                last->next = io;
                break;
            }
            last = (struct edwork_shard_io *)last->next;
        }
    } else {
        edfs_context->shard_io = io;
    }
    thread_mutex_unlock(&edfs_context->shard_lock);
}

int edwork_process_json(struct edfs *edfs_context, struct edfs_key_data *key, const unsigned char *payload, int size, uint64_t *ino) {
    if (size <= 64)
        return -1;

    log_debug("json: %s", payload + 64);
    if (!verify(edfs_context, key, (const char *)payload + 64, size - 64, payload, 64)) {
        log_warn("packet signature verification failed, dropping");
        return -1;
    }

    JSON_Value *root_value = json_parse_string((const char *)payload + 64);
    if (!root_value)
        return 0;

    if (json_value_get_type(root_value) != JSONObject) {
        json_value_free(root_value);
        return 0;
    }
    JSON_Object *root_object = json_value_get_object(root_value);
    int written = 1;
    if (root_object) {
        const char *name = json_object_get_string(root_object, "name");
        const char *b64name = json_object_get_string(root_object, "inode");
        uint64_t inode = unpacked_ino(b64name);
        if (ino)
            *ino = inode;
        const char *parentb64name = json_object_get_string(root_object, "parent");
        uint64_t parent = unpacked_ino(parentb64name);
        int type = (int)json_object_get_number(root_object, "type");
        uint64_t timestamp = (uint64_t)json_object_get_number(root_object, "timestamp");
        uint64_t generation = (uint64_t)json_object_get_number(root_object, "version");
        int deleted = (int)json_object_get_number(root_object, "deleted");
        uint64_t current_generation = 0;
        uint64_t current_timestamp = 0;
        if ((parent == 0) && (inode == edfs_root_inode(key)) && (!deleted) && (b64name)) {
            read_file_json(edfs_context, key, inode, NULL, NULL, &current_timestamp, NULL, NULL, NULL, 0, NULL, NULL, &current_generation, NULL, NULL);
            if ((current_generation > generation) || ((current_generation == generation) && (current_timestamp >= timestamp))) {
                if (current_generation != generation)
                    log_warn("refused to update descriptor: received version is older (%" PRIu64 " > %" PRIu64 ")", current_generation, generation);
                json_value_free(root_value);
                return 0;
            }
            if (edfs_write_file(edfs_context, key, key->working_directory, b64name, (const unsigned char *)payload, size , ".json", 0, NULL, NULL, NULL, NULL, 1, 0, 0) != size ) {
                log_warn("error writing root file %s", b64name);
                written = -1;
            }
            return written;
        }
        if ((inode) && (name) && (b64name) && (parent) && (type) && (timestamp)) {
            uint64_t current_parent = 0;
            time_t current_modified = 0;
            time_t current_created = 0;
            int64_t current_size = 0;
            int current_type = read_file_json(edfs_context, key, inode, &current_parent, &current_size, &current_timestamp, NULL, NULL, NULL, 0, &current_created, &current_modified, &current_generation, NULL, NULL);
            int do_write = 1;
            if ((current_type) || (current_generation)) {
                // check all the parameters, not just modified, in case of a setattr(mtime)
                // also, allows a 0.1s difference
#ifdef EDFS_SKIP_GENERATION_CHECK
                if ((current_generation >= generation) && (current_timestamp > timestamp)) {
#else
                if ((current_generation > generation) || ((current_generation == generation) && (current_timestamp >= timestamp))) {
#endif
                    do_write = 0;
                    written = 0;
                    if (current_generation != generation)
                        log_warn("refused to update descriptor: received version is older (%" PRIu64 " > %" PRIu64 ")", current_generation, generation);
                    if ((edfs_context->shards) && ((inode % edfs_context->shards) == edfs_context->shard_id) && (current_generation == generation) && (!deleted)) {
                        uint64_t file_size = (uint64_t)json_object_get_number(root_object, "size");
                        if (file_size) {
                            edfs_queue_ensure_data(edfs_context, key, inode, file_size, 0, 0, generation + 1);
                        }
                    }
                } else
                if (current_type) {
                    if (current_parent != parent) {
                        do_write = 0;
                        written = 0;
                        log_warn("refused to update descriptor: current parrent inode is different");
                    } else
                    if (((current_type & S_IFDIR) && ((type & S_IFDIR) == 0)) || (((current_type & S_IFDIR) == 0) && (type & S_IFDIR))) {
                        do_write = 0;
                        written = -1;
                        log_warn("refused to update descriptor: inode type change is not supported");
                    }
                }
            } else
            if (deleted) {
                do_write = 0;
                written = 0;
            }
            if (do_write) {
                log_info("sync descriptor for inode %s", b64name);
                if (deleted) {
                    if (type & S_IFDIR)
                        remove_node(edfs_context, key, parent, inode, 0, generation, 1);
                    else
                        remove_node(edfs_context, key, parent, inode, 1, generation, 1);
                }
                if (edfs_write_file(edfs_context, key, key->working_directory, b64name, (const unsigned char *)payload, size , ".json", 0, NULL, NULL, NULL, NULL, 1, 0, 0) != size ) {
                    log_warn("error writing file %s", b64name);
                    written = -1;
                } else
                if ((!current_type) && (!deleted)) {
                    makesyncnode(edfs_context, key, parentb64name, b64name, name);
                }
                if ((edfs_context->shards) && ((inode % edfs_context->shards) == edfs_context->shard_id)) {
                    uint64_t file_size = (uint64_t)json_object_get_number(root_object, "size");
                    if (file_size)
                        edfs_queue_ensure_data(edfs_context, key, inode, file_size, 0, 0, generation + 1);
                }
#ifndef EDFS_NO_JS
                if (edfs_context->app_mode == 1) {
                    if ((name) && (written == 1) && (!strcmp(name, ".app.js")))
                        key->reload_js = 1;
                }
#endif
            } else
            if (!deleted) {
                char path[MAX_PATH_LEN];
                snprintf(path, sizeof(path), "%s/%s/%s", key->working_directory, parentb64name, b64name);
                if (!edfs_file_exists(path)) {
                    makesyncnode(edfs_context, key, parentb64name, b64name, name);
                }
            }
        } else {
            log_error("refused to update descriptor: received JSON is missing at least one required field");
            written = 0;
        }
    } else {
        log_error("received an invalid JSON buffer");
        written = 0;
    }
    json_value_free(root_value);
    return written;
}

int edwork_cache_addr(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, void *clientaddr, int clientaddrlen) {
    if ((!clientaddr) || (clientaddrlen <= 0) || (!key))
        return 0;
    if (edfs_context->mutex_initialized)
        thread_mutex_lock(&key->ino_cache_lock);
    // on 32bit, inode is truncated!
    struct edfs_ino_cache *avl_cache = (struct edfs_ino_cache *)avl_search(&key->ino_cache, (void *)(uintptr_t)inode);
    if (!avl_cache) {
        avl_cache = (struct edfs_ino_cache *)malloc(sizeof(struct edfs_ino_cache));
        if (!avl_cache) {
            if (edfs_context->mutex_initialized)
                thread_mutex_unlock(&key->ino_cache_lock);
            return 0;
        }
        memset(avl_cache, 0, sizeof(struct edfs_ino_cache));
        avl_cache->inode = inode;
        avl_cache->clientaddr_size = clientaddrlen;
        avl_insert(&key->ino_cache, (void *)(uintptr_t)inode, (void *)avl_cache);
    } else
    if (avl_cache->inode != inode) {
        avl_cache->inode = inode;
        memset(avl_cache, 0, sizeof(struct edfs_ino_cache));
    }
    int i;
    for (i = 0; i < avl_cache->len; i++) {
        if (!memcmp(clientaddr, &avl_cache->clientaddr[i], clientaddrlen)) {
            if (edfs_context->mutex_initialized)
                thread_mutex_unlock(&key->ino_cache_lock);
            return 1;
        }
    }
    if (avl_cache->len < EDFS_INO_CACHE_ADDR) {
        memcpy(&avl_cache->clientaddr[i], clientaddr, clientaddrlen);
        avl_cache->len++;
    } else {
        if (avl_cache->offset >= EDFS_INO_CACHE_ADDR)
            avl_cache->offset = 0;

        memcpy(&avl_cache->clientaddr[avl_cache->offset++], clientaddr, clientaddrlen);
    }

    if (edfs_context->mutex_initialized)
        thread_mutex_unlock(&key->ino_cache_lock);

    log_trace("caching node (%s)", edwork_addr_ipv4(clientaddr));
    return 1;
}

int edwork_process_data(struct edfs *edfs_context, struct edfs_key_data *key, const unsigned char *payload, int size, int do_verify, void *clientaddr, int clientaddrlen) {
    if (do_verify) {
        if (size <= 160) {
            log_warn("dropping DATA, packet too small");
            return -1;
        }
    } else {
        if (size <= 96) {
            log_warn("dropping DAT2, packet too small");
            return -1;
        }
    }

    int signature_size = 0;
    int delta_size = 32;
    if (do_verify) {
        unsigned char buffer[EDWORK_PACKET_SIZE];
        memcpy(buffer, payload + 64, size - 64);
        memcpy(buffer + size - 64, "data", 4);
        // 64 - 4
        int buffer_size = size - 60;
        if (!verify(edfs_context, key, (const char *)buffer, buffer_size, payload, 64)) {
            log_warn("data packet signature verification failed, dropping");
            return -1;
        }
        signature_size = 64;
        // 32 + 2 * 64
        delta_size = 160;
    }

    int written = 0;

    uint64_t inode = ntohll(*(uint64_t *)(payload + signature_size));
    uint64_t chunk = ntohll(*(uint64_t *)(payload + signature_size + 8));
    uint64_t timestamp = ntohll(*(uint64_t *)(payload + signature_size + 16));
    uint64_t datasize = ntohll(*(uint64_t *)(payload + signature_size + 24));

    if ((datasize > 0) && (datasize <= size - delta_size) && (datasize <= BLOCK_SIZE_MAX)) {
        if (!do_verify) {
#ifdef USE_COMPRESSION
            unsigned char compressed_buffer[BLOCK_SIZE_MAX];
            mz_ulong max_len = sizeof(compressed_buffer);
            if (uncompress(compressed_buffer, &max_len, payload + delta_size + signature_size + 64, datasize - 64) != Z_OK) {
                log_warn("error uncompressing data packet");
                return -1;
            }

            if (!verify(edfs_context, key, (const char *)compressed_buffer, max_len, payload + delta_size + signature_size, 64)) {
                log_warn("data packet content signature verification failed, dropping");
                return -1;
            }
#else
            if (!verify(edfs_context, key, (const char *)payload + delta_size + signature_size + 64, datasize - 64, payload + delta_size + signature_size, 64)) {
                log_warn("data packet content signature verification failed, dropping");
                return -1;
            }
#endif
        }

        // includes a signature
        if (signature_size)
            datasize += 64;
        int written_bytes = edfs_write_block(edfs_context, key, inode, chunk, payload + 32 + signature_size, datasize, timestamp / 1000000);
        edwork_cache_addr(edfs_context, key, inode, clientaddr, clientaddrlen);

        if ((edfs_context->shards) && ((inode % edfs_context->shards) == edfs_context->shard_id))
            edfs_queue_ensure_data(edfs_context, key, inode, (uint64_t)0, 1, 0, 0);

        if (written_bytes == datasize) {
            log_trace("written chunk %" PRIu64, chunk);
            written = 1;
        } else {
            if (written_bytes == -1)
                written = -1;
            log_warn("error in write: %i bytes written instead of %i", (int)written_bytes, datasize);
        }
    } else {
        log_warn("wrong data block size: should be %i, advertised %i", (int)size - delta_size, (int)datasize);
    }
    return written;
}

int edwork_process_hash(struct edfs *edfs_context, struct edfs_key_data *key, const unsigned char *payload, int size, void *clientaddr, int clientaddrlen) {
    if (size <= 96) {
        log_warn("dropping DATI, packet too small");
        return -1;
    }

    int signature_size = 0;
    int delta_size = 32;


    int written = 0;

    uint64_t inode = ntohll(*(uint64_t *)(payload + signature_size));
    uint64_t chunk = ntohll(*(uint64_t *)(payload + signature_size + 8));
    uint64_t timestamp = ntohll(*(uint64_t *)(payload + signature_size + 16));
    uint64_t datasize = ntohll(*(uint64_t *)(payload + signature_size + 24));

    if ((datasize > 0) && (datasize <= size - delta_size) && (datasize <= BLOCK_SIZE_MAX)) {
        if (!verify(edfs_context, key, (const char *)payload + delta_size + signature_size + 64, datasize - 64, payload + delta_size + signature_size, 64)) {
            log_warn("dati packet content signature verification failed, dropping");
            return -1;
        }

        // includes a signature
        if (signature_size)
            datasize += 64;

        int written_bytes = edfs_write_hash_block(edfs_context, key, inode, chunk, payload + 32 + signature_size, datasize, timestamp / 1000000);
        edwork_cache_addr(edfs_context, key, inode, clientaddr, clientaddrlen);
        if (written_bytes == datasize) {
            written = 1;
        } else {
            if (written_bytes == -1)
                written = -1;
            log_warn("error in write: %i bytes written instead of %i", (int)written_bytes, datasize);
        }
    } else {
        log_warn("wrong data block size: should be %i, advertised %i", (int)size - delta_size, (int)datasize);
    }
    return written;
}

int edwork_delete(struct edfs *edfs_context, struct edfs_key_data *key, const unsigned char *payload, int size, uint64_t *ino) {
    if (size > 0x100) {
        log_warn("dropping DELETE request, packet too big");
        return 0;
    }
    if (size < 84) {
        log_warn("dropping DELETE request, packet too small");
        return 0;
    }

    unsigned char buffer[0x200];

    memcpy(buffer, payload + 64, size - 64);
    memcpy(buffer + size - 64, "del\x00", 4);
    // 64 - 4

    int buffer_size = size - 60;
    if (!verify(edfs_context, key, (const char *)buffer, buffer_size, payload, 64)) {
        log_warn("DEL signature verification failed, dropping");
        return 0;
    }

    uint64_t inode = ntohll(*(uint64_t *)(payload + 64));
    uint64_t del_timestamp = ntohll(*(uint64_t *)(payload + 72));
    uint64_t del_generation = ntohll(*(uint64_t *)(payload + 80));

    if (ino)
        *ino = inode;

    uint64_t parent;
    uint64_t timestamp;
    uint64_t generation;

    int type = read_file_json(edfs_context, key, inode, &parent, NULL, &timestamp, NULL, NULL, NULL, 0, NULL, NULL, &generation, NULL, NULL);

    if (!type) {
        log_info("nothing to delete (file does not exists)");
        return 0;
    }

    if ((del_generation < generation) || ((del_generation == generation) && (del_timestamp < timestamp + 100000UL ))) {
        log_error("cannot delete inode because it was modified after delete broadcast(%" PRIu64 " > %" PRIu64 ")", generation, del_generation);
        return 0;
    }

#ifndef EDFS_NO_JS
    if (edfs_key_js_call_args(key, "edwork.events.ondelete", "__s", inode, parent, type & S_IFDIR ? "directory" : "file") == 1) {
        log_warn("access denied by JS function");
        return 0;
    }
#endif
    if (type & S_IFDIR)
        return remove_node(edfs_context, key, parent, inode, 0, generation, 0);

    return remove_node(edfs_context, key, parent, inode, 1, generation, 0);
}

int edwork_encrypt(struct edfs *edfs_context, struct edfs_key_data *key, const unsigned char *buffer, int size, unsigned char *out, const unsigned char *dest_i_am, const unsigned char *src_i_am, const unsigned char *shared_secret) {
    struct chacha_ctx ctx;
    unsigned char hash[32];

    if (!key->pub_loaded) {
        EDFS_THREAD_LOCK(edfs_context);
        key->pub_len = read_signature(edfs_context, key->signature, key->pubkey, 1, &key->key_type, NULL);
        if (key->pub_len > 0)
            key->pub_loaded = 1;
        EDFS_THREAD_UNLOCK(edfs_context);
    }

    SHA256_CTX hashctx;
    sha256_init(&hashctx);
    sha256_update(&hashctx, (const BYTE *)"EDFSKEY:", 8);
    if (key->pub_len > 0)
        sha256_update(&hashctx, (const BYTE *)key->pubkey, key->pub_len);
    if (dest_i_am)
        sha256_update(&hashctx, (const BYTE *)dest_i_am, 32);
    if (shared_secret)
        sha256_update(&hashctx, (const BYTE *)shared_secret, 32);
    sha256_final(&hashctx, hash);

    chacha_keysetup(&ctx, hash, 256);
    chacha_ivsetup(&ctx, src_i_am, NULL);

    chacha_encrypt_bytes(&ctx, buffer, out, size);
    return size;
}

int edwork_decrypt(struct edfs *edfs_context, struct edfs_key_data *key, const unsigned char *buffer, int size, unsigned char *out, const unsigned char *dest_i_am, const unsigned char *src_i_am, const unsigned char *shared_secret) {
    // dest and  src reversed
    return edwork_encrypt(edfs_context, key, buffer, size, out, src_i_am, dest_i_am, shared_secret);
}

int edwork_check_proof_of_work(struct edwork_data *edwork, const unsigned char *payload, unsigned int payload_size, int payload_offset, uint64_t timestamp, int work_level, const char *work_prefix, const unsigned char *who_am_i) {
    const unsigned char *proof_of_work = payload + payload_offset;
    int proof_of_work_size = payload_size - payload_offset;

    if (proof_of_work_size < 10) {
        log_error("proof of work stamp too small (%i)", proof_of_work_size);
        return 0;
    }

    sha3_context ctx;
    unsigned char want_hash[64];

    sha3_Init256(&ctx);
    sha3_Update(&ctx, payload, payload_offset);
    if (who_am_i)
        sha3_Update(&ctx, who_am_i, 32);

    int encode_len = base64_encode_no_padding((const unsigned char *)sha3_Finalize(&ctx), 32, want_hash, 64);
    int proof_timestamp = edfs_proof_of_work_verify(work_level, proof_of_work, proof_of_work_size, want_hash, encode_len, (const unsigned char *)work_prefix, strlen(work_prefix));
    if (!proof_timestamp) {
        log_warn("proof of work validation failed");
        return 0;
    }

    int timestamp_epoch = timestamp/1000000;
    if (abs(timestamp_epoch - proof_timestamp) > 60) {
        log_warn("proof of work validation failed: timestamp validation failed");
        return 0;
    }

    if (!edwork_try_spend(edwork, proof_of_work, proof_of_work_size)) {
        log_warn("token already spent");
        return 0;
    }

    return 1;
}

void edfs_try_reset_proof(struct edfs *edfs_context, struct edfs_key_data *key) {
    if ((key->chain) && (!key->read_only) && (!edfs_context->read_only_fs)) {
        key->proof_inodes_len = 0;
        memset(key->proof_of_time, 0, 40);
    }
}

void edfs_broadcast_top(struct edfs *edfs_context, struct edfs_key_data *key, void *use_clientaddr, int clientaddr_len) {
    if ((!edfs_context) || (!key->chain))
        return;

    if ((use_clientaddr) && (clientaddr_len)) {
        if (microseconds() - key->client_top_broadcast_timestamp < 1000000)
            return;
    }
    char b64name[MAX_B64_HASH_LEN];
    unsigned char buffer[EDWORK_PACKET_SIZE];
    int len = edfs_read_file(edfs_context, key, key->blockchain_directory, computeblockname(key->chain->index, b64name), buffer, EDWORK_PACKET_SIZE, NULL, 0, 0, 0, NULL, 0, 1, 0, 0);
    if (len > 0) {
        edfs_notify_io(edfs_context, key, "topb", (const unsigned char *)buffer, len, NULL, 0, 0, 0, 0, 0, 0, use_clientaddr, clientaddr_len, NULL, NULL);
        log_info("broadcasting chain block");
        if ((use_clientaddr) && (clientaddr_len))
            key->client_top_broadcast_timestamp = microseconds();
    }
}

int edfs_block_contains_descriptor(struct block *blockchain, uint64_t inode, uint64_t inode_generation) {
    if (!blockchain)
        return 0;

    int i;
    int record_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + 32;
    int len = blockchain->data_len - 72;
    uint64_t blockchain_generation = 0;
    if (len >= record_size) {
        unsigned char *ptr = blockchain->data;
        for (i = 0; i < len; i += record_size) {
            uint64_t blockchain_inode = ntohll(*(uint64_t *)ptr);
            memcpy(&blockchain_generation, ptr + sizeof(uint64_t), sizeof(uint64_t));
            blockchain_generation = ntohll(blockchain_generation);
            if ((inode == blockchain_inode) && (inode_generation == blockchain_generation))
                return 1;
        }
    }
    return 0;
}

void edfs_try_new_block(struct edfs *edfs_context, struct edfs_key_data *key) {
    if ((key->chain) && (!edfs_context->read_only_fs)  && (!key->read_only) && (key->proof_inodes_len)) {
        uint64_t chain_timestamp = key->chain->timestamp;

        if (edfs_context->start_timestamp > chain_timestamp)
            chain_timestamp = edfs_context->start_timestamp;

        int descriptors = 0;
        if (((microseconds() - chain_timestamp >= EDFS_BLOCKCHAIN_NEW_BLOCK_TIMEOUT) || (key->proof_inodes_len >= MAX_PROOF_INODES)) && (microseconds() - chain_timestamp >= EDFS_BLOCKCHAIN_NEW_BLOCK_TIMEOUT)) {
            log_info("mining new block");
            edwork_callback_lock(edfs_context->edwork, 1);
            edfs_sort(key->proof_inodes, key->proof_inodes_len);
            int block_data_size = key->proof_inodes_len * (sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + 32) + 72;
            unsigned char *block_data = (unsigned char *)malloc(block_data_size);
            unsigned char *ptr = block_data;
            int i;
            for (i = 0; i < key->proof_inodes_len; i++) {
                uint64_t inode = key->proof_inodes[i];
                uint64_t generation = 0;
                uint64_t timestamp = 0;
                // set hash to 0 for deleted file
                if (!read_file_json(edfs_context, key, inode, NULL, NULL, &timestamp, NULL, NULL, NULL, 0, NULL, NULL, &generation, ptr + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t), NULL))
                    memset(ptr + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t), 0, 32);

                if (edfs_block_contains_descriptor(key->chain, inode, generation)) {
                    log_debug("data already in blockchain");
                    continue;
                }

                descriptors ++;
                uint64_t inode_be = htonll(inode);
                memcpy(ptr, &inode_be, sizeof(uint64_t));

                ptr += sizeof(uint64_t);
                generation = htonll(generation);
                timestamp = htonll(timestamp);
                memcpy(ptr, &generation, sizeof(uint64_t));
                ptr += sizeof(uint64_t);
                memcpy(ptr, &timestamp, sizeof(uint64_t));
                ptr += sizeof(uint64_t) + 32;
            }
            if (!descriptors) {
                log_debug("no need for new block");
                memset(key->proof_of_time, 0, 40);
                key->proof_inodes_len = 0;
                edwork_callback_lock(edfs_context->edwork, 0);
                return;
            }
            memcpy(ptr, edwork_who_i_am(edfs_context->edwork), 32);
            ptr += 32;
            memcpy(ptr, key->proof_of_time, 40);
            ptr += 40;

            struct block *old_chain = key->chain;
            struct block *newblock = block_new(key->chain, block_data, block_data_size);
            if (newblock) {
                unsigned char previous_hash[32];
                unsigned char *previous_hash_ptr = previous_hash;
                if (key->chain)
                    memcpy(previous_hash, key->chain->hash, 32);
                else
                    previous_hash_ptr = NULL;
                memset(key->proof_of_time, 0, 40);
                key->proof_inodes_len = 0;
                edwork_callback_lock(edfs_context->edwork, 0);
                key->mining_flag = 1;
                int has_new_block = block_mine_with_copy(newblock, BLOCKCHAIN_COMPLEXITY, previous_hash_ptr, &key->mining_flag);
                key->mining_flag = 0;
                edwork_callback_lock(edfs_context->edwork, 1);
                // check if someone finished faster
                if ((has_new_block) && (key->chain->index == newblock->index - 1) && (key->chain == old_chain)) {
                    key->chain = newblock;
                    edfs_block_save(edfs_context, key, key->chain);
                    // TODO: update all directory hashes
                    edfs_broadcast_top(edfs_context, key, NULL, 0);
                } else
                    block_free(newblock);
                edwork_callback_lock(edfs_context->edwork, 0);
            } else
                edwork_callback_lock(edfs_context->edwork, 0);
        }
    }
}

void edfs_update_proof_inode(struct edfs_key_data *key, uint64_t ino) {
   if (ino) {
        int found = 0;
        int i;
        for (i = 0; i < key->proof_inodes_len; i++) {
            if (key->proof_inodes[i] == ino) {
                found = 1;
                break;
            }
        }
        if ((!found) && (key->proof_inodes_len < MAX_PROOF_INODES))
            key->proof_inodes[key->proof_inodes_len++] = ino;
    }
}

void edfs_update_proof_hash(struct edfs_key_data *key, uint64_t sequence, uint64_t timestamp, const char *type, const unsigned char *payload, unsigned int payload_size, const unsigned char *who_am_i, uint64_t ino) {
    sha3_context ctx;

    sequence = htonll(sequence);
    timestamp = htonll(timestamp);

    sha3_Init256(&ctx);
    sha3_Update(&ctx, (const unsigned char *)key->proof_of_time, 40);
    sha3_Update(&ctx, (const unsigned char *)&sequence, sizeof(uint64_t));
    sha3_Update(&ctx, (const unsigned char *)&timestamp, sizeof(uint64_t));
    sha3_Update(&ctx, (const unsigned char *)type, 4);
    sha3_Update(&ctx, who_am_i, 32);
    if (payload_size > 0)
        sha3_Update(&ctx, payload, payload_size);

    const unsigned char *hash = (const unsigned char *)sha3_Finalize(&ctx);
    memcpy(key->proof_of_time, hash + 8, 32);

    uint64_t messages;
    memcpy(&messages, key->proof_of_time, sizeof(uint64_t));
    messages = htonll(ntohll(messages) + 1);
    memcpy(key->proof_of_time, &messages, sizeof(uint64_t));
}

int edfs_check_blockhash(struct edfs *edfs_context, struct edfs_key_data *key, const unsigned char *blockhash, int maxlevel) {
    if (!blockhash)
        return 0;
    if (!key->chain)
        return 0;

    struct block *block2 = key->chain;
    do {
        if (!memcmp(block2->hash, blockhash, 32))
            return 1;

        block2 = (struct block *)block2->previous_block;
    } while ((block2) && (maxlevel-- > 0));
    if (!key->hblk_scheduled) {
        key->block_timestamp = time(NULL);
        key->hblk_scheduled = 1;
        edfs_schedule(edfs_context, edfs_blockchain_request, 500000, 0, 1, microseconds(), 0, 1, key);
    }

    return 0;
}

void edfs_new_chain_request_descriptors(struct edfs *edfs_context, struct edfs_key_data *key, int level) {
    struct block *blockchain = key->chain;
    unsigned char hash[32];

    if (!blockchain)
        return;

    uint64_t generation = 0;

    int i;
    int record_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + 32;
    do {
        int len = blockchain->data_len - 72;
        if (len >= record_size) {
            unsigned char *ptr = blockchain->data;
            for (i = 0; i < len; i += record_size) {
                uint64_t inode = ntohll(*(uint64_t *)ptr);
                uint64_t inode_version = 0;
                int64_t file_size = 0;
                int type = read_file_json(edfs_context, key, inode, NULL, &file_size, NULL, NULL, NULL, NULL, 0, NULL, NULL, &inode_version, hash, NULL);
                memcpy(&generation, ptr + sizeof(uint64_t), sizeof(uint64_t));
                generation = ntohll(generation);
                if ((generation > inode_version) || ((generation == inode_version) && (memcmp(hash, ptr + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t), 32))))
                    edfs_notify_io(edfs_context, key, "wand", ptr, 8, NULL, 0, 0, 0, inode, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);

                if ((edfs_context->shards) && ((inode % edfs_context->shards) == edfs_context->shard_id) && (type) && (file_size) && (blockchain->timestamp >= microseconds() - 7ULL * 24ULL * 3600000000ULL))
                    edfs_queue_ensure_data(edfs_context, key, inode, file_size, 1, 0, generation + 1);

                ptr += record_size;
            }
        }
        blockchain = (struct block *)blockchain->previous_block;
    } while ((blockchain) && (level-- > 0));
}

void edfs_chain_ensure_descriptors(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t min_timestamp) {
    struct block *blockchain = key->chain;
    unsigned char hash[32];
    if ((!blockchain) || (edfs_context->network_done))
        return;

    uint64_t generation = 0;
    int i;
    int record_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + 32;
    do {
        if (blockchain->timestamp < min_timestamp)
            break;
        int len = blockchain->data_len - 72;
        if (len >= record_size) {
            unsigned char *ptr = blockchain->data;
            for (i = 0; i < len; i += record_size) {
                uint64_t inode = ntohll(*(uint64_t *)ptr);
                uint64_t inode_version = 0;
                int64_t file_size = 0;

                read_file_json(edfs_context, key, inode, NULL, &file_size, NULL, NULL, NULL, NULL, 0, NULL, NULL, &inode_version, hash, NULL);
                memcpy(&generation, ptr + sizeof(uint64_t), sizeof(uint64_t));
                generation = ntohll(generation);
                if (generation > inode_version)
                    edfs_notify_io(edfs_context, key, "wand", ptr, 8, NULL, 0, 0, 0, inode, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);

#ifdef EDFS_RESTART_SHARD
                if ((edfs_context->shards) && ((inode % edfs_context->shards) == edfs_context->shard_id) && (type) && (file_size)) {
                    uint64_t last_file_chunk = file_size / BLOCK_SIZE;
                    if ((last_file_chunk % BLOCK_SIZE == 0) && (last_file_chunk))
                        last_file_chunk --;
                    if (!chunk_exists2(key, inode, last_file_chunk)) {
                        uint64_t chunk = 0;
                        for (chunk = 0; chunk <= last_file_chunk; chunk ++) {
                            if (!chunk_exists2(key, inode, chunk)) {
                                edfs_schedule(edfs_context, edfs_shard_data_request, 1000000, 7ULL * 24ULL * 3600000000ULL, inode, chunk, 1, 1, key);
                                break;
                            }
                        }
                    }
                }
#endif
                if (edfs_context->network_done)
                    return;
                ptr += record_size;
            }
        }
        if (edfs_context->network_done)
            break;
        blockchain = (struct block *)blockchain->previous_block;
    } while (blockchain);
}

static int edfs_schedule_vote(struct doops_loop *loop) {
    struct vote_container *vote = (struct vote_container *)loop_event_data(loop);
    if (vote) {
        unsigned char winner[0x100];
        if (edfs_key_data_vote_winner(vote->key_data, vote->subject, vote->subject_size, winner, sizeof(winner)) == 1) {
            log_trace("vote finalized");
        }
        free(vote);
    }
    return 1;
}

int edwork_vote_received(struct edfs *edfs_context, const unsigned char *payload, int size) {
    if (size < 96) {
        log_warn("invalid vote packet");
        return -1;
    }

    unsigned char key_hash[32];
    uint64_t key_checksum = XXH64(payload, 32, 0);
    struct edfs_key_data *key = edfs_context->key_data;
    struct edfs_key_data *packet_key = NULL;
    while (key) {
        sha256(key->pubkey, key->pub_len, key_hash);
        hmac_sha256((const BYTE *)"key id", 6, (const BYTE *)key_hash, 32, NULL, 0, (BYTE *)key_hash);
        if (XXH64(key_hash, 32, 0) == key_checksum) {
            packet_key = key;
            break;
        }
        key = (struct edfs_key_data *)key->next_key;
    }
    if (!packet_key) {
        log_warn("partition key not in store");
        return -1;
    }
    unsigned char buffer[EDWORK_PACKET_SIZE];
    memcpy(buffer, payload + 64, size - 64);
    memcpy(buffer + size - 64, "vote", 4);
    // 64 - 4
    int buffer_size = size - 60;
    if (!verify(edfs_context, packet_key, (const char *)buffer, buffer_size, payload, 64)) {
        log_warn("vote packet signature verification failed, dropping");
        return -1;
    }
    int subject_size = (int)payload[64];
    if (subject_size + 66 > size) {
        log_warn("invalid vote packet");
        return -1;
    }
    const unsigned char *subject = payload + 65;
    int timeout = (int)payload[65 + subject_size];
    const unsigned char *vote = payload + 66 + subject_size;
    int vote_size = size - 66 - subject_size;
    if (vote_size <= 0) {
        log_warn("invalid vote");
        return -1;
    }
    if (timeout != EDWORK_VOTE_TIMEOUT) {
        log_warn("vote timeout mismatch, ignoring vote");
        return -1;
    }
    int vote_err = edfs_key_data_vote(packet_key, subject, subject_size, vote, vote_size, timeout);
    // schedule new vote
    if (vote_err == 1) {
        struct vote_container *vote = malloc(sizeof(struct vote_container));
        if (vote) {
            vote->key_data = packet_key;
            memcpy(vote->subject, subject, subject_size);
            vote->subject_size = subject_size;
            loop_add(&edfs_context->loop, edfs_schedule_vote, EDWORK_VOTE_TIMEOUT * 1000, vote);
        }
    }
    return vote_err;
}

void edwork_callback(struct edwork_data *edwork, uint64_t sequence, uint64_t timestamp, const char *type, const unsigned char *payload, unsigned int payload_size, struct edfs_key_data *key, void *clientaddr, int clientaddrlen, const unsigned char *who_am_i, const unsigned char *blockhash, void *userdata, int is_sctp, int is_listen_socket) {
    unsigned char buffer[BLOCK_SIZE_MAX];
    struct edfs *edfs_context = (struct edfs *)userdata;

    if ((!edwork) || (!type) || (!edfs_context))
        return;
    uint64_t now = microseconds();
    // 30 seconds before
    if (timestamp > microseconds() + 30000000) {
        log_warn("ignoring message with timestamp in the future received (%s)", edwork_addr_ipv4(clientaddr));
        return;
    }
    // 5 minutes back
    if (timestamp < microseconds() - 300000000) {
        log_warn("ignoring too old message (%s)", edwork_addr_ipv4(clientaddr));
        return;
    }
    if (!memcmp(type, "ping", 4)) {
        log_info("PING received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        edfs_context->ping_received = time(NULL);
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        return;
    }
    if (!memcmp(type, "helo", 4)) {
        log_info("HELO received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        if (is_sctp) {
            edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
            if (edwork_send_to_peer(edwork, key, "ping", NULL, 0, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) > 0)
                log_info("PING sent");
        } else {
            log_warn("HELO received on non-SCTP socket");
        }
        return;
    }
    if (!memcmp(type, "addr", 4)) {
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        log_info("ADDR list received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        if (time(NULL) - edfs_context->list_timestamp > 10) {
            log_warn("dropping non-requested ADDR");
            return;
        }
        if (payload_size < 4) {
            log_warn("ADDR packet too small");
            return;
        }
        int records = edwork_add_node_list(edwork, payload + 4, payload_size - 4);
        if (records > 0) {
            uint32_t offset = htonl(ntohl(*(uint32_t *)payload) + records);
            edfs_notify_io(edfs_context, key, "list", (const unsigned char *)&offset, sizeof(uint32_t), NULL, 0, 0, 0, 0, EDWORK_LIST_WORK_LEVEL, 0, clientaddr, clientaddrlen, NULL, NULL);
            edfs_context->list_timestamp = time(NULL);
        }
        return;
    }
    if (!memcmp(type, "ack\x00", 4)) {
        log_info("ACK received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        if ((!payload) || (payload_size != 8)) {
            log_error("invalid payload");
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        edwork_confirm_seq(edwork, key, ntohll(*(uint64_t *)payload), 1);
        return;
    }
    if (!memcmp(type, "nack", 4)) {
        log_info("NACK received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        if ((!payload) || (payload_size != 8)) {
            log_error("invalid payload");
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        edwork_confirm_seq(edwork, key, ntohll(*(uint64_t *)payload), 1);
        return;
    }
    if ((!memcmp(type, "want", 4)) || (!memcmp(type, "wan3", 4)) || (!memcmp(type, "wan4", 4)) || (!memcmp(type, "wan5", 4))) {
        log_info("WANT received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
#ifdef EDFS_RANDOMLY_IGNORE_REQUESTS
        int magnitude = edwork_magnitude(edwork);
        int randomly_ignore = 0;
        if (magnitude >= 1000)
            randomly_ignore = ((edwork_random() % 2) == 1);
        else
        if (magnitude >= 500)
            randomly_ignore = ((edwork_random() % 4) == 1);
        else
        if (magnitude >= 100)
            randomly_ignore = ((edwork_random() % 6) == 1);
        else
        if (magnitude >= 50)
            randomly_ignore = ((edwork_random() % 10) == 1);
        else
        if (magnitude >= 20)
            randomly_ignore = ((edwork_random() % 20) == 1);

        if (randomly_ignore) {
            log_info("randomly ignoring request");
            return;
        }
#endif

        int is_bigchunk = !memcmp(type, "wan5", 4);
        int is_encrypted = (is_bigchunk) || (!memcmp(type, "wan4", 4));

        if ((!payload) || (payload_size < 68)) {
            log_warn("WANT packet too small");
            return;
        }

        if (!edfs_check_blockhash(edfs_context, key, blockhash, 1)) {
            log_warn("blockchain has different hash or length for %s", edwork_addr_ipv4(clientaddr));
            edfs_broadcast_top(edfs_context, key, clientaddr, clientaddrlen);
            return;
        }

        uint64_t ino = ntohll(*(uint64_t *)payload);
        uint64_t chunk = ntohll(*(uint64_t *)(payload + 8));
        unsigned short other_chunks = 0;
        int other_chunk_index = 0;
        int payload_offset;
        if (is_bigchunk) {
            other_chunks = ntohs(*(uint16_t *)(payload + 20));
            payload_offset = 54 + other_chunks * sizeof(uint64_t);

            log_debug("big chunk requested (%i chunks)", (int)other_chunks);

            if (other_chunks > 10) {
                log_warn("too many forward chunks requested");
                return;
            }

            if (payload_size < 70 + other_chunks * sizeof(uint64_t)) {
                log_warn("WANT packet too small");
                return;
            }
        } else
            payload_offset = is_encrypted ? 52 : 20;
        if (!edwork_check_proof_of_work(edwork, payload, payload_size, payload_offset, timestamp, EDWORK_WANT_WORK_LEVEL, EDWORK_WANT_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }

        void *clientinfo = edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        if (clientinfo) {
            uint64_t last_ino;
            uint64_t last_chunk;
            uint64_t last_msg_timestamp;
            if (edwork_get_info(clientinfo, &last_ino, &last_chunk, &last_msg_timestamp)) {
                if ((ino == last_ino) && (chunk == last_chunk) && ((microseconds() - last_msg_timestamp) <= 50000)) {
                    log_info("ignoring same request from same client");
                    return;
                }
            }
            edwork_set_info(clientinfo, ino, chunk, microseconds());
        }

        if (ino > 0) {
            int loop_count = 0;
            int size;
            uint32_t chunk_hash = ntohll(*(uint32_t *)(payload + 16));
one_loop:
            size = edfs_reply_chunk(edfs_context, key, ino, chunk, buffer + 32, sizeof(buffer), chunk_hash);
            if (size > 0) {
                unsigned char *additional_data = buffer;
                *(uint64_t *)additional_data = htonll(ino);
                *(uint64_t *)(additional_data + 8) = htonll(chunk);
                *(uint64_t *)(additional_data + 16) = htonll(microseconds());
                *(uint64_t *)(additional_data + 24) = htonll(size);

                if (is_encrypted) {
                    if (payload_size < 100) {
                        log_warn("WAN4 packet too small");
                        return;
                    }
                    unsigned char shared_secret[32];

                    if (is_bigchunk)
                        curve25519(shared_secret, edfs_context->key.secret, payload + 22 + other_chunks * sizeof(uint64_t));
                    else
                        curve25519(shared_secret, edfs_context->key.secret, payload + 20);

                    unsigned char buf2[BLOCK_SIZE_MAX];
                    memcpy(buf2, edfs_context->key.pk, 32);

                    int size2 = edwork_encrypt(edfs_context, key, buffer, size + 32, buf2 + 32, who_am_i, edwork_who_i_am(edwork), shared_secret);
                    if (edwork_send_to_peer(edwork, key, "dat4", buf2, size2 + 32, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0) {
                        log_error("error sending DAT4");
                        if ((!loop_count) && (edwork_unspend(edwork, payload + payload_offset, payload_size - payload_offset)))
                            log_trace("token unspent");
                    } else {
                        log_info("DAT4 sent");
                        if (other_chunks > 0) {
                            if (other_chunk_index < other_chunks) {
                                chunk_hash = 0;
                                uint64_t other_chunk = ntohll(*(uint64_t *)(payload + 22 + other_chunk_index * sizeof(uint64_t)));
                                if (other_chunk != chunk) {
                                    other_chunk_index ++;
                                    chunk = other_chunk;
                                    goto one_loop;
                                }
                            }
                        }
#ifndef EDFS_DISABLE_FORWARD_BLOCK_SEND
                        else
                        if ((is_sctp) && (loop_count < 2)) {
                            chunk_hash = 0;
                            chunk += 10;
                            loop_count ++;
                            goto one_loop;
                        }
#endif
                    }
                } else
                if (!memcmp(type, "wan3", 4)) {
                    unsigned char buf2[BLOCK_SIZE_MAX];
                    int size2 = edwork_encrypt(edfs_context, key, buffer, size + 32, buf2, who_am_i, edwork_who_i_am(edwork), NULL);
                    if (edwork_send_to_peer(edwork, key, "dat3", buf2, size2, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0)
                        log_error("error sending DAT3");
                    else
                        log_info("DAT3 sent");
                } else {
                    if (edwork_send_to_peer(edwork, key, "dat2", buffer, size + 32, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0)
                        log_error("error sending DAT2");
                    else
                        log_info("DAT2 sent");
                }
            } else
            if ((edfs_context->proxy) && (microseconds() - edfs_context->proxy_timestamp > 500000)) {
                log_trace("forwarding chunk request");
                request_data(edfs_context, key, ino, chunk, 1, 0, NULL, NULL, chunk_hash);
                edfs_context->proxy_timestamp = microseconds();
            }
        }
        return;
    }
    if (!memcmp(type, "list", 4)) {
        log_info("LIST request received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        uint32_t offset = 0;
        if ((payload) && (payload_size >= sizeof(uint32_t))) {
            offset = ntohl(*(uint32_t *)payload);
        } else {
            log_warn("invalid ADDR package");
            return;
        }

        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 4, timestamp, EDWORK_LIST_WORK_LEVEL, EDWORK_LIST_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }

        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);

        // add offset
        int size = BLOCK_SIZE - 4;
        memcpy(buffer, payload, 4);
        int records = edwork_get_node_list(edwork, buffer + 4, &size, (unsigned int)offset, time(NULL) - EDWORK_LAST_SEEN_TIMEOUT, 0);
        log_info("%i records found (offset: %i)", records, offset);
        if (records > 0) {
            size += 4;
            if (edwork_send_to_peer(edwork, key, "addr", buffer, size, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL * 10) <= 0) {
                log_warn("error sending address list");
            }
        }
        return;
    }
    if (!memcmp(type, "desc", 4)) {
        log_info("DESC received (%s)", edwork_addr_ipv4(clientaddr));
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        // json payload
        uint64_t ino;
        int err = edwork_process_json(edfs_context, key, payload, payload_size, &ino);
        *(uint64_t *)buffer = htonll(ino);
        if (err > 0) {
            edfs_update_proof_hash(key, sequence, timestamp, type, payload, payload_size, who_am_i, ino);
            edfs_update_proof_inode(key, ino);
            if (edwork_send_to_peer(edwork, key, "ack\x00", buffer, sizeof(uint64_t), clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0) {
                log_error("error sending ACK");
                return;
            }
            log_info("DESC acknoledged");
            // rebroadcast without ack 3 seconds
            if (timestamp > now - 3000000UL)
                edwork_broadcast_except(edwork, key, "desc", payload, payload_size, 0, EDWORK_NODES, clientaddr, clientaddrlen, timestamp, ino);
        } else {
            if (!err) {
                if (edwork_send_to_peer(edwork, key, "nack", buffer, sizeof(uint64_t), clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0) {
                    log_error("error sending NACK");
                    return;
                }
            } else
                log_warn("invalid data received");
        }
        return;
    }
    if (!memcmp(type, "data", 4)) {
        log_info("DATA received (%s)", edwork_addr_ipv4(clientaddr));
        if (!edfs_check_blockhash(edfs_context, key, blockhash, 1)) {
            log_warn("blockchain has different hash or length for %s", edwork_addr_ipv4(clientaddr));
            edfs_broadcast_top(edfs_context, key, clientaddr, clientaddrlen);
            return;
        }
        int err;
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        if (EDFS_DATA_BROADCAST_ENCRYPTED) {
            int size = edwork_decrypt(edfs_context, key, payload, payload_size, buffer, who_am_i, NULL, NULL);
            if (size <= 0) {
                log_warn("error decrypting DATA packet");
                return;
            }
            err = edwork_process_data(edfs_context, key, buffer, size, 1, NULL, 0);
        }  else
            err = edwork_process_data(edfs_context, key, payload, payload_size, 1, NULL, 0);
        if (err > 0) {
#ifndef EDWORK_NO_ACK_DATA
            *(uint64_t *)buffer = htonll(sequence);
            if (edwork_send_to_peer(edwork, key, "ack\x00", buffer, sizeof(uint64_t), clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0) {
                log_error("error sending ACK");
                return;
            }
            log_info("DATA acknoledged");
#endif
        } else {
            if (!err) {
                // refused to write
                if (edwork_send_to_peer(edwork, key, "nack", buffer, sizeof(uint64_t), clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0) {
                    log_error("error sending NACK");
                    return;
                }
            }
            log_warn("will not write data block");
        }
        return;
    }
    if (!memcmp(type, "dat2", 4)) {
        log_info("DAT2 received (%s)", edwork_addr_ipv4(clientaddr));
        if (!edfs_check_blockhash(edfs_context, key, blockhash, 0)) {
            log_warn("blockchain has different hash or length for %s", edwork_addr_ipv4(clientaddr));
            edfs_broadcast_top(edfs_context, key, clientaddr, clientaddrlen);
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        int err = edwork_process_data(edfs_context, key, payload, payload_size, 0, clientaddr, clientaddrlen);
        if (err <= 0)
            log_warn("DAT2: will not write data block");
        return;
    }
    if (!memcmp(type, "dat3", 4)) {
        log_info("DAT3 received (%s)", edwork_addr_ipv4(clientaddr));
        if (!edfs_check_blockhash(edfs_context, key, blockhash, 0)) {
            log_warn("blockchain has different hash or length for %s", edwork_addr_ipv4(clientaddr));
            edfs_broadcast_top(edfs_context, key, clientaddr, clientaddrlen);
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        int size = edwork_decrypt(edfs_context, key, payload, payload_size, buffer, who_am_i, edwork_who_i_am(edwork), NULL);
        int err = edwork_process_data(edfs_context, key, buffer, size, 0, clientaddr, clientaddrlen);
        if (err <= 0)
            log_warn("DAT3: will not write data block");
        return;
    }
    if (!memcmp(type, "dat4", 4)) {
        log_info("DAT4 received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 32) {
            log_error("DAT4 packet too small");
            return;
        }
        if (!edfs_check_blockhash(edfs_context, key, blockhash, 0)) {
            log_warn("blockchain has different hash or length for %s", edwork_addr_ipv4(clientaddr));
            edfs_broadcast_top(edfs_context, key, clientaddr, clientaddrlen);
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);

        unsigned char shared_secret[32];
        curve25519(shared_secret, edfs_context->key.secret, payload);

        int size = edwork_decrypt(edfs_context, key, payload + 32, payload_size - 32, buffer, who_am_i, edwork_who_i_am(edwork), shared_secret);
        int err = edwork_process_data(edfs_context, key, buffer, size, 0, clientaddr, clientaddrlen);
        if (err == 0) {
            curve25519(shared_secret, edfs_context->previous_key.secret, payload);
            size = edwork_decrypt(edfs_context, key, payload + 32, payload_size - 32, buffer, who_am_i, edwork_who_i_am(edwork), shared_secret);
            err = edwork_process_data(edfs_context, key, buffer, size, 0, clientaddr, clientaddrlen);
        }
        if (err <= 0)
            log_warn("DAT4: will not write data block");
        return;
    }
    if (!memcmp(type, "del\x00", 4)) {
        log_info("DEL received (%s)", edwork_addr_ipv4(clientaddr));
        uint64_t ino;
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        if (edwork_delete(edfs_context, key, payload, payload_size, &ino)) {
            *(uint64_t *)buffer = htonll(sequence);
            if (edwork_send_to_peer(edwork, key, "ack\x00", buffer, sizeof(uint64_t), clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0) {
                log_error("error sending ACK");
                return;
            }
            log_info("DEL acknoledged");
            // rebroadcast without acks 3 seconds
            if (timestamp > now - 3000000UL)
                edwork_broadcast_except(edwork, key, "del\x00", payload, payload_size, 0, EDWORK_NODES, clientaddr, clientaddrlen, timestamp, ino);
        } else {
            log_warn("will not delete data");
        }
        return;
    }
    if (!memcmp(type, "root", 4)) {
        log_info("ROOT request received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 8) {
            log_warn("invalid ROOT request");
            return;
        }
        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 8, timestamp, EDWORK_ROOT_WORK_LEVEL, EDWORK_ROOT_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }

        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        edwork_resync(edfs_context, key, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        *(uint64_t *)buffer = htonll(1);
        edwork_send_to_peer(edwork, key, "ack\x00", buffer, sizeof(uint64_t), clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL);
        log_info("ROOT acknoledged");
        return;
    }
    if (!memcmp(type, "roo2", 4)) {
        log_info("ROO2 request received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 8) {
            log_warn("invalid ROO2 request");
            return;
        }
        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 8, timestamp, EDWORK_ROOT_WORK_LEVEL, EDWORK_ROOT_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        edwork_resync_desc(edfs_context, key, ntohll(*(uint64_t *)payload), clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        usleep(500);
        edwork_resync_dir_desc(edfs_context, key, ntohll(*(uint64_t *)payload), clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        return;
    }
    if (!memcmp(type, "roo3", 4)) {
        log_info("ROO3 request received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 8) {
            log_warn("invalid ROO3 request");
            return;
        }
        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 8, timestamp, EDWORK_ROOT_WORK_LEVEL, EDWORK_ROOT_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        edwork_resync_desc(edfs_context, key, ntohll(*(uint64_t *)payload), clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        return;
    }
    if (!memcmp(type, "hash", 4)) {
        log_info("HASH request received (%s)", edwork_addr_ipv4(clientaddr));
        void *clientinfo = edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
#ifdef EDFS_RANDOMLY_IGNORE_REQUESTS
        int magnitude = edwork_magnitude(edwork);
        int randomly_ignore = 0;
        if (magnitude >= 1000)
            randomly_ignore = ((edwork_random() % 2) == 1);
        else
        if (magnitude >= 500)
            randomly_ignore = ((edwork_random() % 4) == 1);
        else
        if (magnitude >= 100)
            randomly_ignore = ((edwork_random() % 6) == 1);
        else
        if (magnitude >= 50)
            randomly_ignore = ((edwork_random() % 10) == 1);
        else
        if (magnitude >= 20)
            randomly_ignore = ((edwork_random() % 20) == 1);

        if (randomly_ignore) {
            log_info("randomly ignoring request");
            return;
        }
#endif

        if ((!payload) || (payload_size < 100)) {
            log_warn("HASH packet too small");
            return;
        }

        uint64_t ino = ntohll(*(uint64_t *)payload);
        uint64_t chunk = ntohll(*(uint64_t *)(payload + 8));

        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 52, timestamp, EDWORK_WANT_WORK_LEVEL, EDWORK_WANT_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }

        if (clientinfo) {
            uint64_t last_ino;
            uint64_t last_chunk;
            uint64_t last_msg_timestamp;
            if (edwork_get_info(clientinfo, &last_ino, &last_chunk, &last_msg_timestamp)) {
                if ((ino == last_ino) && (chunk == last_chunk) && ((microseconds() - last_msg_timestamp) <= 50000)) {
                    log_info("ignoring same request from same client");
                    return;
                }
            }
            edwork_set_info(clientinfo, ino, chunk, microseconds());
        }

        if (ino > 0) {
            int size = edfs_reply_hash(edfs_context, key, ino, chunk, buffer + 32, sizeof(buffer), ntohl(*(uint64_t *)(payload + 16)));
            if (size > 0) {
                if (!edfs_check_blockhash(edfs_context, key, blockhash, 0)) {
                    log_warn("blockchain has different hash or length for %s", edwork_addr_ipv4(clientaddr));
                    edfs_broadcast_top(edfs_context, key, clientaddr, clientaddrlen);
                    return;
                }

                // unsigned char additional_data[32];
                unsigned char *additional_data = buffer;
                *(uint64_t *)additional_data = htonll(ino);
                *(uint64_t *)(additional_data + 8) = htonll(chunk);
                *(uint64_t *)(additional_data + 16) = htonll(microseconds());
                *(uint64_t *)(additional_data + 24) = htonll(size);


                unsigned char shared_secret[32];
                curve25519(shared_secret, edfs_context->key.secret, payload + 20);

                unsigned char buf2[BLOCK_SIZE_MAX];
                memcpy(buf2, edfs_context->key.pk, 32);

                int size2 = edwork_encrypt(edfs_context, key, buffer, size + 32, buf2 + 32, who_am_i, edwork_who_i_am(edwork), shared_secret);
                if (edwork_send_to_peer(edwork, key, "dati", buf2, size2 + 32, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0)
                    log_error("error sending DATI");
                else
                    log_info("DATI sent");
            } else
            if ((edfs_context->proxy) && (microseconds() - edfs_context->proxy_timestamp > 500000)) {
                edfs_notify_io(edfs_context, key, "hash", payload, 20, edfs_context->key.pk, 32, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
                edfs_context->proxy_timestamp = microseconds();
            }
        }
        return;
    }
    if (!memcmp(type, "wand", 4)) {
        if (payload_size < 8) {
            log_warn("WAND packet too small");
            return;
        }

       if (!edwork_check_proof_of_work(edwork, payload, payload_size, 8, timestamp, EDWORK_WANT_WORK_LEVEL, EDWORK_WANT_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }

        uint64_t ino = ntohll(*(uint64_t *)payload);
        if (!ino) {
            log_warn("invalid WAND request");
            return;
        }
        // if (!edfs_check_blockhash(edfs_context, key, blockhash, 1)) {
        //     log_warn("blockchain has different hash or length for %s", edwork_addr_ipv4(clientaddr));
        //     return;
        // }
        char b64name[MAX_B64_HASH_LEN];
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);
        int len = edfs_read_file(edfs_context, key, key->working_directory, computename(ino, b64name), buffer, EDWORK_PACKET_SIZE, ".json", 0, 0, 0, NULL, 0, 1, 0, 0);
        if (len > 0) {
            if (edwork_send_to_peer(edfs_context->edwork, key, "desc", buffer, len, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0)
                log_error("error sending DESC");
            else
                log_info("DESC sent");
        } else
        if ((edfs_context->proxy) && (microseconds() - edfs_context->proxy_timestamp > 500000)) {
            // EDFS_THREAD_LOCK(edfs_context);
            edfs_notify_io(edfs_context, key, "wand", payload, 8, NULL, 0, 0, 0, ino, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
            // EDFS_THREAD_UNLOCK(edfs_context);
            edfs_context->proxy_timestamp = microseconds();
        }
        return;
    }
    if (!memcmp(type, "dati", 4)) {
        log_info("DATI received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 32) {
            log_error("DATI packet too small");
            return;
        }
        if (!edfs_check_blockhash(edfs_context, key, blockhash, 1)) {
            log_warn("blockchain has different hash or length for %s", edwork_addr_ipv4(clientaddr));
            edfs_broadcast_top(edfs_context, key, clientaddr, clientaddrlen);
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);

        unsigned char shared_secret[32];
        curve25519(shared_secret, edfs_context->key.secret, payload);

        int size = edwork_decrypt(edfs_context, key, payload + 32, payload_size - 32, buffer, who_am_i, edwork_who_i_am(edwork), shared_secret);
        int err = edwork_process_hash(edfs_context, key, buffer, size, clientaddr, clientaddrlen);
        if (err <= 0)
            log_warn("DATI: will not write data block");
        return;
    }
    if (!memcmp(type, "hblk", 4)) {
        log_info("HBLK request received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        int is_top = 0;
        if (payload_size < 48) {
            log_error("HBLK packet too small");
            return;
        }
        // index is 0 for last block, or 1 for genesis block, 2 for second block and so on
        uint64_t index = ntohll(*(uint64_t *)payload);
        if (!index) {
            // is top
            is_top = 1;
            if (key->chain) {
                index = key->chain->index;
            } else {
                log_warn("HBLK request cannot be fulfilled");
                return;
            }
        } else
            index --;
        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 8, timestamp, EDWORK_WANT_WORK_LEVEL, EDWORK_WANT_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work", payload_size);
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen, is_sctp, is_listen_socket);

        char b64name[MAX_B64_HASH_LEN];
        computeblockname(index, b64name);
        int len = edfs_read_file(edfs_context, key, key->blockchain_directory, b64name, buffer, EDWORK_PACKET_SIZE, NULL, 0, 0, 0, NULL, 0, 1, 0, 0);
        if (len > 0) {
            if (edwork_send_to_peer(edfs_context->edwork, key, is_top ? "topb" : "blkd", buffer, len, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0)
                log_error("error sending chain block");
            else
                log_info("chain block sent");
        }
        return;
    }
    if (!memcmp(type, "blkd", 4)) {
        log_info("BLKD received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 120) {
            log_warn("invalid BLKD packet");
            return;
        }
        if (!verify(edfs_context, key, (const char *)payload + 64, payload_size - 64, payload, 64)) {
            log_warn("blockchain packet signature verification failed, dropping");
            return;
        }
        struct block *newblock = block_load_buffer(payload + 64, payload_size - 64);
        if (!newblock) {
            log_error("invalid chain block received");
            return;
        }
        // hblk is index 1-based, blocks are 0-based
        uint64_t requested_block = htonll(newblock->index + 2);
        char b64name[MAX_B64_HASH_LEN];
        if ((!key->chain) && (!newblock->index)) {
            edfs_write_file(edfs_context, key, key->blockchain_directory, computeblockname(newblock->index, b64name), payload, payload_size, NULL, 0, NULL, NULL, NULL, NULL, 1, 0, 0);
            key->chain = newblock;
            key->mining_flag = 0;
            edfs_new_chain_request_descriptors(edfs_context, key, 0);
            key->top_broadcast_timestamp = 0;
            edfs_try_reset_proof(edfs_context, key);
            key->block_timestamp = time(NULL);
            edfs_notify_io(edfs_context, key, "hblk", (const unsigned char *)&requested_block, sizeof(uint64_t), NULL, 0, 0, 0, 0, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
        } else
        if ((key->chain) && (newblock->index == key->chain->index + 1)) {
            newblock->previous_block = key->chain;
            if (block_verify(newblock, BLOCKCHAIN_COMPLEXITY)) {
                edfs_notify_io(edfs_context, key, "hblk", (const unsigned char *)&requested_block, sizeof(uint64_t), NULL, 0, 0, 0, 0, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
                edfs_write_file(edfs_context, key, key->blockchain_directory, computeblockname(newblock->index, b64name), payload, payload_size, NULL, 0, NULL, NULL, NULL, NULL, 1, 0, 0);
                key->chain = newblock;
                key->mining_flag = 0;
                edfs_new_chain_request_descriptors(edfs_context, key, 0);
                key->top_broadcast_timestamp = 0;
                edfs_try_reset_proof(edfs_context, key);
                key->block_timestamp = time(NULL);
                key->chain_errors = 0;
            } else {
                log_error("block verify error");
                // fork? resync chain
                if (key->chain) {
                    struct block *previous_block = (struct block *)key->chain->previous_block;
                    block_free(key->chain);
                    key->chain = previous_block;
                    key->mining_flag = 0;
                    edfs_schedule(edfs_context, edfs_blockchain_request, 50000, 0, 0, 0, 0, 1, key);
                    key->block_timestamp = time(NULL);
                }
                block_free(newblock);
            }
        } else {
            char b64name[MAX_B64_HASH_LEN];
            computeblockname(newblock->index, b64name);
            int len = edfs_read_file(edfs_context, key, key->blockchain_directory, b64name, buffer, EDWORK_PACKET_SIZE, NULL, 0, 0, 0, NULL, 0, 1, 0, 0);
            if (len > 64) {
                struct block *temp_block = block_load_buffer(buffer + 64, len - 64);
                if ((temp_block) && (memcmp(temp_block->hash, newblock->hash, 32))) {
                    if (edwork_send_to_peer(edfs_context->edwork, key, "blkd", buffer, len, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0)
                        log_error("error sending chain block");
                    log_warn("invalid block received (%i)", (int)newblock->index);
                    key->chain_errors ++;
                } else {
                    log_trace("already owned received block (%i)", (int)newblock->index);
                    key->chain_errors = 0;
                }

                block_free(temp_block);
                block_free(newblock);
                newblock = NULL;
            } else {
                key->chain_errors ++;
                log_warn("invalid block received (%i)", (int)newblock->index);
            }

            if (newblock) {
                computeblockname(newblock->index  + 1, b64name);
                len = edfs_read_file(edfs_context, key, key->blockchain_directory, b64name, buffer, EDWORK_PACKET_SIZE, NULL, 0, 0, 0, NULL, 0, 1, 0, 0);
                if (len > 64) {
                    if (edwork_send_to_peer(edfs_context->edwork, key, "blkd", buffer, len, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL) <= 0)
                        log_error("error sending chain block");
                }
                block_free(newblock);
            }

            if (key->chain_errors >= 10000) {
                EDFS_THREAD_LOCK(edfs_context);
                blockchain_free(key->chain);
                key->chain = NULL;
                key->mining_flag = 0;
                EDFS_THREAD_UNLOCK(edfs_context);
                key->chain_errors = 0;
                key->block_timestamp = time(NULL);
                edfs_schedule(edfs_context, edfs_blockchain_request, 100000, 0, 0, 0, 0, 1, key);
            }
        }
        return;
    }
    if (!memcmp(type, "topb", 4)) {
        log_info("TOPB received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 120) {
            log_warn("invalid TOPB packet");
            return;
        }
        if (!verify(edfs_context, key, (const char *)payload + 64, payload_size - 64, payload, 64)) {
            log_warn("blockchain packet signature verification failed, dropping");
            return;
        }
        struct block *topblock = block_load_buffer(payload + 64, payload_size - 64);
        if (!topblock) {
            log_error("invalid top block received");
            return;
        }
        char b64name[MAX_B64_HASH_LEN];
        if ((key->chain) && (key->chain->index >= topblock->index)) {
            int update_current_chain = 0;
            if (key->chain->index == topblock->index) {
                int hash_compare = memcmp(topblock->hash, key->chain->hash, 32);
                if (!hash_compare) {
                    log_info("same block, chain is valid");
                    key->block_timestamp = time(NULL);
                    block_free(topblock);
                    return;
                }
                // conflict, mediate
                if (topblock->data_len > key->chain->data_len) {
                    log_trace("block is larger");
                    update_current_chain = 1;
                } else
                if (topblock->data_len == key->chain->data_len) {
                    if (hash_compare > 0) {
                        update_current_chain = 1;
                        log_trace("block hash is larger");
                    } else {
                        log_trace("block hash is smaller");
                    }
                }
            }
            if (update_current_chain) {
                struct block *previous_block = (struct block *)key->chain->previous_block;
                if ((previous_block) && (previous_block->timestamp + EDFS_BLOCKCHAIN_MIN_TIMEOUT > topblock->timestamp)) {
                    log_warn("updated top block is too early");
                    block_free(topblock);
                    return;
                }
                topblock->previous_block = previous_block;
                if (block_verify(topblock, BLOCKCHAIN_COMPLEXITY)) {
                    block_free(key->chain);
                    key->chain = topblock;
                    key->mining_flag = 0;
                    edfs_write_file(edfs_context, key, key->blockchain_directory, computeblockname(topblock->index, b64name), payload, payload_size, NULL, 0, NULL, NULL, NULL, NULL, 1, 0, 0);
                    edfs_new_chain_request_descriptors(edfs_context, key, 0);
                    key->top_broadcast_timestamp = 0;
                    edfs_try_reset_proof(edfs_context, key);
                    edfs_broadcast_top(edfs_context, key, NULL, 0);
                    log_warn("mediated current block");
                    key->chain_errors = 0;
                    key->block_timestamp = time(NULL);
                } else {
                    log_warn("cannot mediate received block (block verify failed)");
                    // fork? resync chain
                    if (key->chain) {
                        key->chain_errors ++;
                        struct block *previous_block = NULL;
                        if (key->chain_errors < 10000) {
                            EDFS_THREAD_LOCK(edfs_context);
                            previous_block = (struct block *)key->chain->previous_block;
                            block_free(key->chain);
                            key->chain = previous_block;
                            key->mining_flag = 0;
                            EDFS_THREAD_UNLOCK(edfs_context);
                        } else {
                            EDFS_THREAD_LOCK(edfs_context);
                            blockchain_free(key->chain);
                            key->chain = NULL;
                            key->mining_flag = 0;
                            EDFS_THREAD_UNLOCK(edfs_context);
                            key->chain_errors = 0;
                        }
                        key->block_timestamp = time(NULL);
                        edfs_schedule(edfs_context, edfs_blockchain_request, 100000, 0, 0, 0, 0, 1, key);
                    }
                    block_free(topblock);
                }
            } else {
                if (key->chain->index == topblock->index)
                    log_warn("owned chain index is bigger");
                else
                if (key->chain->index > topblock->index)
                    log_warn("owned chain index is newer");
                // force rebroadcast top
                key->chain_errors ++;
                edfs_broadcast_top(edfs_context, key, clientaddr, clientaddrlen);
                if ((key->chain->index == topblock->index) && (microseconds() - key->top_broadcast_timestamp >= EDFS_BLOCKCHAIN_MIN_TIMEOUT / 2)) {
                    key->top_broadcast_timestamp = microseconds();
                    edfs_broadcast_top(edfs_context, key, NULL, 0);
                }
                block_free(topblock);
            }
            return;
        }
        if ((!key->chain) && (topblock->index)) {
            // request all chain
            key->block_timestamp = time(NULL);
            edfs_schedule(edfs_context, edfs_blockchain_request, 100000, 0, 0, 0, 0, 1, key);
        }
        if ((key->chain) && (topblock->index != key->chain->index + 1)) {
            log_warn("invalid block index");
            key->chain_errors ++;
            key->block_timestamp = time(NULL);
            edfs_schedule(edfs_context, edfs_blockchain_request, 100000, 0, 0, 0, 0, 1, key);
            block_free(topblock);
            return;
        }
        if ((key->chain) && (key->chain->timestamp + EDFS_BLOCKCHAIN_MIN_TIMEOUT > topblock->timestamp)) {
            log_warn("top block is too early");
            block_free(topblock);
            return;
        }
        edfs_write_file(edfs_context, key, key->blockchain_directory, computeblockname(topblock->index, b64name), payload, payload_size, NULL, 0, NULL, NULL, NULL, NULL, 1, 0, 0);
        topblock->previous_block = key->chain;
        key->chain = topblock;
        if (block_verify(topblock, BLOCKCHAIN_COMPLEXITY)) {
            key->mining_flag = 0;
            edfs_new_chain_request_descriptors(edfs_context, key, 0);
            key->top_broadcast_timestamp = 0;
            edfs_try_reset_proof(edfs_context, key);
            log_trace("set new block");
            usleep(1000);
            edfs_broadcast_top(edfs_context, key, NULL, 0);
            key->block_timestamp = time(NULL);
        } else {
            log_error("block verify error");
            key->chain_errors ++;
            key->chain = (struct block *)key->chain->previous_block;
            block_free(topblock);
        }
        if (key->chain_errors >= 10000) {
            EDFS_THREAD_LOCK(edfs_context);
            blockchain_free(key->chain);
            key->chain = NULL;
            key->mining_flag = 0;
            EDFS_THREAD_UNLOCK(edfs_context);
            key->chain_errors = 0;
            key->block_timestamp = time(NULL);
            edfs_schedule(edfs_context, edfs_blockchain_request, 100000, 0, 0, 0, 0, 1, key);
        }
        return;
    }
    if (!memcmp(type, "vote", 4)) {
        log_info("VOTE received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 32) {
            log_warn("VOTE packet too small");
            return;
        }

        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 32, timestamp, EDWORK_VOTE_WORK_LEVEL, EDWORK_VOTE_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }
        edwork_vote_received(edfs_context, payload, payload_size);
        return;
    }
#ifdef EDWORK_PEER_DISCOVERY_SERVICE
    if (!memcmp(type, "disc", 4)) {
        log_info("DISC received (%s)", edwork_addr_ipv4(clientaddr));

        if (payload_size < 32) {
            log_warn("DISC packet too small");
            return;
        }

        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 32, timestamp, EDWORK_LIST_WORK_LEVEL, EDWORK_LIST_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }

        unsigned char key_hash[32];
        uint64_t key_checksum = XXH64(payload, 32, 0);

        struct edfs_key_data *key = edfs_context->key_data;
        while (key) {
            sha256(key->pubkey, key->pub_len, key_hash);
            hmac_sha256((const BYTE *)"key id", 6, (const BYTE *)key_hash, 32, NULL, 0, (BYTE *)key_hash);
            if (XXH64(key_hash, 32, 0) == key_checksum) {
                log_trace("ignoring discovery request for own key");
                return;
            }
            key = (struct edfs_key_data *)key->next_key;
        }

        struct edfs_peer_discovery_data *peers = (struct edfs_peer_discovery_data *)avl_search(&edfs_context->peer_discovery, (void *)(uintptr_t)key_checksum);
        if (!peers) {
            peers = (struct edfs_peer_discovery_data *)malloc(sizeof(struct edfs_peer_discovery_data));
            if (peers) {
                memset(peers, 0, sizeof(struct edfs_peer_discovery_data));
                avl_insert(&edfs_context->peer_discovery, (void *)(uintptr_t)key_checksum, peers);
            }
        }

        if (!peers)
            return;

        int size = BLOCK_SIZE;
        int records = edfs_get_peer_list(peers, buffer, &size);
        if (records > 0) {
            if (edwork_send_to_peer(edwork, key, "add2", buffer, size, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL * 10) <= 0) {
                log_warn("error sending address list");
            } else
                log_info("sent %i peer addresses", records);
        }

        edfs_add_to_peer_discovery(peers, clientaddr, clientaddrlen);
        return;
    }
    if (!memcmp(type, "add2", 4)) {
        log_info("ADD2 list received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        if (time(NULL) - edfs_context->disc_timestamp > 10) {
            log_warn("dropping non-requested ADD2");
            return;
        }
        if (payload_size < 7) {
            log_warn("ADDR packet too small");
            return;
        }
        // offset is ignore
        edwork_add_node_list(edwork, payload, payload_size);
        return;
    }
#endif
    log_error("unsupported message type received: %s", type);
}

void edwork_save_nodes(struct edfs *edfs_context) {
    unsigned char buffer[BLOCK_SIZE];
    int size = BLOCK_SIZE;
    unsigned int offset = 0;
    int records = edwork_get_node_list(edfs_context->edwork, buffer, &size, (unsigned int)offset, time(NULL) - 48 * 3600, 1);
    if (records > 0) {
        FILE *out = fopen(edfs_context->nodes_file, "wb");
        if (out) {
            offset += records;
            do {
                uint32_t size_data = htonl(size);
                fwrite(&size_data, 1, sizeof(uint32_t), out);
                fwrite(buffer, 1, size, out);
                records = edwork_get_node_list(edfs_context->edwork, buffer, &size, offset, time(NULL) - 48 * 3600, 1);

                if (records > 0)
                    offset += records;
            } while (records > 0);
            fclose(out);
        }
    }
}

int edfs_list_request(struct edfs *edfs_context, uint64_t userdata_a, uint64_t userdata_b, void *data) {
    uint32_t offset = 0;
    struct edfs_key_data *key = (struct edfs_key_data *)data;
    edfs_notify_io(edfs_context, key ? key : edfs_context->primary_key , "list", (const unsigned char *)&offset, sizeof(uint32_t), NULL, 0, 0, 0, 0, EDWORK_LIST_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
    return 0;
}

void edwork_load_nodes(struct edfs *edfs_context) {
    JSON_Value *root_value = json_parse_file_with_comments(edfs_context->default_nodes);
    if (root_value) {
        if (json_value_get_type(root_value) == JSONArray) {
            JSON_Array *arr = json_value_get_array(root_value);
            int len = json_array_get_count(arr);
            int i;
            for (i = 0; i < len; i++) {
                JSON_Object *obj = json_array_get_object(arr, i);
                if (obj) {
                    const char *host = json_object_get_string(obj, "host");
                    int port = (int)json_object_get_number(obj, "port");
                    int sctp = (int)json_object_get_number(obj, "sctp");
                    if (port <= 0)
                        port = EDWORK_PORT;
                    if ((host) && (host[0]))
                        edwork_add_node(edfs_context->edwork, host, port, 0, sctp, 0, 0);
                }
            }
        }
        json_value_free(root_value);
    }

    FILE *in = fopen(edfs_context->nodes_file, "rb");
    if (in) {
        uint32_t size;
        unsigned char buffer[BLOCK_SIZE];

        while (fread(&size, 1, sizeof(uint32_t), in) == sizeof(uint32_t)) {
            size = ntohl(size);
            if (size > BLOCK_SIZE) {
                log_error("ERROR LOADING NODE LIST (block size)");
                break;
            }
            if (fread(buffer, 1, size, in) != size) {
                log_error("ERROR LOADING NODE LIST");
                break;
            }
            edwork_add_node_list(edfs_context->edwork, buffer, (int)size);
        }
        fclose(in);
    }
    edfs_schedule(edfs_context, edfs_list_request, 1000000, 10000000, 0, 0, 0, 0, NULL);
    edfs_context->list_timestamp = time(NULL);
#ifdef EDWORK_PEER_DISCOVERY_SERVICE
    usleep(50000);
    edwork_broadcast_discovery(edfs_context);
#endif
}

int string_ends_with(const char * str, const char *suffix, int suffix_len) {
    int str_len = strlen(str);
    return (str_len >= suffix_len) && (0 == strcmp(str + (str_len-suffix_len), suffix));
}

unsigned int edwork_resync(struct edfs *edfs_context, struct edfs_key_data *key, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket) {
    tinydir_dir dir;

    if (tinydir_open(&dir, key->working_directory)) {
        log_error("error opening edfs directory %s", key->working_directory);
        return 0;
    }
    if ((clientaddr) && (clientaddrlen))
        log_info("resync requested by remote");
    else
        log_info("resync requested by local");

    unsigned int rebroadcast_count = 0;
    while (dir.has_next) {
        tinydir_file file;
        tinydir_readfile(&dir, &file);

        if (!file.is_dir) {
            // do not send root object
            if (string_ends_with(file.name, ".json", 5)) {
                unsigned char buffer[EDWORK_PACKET_SIZE];
                int len = edfs_read_file(edfs_context, key, key->working_directory, file.name, buffer, EDWORK_PACKET_SIZE, NULL, 0, 0, 0, NULL, 0, 1, 0, 0);
                if (len > 0) {
                    if ((clientaddr) && (clientaddrlen)) {
                        edwork_send_to_peer(edfs_context->edwork, key, "desc", buffer, len, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL);
                        usleep(200);
                    } else
                        edwork_broadcast(edfs_context->edwork, key, "desc", buffer, len, 0, EDWORK_NODES, 0, 0, 0);
                } else
                    log_debug("error");
            }
        }
        tinydir_next(&dir);
    }
    tinydir_close(&dir);
    return rebroadcast_count;
}

unsigned int edwork_resync_desc(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket) {
    unsigned char buffer[EDWORK_PACKET_SIZE];
    char b64name[MAX_B64_HASH_LEN];

    int len = edfs_read_file(edfs_context, key, key->working_directory, computename(inode, b64name), buffer, EDWORK_PACKET_SIZE, ".json", 0, 0, 0, NULL, 0, 1, 0, 0);
    if (len > 0) {
        if ((clientaddr) && (clientaddrlen))
            edwork_send_to_peer(edfs_context->edwork, key, "desc", buffer, len, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL);
        else
            edwork_broadcast(edfs_context->edwork, key, "desc", buffer, len, 0, EDWORK_NODES, 0, 0, 0);
        return 1;
    } else
        log_debug("error");
    return 0;
}

unsigned int edwork_resync_dir_desc(struct edfs *edfs_context, struct edfs_key_data *key, uint64_t inode, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket) {
    unsigned char buffer[EDWORK_PACKET_SIZE];
    char b64name[MAX_B64_HASH_LEN];
    char path[MAX_PATH_LEN];

    tinydir_dir dir;

    snprintf(path, sizeof(path), "%s/%s", key->working_directory, computename(inode, b64name));
    if (tinydir_open(&dir, path)) {
        log_error("error opening directory %s", path);
        return 0;
    }
    if ((clientaddr) && (clientaddrlen))
        log_info("resync requested by remote");
    else
        log_info("resync requested by local");

    unsigned int rebroadcast_count = 0;
    while (dir.has_next) {
        tinydir_file file;
        tinydir_readfile(&dir, &file);

        if (!file.is_dir) {
            int len = edfs_read_file(edfs_context, key, key->working_directory, file.name, buffer, EDWORK_PACKET_SIZE, ".json", 0, 0, 0, NULL, 0, 1, 0, 0);
            if (len > 0) {
                if ((clientaddr) && (clientaddrlen)) {
                    edwork_send_to_peer(edfs_context->edwork, key, "desc", buffer, len, clientaddr, clientaddrlen, is_sctp, is_listen_socket, EDWORK_SCTP_TTL);
                    usleep(500);
                } else
                    edwork_broadcast(edfs_context->edwork, key, "desc", buffer, len, 0, EDWORK_NODES, 0, 0, 0);
            } else
                log_debug("error");
        }
        tinydir_next(&dir);
    }
    tinydir_close(&dir);
    return rebroadcast_count;
}

int edfs_check_descriptors(struct edfs *edfs_context, uint64_t userdata_a, uint64_t userdata_b, void *data) {
    struct edfs_key_data *key = (struct edfs_key_data *)data;
    if (key)
        edfs_chain_ensure_descriptors(edfs_context, key, microseconds() - 24ULL * 3600000000ULL);
    return 1;
}

int edwork_shard_queue(void *userdata) {
    struct edfs *edfs_context = (struct edfs *)userdata;
    while (!edfs_context->network_done) {
        thread_mutex_lock(&edfs_context->shard_lock);
        struct edwork_shard_io *io = edfs_context->shard_io;
        if (io)
            edfs_context->shard_io = (struct edwork_shard_io *)io->next;
        thread_mutex_unlock(&edfs_context->shard_lock);
        if (io) {
            edfs_ensure_data(edfs_context, io->key, io->inode, io->file_size, io->try_update_hash, io->start_chunk, io->json_version);
            free(io);
        }
#ifdef _WIN32
        Sleep(50);
#else
        usleep(50000);
#endif
    }
    thread_mutex_lock(&edfs_context->shard_lock);
    struct edwork_shard_io *io = edfs_context->shard_io;
    while (io) {
        struct edwork_shard_io *io_next_shard = (struct edwork_shard_io *)io->next;
        free(io);
        io = io_next_shard;
    }
    edfs_context->shard_io = NULL;
    thread_mutex_unlock(&edfs_context->shard_lock);
    return 0;
}

#ifdef WITH_CACHE_WARMUP
int edwork_warmup_thread(void *userdata) {
    struct edfs *edfs_context = (struct edfs *)userdata;
    while (!edfs_context->network_done) {
        if (edfs_context->warmup_inode) {
            log_trace("warming cache");
            edfs_warm_cache(edfs_context, edfs_context->warmup_key_dir, edfs_context->warmup_inode, edfs_context->warmup_chunk, 500);
            edfs_context->warmup_inode = 0;
        } else {
#ifdef _WIN32
            Sleep(50);
#else
            usleep(50000);
#endif
        }
    }
}
#endif

void edfs_log_lock(void *userdata, int lock) {
    thread_mutex_t *log_lock = (thread_mutex_t *)userdata;
    if (log_lock) {
        if (lock)
            thread_mutex_lock(log_lock);
        else
            thread_mutex_unlock(log_lock);
    }
}

struct edfs_key_data *edfs_find_key(uint64_t keyid, void *userdata) {
    struct edfs *edfs_context = (struct edfs *)userdata;
    if ((!edfs_context) || (!edfs_context->key_data))
        return NULL;

    if (!keyid)
        return edfs_context->primary_key;

    return (struct edfs_key_data *)avl_search(&edfs_context->key_tree, (void *)(uintptr_t)keyid);
}

int edwork_load_key(struct edfs *edfs_context, const char *filename) {
    char fullpath[MAX_PATH_LEN];
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", edfs_context->edfs_directory, filename);

    struct edfs_key_data *key = (struct edfs_key_data *)malloc(sizeof(struct edfs_key_data));
    if (!key) {
        log_error("memory allocation failed");
        return 0;
    }

    edfs_key_data_init(key, fullpath);
#ifndef EDFS_NO_JS
    key->edfs_context = edfs_context;
#endif

    key->pub_len = read_signature(edfs_context, key->signature, key->pubkey, 1, &key->key_type, NULL);
    if (key->pub_len > 0) {
        key->pub_loaded = 1;

        unsigned char hash[32];
        sha256(key->pubkey, 32, hash);
        key->key_id_xxh64_be = htonll(XXH64(hash, 32, 0));

        struct edfs_key_data *old_key = edfs_find_key(key->key_id_xxh64_be, edfs_context);
        if ((key->key_id_xxh64_be) && (old_key) && (old_key->read_only == 0)) {
            log_warn("already loaded key %s", key->signature);
            edfs_key_data_deinit(key);
            free(key);
            return 0;
        }

        sha256(key->pubkey, 32, key->key_id);

        key->read_only = 1;

        key->sig_len = read_signature(edfs_context, key->signature, key->sigkey, 0, &key->sign_key_type, key->pubkey);
        if (key->sig_len) {
            switch (key->sign_key_type) {
                case KEY_HS256:
                    key->signature_size = 32;
                    key->key_loaded = 1;
                    key->read_only = 0;
                    break;
                case KEY_EDD25519:
                    key->signature_size = 64;
                    key->key_loaded = 1;
                    key->read_only = 0;
                    break;
            }
        }
        if ((old_key) && (old_key->read_only) && (!key->read_only)) {
            old_key->read_only = 0;
            old_key->key_loaded = 0;
            old_key->pub_loaded = 0;
            old_key->signature_size = key->signature_size;
            old_key->sign_key_type = key->sign_key_type;
            old_key->sig_len = key->sig_len;
            old_key->pub_len = key->pub_len;
            memcpy(old_key->pubkey, key->pubkey, key->pub_len);
            memcpy(old_key->sigkey, key->sigkey, key->sig_len);
            edfs_try_reset_proof(edfs_context, old_key);

            log_info("updated key %s to read/write", key->signature);

            edfs_key_data_deinit(key);
            free(key);
            return 2;
        }
        if (old_key) {
            log_warn("already loaded key %s", key->signature);
            edfs_key_data_deinit(key);
            free(key);
            return 0;
        }
    } else {
        log_error("error loading key %s", key->signature);
        edfs_key_data_deinit(key);
        return 0;
    }

    recursive_mkdir(key->working_directory);
    recursive_mkdir(key->cache_directory);
    recursive_mkdir(key->blockchain_directory);

    key->next_key = edfs_context->key_data;
    edfs_context->key_data = key;

    avl_insert(&edfs_context->key_tree, (void *)(uintptr_t)key->key_id_xxh64_be, (void *)key);

    return 1;
}

static int edfs_schedule_free(struct doops_loop *loop, void *foreachdata) {
    free(loop_event_data(loop));
    return 0;
}

int edwork_load_keys(struct edfs *edfs_context) {
    tinydir_dir dir;
    if (tinydir_open(&dir, edfs_context->edfs_directory))
        return 0;

    int loaded = 0;
    uint64_t primary_key_id = (uint64_t)edfs_settings_get_number(edfs_context, "edfs.primary_key");
    while (dir.has_next) {
        tinydir_file file;
        tinydir_readfile(&dir, &file);
        if ((file.is_dir) && (file.name[0] != '.')) {
            if (edwork_load_key(edfs_context, file.name)) {
                if ((primary_key_id) && (!edfs_context->use_key_id) && (edfs_context->key_data) && (XXH32(edfs_context->key_data->key_id, sizeof(edfs_context->key_data->key_id), 0) == primary_key_id))
                    edfs_context->primary_key = edfs_context->key_data;
                loaded ++;
            }
        }
        tinydir_next(&dir);
    }
    tinydir_close(&dir);
    return loaded;
}

void edfs_vote(struct edfs *edfs_context, struct edfs_key_data *key, const char *subject, int subject_len, const unsigned char *vote_data, int len, int timeout) {
    unsigned char buffer[EDWORK_PACKET_SIZE];
    if (subject_len < 0)
        subject_len = strlen(subject);
    if (subject_len > 0xFF)
        subject_len = 0xFF;
    buffer[0] = (unsigned int)subject_len;
    memcpy(buffer + 1, subject, subject_len);
    buffer[subject_len + 1] = (unsigned char)timeout;
    edfs_notify_io(edfs_context, key ? key : edfs_context->primary_key , "vote", (const unsigned char *)buffer, subject_len + 2, vote_data, len, 0, 1, 0, EDWORK_VOTE_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
}

int edwork_thread(void *userdata) {
    struct edfs *edfs_context = (struct edfs *)userdata;

    edwork_init();

    if (edfs_context->port <= 0)
        edfs_context->port = EDWORK_PORT;

    if (!edwork_load_keys(edfs_context)) {
        edfs_use_key(edfs_context, "wG5RPGPCly9kNWs2_DZRMU8DtQGmXxRduafL9M-AMX-9H3n3V3udUagWE_HyDAMw5GOka8ppuzuO7pp_x5i5ew", "siy3GXOHnVySVUlHUDVGt7v6nMKWjy39Hy23M40Toos");
        if (edfs_context->key_data) {
            log_warn("using default key");
        } else {
            log_fatal("no available keys");
            edfs_context->network_done = 1;
            return 0;
        }
        edfs_set_resync(edfs_context, 1);
    }

    if (!edfs_context->primary_key) {
        if (edfs_context->use_key_id) {
            edfs_context->primary_key = edfs_find_key(edfs_context->use_key_id, edfs_context);
            if (!edfs_context->primary_key) {
                log_fatal("unknown primary key");
                edfs_context->network_done = 1;
                return 0;
            }
        } else
            edfs_context->primary_key = edfs_context->key_data;
    }

    edfs_init(edfs_context);

    struct edwork_data *edwork = edwork_create(edfs_context->port, edfs_find_key);
    if (!edwork) {
        log_fatal("error creating network node");
        edfs_context->network_done = 1;
        return 0;
    }

    thread_mutex_t log_lock;
    thread_mutex_init(&log_lock);
    log_set_udata(&log_lock);
    log_set_lock(edfs_log_lock);


    edfs_context->edwork = edwork;
#ifdef WITH_SCTP
    if (edfs_context->force_sctp)
        edwork_force_sctp(edfs_context->edwork, 1);
#endif

    char *host_and_port = edfs_context->host_and_port;
    if ((host_and_port) && (host_and_port[0])) {
        int add_port = EDWORK_PORT;
        char *port_ptr = NULL;
        if (host_and_port[0] == '[') {
            host_and_port ++;
            char *ipv6_port = strchr(host_and_port, ']');
            if (ipv6_port) {
                port_ptr = strchr(ipv6_port, ':');
                ipv6_port[0] = 0;
            }
        } else
            port_ptr = strchr(host_and_port, ':');
        if (port_ptr) {
            *port_ptr = 0;
            port_ptr++;
            add_port = atoi(port_ptr);
            if (add_port <= 0)
                add_port = EDWORK_PORT;
        }
        if (host_and_port[0])
            edwork_add_node(edwork, host_and_port, add_port, 0, 3, 0, 0);
        else
            log_error("error parsing url: %s", host_and_port);
    }

    edwork_load_nodes(edfs_context);
    time_t startup = time(NULL);
#ifdef WITH_SCTP
    time_t seen_scan = time(NULL);
#endif
    int broadcast_offset = 0;

    struct edfs_key_data *key = edfs_context->key_data;
    while (key) {
        edfs_schedule(edfs_context, edfs_check_descriptors, 10000000, 0, 0, 0, 0, 0, key);
        key->hblk_scheduled = 1;
        edfs_schedule(edfs_context, edfs_blockchain_request, 50000, 0, 0, 0, 0, 0, key);
        if (!edfs_context->resync)
            key->block_timestamp = startup + 20;

#ifdef EDWORK_PEER_DISCOVERY_SERVICE
        edwork_broadcast_discovery_key(edfs_context, key);
#endif
        key = (struct edfs_key_data *)key->next_key;
    }

    int ping_count = 0;

    if (edfs_context->resync) {
        loop_schedule(&edfs_context->loop, {
            uint64_t ack = htonll(1);
            key = edfs_context->key_data;
            while (key) {
                edfs_notify_io(edfs_context, key, "root", (const unsigned char *)&ack, sizeof(uint64_t), NULL, 0, 2, 0, 1, EDWORK_ROOT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
                key = (struct edfs_key_data *)key->next_key;
            }
            edfs_context->resync = 0;

            return 1;
        }, EDWORK_INIT_INTERVAL * 1000);
    }

    if (edfs_context->force_rebroadcast) {
        loop_schedule(&edfs_context->loop, {
            key = edfs_context->key_data;
            while (key) {
                edwork_resync(edfs_context, key, NULL, 0, 0, 0);
                key = (struct edfs_key_data *)key->next_key;
            }
            edfs_context->force_rebroadcast = 0;

            return 1;
        }, EDWORK_INIT_INTERVAL * 1000);
    }
        
    loop_schedule(&edfs_context->loop, {
        // max 1000 keys
        uint64_t key_buffer[1000];
        int key_buffer_index = 0;
        key = edfs_context->key_data;
        int force_broadcast_to_all = ((ping_count % 90) == 0);
        while (key) {
            key_buffer[key_buffer_index ++] = key->key_id_xxh64_be;
            if (key_buffer_index == 1000) {
                edwork_broadcast(edwork, NULL, "ping", (unsigned char *)key_buffer, key_buffer_index * sizeof(uint64_t), 0, EDWORK_NODES, 0, 1, force_broadcast_to_all ? time(NULL) - 24 * 3600 : 0);
                key_buffer_index = 0;
            }
#ifndef EDFS_NO_JS
            if ((edfs_context->app_mode) && ((ping_count <= 2) || (key->reload_js = 1)))
                edfs_reload_app(edfs_context, key);
#endif
            key = (struct edfs_key_data *)key->next_key;
        }
        if (key_buffer_index > 0)
            edwork_broadcast(edwork, NULL, "ping", (unsigned char *)key_buffer, key_buffer_index * sizeof(uint64_t), 0, EDWORK_NODES, 0, 1, force_broadcast_to_all ? time(NULL) - 24 * 3600 : 0);
        ping_count ++;
    }, - EDWORK_PING_INTERVAL * 1000);

    loop_schedule(&edfs_context->loop, {
        uint32_t offset = htonl(0);
        key = edfs_context->key_data;
        while (key) {
            edfs_notify_io(edfs_context, key, "list", (const unsigned char *)&offset, sizeof(uint32_t), NULL, 0, 0, 0, 0, EDWORK_LIST_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
            key = (struct edfs_key_data *)key->next_key;
        }
        edfs_context->list_timestamp = time(NULL);

#ifdef EDWORK_PEER_DISCOVERY_SERVICE
        if (!edfs_context->ping_received)
            edwork_broadcast_discovery(edfs_context);
#endif
#ifdef WITH_SCTP
        if (time(NULL) - seen_scan > EDWORK_LAST_SEEN_TIMEOUT) {
            log_trace("trying to reconnect SCTP sockets");
            int reconnected_count = edwork_reconnect(edwork, EDWORK_LAST_SEEN_TIMEOUT);
            if (reconnected_count)
                log_trace("tried to reconnect %i SCTP sockets", reconnected_count);
            seen_scan = time(NULL);
        }
#endif
    }, - (EDWORK_LIST_INTERVAL * 1000));

    loop_schedule(&edfs_context->loop, {
        edwork_save_nodes(edfs_context);
    }, EDWORK_NODE_WRITE_INTERVAL * 1000);


    loop_schedule(&edfs_context->loop, {
        int count = 0;
        key = edfs_context->key_data;
        while (key) {
            count += edwork_rebroadcast(edwork, key, EDWORK_REBROADCAST, broadcast_offset);
            key = (struct edfs_key_data *)key->next_key;
        }

        if (count)
            log_info("rebroadcasted %i edwork blocks, offset %i", count, broadcast_offset);
        if (count < EDWORK_REBROADCAST)
            broadcast_offset = 0;
        else
            broadcast_offset += count;
    }, EDWORK_REBROADCAST_INTERVAL * 1000);

#ifdef WITH_SMARTCARD
    loop_schedule(&edfs_context->loop, {
        edwork_smartcard_iterate(&edfs_context->smartcard_context);
    }, 1000);
#endif

#ifndef EDFS_NO_JS
    if (edfs_context->app_mode) {
        loop_schedule(&edfs_context->loop, {
            key = edfs_context->key_data;
            while (key) {
                edfs_key_data_js_loop(key);
                key = (struct edfs_key_data *)key->next_key;
            }
        }, 50);
    }
#endif
    loop_schedule(&edfs_context->loop, {
        log_info("generating new identity");
        edwork_reset_id(edfs_context->edwork);
    }, EDWORK_ID_EXPIRES * 1000);

    loop_add_io(&edfs_context->loop, edwork_udp_socket(edwork), DOOPS_READ);
    loop_on_read(&edfs_context->loop, {
        edwork_dispatch(edwork, edwork_callback, 0, edfs_context);
    });

    loop_schedule(&edfs_context->loop, {
        key = edfs_context->key_data;
        while (key) {
            edfs_try_new_block(edfs_context, key);
            key = (struct edfs_key_data *)key->next_key;
        }
    }, 2000);
    loop_run(&edfs_context->loop);

    loop_foreach_callback(&edfs_context->loop, edfs_schedule_foreach, edfs_schedule_free, NULL);
    loop_foreach_callback(&edfs_context->loop, edfs_schedule_foreach_data, edfs_schedule_free, NULL);
    loop_foreach_callback(&edfs_context->loop, edfs_schedule_vote, edfs_schedule_free, NULL);

    loop_deinit(&edfs_context->loop);

    log_set_lock(NULL);
    log_set_udata(NULL);
    thread_mutex_term(&log_lock);

    edwork_save_nodes(edfs_context);

    edwork_close(edwork);

    edwork_done();

    edfs_context->edwork = NULL;
    edwork_destroy(edwork);

    return 0;
}

uint64_t edfs_pathtoinode_key(struct edfs_key_data *key, const char *path, uint64_t *parentinode, const char **nameptr) {
    uint64_t inode = key ? edfs_root_inode(key) : 1;

    if (parentinode)
        *parentinode = 0;
    if (nameptr)
        *nameptr = NULL;
    if (!path)
        return inode;
    int len = strlen(path);
    if (!len)
        return inode;

    int i;
    int chunk_len;
    int start = 0;

    if (path[start] == '/')
        start ++;

    for (i = start; i < len; i++) {
        if ((path[i] == '/') || (path[i] == '\\')) {
            chunk_len = i - start;
            if (chunk_len > 0) {
                if (parentinode)
                    *parentinode = inode;
                inode = computeinode2(key ? key : NULL, inode, path + start, chunk_len);
                if (nameptr)
                    *nameptr = path + start;
                start = i + 1;
            }
        }
    }
    chunk_len = i - start;
    if (chunk_len > 0) {
        if (parentinode)
            *parentinode = inode;
        inode = computeinode2(key ? key : NULL, inode, path + start, chunk_len);
        if (nameptr)
            *nameptr = path + start;
        start = i + 1;
    }
    return inode;
}

uint64_t edfs_pathtoinode(struct edfs *edfs_context, const char *path, uint64_t *parentinode, const char **nameptr) {
    return edfs_pathtoinode_key(edfs_context ? edfs_context->primary_key : NULL, path, parentinode, nameptr);
}

char *edfs_lazy_read_file(struct edfs *edfs_context, struct edfs_key_data *key, const char *filename, int *file_size, uint64_t offset, int max_size) {
    if (!edfs_context->mutex_initialized)
        usleep(10000000);

    if (file_size)
        *file_size = 0;

    uint64_t parent;
    const char *name = NULL;
    edfs_ino_t inode = edfs_pathtoinode_key(key, filename, &parent, &name);
    int type = edfs_lookup_inode_key(edfs_context, key, inode, name);
    if ((!type) || (type & S_IFDIR)) {
        if (file_size)
            *file_size = -1;
        return NULL;
    }

    edfs_stat stbuf;
    int err = edfs_getattr_key(edfs_context, key, inode, &stbuf);
    if (err) {
        if (file_size)
            *file_size = -1;
        return NULL;
    }

    struct filewritebuf *fbuf = NULL;
    err = edfs_open_key(edfs_context, key, inode, O_RDONLY, &fbuf);
    if (err) {
        if (file_size)
            *file_size = -1;
        return NULL;
    }

    char *data_buffer = NULL;
    if (stbuf.st_size > 0) {
        if ((max_size > 0) && (stbuf.st_size > max_size))
            stbuf.st_size = max_size;

        data_buffer = ( char *)malloc(stbuf.st_size + 1);
        if (file_size)
            *file_size = stbuf.st_size;

        if (data_buffer) {
            int size = edfs_read(edfs_context, inode, stbuf.st_size, offset, data_buffer, fbuf);
            if (size > 0) {
                if (file_size)
                    *file_size = size;
                data_buffer[size] = 0;
            } else {
                if (file_size)
                    *file_size = -1;
                free(data_buffer);
                data_buffer = NULL;
            }
        }
    }
    edfs_close(edfs_context, fbuf);
    return data_buffer;
}


void edfs_edwork_init(struct edfs *edfs_context, int port) {
    if (!edfs_context)
        return;

    if (port <= 0)
        port = EDWORK_PORT;

    if (!edfs_context->mutex_initialized) {
        edfs_context->port = port;
        thread_mutex_init(&edfs_context->lock);
        thread_mutex_lock(&edfs_context->lock);

        thread_mutex_init(&edfs_context->shard_lock);
#ifdef EDFS_MULTITHREADED
        thread_mutex_init(&edfs_context->thread_lock);
#endif

        edfs_context->mutex_initialized = 1;
        edfs_context->network_thread = thread_create(edwork_thread, (void *)edfs_context, "edwork", 8192 * 1024);
        edfs_context->shard_thread = thread_create(edwork_shard_queue, (void *)edfs_context, "edwork shard", 8192 * 1024);
#ifdef WITH_CACHE_WARMUP
        edfs_context->warmup_thread = thread_create(edwork_warmup_thread, (void *)edfs_context, "edwork warmup", 8192 * 1024);
#endif
        thread_mutex_unlock(&edfs_context->lock);

        edfs_context->start_timestamp = microseconds();
    } else
        log_error("edwork already initialized");
}

int edfs_edwork_is_initialized(struct edfs *edfs_context) {
    if (!edfs_context)
        return 0;

    if (!edfs_context->mutex_initialized)
        return 0;

    if (!edfs_context->primary_key)
        return 0;

    return 1;
}

int edfs_edwork_wait_initialization(struct edfs *edfs_context, int timeout_ms) {
    uint64_t timeout = microseconds() + timeout_ms * 1000;
    while (!edfs_edwork_is_initialized(edfs_context)) {
        if (microseconds() >= timeout)
            return 0;
        usleep(5000);
    }
    return 1;
}

void edfs_edwork_done(struct edfs *edfs_context) {
    if (!edfs_context)
        return;

    loop_quit(&edfs_context->loop);
    if (!edfs_context->mutex_initialized) {
        log_error("edwork not initialized");
        return;
    }
    if (edfs_context->shard_thread) {
        log_info("waiting for shard thread to finish ...");
        edfs_context->network_done = 1;
        thread_join(edfs_context->shard_thread);
        thread_destroy(edfs_context->shard_thread);
        log_info("edwork shard done");
    }
    #ifdef WITH_CACHE_WARMUP
        if (edfs_context->warmup_thread) {
            log_info("waiting for edwork warmup thread to finish ...");
            edfs_context->network_done = 1;
            thread_join(edfs_context->warmup_thread);
            thread_destroy(edfs_context->warmup_thread);
            log_info("edwork warmup done");
        }
    #endif
    if (edfs_context->network_thread) {
        log_info("waiting for edwork thread to finish ...");
        edfs_context->network_done = 1;
        thread_join(edfs_context->network_thread);
        thread_destroy(edfs_context->network_thread);
        log_info("edwork done");
    }

    edfs_context->mutex_initialized = 0;
    thread_mutex_term(&edfs_context->lock);
    thread_mutex_term(&edfs_context->shard_lock);
#ifdef EDFS_MULTITHREADED
    thread_mutex_term(&edfs_context->thread_lock);
#endif
}

static void recursive_mkdir(const char *dir) {
    char tmp[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);

    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            EDFS_MKDIR(tmp, S_IRWXU);
            *p = '/';
        }
    }
    EDFS_MKDIR(tmp, S_IRWXU);
}

void edfs_block_save(struct edfs *edfs_context, struct edfs_key_data *key, struct block *chain) {
    if (!chain)
        return;

    int size = 0;
    char b64name[MAX_B64_HASH_LEN];
    unsigned char *buffer = block_save_buffer(chain, &size);
    if (buffer) {
#ifndef EDFS_NO_JS
        if (edfs_key_js_call(key, "edwork.events.onblockchain", "mine", NULL) == 1) {
            log_warn("block write denied by JS function");
            return;
        }
#endif
        edfs_write_file(edfs_context, key, key->blockchain_directory, computeblockname(chain->index, b64name), buffer, size, NULL, 1, NULL, NULL, NULL, NULL, 0, 0, 0);
        free(buffer);
    }
}

struct block *edfs_blockchain_load(struct edfs *edfs_context, struct edfs_key_data *key) {
    uint64_t i = 0;
    struct block *newblock = NULL;
    struct block *top_block;
    do {
        top_block = newblock;

        char b64name[MAX_B64_HASH_LEN];
        unsigned char buffer[BLOCK_SIZE_MAX];
        int len = edfs_read_file(edfs_context, key, key->blockchain_directory, computeblockname(i ++, b64name), buffer, BLOCK_SIZE_MAX, NULL, 0, 1, 0, NULL, 0, 0, 0, 0);
        if (len <= 0)
            break;

        newblock = block_load_buffer(buffer, len);
        if (newblock)
            newblock->previous_block = top_block;
    } while (newblock);
    return top_block;
}

int edfs_init(struct edfs *edfs_context) {
    if (!edfs_context)
        return -1;

    recursive_mkdir(edfs_context->edfs_directory);
    struct edfs_key_data *key;

    if (edfs_context->read_only_fs) {
        log_info("read-only filesytem");
    } else {
        // init root foloder
        key = edfs_context->key_data;
        while (key) {
            read_file_json(edfs_context, key, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL);
            key = (struct edfs_key_data *)key->next_key;
        }
    }
    key = edfs_context->key_data;
    while (key) {
        recursive_mkdir(key->working_directory);
        recursive_mkdir(key->cache_directory);
        key->chain = edfs_blockchain_load(edfs_context, key);
        if (key->chain) {
            time_t stamp = (time_t)(key->chain->timestamp / 1000000UL);
            struct tm *tstamp = gmtime(&stamp);
            if (blockchain_verify(key->chain, BLOCKCHAIN_COMPLEXITY)) {
                key->top_broadcast_timestamp = 0;
                log_info("blockchain verified, head is %" PRIu64 ", UTC: %s", key->chain->index, asctime(tstamp));
            } else {
                log_error("blockchain is invalid, head is %" PRIu64 ", UTC: %s", key->chain->index, asctime(tstamp));
                while (key->chain) {
                    struct block *chain = key->chain;
                    struct block *top_chain = chain;
                    while (chain) {
                        if (!block_verify(chain, BLOCKCHAIN_COMPLEXITY)) {
                            key->chain = (struct block *)chain->previous_block;
                            chain->previous_block = NULL;
                            // free invalid chain
                            blockchain_free(top_chain);
                            break;
                        }
                        chain = (struct block *)chain->previous_block;
                    }
                    // found a valid chain?
                    if (!chain)
                        break;
                }
                if (key->chain)
                    log_info("blockchain is invalid, new head is %" PRIu64 ", UTC: %s", key->chain->index, asctime(tstamp));

                recursive_rmdir(key->blockchain_directory);
                recursive_mkdir(key->blockchain_directory);
                struct block *chain = key->chain;
                while (chain) {
                    edfs_block_save(edfs_context, key, chain);
                    chain = (struct block *)chain->previous_block;
                }
            }
            key->top_broadcast_timestamp = 0;
        }
        recursive_mkdir(key->blockchain_directory);
        key = (struct edfs_key_data *)key->next_key;
    }
    return 0;
}

void edfs_set_store_key(struct edfs *edfs_context, const unsigned char *key, int len) {
    if ((len) && (key)) {
        hmac_sha256((const BYTE *)key, len, (const BYTE *)"localstorage key", 16, NULL, 0, (BYTE *)edfs_context->storekey);
        edfs_context->has_storekey = 1;
    } else
        edfs_context->has_storekey = 0;
}

char *edfs_add_to_path(const char *path, const char *subpath) {
    int len = strlen(path) + strlen(subpath) + 2;
    char *fullpath = (char *)malloc(len);
    if (fullpath)
        snprintf(fullpath, len, "%s/%s", path, subpath);

    return fullpath;
}

struct edfs *edfs_create_context(const char *use_working_directory) {
    struct edfs *edfs_context = (struct edfs *)malloc(sizeof(struct edfs));
    if (edfs_context) {
        memset(edfs_context, 0, sizeof(struct edfs));

        if ((!use_working_directory) || (!use_working_directory[0]))
            use_working_directory = default_working_directory;

        edfs_context->edfs_directory = strdup(use_working_directory);
        edfs_context->nodes_file = edfs_add_to_path(use_working_directory, "nodes");
        edfs_context->default_nodes = edfs_add_to_path(use_working_directory, "default_nodes.json");
        edfs_context->forward_chunks = 5;
        edfs_make_key(edfs_context);

#ifdef EDWORK_PEER_DISCOVERY_SERVICE
        avl_initialize(&edfs_context->peer_discovery, ino_compare, avl_ino_destructor);
#endif
        avl_initialize(&edfs_context->key_tree, ino_compare, avl_ino_destructor);
#ifdef WITH_SMARTCARD
        edwork_smartcard_init(&edfs_context->smartcard_context);
#endif

        loop_init(&edfs_context->loop);
    }
    return edfs_context;
}

void edfs_destroy_context(struct edfs *edfs_context) {
    if (!edfs_context)
        return;

#ifdef EDWORK_PEER_DISCOVERY_SERVICE
    avl_destroy(&edfs_context->peer_discovery, avl_ino_key_data_destructor);
#endif
    avl_destroy(&edfs_context->key_tree, avl_no_destructor);

    while (edfs_context->key_data) {
        struct edfs_key_data *next = (struct edfs_key_data *)edfs_context->key_data->next_key;
        edfs_key_data_deinit(edfs_context->key_data);
        free(edfs_context->key_data);
        edfs_context->key_data = next;
    }
    free(edfs_context->edfs_directory);
    free(edfs_context->nodes_file);
    free(edfs_context->default_nodes);
    free(edfs_context->host_and_port);
#ifdef WITH_SMARTCARD
    edwork_smartcard_done(&edfs_context->smartcard_context);
#endif
    free(edfs_context);
}

void edfs_set_resync(struct edfs *edfs_context, int resync_val) {
    if (!edfs_context)
        return;
    edfs_context->resync = resync_val;
}

void edfs_set_forward_chunks(struct edfs *edfs_context, int forward_chunks) {
    if (!edfs_context)
        return;
    edfs_context->forward_chunks = forward_chunks;
}

void edfs_set_rebroadcast(struct edfs *edfs_context, int rebroadcast_val) {
    if (!edfs_context)
        return;
    edfs_context->force_rebroadcast = rebroadcast_val;
}

void edfs_set_readonly(struct edfs *edfs_context, int readonly_val) {
    if (!edfs_context)
        return;
    edfs_context->read_only_fs = readonly_val;
}

int edwork_readonly(struct edfs *edfs_context) {
    if (!edfs_context)
        return 1;
    return edfs_context->read_only_fs;
}

void edfs_set_initial_friend(struct edfs *edfs_context, const char *peer) {
    if ((!edfs_context) || (!peer))
        return;

    if (edfs_context->edwork) {
        if ((peer) && (peer[0])) {
            int add_port = EDWORK_PORT;
            char *port_ptr = NULL;
            if (peer[0] == '[') {
                peer ++;
                char *ipv6_port = (char *)strchr(peer, ']');
                if (ipv6_port) {
                    port_ptr = strchr(ipv6_port, ':');
                    ipv6_port[0] = 0;
                }
            } else
                port_ptr = (char *)strchr(peer, ':');
            if (port_ptr) {
                *port_ptr = 0;
                port_ptr++;
                add_port = atoi(port_ptr);
                if (add_port <= 0)
                    add_port = EDWORK_PORT;
            }
            if (peer[0])
                edwork_add_node(edfs_context->edwork, peer, add_port, 0, 3, 0, 0);
        }
    }
    int len = strlen(peer);
    if (len <= 0)
        return;

    if (edfs_context->host_and_port)
        free(edfs_context->host_and_port);
    edfs_context->host_and_port = (char *)malloc(len + 1);
    if (!edfs_context->host_and_port)
        return;

    memcpy(edfs_context->host_and_port, peer, len);
    edfs_context->host_and_port[len] = 0;
}

void edfs_set_proxy(struct edfs *edfs_context, int proxy) {
    if (!edfs_context)
        return;
    edfs_context->proxy = (proxy != 0);
}

void edfs_set_force_sctp(struct edfs *edfs_context, int force_sctp) {
    if (!edfs_context)
        return;
#ifdef WITH_SCTP
    edfs_context->force_sctp = (force_sctp != 0);
    if (edfs_context->edwork)
        edwork_force_sctp(edfs_context->edwork, edfs_context->force_sctp);
#endif
}

void edfs_set_shard(struct edfs *edfs_context, int shard_id, int shards) {
    if ((!edfs_context) || (shard_id <= 0) || (shards <= 0))
        return;

    edfs_context->shard_id = shard_id - 1;
    edfs_context->shards = shards;
}

void edfs_set_partition_key(struct edfs *edfs_context, char *key_id) {
    if (key_id) {
        if (strlen(key_id) > 32) {
            unsigned char public_key[MAX_KEY_SIZE];
            size_t len = base64_decode_no_padding((const BYTE *)key_id, public_key, MAX_KEY_SIZE);
            if (len >= 32) {
                if (len == 64) {
                    public_key[0] &= 248;
                    public_key[31] &= 63;
                    public_key[31] |= 64;

                    ed25519_get_pubkey(public_key, public_key);
                }
                unsigned char hash[32];
                sha256(public_key, 32, hash);
                edfs_context->use_key_id = htonll(XXH64(hash, 32, 0));
            } else
                log_error("invalid key id");
        } else
            base32_decode((const BYTE *)key_id, (BYTE *)&edfs_context->use_key_id, sizeof(uint64_t));
    } else
        edfs_context->use_key_id = 0;
}

static JSON_Value *read_json_settings(const struct edfs *edfs_context, int create_new) {
    char fullpath[MAX_PATH_LEN];
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/settings.json", edfs_context->edfs_directory);

    JSON_Value *root_value = json_parse_file(fullpath);
    if ((!root_value) || (json_value_get_type(root_value) != JSONObject)) {
        if (root_value)
            json_value_free(root_value);

        if (create_new)
            return json_value_init_object();

        if (root_value)
            log_error("invlaid root object in JSON file");
        return 0;
    }

    return root_value;
}

int edfs_settings_set(const struct edfs *edfs_context, const char *key, const char *value) {
    if (!edfs_context)
        return -1;

    JSON_Value *root_value = read_json_settings(edfs_context, 1);
    if (!root_value)
        return -1;

    JSON_Object *root_object = json_value_get_object(root_value);
    if (root_object) {
        if (value)
            json_object_dotset_string(root_object, key ? key : "", value);
        else
            json_object_dotremove(root_object, key ? key : "");
        char fullpath[MAX_PATH_LEN];
        fullpath[0] = 0;
        snprintf(fullpath, MAX_PATH_LEN, "%s/settings.json", edfs_context->edfs_directory);
        json_serialize_to_file_pretty(root_value, fullpath);
    }
    json_value_free(root_value);

    return 0;
}

int edfs_settings_set_number(const struct edfs *edfs_context, const char *key, double value) {
    if (!edfs_context)
        return -1;

    JSON_Value *root_value = read_json_settings(edfs_context, 1);
    if (!root_value)
        return -1;

    JSON_Object *root_object = json_value_get_object(root_value);
    if (root_object) {
        json_object_dotset_number(root_object, key ? key : "", value);
        char fullpath[MAX_PATH_LEN];
        fullpath[0] = 0;
        snprintf(fullpath, MAX_PATH_LEN, "%s/settings.json", edfs_context->edfs_directory);
        json_serialize_to_file_pretty(root_value, fullpath);
    }
    json_value_free(root_value);

    return 0;
}

int edfs_settings_get(const struct edfs *edfs_context, const char *key, char *value, int value_len) {
    if (!edfs_context)
        return -1;

    JSON_Value *root_value = read_json_settings(edfs_context, 0);
    if (!root_value) {
        if ((value) && (value_len > 0))
            value[0] = 0;
        return 0;
    }

    if ((value) && (value_len > 0))
        value[0] = 0;

    JSON_Object *root_object = json_value_get_object(root_value);
    const char *json_value = json_object_dotget_string(root_object, key ? key : "");
    if ((json_value) && (value) && (value_len > 0))
        strncpy(value, json_value, value_len);
    json_value_free(root_value);
    return 1;
}

double edfs_settings_get_number(const struct edfs *edfs_context, const char *key) {
    if (!edfs_context)
        return 0;

    JSON_Value *root_value = read_json_settings(edfs_context, 0);
    if (!root_value)
        return 0;

    JSON_Object *root_object = json_value_get_object(root_value);
    double json_value = json_object_dotget_number(root_object, key ? key : "");
    json_value_free(root_value);
    return json_value;
}

#ifdef WITH_SMARTCARD
void edfs_set_smartcard_callback(struct edfs *edfs_context, edwork_smartcard_ui_callback callback) {
    if (!edfs_context)
        return;
    edfs_context->smartcard_context.status_changed = callback;
}

void edfs_set_smartcard_pin_callback(struct edfs *edfs_context, edwork_smartcard_read_pin_callback callback) {
    if (!edfs_context)
        return;
    edfs_context->smartcard_context.read_pin = callback;
}

struct edwork_smartcard_context *edfs_get_smartcard_context(struct edfs *edfs_context) {
    if (!edfs_context)
        return NULL;
    return &edfs_context->smartcard_context;
}
#endif

#ifndef EDFS_NO_JS
void edfs_set_app_mode(struct edfs *edfs_context, unsigned char app_mode) {
    if (!edfs_context)
        return;
    edfs_context->app_mode = app_mode;
}

void edfs_notify_window_close(struct edfs *edfs_context, void *window) {
    if (!edfs_context)
        return;
    struct edfs_key_data *key = edfs_context->key_data;
    while (key) {
        if (key->js_window == window) {
            key->js_window = NULL;
            break;
        }
        key = (struct edfs_key_data *)key->next_key;
    }
}

int edfs_app_window_count(struct edfs *edfs_context) {
    if (!edfs_context)
        return 0;
    int windows = 0;
    struct edfs_key_data *key = edfs_context->key_data;
    while (key) {
        if (key->js_window)
            windows ++;
        key = (struct edfs_key_data *)key->next_key;
    }
    return windows;
}

int edfs_verify_window_event(struct edfs *edfs_context, void *window) {
    if ((!edfs_context) || (!window))
        return 0;
    struct edfs_key_data *key = edfs_context->key_data;
    while (key) {
        if (key->js_window == window) {
            log_trace("JS ui event dispatched");
            edfs_key_js_call(key, "edwork.events.onuievent", NULL);
            return 1;
        }
        key = (struct edfs_key_data *)key->next_key;
    }
    return 0;
}

int edfs_app_mode(struct edfs *edfs_context) {
    if (!edfs_context)
        return 0;
    return (int)edfs_context->app_mode;
}
#endif
