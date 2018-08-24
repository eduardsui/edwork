#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64
#define THREAD_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#ifndef _WIN32
    #include <unistd.h>
#endif
#include <time.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "sha256.h"
#include "base64.h"
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

#define BLOCK_SIZE_MAX      BLOCK_SIZE + 0x3000
#define EDFS_INO_CACHE_ADDR 20

#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...)            fprintf(stderr, __VA_ARGS__)
#define DEBUG_DUMP_HEX(buf, len)    {int __i__; for (__i__ = 0; __i__ < len; __i__++) { DEBUG_PRINT("%02X ", (unsigned int)(buf)[__i__]); } }
#define DEBUG_INDEX(fields)         print_index(fields)
#define DEBUG_DUMP(buf, length)     fwrite(buf, 1, length, stderr);
#define DEBUG_DUMP_HEX_LABEL(title, buf, len)    {fprintf(stderr, "%s (%i): ", title, (int)len); DEBUG_DUMP_HEX(buf, len); fprintf(stderr, "\n");}
#else
#define DEBUG_PRINT(...)            { }
#define DEBUG_DUMP_HEX(buf, len)    { }
#define DEBUG_INDEX(fields)         { }
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

    struct timezone {
        int tz_minuteswest;
        int tz_dsttime;
    };

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

struct dirbuf {
    edfs_ino_t ino;
    void *userdata;
    size_t size;
    int64_t start;
};

struct filewritebuf {
    edfs_ino_t ino;
    unsigned char *p;
    int64_t offset;
    int64_t file_size;

    uint64_t last_read_chunk;

    int last_read_size;
    int size;
    int written_data;

    int check_hash;
    int in_read;
};

struct edwork_io {
    uint64_t ino;
    char type[4];
    unsigned char buffer[EDWORK_PACKET_SIZE];
    int size;
    unsigned char ack;

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

struct edfs {
    int read_only_fs;
    int ping_received;

    int resync;
    int force_rebroadcast;
    char *host_and_port;
    unsigned int list_offset;
    time_t list_timestamp;

    char *working_directory;
    char *cache_directory;
    char *signature;
    char *nodes_file;
    char *default_nodes;

    struct edwork_data *edwork;
    struct edwork_io *queue;

    thread_ptr_t network_thread;
    thread_mutex_t lock;
    thread_mutex_t io_lock;
#ifdef EDFS_MULTITHREADED
    thread_mutex_t thread_lock;
#endif
    int network_done;
    int mutex_initialized;

    int port;

    unsigned char sigkey[MAX_KEY_SIZE];
    unsigned char pubkey[MAX_KEY_SIZE];
    int key_loaded;
    int pub_loaded;
    size_t pub_len;
    int pubkey_size;
    int key_type;
    int signature_size;
    size_t sig_len;

    struct edfs_x25519_key key;

    avl_tree_t ino_cache;
    thread_mutex_t ino_cache_lock;

    int forward_chunks;
};

#ifdef EDFS_MULTITHREADED
    #define EDFS_THREAD_LOCK(edfs_context)      if (edfs_context->mutex_initialized) thread_mutex_lock(&edfs_context->thread_lock);
    #define EDFS_THREAD_UNLOCK(edfs_context)    if (edfs_context->mutex_initialized) thread_mutex_unlock(&edfs_context->thread_lock);
#else
    #define EDFS_THREAD_LOCK(edfs_context)
    #define EDFS_THREAD_UNLOCK(edfs_context)
#endif


int sign(struct edfs *edfs_context, const char *str, int len, unsigned char *hash, int *info_key_type);
int edfs_flush_chunk(struct edfs *edfs_context, edfs_ino_t ino, struct filewritebuf *fi);
unsigned int edwork_resync(struct edfs *edfs_context, void *clientaddr, int clientaddrlen);
unsigned int edwork_resync_desc(struct edfs *edfs_context, uint64_t inode, void *clientaddr, int clientaddrlen);
unsigned int edwork_resync_dir_desc(struct edfs *edfs_context, uint64_t inode, void *clientaddr, int clientaddrlen);
int edwork_encrypt(struct edfs *edfs_context, const unsigned char *buffer, int size, unsigned char *out, const unsigned char *dest_i_am, const unsigned char *src_i_am, const unsigned char *shared_secret);

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
    // nothink
}

void avl_ino_key_data_destructor(void *key, void *data) {
    free(data);
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

    int len = base64_encode((const BYTE *)&in, (BYTE *)out, 16, 0);
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

#ifdef EDFS_HASHCASH_ASCII_STRING
        uint64_t counter_be = htonll(counter);
        const BYTE *counter_ptr = (const BYTE *)&counter_be;
        int offset = 0;
        do {
            if (counter_ptr[offset])
                break;
            offset ++;
        } while (offset < 7);

        len = base64_encode(counter_ptr + offset, (BYTE *)ptr, 8 - offset, 0);
        sha3_Update(&ctx, proof_str, proof_len + len);
#else
        len = 8;
        sha3_Update(&ctx, proof_str, proof_len);
        sha3_Update(&ctx, (unsigned char *)&counter, 8);
#endif

        hash = (const unsigned char *)sha3_Finalize(&ctx);

        if (!memcmp(hash, ref_hash, bytes)) {
            if ((!mbits) || ((hash[bytes] >> mbits) == (ref_hash[bytes] >> mbits))) {
                if (proof_of_work)
                    memcpy(proof_of_work, hash, 32);
#ifndef EDFS_HASHCASH_ASCII_STRING
                memcpy(proof_str + proof_len, &counter, 8);
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
            log_debug("proof to small");
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
                    log_debug("verify buffer to small");
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

void notify_io(struct edfs *edfs_context, const char type[4], const unsigned char *buffer, int buffer_size, const unsigned char *append_data, int append_len, unsigned char ack, int do_sign, uint64_t ino, struct edwork_data *edwork, int proof_of_work, int loose_encrypt, void *use_clientaddr, int clientaddr_len, unsigned char *proof_of_work_cache, int *proof_of_work_size_cache) {
    struct edwork_io *ioblock = (struct edwork_io *)malloc(sizeof(struct edwork_io));
    if (!ioblock) {
        log_error("error allocating ioblock");
        return;
    }

    ioblock->ino = ino;
    memcpy(ioblock->type, type, 4);
    if ((buffer) && (buffer_size > 0) && (append_len >= 0) && (buffer_size + append_len < EDWORK_PACKET_SIZE)) {
        int offset = 0;
        if (do_sign)
            offset = 64;

        memcpy(ioblock->buffer + offset, buffer, buffer_size);
        if (append_len > 0) {
            memcpy(ioblock->buffer + offset + buffer_size, append_data, append_len);
            buffer_size += append_len;
        }
        if (do_sign) {
            memcpy(ioblock->buffer + offset + buffer_size, type, 4);
            int signature_size = sign(edfs_context, (const char *)ioblock->buffer + offset, buffer_size + 4, ioblock->buffer, NULL);
            if (signature_size < 0) {
                free(ioblock);
                log_error("error signing block");
                return;
            }
            buffer_size += offset;
        }
        if (loose_encrypt) {
            unsigned char buf2[BLOCK_SIZE_MAX];
            int size2 = edwork_encrypt(edfs_context, ioblock->buffer, buffer_size, buf2, NULL, edwork_who_i_am(edfs_context->edwork), NULL);
            memcpy(ioblock->buffer, buf2, size2);
            buffer_size = size2;
        }
        if (proof_of_work > 0) {
            if ((proof_of_work_cache) && (proof_of_work_size_cache) && (*proof_of_work_size_cache > 0)) {
                memcpy(ioblock->buffer + buffer_size, proof_of_work_cache, *proof_of_work_size_cache);
                buffer_size += *proof_of_work_size_cache;
            } else {
                sha3_context ctx;
                unsigned char out[64];

                sha3_Init256(&ctx);
                sha3_Update(&ctx, ioblock->buffer + offset, buffer_size);
                if (edwork)
                    sha3_Update(&ctx, edwork_who_i_am(edwork), 32);
                int encode_len = base64_encode((const unsigned char *)sha3_Finalize(&ctx), out, 32, 0);

                int proof_of_work_size = edfs_proof_of_work(proof_of_work, time(NULL), out, encode_len, ioblock->buffer + buffer_size, EDWORK_PACKET_SIZE - buffer_size, NULL);
                if ((proof_of_work_cache) && (proof_of_work_size_cache)) {
                    memcpy(proof_of_work_cache, ioblock->buffer + buffer_size, proof_of_work_size);
                    *proof_of_work_size_cache = proof_of_work_size;
                }
                buffer_size += proof_of_work_size;
            }
        }
        ioblock->size = buffer_size;
    } else {
        ioblock->size = 0;
    }
    ioblock->ack = ack;
    ioblock->next = NULL;

    if (edwork) {
        switch (ack) {
            case 3:
                edwork_broadcast_client(edwork, type, ioblock->buffer, ioblock->size, 0, EDWORK_DATA_NODES, ino, use_clientaddr, clientaddr_len);
                break;
            case 2:
                edwork_broadcast_client(edwork, type, ioblock->buffer, ioblock->size, 1, EDWORK_NODES, ino, use_clientaddr, clientaddr_len);
                break;
            default:
                edwork_broadcast_client(edwork, type, ioblock->buffer, ioblock->size, ack ? EDWORK_NODES : 0, EDWORK_NODES, ino, use_clientaddr, clientaddr_len);
                break;
        }            
        free(ioblock);
        return;
    }
    if (edfs_context->mutex_initialized)
        thread_mutex_lock(&edfs_context->lock);
    if (edfs_context->queue) {
        struct edwork_io *ref_queue = (struct edwork_io *)edfs_context->queue;
        while (ref_queue) {
            if (!ref_queue->next) {
                ref_queue->next = (void *)ioblock;
                break;
            }
            ref_queue = (struct edwork_io *)ref_queue->next;
        }
    } else {
        edfs_context->queue = ioblock;
    }
    if (edfs_context->mutex_initialized)
        thread_mutex_unlock(&edfs_context->lock);
}

char *adjustpath(struct edfs *edfs_context, char *fullpath, const char *name) {
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", edfs_context->working_directory, name);
    return fullpath;
}

char *adjustpath2(struct edfs *edfs_context, char *fullpath, const char *name, uint64_t chunk) {
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s/%" PRIu64, edfs_context->working_directory, name, chunk);
    return fullpath;
}

char *adjustpath3(struct edfs *edfs_context, char *fullpath, const char *name, uint64_t chunk) {
    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s/hash.%" PRIu64, edfs_context->working_directory, name, chunk);
    return fullpath;
}

uint64_t computeinode2(uint64_t parent_inode, const char *name, int name_len) {
    unsigned char hash[32];
    uint64_t inode;

    parent_inode = htonll(parent_inode);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)&parent_inode, sizeof(parent_inode));
    if (name)
        sha256_update(&ctx, (const BYTE *)name, name_len);
    sha256_final(&ctx, hash);

    inode = XXH64(hash, 32, 0);
    return ntohll(inode);
}

uint64_t computeinode(uint64_t parent_inode, const char *name) {
    return computeinode2(parent_inode, name, strlen(name));
}

const char *computename(uint64_t inode, char *out) {
    inode = htonll(inode);
    size_t len = base64_encode((const BYTE *)&inode, (BYTE *)out, sizeof(inode), 0);
    out[len] = 0;
    return (const char *)out;
}

int signature_allows_write(struct edfs *edfs_context) {
    if (!edfs_context)
        return 0;

    JSON_Value *root_value = json_parse_file(edfs_context->signature);
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

        len = 1;
    } else
    if (!strcmp(algorithm, "ED25519")) {
        const char *kty = json_object_get_string(root_object, "kty");
        if ((kty) && (strcmp(kty, "EDD25519"))) {
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
        len = 1;

        if (len) {
            k = json_object_get_string(root_object, "pk");
            if ((!k) || (!k[0])) {
                json_value_free(root_value);
                return 0;
            }
            key_len = strlen(k);
            if ((!key_len) || (key_len > MAX_KEY_SIZE / 2))
                len = 0;
        }
    }

    json_value_free(root_value);
    return len;
}

size_t base64_decode_no_padding(const BYTE in[], BYTE out[], size_t len) {
    int in_len = strlen((const char *)in);
    if (in_len % 3) {
        char buf[BLOCK_SIZE];
        memcpy(buf, in, in_len);
        while (in_len % 3)
            buf[in_len++] = '=';
        buf[in_len] = 0;

        return base64_decode((const BYTE *)buf, out, len);
    }
    return base64_decode(in, out, len);
}

int read_signature(const char *sig, unsigned char *sigdata, int verify, int *key_type, unsigned char *pubdata) {
    JSON_Value *root_value = json_parse_file(sig);
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
        len = base64_decode_no_padding((const BYTE *)k, (BYTE *)sigdata, key_len);
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
        len = base64_decode_no_padding((const BYTE *)k, (BYTE *)sigdata, key_len);
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
                base64_decode_no_padding((const BYTE *)k, (BYTE *)pubdata, MAX_KEY_SIZE);
            }
        }
    }

    json_value_free(root_value);
    return len;
}

int sign(struct edfs *edfs_context, const char *str, int len, unsigned char *hash, int *info_key_type) {
    if (info_key_type)
        *info_key_type = 0;
    if (!edfs_context->key_loaded) {
        EDFS_THREAD_LOCK(edfs_context);
        edfs_context->sig_len = read_signature(edfs_context->signature, edfs_context->sigkey, 0, &edfs_context->key_type, edfs_context->pubkey);
        EDFS_THREAD_UNLOCK(edfs_context);
    }
    if (!edfs_context->sig_len)
        return 0;
    switch (edfs_context->key_type) {
        case KEY_HS256:
            if (info_key_type)
                *info_key_type = edfs_context->key_type;
            hmac_sha256((const BYTE *)edfs_context->sigkey, edfs_context->sig_len, (const BYTE *)str, len, NULL, 0, (BYTE *)hash);
            edfs_context->signature_size = 32;
            edfs_context->key_loaded = 1;
            break;
        case KEY_EDD25519:
            if (info_key_type)
                *info_key_type = edfs_context->key_type;
            ed25519_sign(hash, (const unsigned char *)str, len, edfs_context->pubkey, edfs_context->sigkey);
            edfs_context->signature_size = 64;
            edfs_context->key_loaded = 1;
            break;
    }
    return edfs_context->signature_size;
}

int verify(struct edfs *edfs_context, const char *str, int len, const unsigned char *hash, int hash_size) {
    unsigned char hash2[32];
      
    if (!edfs_context->pub_loaded) {
        EDFS_THREAD_LOCK(edfs_context);
        edfs_context->pub_len = read_signature(edfs_context->signature, edfs_context->pubkey, 1, &edfs_context->key_type, NULL);
        EDFS_THREAD_UNLOCK(edfs_context);
    }

    if (!edfs_context->pub_len) {
        log_error("verify error (no signature found)");
        return 0;
    }
    if (len < 0) {
        log_error("verify error (invalid message length)");
        return 0;
    }
    switch (edfs_context->key_type) {
        case KEY_HS256:
            if (hash_size < 32) {
                log_error("verify error (invalid public key)");
                return 0;
            }
            edfs_context->pub_loaded = 1;
            hmac_sha256((const BYTE *)edfs_context->pubkey, edfs_context->pub_len, (const BYTE *)str, len, NULL, 0, (BYTE *)hash2);
            if (!memcmp(hash2, hash, 32))
                return 1;
            log_warn("verify failed");
            return 0;
            break;
        case KEY_EDD25519:
            if ((hash_size != 64) || (edfs_context->pub_len != 32)) {
                log_error("verify error (invalid hash or public key)");
                return 0;
            }
            edfs_context->pub_loaded = 1;
            if (ed25519_verify(hash, (const unsigned char *)str, len, edfs_context->pubkey))
                return 1;
            log_error("verification failed for %i bytes", len);
            return 0;
            break;
    }
    log_error("unsupported key type");
    return 0;
}

int fwrite_signature(const unsigned char *data, int len, FILE *f, unsigned char *signature, int signature_size) {
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
    return fwrite(data, 1, len, f);
}

int fwrite_compressed(const unsigned char *data, int len, FILE *f, unsigned char *signature, int signature_size, unsigned char *compressed_buffer, mz_ulong *max_len) {
    if (compress(compressed_buffer, max_len, data, len) == Z_OK) {
        int written = fwrite_signature(compressed_buffer, *max_len, f, signature, signature_size);
        if (written > 0)
            written = len;
        return written;
    }
    return -EIO;
}

int fread_signature(unsigned char *data, int len, FILE *f, unsigned char *signature) {
    if (signature) {
        int read_size = fread(signature, 1, 64, f);
        if (read_size != 64) {
            errno = EIO;
            return -EIO;
        }
    }
    return fread(data, 1, len, f);
}

int fread_compressed(unsigned char *data, int len, FILE *f, unsigned char *signature) {
    unsigned char compressed_buffer[BLOCK_SIZE_MAX];
    int bytes_read = fread_signature(compressed_buffer, BLOCK_SIZE_MAX, f, signature);
    if (bytes_read > 0) {
        mz_ulong max_len = len;
        if (uncompress(data, &max_len, compressed_buffer, bytes_read) == Z_OK)
            return max_len;
        errno = EIO;
        return -EIO;
    }
    return bytes_read;
}

int edfs_write_file(struct edfs *edfs_context, const char *base_path, const char *name, const unsigned char *data, int len, const char *suffix, int do_sign, unsigned char *compressed_buffer, mz_ulong *max_len, unsigned char signature[64], int *sig_size) {
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


    if (do_sign) {
        hash_size = sign(edfs_context, (const char *)data, len, hash, NULL);
        if (!hash_size)
            return -EIO;
        if (signature) {
            memcpy(signature, hash, hash_size);
            if (hash_size == 32)
                memset(signature + 32, 0, 32);
        }
        if (sig_size)
            *sig_size = hash_size;
    }

    int written;
    if ((compressed_buffer) && (max_len))
        written = fwrite_compressed(data, len, f, hash, hash_size, compressed_buffer, max_len);
    else
        written = fwrite_signature(data, len, f, hash, hash_size);

    if (written < 0) {
        int err = -errno;
        fclose(f);
        return err;
    }
    fclose(f);
    return written;
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

int edfs_read_file(struct edfs *edfs_context, const char *base_path, const char *name, unsigned char *data, int len, const char *suffix, int as_text_file, int check_signature, int compression, int *filesize, uint32_t signature_hash) {
    FILE *f;
    char fullpath[MAX_PATH_LEN];
    unsigned char sig_buf[BLOCK_SIZE];
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

    int bytes_read;
    if ((compression) || ((check_signature) && ((len < BLOCK_SIZE) && (len > 0)))) {
        if (compression) {
            sig_bytes_read = fread_compressed(sig_buf, BLOCK_SIZE, f, check_signature ? hash : NULL);
        } else {
            sig_bytes_read = fread_signature(sig_buf, BLOCK_SIZE, f, check_signature ? hash : NULL);
        }
        sig_ptr = sig_buf;
        if (sig_bytes_read <= 0) {
            bytes_read = sig_bytes_read;
        } else {
            bytes_read = edfs_min(len, sig_bytes_read);
            memcpy(data, sig_buf, bytes_read);
        }
    } else {
        bytes_read = fread_signature(data, len, f, check_signature ? hash : NULL);
        sig_ptr = data;
        sig_bytes_read = bytes_read;
    }
    if ((bytes_read < 0) || (sig_bytes_read < 0)) {
        int err = -errno;
        fclose(f);
        return err;
    }
    fclose(f);
    if (as_text_file)
        data[bytes_read] = 0;
    if (check_signature) {
        if (verify(edfs_context, (const char *)sig_ptr, sig_bytes_read, hash, sizeof(hash))) {
            if (signature_hash) {
                if (XXH32(hash, sizeof(hash), 0) != signature_hash) {
                    log_warn("different chunk version received");
                    return -EIO;
                }
            }
            return bytes_read;
        }
        return -EIO;
    }

    if (filesize)
        *filesize = sig_bytes_read;

    return bytes_read;
}

int verify_file(struct edfs *edfs_context, const char *base_path, const char *name) {
    unsigned char data[BLOCK_SIZE];
    if (edfs_read_file(edfs_context, base_path, name, data, BLOCK_SIZE, NULL, 0, 1, 0, NULL, 0) <= 0)
        return 0;
    return 1;
}

uint64_t unpacked_ino(const char *data) {
    uint64_t ino = 0;
    if ((data) && (data[0])) {
        unsigned char buf[MAX_B64_HASH_LEN];
        if (base64_decode_no_padding((const BYTE *)data, (BYTE *)buf, strlen(data)) == 8)
            ino = ntohll((*(uint64_t *)buf));
    }
    return ino;
}

void write_json(struct edfs *edfs_context, const char *base_path, const char *name, int64_t size, uint64_t inode, uint64_t parent, int type, unsigned char *last_hash, time_t created, time_t modified, uint64_t timestamp, uint64_t generation) {
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
        int len = base64_encode((const BYTE *)last_hash, (BYTE *)buffer, 32, 0);
        if (len < 0)
            len = 0;
        buffer[len] = 0;

        json_object_set_string(root_object, "iostamp", buffer);
    }
    json_object_set_number(root_object, "version", generation);
    serialized_string = json_serialize_to_string_pretty(root_value);
    int sig_size = sign(edfs_context, serialized_string, strlen(serialized_string), sigdata, NULL);
    if (!sig_size) {
        json_value_free(root_value);
        return;
    }
    int string_len = strlen(serialized_string);
    unsigned char signature[64];
    if (edfs_context->mutex_initialized)
        thread_mutex_lock(&edfs_context->io_lock);
    edfs_write_file(edfs_context, base_path, b64name, (const unsigned char *)serialized_string, string_len, ".json", 1, NULL, NULL, signature, NULL);
    if (edfs_context->mutex_initialized)
        thread_mutex_unlock(&edfs_context->io_lock);

    // do not broadcast root object
    if (parent != 0)
        notify_io(edfs_context, "desc", signature, 64, (const unsigned char *)serialized_string, string_len, 1, 0, inode, edfs_context->edwork, 0, 0, NULL, 0, NULL, NULL);

    json_free_serialized_string(serialized_string);
    json_value_free(root_value);
}

JSON_Value *read_json(struct edfs *edfs_context, const char *base_path, uint64_t inode) {
    char data[MAX_INODE_DESCRIPTOR_SIZE];

    char b64name[MAX_B64_HASH_LEN];
    computename(inode, b64name);

    if (edfs_context->mutex_initialized)
        thread_mutex_lock(&edfs_context->io_lock);
    int data_size = edfs_read_file(edfs_context, base_path, b64name, (unsigned char *)data, MAX_INODE_DESCRIPTOR_SIZE - 1, ".json", 1, 1, 0, NULL, 0);
    if (edfs_context->mutex_initialized)
        thread_mutex_unlock(&edfs_context->io_lock);
    if (data_size <= 0)
        return 0;

    // signature is ok, proceed to processing
    JSON_Value *root_value = json_parse_string(data);
    if (json_value_get_type(root_value) != JSONObject) {
        json_value_free(root_value);
        log_error("invlaid root object in JSON file");
        return 0;
    }
    return root_value;
}

int write_json2(struct edfs *edfs_context, const char *base_path, uint64_t inode, JSON_Value *root_value) {
    char b64name[MAX_B64_HASH_LEN];
    computename(inode, b64name);
    int written = 0;

    char *serialized_string = json_serialize_to_string_pretty(root_value);
    if (!serialized_string)
        return 0;

    if (edfs_context->mutex_initialized)
        thread_mutex_lock(&edfs_context->io_lock);

    int string_len = strlen(serialized_string);
    unsigned char signature[64];
    if (edfs_write_file(edfs_context, edfs_context->working_directory, b64name, (const unsigned char *)serialized_string, string_len , ".json", 1, NULL, NULL, signature, NULL) == string_len) {
        written = string_len;

        JSON_Object *root_object = json_value_get_object(root_value);
        if (root_object) {
            uint64_t parent = unpacked_ino(json_object_get_string(root_object, "parent"));
            if (parent != 0)
                notify_io(edfs_context, "desc", signature, 64, (const unsigned char *)serialized_string, string_len, 1, 0, inode, edfs_context->edwork, 0, 0, NULL, 0, NULL, NULL);
        }
    } else
        log_warn("error writing file %s", b64name);

    if (edfs_context->mutex_initialized)
        thread_mutex_unlock(&edfs_context->io_lock);

    return written;
}

int read_file_json(struct edfs *edfs_context, uint64_t inode, uint64_t *parent, int64_t *size, uint64_t *timestamp, edfs_add_directory add_directory, struct dirbuf *b, char *namebuf, int len_namebuf, time_t *created, time_t *modified, uint64_t *generation, unsigned char *iohash) {
    JSON_Value *root_value = read_json(edfs_context, edfs_context->working_directory, inode);
    if (!root_value) {
        if (inode == 1) {
            // first time root
            char fullpath[MAX_PATH_LEN];
            char b64name[MAX_B64_HASH_LEN];
            EDFS_MKDIR(adjustpath(edfs_context, fullpath, computename(1, b64name)), 0755);
            write_json(edfs_context, edfs_context->working_directory, ".", 0, inode, 0, S_IFDIR | 0755, NULL, 0, 0, 0, 0);
            root_value = read_json(edfs_context, edfs_context->working_directory, inode);
        }
        if (!root_value)
            return 0;
    }
    JSON_Object *root_object = json_value_get_object(root_value);

    if (generation)
        *generation = (uint64_t)json_object_get_number(root_object, "version");

    if ((int)json_object_get_number(root_object, "deleted")) {
        // save only generation for deleted objects
        json_value_free(root_value);
        return 0;
    }

    int type = (int)json_object_get_number(root_object, "type");
    if ((add_directory) || ((namebuf) && (len_namebuf > 0))) {
        const char *name = json_object_get_string(root_object, "name");
        if ((name) && (name[0])) {
            if (add_directory)
                b->size += add_directory(name, inode, type, (int64_t)json_object_get_number(root_object, "size"), (time_t)json_object_get_number(root_object, "created"), (time_t)json_object_get_number(root_object, "modified"), (time_t)(json_object_get_number(root_object, "timestamp") / 1000000), b->userdata);
            if ((namebuf) && (len_namebuf)) {
                int name_len = strlen(name);
                if (name_len > len_namebuf - 1)
                    name_len = len_namebuf - 1;
                memcpy(namebuf, name, name_len);
                namebuf[name_len] = 0;
            }
        }
    }
    if (parent) {
        const char *parent_str = json_object_get_string(root_object, "parent");
        *parent = unpacked_ino(parent_str);
    }
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
            int len = base64_decode_no_padding((const BYTE *)iohash_mime, (BYTE *)iohash, mime_len);
            if (len <= 0)
                memset(iohash, 0, 32);
        } else
            memset(iohash, 0, 32);
    }

    json_value_free(root_value);
    return type;
}

int edfs_update_json(struct edfs *edfs_context, uint64_t inode, const char **keys_value) {
    if ((!keys_value) || (!keys_value[0]))
        return 0;

    JSON_Value *root_value = read_json(edfs_context, edfs_context->working_directory, inode);
    if (!root_value)
        return 0;

    JSON_Object *root_object = json_value_get_object(root_value);

    do {
        const char *key = *(keys_value++);
        const char *value = *(keys_value++);

        if (!strcmp(key, "iostamp")) {
            char buffer[64];
            int len = base64_encode((const BYTE *)value, (BYTE *)buffer, 32, 0);
            if (len < 0)
                len = 0;
            buffer[len] = 0;
            json_object_set_string(root_object, key, buffer);
        } else
            json_object_set_string(root_object, key, value);
    } while (*keys_value);

    json_object_set_number(root_object, "version", json_object_get_number(root_object, "version") + 1);
    json_object_set_number(root_object, "timestamp", microseconds());
    write_json2(edfs_context, edfs_context->working_directory, inode, root_value);
    json_value_free(root_value);

    return 1;
}

int edfs_update_json_number(struct edfs *edfs_context, uint64_t inode, const char *key, double value) {
    if ((!key) || (!key[0]))
        return 0;

    JSON_Value *root_value = read_json(edfs_context, edfs_context->working_directory, inode);
    if (!root_value)
        return 0;

    JSON_Object *root_object = json_value_get_object(root_value);

    double old_value = json_object_get_number(root_object, key);
    if (old_value != value) {
        json_object_set_number(root_object, key, value);
        json_object_set_number(root_object, "version", json_object_get_number(root_object, "version") + 1);
        json_object_set_number(root_object, "timestamp", microseconds());
        write_json2(edfs_context, edfs_context->working_directory, inode, root_value);
    }
    json_value_free(root_value);

    return 1;
}

void truncate_inode(struct edfs *edfs_context, const char *b64name, int64_t new_size, int64_t old_size) {
    int64_t start_offset = new_size / BLOCK_SIZE;
    int64_t end_offset = old_size / BLOCK_SIZE;
    char blockname[MAX_PATH_LEN];
    if ((!USE_COMPRESSION) && (new_size % BLOCK_SIZE)) {
        snprintf(blockname, MAX_PATH_LEN, "%s/%s/%" PRIu64, edfs_context->working_directory, b64name, (uint64_t)start_offset);
        log_info("truncating block %s", blockname);
        if (truncate(blockname, new_size % BLOCK_SIZE))
            log_error("error truncating block %s", blockname);
        start_offset++;
    }
    while (start_offset <= end_offset) {
        snprintf(blockname, MAX_PATH_LEN, "%s/%s/%" PRIu64, edfs_context->working_directory, b64name, (uint64_t)start_offset);
        log_info("dropping block %s", blockname);
        if (unlink(blockname))
            log_error("error dropping block %s", blockname);
        start_offset++;
    }
}

int update_file_json(struct edfs *edfs_context, uint64_t inode, edfs_stat *attr, int to_set, edfs_stat *new_attr) {
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
    int type = read_file_json(edfs_context, inode, &parent, &size, &timestamp, NULL, NULL, name, MAX_PATH_LEN, &created, &modified, &generation, hash);
    if ((!type) || (name[0] == 0))
        return 0;

    char b64name[MAX_B64_HASH_LEN];
    computename(inode, b64name);

    if ((to_set & EDFS_SET_ATTR_SIZE) && (type & S_IFREG)) {
        truncate_inode(edfs_context, b64name, attr->st_size, size);
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

    write_json(edfs_context, edfs_context->working_directory, name, size, inode, parent, type, hash, created, modified, 0, generation + 1);
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

int makesyncnode(struct edfs *edfs_context, const char *parentb64name, const char *b64name, const char *name) {
    char fullpath[MAX_PATH_LEN];
    
    // if directory exists, silently ignore it
    EDFS_MKDIR(adjustpath(edfs_context, fullpath, b64name), 0755);
        
    // silently try to make parent node (if not available)
    EDFS_MKDIR(adjustpath(edfs_context, fullpath, parentb64name), 0755);

    unsigned char hash[32];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)&name, strlen(name));
    sha256_update(&ctx, (const BYTE *)&parentb64name, strlen(parentb64name));
    sha256_final(&ctx, hash);

    return edfs_write_file(edfs_context, fullpath, b64name, (const unsigned char *)hash, 32, NULL, 1, NULL, NULL, NULL, NULL);
}

int pathhash(struct edfs *edfs_context, const char *path, unsigned char *hash) {
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
                if (verify_file(edfs_context, path, file.name))
                    sha256_update(&ctx, (const BYTE *)file.name, strlen(file.name));
            }
            tinydir_next(&dir);
        }
        tinydir_close(&dir);
    }
    sha256_final(&ctx, hash);
    return r;
}

int makenode(struct edfs *edfs_context, edfs_ino_t parent, const char *name, int attr, edfs_ino_t *inode_ref) {
    char fullpath[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    char parentb64name[MAX_B64_HASH_LEN];
    unsigned char old_hash[32];
    unsigned char new_hash[32];
    
    uint64_t inode = computeinode(parent, name);
    if (inode_ref)
        *inode_ref = inode;
    
    int type = read_file_json(edfs_context, parent, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, old_hash);
    if (!type)
        return -EPERM;

    int err = EDFS_MKDIR(adjustpath(edfs_context, fullpath, computename(inode, b64name)), 0755);

    if (attr & S_IFDIR)
        attr |= 0755;
    else
        attr |= 0644;

    uint64_t version = (uint64_t)0;

    // increment version for previously deleted object, if any
    read_file_json(edfs_context, inode, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, &version, NULL);

    write_json(edfs_context, edfs_context->working_directory, name, 0, inode, parent, attr, NULL, 0, 0, 0, version);
    
    adjustpath(edfs_context, fullpath, computename(parent, parentb64name));

    unsigned char hash[40];
    SHA256_CTX ctx;

    uint64_t now = htonll(microseconds());
    memcpy(hash, &now, sizeof(uint64_t));

    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)&name, strlen(name));
    sha256_update(&ctx, (const BYTE *)&parentb64name, strlen(parentb64name));
    sha256_final(&ctx, hash + 8);

    err = edfs_write_file(edfs_context, fullpath, b64name, (const unsigned char *)hash, 40, NULL, 1, NULL, NULL, NULL, NULL);

    if (err > 0) {
        pathhash(edfs_context, fullpath, new_hash);
        const char *update_data[] = {"iostamp", (const char *)new_hash, NULL, NULL};
        edfs_update_json(edfs_context, parent, update_data);
    }
    return err;
}

int edfs_setattr(struct edfs *edfs_context, edfs_ino_t ino, edfs_stat *attr, int to_set) {
    if (update_file_json(edfs_context, ino, attr, to_set, NULL))
        return 0;
    return -ENOENT;
}

int edfs_getattr(struct edfs *edfs_context, edfs_ino_t ino, edfs_stat *stbuf) {
    int64_t size = 0;
    uint64_t timestamp = 0;
    time_t modified = 0;
    time_t created = 0;

    int type = read_file_json(edfs_context, ino, NULL, &size, &timestamp, NULL, NULL, NULL, 0, &created, &modified, NULL, NULL);
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

int edfs_lookup_inode(struct edfs *edfs_context, edfs_ino_t inode, const char *ensure_name) {
    char namebuf[MAX_PATH_LEN];
    int type = read_file_json(edfs_context, inode, NULL, NULL, NULL, NULL, NULL, ensure_name ? namebuf : NULL, ensure_name ? sizeof(namebuf) : 0, NULL, NULL, NULL, NULL);
    if ((type) && (ensure_name) && (strncmp(namebuf, ensure_name, sizeof(namebuf)))) {
        log_error("%s collides with %s", ensure_name, namebuf);
        return 0;
    }
    return type;
}

edfs_ino_t edfs_lookup(struct edfs *edfs_context, edfs_ino_t parent, const char *name, edfs_stat *stbuf) {
    int64_t size = 0;
    uint64_t timestamp = 0;
    time_t modified = 0;
    time_t created = 0;

    uint64_t inode = computeinode(parent, name);
    int type = read_file_json(edfs_context, inode, NULL, &size, &timestamp, NULL, NULL, NULL, 0, &created, &modified, NULL, NULL);
    if (!type)
        return 0;

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

int edfs_reply_chunk(struct edfs *edfs_context, edfs_ino_t ino, uint64_t chunk, unsigned char *buf, int size) {
    if (size <= 0)
        return -1;

    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];
    char name[MAX_PATH_LEN];

    snprintf(name, MAX_PATH_LEN, "%s/%" PRIu64, adjustpath(edfs_context, fullpath, computename(ino, b64name)), (uint64_t)chunk);

    FILE *f = fopen(name, "rb");
    if (!f)
        return -errno;

    int err = fread(buf, 1, size, f);
    fclose(f);

    return err;
}

int edfs_reply_hash(struct edfs *edfs_context, edfs_ino_t ino, uint64_t chunk, unsigned char *buf, int size) {
    if (size <= 0)
        return -1;

    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];
    char name[MAX_PATH_LEN];

    snprintf(name, MAX_PATH_LEN, "%s/hash.%" PRIu64, adjustpath(edfs_context, fullpath, computename(ino, b64name)), (uint64_t)chunk);

    FILE *f = fopen(name, "rb");
    if (!f)
        return -errno;

    int err = fread(buf, 1, size, f);
    fclose(f);

    return err;
}

void request_data(struct edfs *edfs_context, edfs_ino_t ino, uint64_t chunk, int encrypted, int use_cached_addr, unsigned char *proof_cache, int *proof_size) {
    unsigned char additional_data[16];
    *(uint64_t *)additional_data = htonll(ino);
    *(uint64_t *)(additional_data + 8)= htonll(chunk);

    struct sockaddr_in *use_clientaddr = NULL;
    int clientaddr_size = 0;
    struct sockaddr_in addrbuffer;
    if (use_cached_addr) {
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&edfs_context->ino_cache_lock);
        struct edfs_ino_cache *avl_cache = (struct edfs_ino_cache *)avl_search(&edfs_context->ino_cache, (void *)(uintptr_t)ino);
        // at least 2 nodes
        if ((avl_cache) && (avl_cache->len >= 1)) {
            memcpy(&addrbuffer, &avl_cache->clientaddr[edwork_random() % avl_cache->len], avl_cache->clientaddr_size);
            use_clientaddr = &addrbuffer;
            clientaddr_size = avl_cache->clientaddr_size;
        }
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&edfs_context->ino_cache_lock);
    }

    EDFS_THREAD_LOCK(edfs_context);
    if (encrypted)
        notify_io(edfs_context, "wan4", additional_data, sizeof(additional_data), edfs_context->key.pk, 32, 0, 0, ino, edfs_context->edwork, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
    else
    // 25% encrypted packages to avoid some problems with firewalls
    if (edwork_random() % 4)
        notify_io(edfs_context, "want", additional_data, sizeof(additional_data), NULL, 0, 0, 0, ino, edfs_context->edwork, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
    else
        notify_io(edfs_context, "wan3", additional_data, sizeof(additional_data), NULL, 0, 0, 0, ino, edfs_context->edwork, EDWORK_WANT_WORK_LEVEL, 0, use_clientaddr, clientaddr_size, proof_cache, proof_size);
    EDFS_THREAD_UNLOCK(edfs_context);
}

void edfs_make_key(struct edfs *edfs_context) {
    edwork_random_bytes(edfs_context->key.secret, 32);

    edfs_context->key.secret[0] &= 248;
    edfs_context->key.secret[31] &= 127;
    edfs_context->key.secret[31] |= 64;

    curve25519(edfs_context->key.pk, edfs_context->key.secret, NULL);
}

int edfs_file_exists(const char *name) {
    struct stat statbuf;   
    return (stat(name, &statbuf) == 0);
}

int chunk_exists(const char *path, uint64_t chunk) {
    char name[MAX_PATH_LEN];
    name[0] = 0;
    snprintf(name, MAX_PATH_LEN, "%s/%" PRIu64, path, (uint64_t)chunk);

    struct stat statbuf;   
    return (stat(name, &statbuf) == 0);
}

uint32_t edfs_get_hash(struct edfs *edfs_context, const char *path, edfs_ino_t ino, uint64_t chunk) {
    uint32_t hash = 0;
    char hash_file[0x100];
    unsigned char buffer[BLOCK_SIZE];
    hash_file[0] = 0;

    int chunks_per_file = BLOCK_SIZE / sizeof(uint32_t);
    uint64_t hash_chunk = chunk / chunks_per_file;
    unsigned int chunk_offset = chunk % chunks_per_file;

    snprintf(hash_file, sizeof(hash_file), "hash.%" PRIu64, hash_chunk);
    int read_size = edfs_read_file(edfs_context, path, hash_file, buffer, BLOCK_SIZE, NULL, 0, 1, 0, NULL, 0);
    if (read_size < 0)
        read_size = 0;
    unsigned int offset = chunk_offset * sizeof(uint32_t);
    if (read_size < offset + sizeof(uint32_t))
        return 0;

    memcpy(&hash, buffer + offset, sizeof(uint32_t));

    return ntohl(hash);
}


int broadcast_edfs_read_file(struct edfs *edfs_context, const char *path, const char *name, unsigned char *buf, int size, edfs_ino_t ino, uint64_t chunk, struct filewritebuf *filebuf) {
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
    if (filebuf->file_size % BLOCK_SIZE == 0)
        last_file_chunk--;

    if (filebuf->check_hash)
        sig_hash = edfs_get_hash(edfs_context, path, ino, chunk);
    int use_addr_cache = 1;
    do {
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&edfs_context->io_lock);
        int filesize;
        int read_size = edfs_read_file(edfs_context, path, name, (unsigned char *)buf, (int)size, NULL, 0, 1, USE_COMPRESSION, &filesize, sig_hash);
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&edfs_context->io_lock);

#ifdef EDFS_REMOVE_INCOMPLETE_CHUNKS
        if ((read_size > 0) && (read_size < size) && (chunk < filebuf->last_read_chunk)) {
            // incomplete chunk, remove it
            if (filesize < BLOCK_SIZE)
                edfs_unlink_file(edfs_context, path, name);
            read_size = -2;
        }
#endif
        if (read_size < 0) {
            if (microseconds() - start >= EDWORK_MAX_RETRY_TIMEOUT * 1000) {
                log_error("read timed out");
                break;
            }
            if ((microseconds() - last_key_timestamp >= 1000000)) {
                // new key every second
                EDFS_THREAD_LOCK(edfs_context);
                edfs_make_key(edfs_context);
                EDFS_THREAD_UNLOCK(edfs_context);
                last_key_timestamp = microseconds();
                // new proof every second
                proof_size = 0;
            }
            if (microseconds() - start >= 1000000)
                use_addr_cache = 0;
            // end of file, no more quries
            // this is made to avoid an unnecessary edwork query
            if ((filebuf) && (filebuf->file_size > 0)) {
                if (chunk > last_file_chunk)
                    return read_size;
            }

            request_data(edfs_context, ino, chunk, 1, use_addr_cache, proof_cache, &proof_size);
            log_trace("requesting chunk %s:%" PRIu64, path, chunk);
#ifndef EDFS_NO_FORWARD_WAIT
            if (forward_chunks_requested < edfs_context->forward_chunks) {
                while (chunk_exists(path, forward_chunk))
                    forward_chunk ++;
                if (forward_chunk <= last_file_chunk) {
                    forward_chunks_requested ++;
                    request_data(edfs_context, ino, forward_chunk ++, 1, 1, NULL, NULL);
                    continue;
                }
            }
#endif
            int wait_count = 20;
            while ((!chunk_exists(path, chunk)) && (wait_count-- >= 0)) {
#ifdef _WIN32
                Sleep(1);
#else
                usleep(1000);
#endif
            }
        } else {
            if ((filebuf) && (read_size > 0)) {
                filebuf->last_read_chunk = chunk;
                filebuf->last_read_size = read_size;
            }
            return read_size;
        }
        i++;
    } while (1);
    return -EIO;
}

int read_chunk(struct edfs *edfs_context, const char *path, int64_t chunk, char *buf, size_t size, edfs_ino_t ino, int64_t offset, struct filewritebuf *filebuf) {
    if (offset > 0) {
        int max_size = BLOCK_SIZE - offset;
        if (size > max_size)
            size = max_size;
    }

    if (size <= 0)
        return 0;

    if (size > BLOCK_SIZE)
        size = BLOCK_SIZE;

    char name[MAX_PATH_LEN];
    snprintf(name, MAX_PATH_LEN, "%" PRIu64, (uint64_t)chunk);
    if (!offset) {
        int err = broadcast_edfs_read_file(edfs_context, path, name, (unsigned char *)buf, size, ino, chunk, filebuf);
        if (err == -ENOENT)
            return 0;
        return err;
    }

    unsigned char block_data[BLOCK_SIZE];
    int read_size = broadcast_edfs_read_file(edfs_context, path, name, block_data, (int)offset + size, ino, chunk, filebuf);
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

int edfs_update_chain(struct edfs *edfs_context, uint64_t ino, int64_t file_size, unsigned char *hash, uint64_t *hash_chunks) {
    char fullpath[MAX_PATH_LEN];
    char fullpath2[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    unsigned char signature_data[64];
    uint64_t i;

    uint64_t file_chunks = file_size / BLOCK_SIZE;

    if (file_size % BLOCK_SIZE)
        file_chunks ++;

    int chunks_per_hash = BLOCK_SIZE / sizeof(uint32_t);
    uint64_t max_chunk = file_chunks / chunks_per_hash;

    if (file_chunks % chunks_per_hash)
        max_chunk ++;

    if (hash_chunks)
        *hash_chunks = max_chunk;

    adjustpath(edfs_context, fullpath, computename(ino, b64name));

    SHA256_CTX ctx;
    sha256_init(&ctx);
    for (i = 0; i < max_chunk; i++) {
        fullpath2[0] = 0;
        snprintf(fullpath2, MAX_PATH_LEN, "%s/hash.%" PRIu64, fullpath, i);
        FILE *f = fopen(fullpath2, "rb");
        if (!f) {
            log_error("error reading %s", fullpath2);
            return 0;
        }
        if (fread(signature_data, 1, 64, f) != 64) {
            fclose(f);
            log_error("error reading signature in %s", fullpath2);
            return 0;
        }
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

    char b64name[MAX_B64_HASH_LEN];
    int type = read_file_json(edfs_context, ino, &parent, NULL, &timestamp, NULL, NULL, NULL, 0, &created, &modified, NULL, NULL);
    if (type & S_IFDIR) {
        struct dirbuf dirbuf_container;
        computename(ino, b64name);
        char fullpath[MAX_PATH_LEN];
        adjustpath(edfs_context, fullpath, b64name);

        tinydir_dir dir;
        if (tinydir_open(&dir, fullpath))
            return -EBUSY;

        struct dirbuf *b = dbuf;
        if (!b) {
            b = &dirbuf_container;
            memset(b, 0, sizeof(struct dirbuf));
        }
        b->userdata = userdata;

        if ((add_directory) && (!off)) {
            b->size += add_directory(".", ino, type, 0, created, modified, timestamp / 1000000, userdata);
            b->size += add_directory("..", ino, type, 0, created, modified, timestamp / 1000000, userdata);
        }
        int64_t index = 0;
        int64_t start_at = b->start;

        if (b->size < off + size) {
            while (dir.has_next) {
                tinydir_file file;
                tinydir_readfile(&dir, &file);
                index ++;
                if ((start_at < index) && (!file.is_dir)) {
                    if (verify_file(edfs_context, fullpath, file.name)) {
                        read_file_json(edfs_context, unpacked_ino(file.name), NULL, NULL, NULL, add_directory, b, NULL, 0, NULL, NULL, NULL, NULL);
                        if (b->size >= off + size)
                            break;
                    }
                }
                tinydir_next(&dir);
            }
            if (b->start < index)
                b->start = index;
        }
        tinydir_close(&dir);
    } else {
        return -ENOTDIR;
    }
    return 0;
}

int edfs_releasedir(struct dirbuf *buf) {
    if (buf)
        free(buf);
    return 0;
}

int edfs_open(struct edfs *edfs_context, edfs_ino_t ino, int flags, struct filewritebuf **fbuf) {
    int64_t size = 0;
    static unsigned char null_hash[32];
    unsigned char hash[32];
    unsigned char computed_hash[32];
    int type = read_file_json(edfs_context, ino, NULL, &size, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash);
    if (!type)
        return -EACCES;
    if (type & S_IFDIR)
        return -EISDIR;
    if (fbuf) {
        if ((edfs_context->read_only_fs) && ((flags & 3) != O_RDONLY))
            return -EROFS;

        int check_hash = 0;
        if ((size > 0) && (memcmp(hash, null_hash, 32))) {
            // file hash hash
            int valid_hash = 0;
            uint64_t max_chunks;
            uint64_t i;
            unsigned char additional_data[16];
            *(uint64_t *)additional_data = htonll(ino);
            uint64_t start = microseconds();
            int send_want = 1;
            do {
                if (edfs_update_chain(edfs_context, ino, size, computed_hash, &max_chunks)) {
                    if (!memcmp(hash, computed_hash, 32)) {
                        valid_hash = 1;
                        break;
                    }
                }
                if (send_want) {
                    notify_io(edfs_context, "wand", additional_data, 8, NULL, 0, 0, 0, ino, edfs_context->edwork, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
                    send_want = 0;
                }
                for (i = 0; i < max_chunks; i++) {
                    *(uint64_t *)(additional_data + 8)= htonll(i);
                    EDFS_THREAD_LOCK(edfs_context);
                    notify_io(edfs_context, "hash", additional_data, sizeof(additional_data), edfs_context->key.pk, 32, 0, 0, ino, edfs_context->edwork, EDWORK_WANT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
                    EDFS_THREAD_UNLOCK(edfs_context);
                }
                if (microseconds() - start >= EDWORK_MAX_RETRY_TIMEOUT * 1000) {
                    log_error("hash read timed out");
                    break;
                }
#ifdef _WIN32
                Sleep(5);
#else
                usleep(5000);
#endif
                read_file_json(edfs_context, ino, NULL, &size, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash);
            } while (!valid_hash);

            if (valid_hash) {
                check_hash = 1;
                log_trace("hash is valid");
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
        }
    }

    return 0;
}

int edfs_create(struct edfs *edfs_context, edfs_ino_t parent, const char *name, mode_t mode, uint64_t *inode, struct filewritebuf **buf) {
    if (edfs_context->read_only_fs)
        return -EROFS;

    int err = makenode(edfs_context, parent, name, S_IFREG | 0644, inode);
    if (err <  0)
        return -EACCES;

    if (buf) {
        *buf = (struct filewritebuf *)malloc(sizeof(struct filewritebuf));
        if (*buf) {
            memset(*buf, 0, sizeof(struct filewritebuf));
            (*buf)->ino = *inode;
        }
    }

    return 0;
}

edfs_ino_t edfs_inode(struct filewritebuf *filebuf) {
    if (filebuf)
        return filebuf->ino;
    return 0;
}

int edfs_read(struct edfs *edfs_context, edfs_ino_t ino, size_t size, int64_t off, char *ptr, struct filewritebuf *filebuf) {
    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    if (filebuf) {
        ++ filebuf->in_read;
        edfs_flush_chunk(edfs_context, ino, filebuf);
    }

    adjustpath(edfs_context, fullpath, computename(ino, b64name));

    int64_t chunk = off / BLOCK_SIZE;
    int64_t offset = off % BLOCK_SIZE;
    size_t bytes_read = 0;

    char *buf = ptr;
    while (size > 0) {
        int read_bytes = read_chunk(edfs_context, fullpath, chunk, buf, size, ino, offset, filebuf);
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
    if (filebuf)
        -- filebuf->in_read;
    return bytes_read;
}

int edfs_set_size(struct edfs *edfs_context, uint64_t inode, int64_t new_size) {
    edfs_update_json_number(edfs_context, inode, "size", (double)new_size);
    return 1;
}

int64_t get_size_json(struct edfs *edfs_context, uint64_t inode) {
    int64_t size;

    int type = read_file_json(edfs_context, inode, NULL, &size, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL);
    if (!type)
        return 0;

    return size;
}

int edfs_update_hash(struct edfs *edfs_context, const char *path, int64_t chunk, const unsigned char *buf, int size) {
    uint32_t hash = htonl(XXH32(buf, size, 0));
    char hash_file[0x100];
    unsigned char buffer[BLOCK_SIZE];
    hash_file[0] = 0;

    int chunks_per_file = BLOCK_SIZE / sizeof(uint32_t);
    uint64_t hash_chunk = chunk / chunks_per_file;
    unsigned int chunk_offset = chunk % chunks_per_file;

    snprintf(hash_file, sizeof(hash_file), "hash.%" PRIu64, hash_chunk);
    int read_size = edfs_read_file(edfs_context, path, hash_file, buffer, BLOCK_SIZE, NULL, 0, 1, 0, NULL, 0);
    if (read_size < 0)
        read_size = 0;
    unsigned int offset = chunk_offset * sizeof(uint32_t);
    if (read_size < offset + sizeof(uint32_t)) {
        if (read_size < offset)
            memset(buffer + read_size, 0, offset - read_size);
        read_size = offset + sizeof(uint32_t);
    }
    memcpy(buffer + offset, &hash, sizeof(uint32_t));
    edfs_write_file(edfs_context, path, hash_file, buffer, read_size, NULL, 1, NULL, NULL, NULL, NULL);
    return 0;
}

int make_chunk(struct edfs *edfs_context, edfs_ino_t ino, const char *path, int64_t chunk, const char *buf, size_t size, int64_t offset, int64_t *filesize) {
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

    int read_data = edfs_read_file(edfs_context, path, name, old_data, BLOCK_SIZE, NULL, 0, 1, USE_COMPRESSION, NULL, 0);
    const unsigned char *ptr;

    *(uint64_t *)additional_data = htonll(ino);
    *(uint64_t *)(additional_data + 8) = htonll(chunk);
    *(uint64_t *)(additional_data + 16) = htonll(microseconds());
    *(uint64_t *)(additional_data + 24) = htonll(size);

    if (read_data > 0) {
        if ((read_data >= offset + size) && (!memcmp(old_data + offset, buf, size)))
            return size;

        int to_write = offset + size;
        if (to_write > BLOCK_SIZE)
            to_write = BLOCK_SIZE;
        if (offset) {
            // set to 0, to avoid potential information leak
            memset(old_data + read_data, 0, BLOCK_SIZE - read_data);

            memcpy(old_data + offset, buf, size);
            ptr = (const unsigned char *)old_data;
        } else
            ptr = (const unsigned char *)buf;

        block_written = edfs_write_file(edfs_context, path, name, (const unsigned char *)ptr, (int)to_write, NULL, 1, compressed_buffer, USE_COMPRESSION ? &max_len : NULL, additional_data + 32, NULL);
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
            if (to_write == BLOCK_SIZE) {
                if (USE_COMPRESSION) {
                    *(uint64_t *)(additional_data + 24) = htonll(max_len);
                    notify_io(edfs_context, "data", additional_data, sizeof(additional_data), (const unsigned char *)compressed_buffer, max_len, 3, 1, ino, edfs_context->edwork, 0, EDFS_DATA_BROADCAST_ENCRYPTED, NULL, 0, NULL, NULL);
                } else
                    notify_io(edfs_context, "data", additional_data, sizeof(additional_data), (const unsigned char *)ptr, to_write, 3, 1, ino, edfs_context->edwork, 0, EDFS_DATA_BROADCAST_ENCRYPTED, NULL, 0, NULL, NULL);
            }
            edfs_update_hash(edfs_context, path, chunk, additional_data + 32, 64);
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

        written_bytes = edfs_write_file(edfs_context, path, name, (const unsigned char *)old_data, (int)offset + size, NULL, 1, compressed_buffer, USE_COMPRESSION ? &max_len : NULL, additional_data + 32, NULL);
    } else
    if (offset) {
        return -EBUSY;
    } else
        written_bytes = edfs_write_file(edfs_context, path, name, (const unsigned char *)buf, (int)size, NULL, 1, compressed_buffer, USE_COMPRESSION ? &max_len : NULL, additional_data + 32, NULL);
    if (written_bytes > 0) {
        *filesize += written_bytes;
        if (written_bytes == BLOCK_SIZE) {
            if (USE_COMPRESSION) {
                *(uint64_t *)(additional_data + 24) = htonll(max_len);
                notify_io(edfs_context, "data", additional_data, sizeof(additional_data), (const unsigned char *)compressed_buffer, max_len, 3, 1, ino, edfs_context->edwork, 0, EDFS_DATA_BROADCAST_ENCRYPTED, NULL, 0, NULL, NULL);
            } else
                notify_io(edfs_context, "data", additional_data, sizeof(additional_data), (const unsigned char *)buf, size, 3, 1, ino, edfs_context->edwork, 0, EDFS_DATA_BROADCAST_ENCRYPTED, NULL, 0, NULL, NULL);
        }
        edfs_update_hash(edfs_context, path, chunk, additional_data + 32, 64);
    }
    return written_bytes;
}

int edfs_write_block(struct edfs *edfs_context, uint64_t inode, int64_t chunk, const unsigned char *data, size_t size, time_t timestamp) {
    char fullpath[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    adjustpath2(edfs_context, fullpath, computename(inode, b64name), chunk);

    struct stat attrib;
    if ((timestamp) && (!stat(fullpath, &attrib))) {
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

    FILE *f = fopen(fullpath, "w+b");
    if (!f) {
        log_error("error opening block file %s", fullpath);
        return -1;
    }

    unsigned char signature[64];
    if (size >= 64) {
        if (fread(signature, 1, 64, f) == 64) {
            if (!memcmp(signature, data, 64)) {
                log_debug("file block is exactly the same, not rewriting");
                fclose(f);
                return -1;
            }
        }
        fseek(f, 0, SEEK_SET);
    }
    int written = fwrite(data, 1, size, f);
    if (written < 0)
        log_error("error writing %i bytes to file %s (errno: %i)", fullpath, errno);

    fclose(f);

    return written;
}

int edfs_write_hash_block(struct edfs *edfs_context, uint64_t inode, int64_t chunk, const unsigned char *data, size_t size, time_t timestamp) {
    char fullpath[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    adjustpath3(edfs_context, fullpath, computename(inode, b64name), chunk);

    struct stat attrib;
    if ((timestamp) && (!stat(fullpath, &attrib))) {
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

    FILE *f = fopen(fullpath, "w+b");
    if (!f) {
        log_error("error opening hash file %s", fullpath);
        return -1;
    }

    unsigned char signature[64];
    if (size >= 64) {
        if (fread(signature, 1, 64, f) == 64) {
            if (!memcmp(signature, data, 64)) {
                log_debug("hash block is exactly the same, not rewriting");
                fclose(f);
                return -1;
            }
        }
        fseek(f, 0, SEEK_SET);
    }
    int written = fwrite(data, 1, size, f);
    if (written < 0)
        log_error("error writing %i bytes to file %s (errno: %i)", fullpath, errno);

    fclose(f);

    return written;
}

int edfs_write_chunk(struct edfs *edfs_context, edfs_ino_t ino, const char *buf, size_t size, int64_t off, int64_t *initial_filesize, int set_size) {
    char b64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    adjustpath(edfs_context, fullpath, computename(ino, b64name));

    int64_t chunk = off / BLOCK_SIZE;
    int64_t offset = off % BLOCK_SIZE;
    size_t bytes_written = 0;

    int64_t filesize = *initial_filesize;
    while (size > 0) {
        int written = make_chunk(edfs_context, ino, fullpath, chunk, buf, size, offset, &filesize);
        if (written <= 0) {
            if (filesize != *initial_filesize) {
                if (set_size)
                    edfs_set_size(edfs_context, ino, filesize);
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
            edfs_set_size(edfs_context, ino, filesize);
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
        int64_t initial_filesize = get_size_json(edfs_context, ino);
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&edfs_context->io_lock);
        int64_t filesize = initial_filesize;
        fbuf->file_size = filesize;
        while (size > 0) {
            err = edfs_write_chunk(edfs_context, ino, (const char *)p, edfs_min(BLOCK_SIZE, size), offset, &filesize, 0);
            if (err <= 0)
                break;

            p += err;
            size -= err;
            offset += err;
            fbuf->written_data = 1;
        }
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&edfs_context->io_lock);

        if (offset > initial_filesize) {
             edfs_set_size(edfs_context, ino, filesize);
             fbuf->file_size = filesize;
        }
        free(fbuf->p);
        fbuf->p = NULL;
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
    int64_t initial_filesize = get_size_json(edfs_context, ino);
    return edfs_write_chunk(edfs_context, ino, buf, size, off, &initial_filesize, ((off + size) > initial_filesize));
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

        edfs_flush_chunk(edfs_context, fbuf->ino, fbuf);
        if (fbuf->written_data) {
            unsigned char hash[32];
            if (edfs_update_chain(edfs_context, fbuf->ino, fbuf->file_size, hash, NULL)) {
                const char *update_data[] = {"iostamp", (const char *)hash, NULL, NULL};
                edfs_update_json(edfs_context, fbuf->ino, update_data);
            } else
                log_error("error updating chain");
        }
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&edfs_context->ino_cache_lock);
        void *ino_cache = avl_remove(&edfs_context->ino_cache, (void *)(uintptr_t)fbuf->ino);
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&edfs_context->ino_cache_lock);
        free(ino_cache);
        free(fbuf->p);
        free(fbuf);
    }
    return 0;
}

int edfs_mkdir(struct edfs *edfs_context, edfs_ino_t parent, const char *name, mode_t mode) {
    if (edfs_context->read_only_fs)
        return -EROFS;

    uint64_t inode;
    return makenode(edfs_context, parent, name, S_IFDIR | 0755, &inode);
}

struct dirbuf *edfs_opendir(struct edfs *edfs_context, edfs_ino_t ino) {
    unsigned char hash[32];
    static unsigned char null_hash[32];
    int type = read_file_json(edfs_context, ino, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash);
    if ((type & S_IFDIR) == 0)
        return NULL;

    struct dirbuf *buf = (struct dirbuf *)malloc(sizeof(struct dirbuf));
    if (buf) {
        char path[MAX_PATH_LEN];
        char b64name[MAX_B64_HASH_LEN];
        unsigned char computed_hash[32];
        uint64_t network_inode = htonll(ino);
        if (memcmp(hash, null_hash, 32)) {
            snprintf(path, sizeof(path), "%s/%s", edfs_context->working_directory, computename(ino, b64name));
            unsigned char proof_cache[1024];
            int proof_size = 0;

            uint64_t start = microseconds();
            do {
                pathhash(edfs_context, path, computed_hash);
                if (!memcmp(hash, computed_hash, 32)) {
                    log_trace("directory hash ok");
                    break;
                }
                notify_io(edfs_context, "roo2", (const unsigned char *)&network_inode, sizeof(uint64_t), NULL, 0, 0, 0, 0, edfs_context->edwork, EDWORK_ROOT_WORK_LEVEL, 0, NULL, 0, proof_cache, &proof_size);
#ifdef _WIN32
                Sleep(10);
#else
                usleep(10000);
#endif
                if (microseconds() - start >= EDWORK_MAX_DIR_RETRY_TIMEOUT * 1000) {
                    log_warn("directory read timeout, using last known version");
                    break;
                }
                if (!read_file_json(edfs_context, ino, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, hash)) {
                    log_warn("directory does not exists anymore");
                    break;
                }
            } while (1);

        }

        memset(buf, 0, sizeof(struct dirbuf));
        buf->ino = ino;
    }
    return buf;
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

void rehash_parent(struct edfs *edfs_context, edfs_ino_t parent) {
    char parentb64name[MAX_B64_HASH_LEN];
    char fullpath[MAX_PATH_LEN];

    fullpath[0] = 0;
    snprintf(fullpath, MAX_PATH_LEN, "%s/%s", edfs_context->working_directory, computename(parent, parentb64name));

    unsigned char new_hash[32];
    pathhash(edfs_context, fullpath, new_hash);
    const char *update_data[] = {"iostamp", (const char *)new_hash, NULL, NULL};
    edfs_update_json(edfs_context, parent, update_data);
}

int remove_node(struct edfs *edfs_context, edfs_ino_t parent, edfs_ino_t inode, int recursive, uint64_t generation, int is_broadcast) {
    char fullpath[MAX_PATH_LEN];
    char noderef[MAX_PATH_LEN];
    char b64name[MAX_B64_HASH_LEN];
    char parentb64name[MAX_B64_HASH_LEN];
    int err;

    adjustpath(edfs_context, fullpath, computename(inode, b64name));
    if (recursive)
        err = recursive_rmdir(fullpath);
    else
        err = rmdir(fullpath);

    if (err) {
        log_warn("error removing node %s", fullpath, err);
        return 0;
    }

#ifdef EDFS_USE_HARD_DELETE
    strcat(fullpath, ".json");
    unlink(fullpath);
#else
    if (!is_broadcast)
        edfs_update_json_number(edfs_context, inode, "deleted", 1);
#endif
    if (parent != 0) {
        noderef[0] = 0;
        snprintf(noderef, MAX_PATH_LEN, "%s/%s", computename(parent, parentb64name), b64name);
        unlink(adjustpath(edfs_context, fullpath, noderef));
        if (!is_broadcast)
            rehash_parent(edfs_context, parent);
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

    notify_io(edfs_context, "del\x00", hash, 32, NULL, 0, 1, 1, inode, NULL, 0, 0, NULL, 0, NULL, NULL);
#endif
    return 1;
}

int edfs_rmdir_inode(struct edfs *edfs_context, edfs_ino_t parent, edfs_ino_t inode) {
    uint64_t generation;
    int type = read_file_json(edfs_context, inode, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, &generation, NULL);
    if (!type)
        return -ENOENT;
    if (type & S_IFDIR) {
        if (!remove_node(edfs_context, parent, inode, 0, generation, 0))
            return -errno;
        else
            return 0;
    }
    return -ENOTDIR;
}

int edfs_rmdir(struct edfs *edfs_context, edfs_ino_t parent, const char *name) {
    return edfs_rmdir_inode(edfs_context, parent, computeinode(parent, name));
}

int edfs_unlink_inode(struct edfs *edfs_context, edfs_ino_t parent, edfs_ino_t inode) {
    if (edfs_context->read_only_fs)
        return -EROFS;

    uint64_t generation;
    int type = read_file_json(edfs_context, inode, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, &generation, NULL);
    if (!type)
        return -ENOENT;
    if (type & S_IFDIR)
        return -EISDIR;
    else
    if (!remove_node(edfs_context, parent, inode, 1, generation, 0))
        return -errno;

    return 0;
}

int edfs_unlink(struct edfs *edfs_context, edfs_ino_t parent, const char *name) {
    return edfs_unlink_inode(edfs_context, parent, computeinode(parent, name));
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

    if ((mode & S_IFREG) == 0)
        return -EACCES;

    
    return makenode(edfs_context, parent, name, S_IFREG | 0644, inode);
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
    size_t len = base64_encode((const BYTE *)private_key, (BYTE *)b64buffer, 64, 0);
    if (len > 0) {
        b64buffer[len] = 0;
        json_object_set_string(root_object, "k", b64buffer);
    }

    b64buffer[0] = 0;
    len = base64_encode((const BYTE *)public_key, (BYTE *)b64buffer, 32, 0);
    if (len > 0) {
        b64buffer[len] = 0;
        json_object_set_string(root_object, "pk", b64buffer);
    }
    json_serialize_to_file_pretty(root_value, edfs_context->signature);
    json_value_free(root_value);

    return 0;
}

int edwork_process_json(struct edfs *edfs_context, const unsigned char *payload, int size, uint64_t *ino) {
    if (size <= 64)
        return -1;

    log_debug("json: %s", payload + 64);
    if (!verify(edfs_context, (const char *)payload + 64, size - 64, payload, 64)) {
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
        if ((parent == 0) && (inode == 1) && (!deleted) && (b64name)) {
            read_file_json(edfs_context, inode, NULL, NULL, &current_timestamp, NULL, NULL, NULL, 0, NULL, NULL, &current_generation, NULL);
            if ((current_generation > generation) || ((current_generation == generation) && (current_timestamp >= timestamp))) {
                log_warn("refused to update descriptor: received version is older (%" PRIu64 " > %" PRIu64 ")", current_generation, generation);
                json_value_free(root_value);
                return 0;
            }
            if (edfs_context->mutex_initialized)
                thread_mutex_lock(&edfs_context->io_lock);
            if (edfs_write_file(edfs_context, edfs_context->working_directory, b64name, (const unsigned char *)payload, size , ".json", 0, NULL, NULL, NULL, NULL) != size ) {
                log_warn("error writing root file %s", b64name);
                written = -1;
            }
            if (edfs_context->mutex_initialized)
                thread_mutex_unlock(&edfs_context->io_lock);
            return written;
        }
        if ((inode) && (name) && (b64name) && (parent) && (type) && (timestamp)) {
            uint64_t current_parent = 0;
            time_t current_modified = 0;
            time_t current_created = 0;
            int64_t current_size = 0;
            int current_type = read_file_json(edfs_context, inode, &current_parent, &current_size, &current_timestamp, NULL, NULL, NULL, 0, &current_created, &current_modified, &current_generation, NULL);
            int do_write = 1;
            if (current_type) {
                // check all the parameters, not just modified, in case of a setattr(mtime)
                // also, allows a 0.1s difference
                if ((current_generation > generation) || ((current_generation == generation) && (current_timestamp >= timestamp))) {
                    do_write = 0;
                    written = 0;
                    log_warn("refused to update descriptor: received version is older (%" PRIu64 " > %" PRIu64 ")", current_generation, generation);
                } else
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
            } else
            if (deleted) {
                do_write = 0;
                written = 0;
            }
            if (do_write) {
                log_info("sync descriptor for inode %s", b64name);
                if (deleted) {
                    if (type & S_IFDIR)
                        remove_node(edfs_context, parent, inode, 0, generation, 1);
                    else
                        remove_node(edfs_context, parent, inode, 1, generation, 1);
                }
                if (edfs_context->mutex_initialized)
                    thread_mutex_lock(&edfs_context->io_lock);
                if (edfs_write_file(edfs_context, edfs_context->working_directory, b64name, (const unsigned char *)payload, size , ".json", 0, NULL, NULL, NULL, NULL) != size ) {
                    log_warn("error writing file %s", b64name);
                    written = -1;
                } else
                if ((!current_type) && (!deleted))
                    makesyncnode(edfs_context, parentb64name, b64name, name);
                if (edfs_context->mutex_initialized)
                    thread_mutex_unlock(&edfs_context->io_lock);
            } else
            if (!deleted) {
                char path[MAX_PATH_LEN];
                snprintf(path, sizeof(path), "%s/%s/%s", edfs_context->working_directory, parentb64name, b64name);
                if (!edfs_file_exists(path)) {
                    if (edfs_context->mutex_initialized)
                        thread_mutex_lock(&edfs_context->io_lock);
                    makesyncnode(edfs_context, parentb64name, b64name, name);
                    if (edfs_context->mutex_initialized)
                        thread_mutex_unlock(&edfs_context->io_lock);
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

int edwork_cache_addr(struct edfs *edfs_context, uint64_t inode, void *clientaddr, int clientaddrlen) {
    if ((!clientaddr) || (clientaddrlen <= 0))
        return 0;
    if (edfs_context->mutex_initialized)
        thread_mutex_lock(&edfs_context->ino_cache_lock);
    // on 32bit, inode is truncated!
    struct edfs_ino_cache *avl_cache = (struct edfs_ino_cache *)avl_search(&edfs_context->ino_cache, (void *)(uintptr_t)inode);
    if (!avl_cache) {
        avl_cache = (struct edfs_ino_cache *)malloc(sizeof(struct edfs_ino_cache));
        if (!avl_cache) {
            if (edfs_context->mutex_initialized)
                thread_mutex_unlock(&edfs_context->ino_cache_lock);
            return 0;
        }
        memset(avl_cache, 0, sizeof(struct edfs_ino_cache));
        avl_cache->inode = inode;
        avl_cache->clientaddr_size = clientaddrlen;
        avl_insert(&edfs_context->ino_cache, (void *)(uintptr_t)inode, (void *)avl_cache);
    } else
    if (avl_cache->inode != inode) {
        avl_cache->inode = inode;
        memset(avl_cache, 0, sizeof(struct edfs_ino_cache));
    }
    int i;
    for (i = 0; i < avl_cache->len; i++) {
        if (!memcmp(clientaddr, &avl_cache->clientaddr[i], clientaddrlen)) {
            if (edfs_context->mutex_initialized)
                thread_mutex_unlock(&edfs_context->ino_cache_lock);
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
        thread_mutex_unlock(&edfs_context->ino_cache_lock);

    log_trace("caching node (%s)", edwork_addr_ipv4(clientaddr));
    return 1;
}

int edwork_process_data(struct edfs *edfs_context, const unsigned char *payload, int size, int do_verify, void *clientaddr, int clientaddrlen) {
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
        if (!verify(edfs_context, (const char *)buffer, buffer_size, payload, 64)) {
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

            if (!verify(edfs_context, (const char *)compressed_buffer, max_len, payload + delta_size + signature_size, 64)) {
                log_warn("data packet content signature verification failed, dropping");
                return -1;
            }
#else
            if (!verify(edfs_context, (const char *)payload + delta_size + signature_size + 64, datasize - 64, payload + delta_size + signature_size, 64)) {
                log_warn("data packet content signature verification failed, dropping");
                return -1;
            }
#endif
        }

        // includes a signature
        if (signature_size)
            datasize += 64;
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&edfs_context->io_lock);
        int written_bytes = edfs_write_block(edfs_context, inode, chunk, payload + 32 + signature_size, datasize, timestamp / 1000000);
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&edfs_context->io_lock);
        edwork_cache_addr(edfs_context, inode, clientaddr, clientaddrlen);
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

int edwork_process_hash(struct edfs *edfs_context, const unsigned char *payload, int size, void *clientaddr, int clientaddrlen) {
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
        if (!verify(edfs_context, (const char *)payload + delta_size + signature_size + 64, datasize - 64, payload + delta_size + signature_size, 64)) {
            log_warn("dati packet content signature verification failed, dropping");
            return -1;
        }

        // includes a signature
        if (signature_size)
            datasize += 64;
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&edfs_context->io_lock);
        int written_bytes = edfs_write_hash_block(edfs_context, inode, chunk, payload + 32 + signature_size, datasize, timestamp / 1000000);
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&edfs_context->io_lock);
        edwork_cache_addr(edfs_context, inode, clientaddr, clientaddrlen);
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

int edwork_delete(struct edfs *edfs_context, const unsigned char *payload, int size, uint64_t *ino) {
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
    if (!verify(edfs_context, (const char *)buffer, buffer_size, payload, 64)) {
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

    int type = read_file_json(edfs_context, inode, &parent, NULL, &timestamp, NULL, NULL, NULL, 0, NULL, NULL, &generation, NULL);

    if (!type) {
        log_info("nothing to delete (file does not exists)");
        return 0;
    }

    if ((del_generation < generation) || ((del_generation == generation) && (del_timestamp < timestamp + 100000UL ))) {
        log_error("cannot delete inode because it was modified after delete broadcast(%" PRIu64 " > %" PRIu64 ")", generation, del_generation);
        return 0;
    }

    if (type & S_IFDIR)
        return remove_node(edfs_context, parent, inode, 0, generation, 0);

    return remove_node(edfs_context, parent, inode, 1, generation, 0);
}

int edwork_encrypt(struct edfs *edfs_context, const unsigned char *buffer, int size, unsigned char *out, const unsigned char *dest_i_am, const unsigned char *src_i_am, const unsigned char *shared_secret) {
    struct chacha_ctx ctx;
    unsigned char hash[32];

    if (!edfs_context->pub_loaded) {
        EDFS_THREAD_LOCK(edfs_context);
        edfs_context->pub_len = read_signature(edfs_context->signature, edfs_context->pubkey, 1, &edfs_context->key_type, NULL);
        if (edfs_context->pub_len > 0)
            edfs_context->pub_loaded = 1;
        EDFS_THREAD_UNLOCK(edfs_context);
    }

    SHA256_CTX hashctx;
    sha256_init(&hashctx);
    sha256_update(&hashctx, (const BYTE *)"EDFSKEY:", 8);
    if (edfs_context->pub_len > 0)
        sha256_update(&hashctx, (const BYTE *)edfs_context->pubkey, edfs_context->pub_len);
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

int edwork_decrypt(struct edfs *edfs_context, const unsigned char *buffer, int size, unsigned char *out, const unsigned char *dest_i_am, const unsigned char *src_i_am, const unsigned char *shared_secret) {
    // dest and  src reversed
    return edwork_encrypt(edfs_context, buffer, size, out, src_i_am, dest_i_am, shared_secret);
}

int edwork_check_proof_of_work(struct edwork_data *edwork, const unsigned char *payload, unsigned int payload_size, int payload_offset, uint64_t timestamp, int work_level, const char *work_prefix, const unsigned char *who_am_i) {
    const unsigned char *proof_of_work = payload + payload_offset;
    int proof_of_work_size = payload_size - payload_offset;

    if (proof_of_work_size < 10) {
        log_error("proof of work stamp to small");
        return 0;
    }

    sha3_context ctx;
    unsigned char want_hash[64];

    sha3_Init256(&ctx);
    sha3_Update(&ctx, payload, payload_offset);
    if (who_am_i)
        sha3_Update(&ctx, who_am_i, 32);

    int encode_len = base64_encode((const unsigned char *)sha3_Finalize(&ctx), want_hash, 32, 0);

    int proof_timestamp = edfs_proof_of_work_verify(work_level, proof_of_work, proof_of_work_size, want_hash, encode_len, (const unsigned char *)work_prefix, strlen(work_prefix));
    if (!proof_timestamp) {
        log_error("proof of work validation failed");
        return 0;
    }

    int timestamp_epoch = timestamp/1000000;
    if (abs(timestamp_epoch - proof_timestamp) > 60) {
        log_error("proof of work validation failed: timestamp validation failed");
        return 0;
    }

    if (!edwork_try_spend(edwork, proof_of_work, proof_of_work_size)) {
        log_error("token already spent");
        return 0;
    }

    return 1;
}

void edwork_callback(struct edwork_data *edwork, uint64_t sequence, uint64_t timestamp, const char *type, const unsigned char *payload, unsigned int payload_size, void *clientaddr, int clientaddrlen, const unsigned char *who_am_i, void *userdata) {
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
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        return;
    }
    if (!memcmp(type, "addr", 4)) {
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        log_info("ADDR list received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        if (time(NULL) - edfs_context->list_timestamp > 10) {
            log_warn("dropping non-requested ADDR");
            return;
        }
        edwork_add_node_list(edwork, payload, payload_size);
        if (payload_size >= BLOCK_SIZE - 0x100) {
            uint32_t offset = htonl(edfs_context->list_offset);
            notify_io(edfs_context, "list", (const unsigned char *)&offset, sizeof(uint32_t), NULL, 0, 0, 0, 0, edwork, EDWORK_LIST_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
            edfs_context->list_offset ++;
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
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        edwork_confirm_seq(edwork, ntohll(*(uint64_t *)payload), 1);
        return;
    }
    if (!memcmp(type, "nack", 4)) {
        log_info("NACK received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
        if ((!payload) || (payload_size != 8)) {
            log_error("invalid payload");
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        edwork_confirm_seq(edwork, ntohll(*(uint64_t *)payload), 1);
        return;
    }
    if ((!memcmp(type, "want", 4)) || (!memcmp(type, "wan3", 4)) || (!memcmp(type, "wan4", 4))) {
        log_info("WANT received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
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

        int is_encrypted = !memcmp(type, "wan4", 4);

        if ((!payload) || (payload_size < 64)) {
            log_warn("WANT packet to small");
            return;
        }

        void *clientinfo = edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        uint64_t ino = ntohll(*(uint64_t *)payload);
        uint64_t chunk = ntohll(*(uint64_t *)(payload + 8));

        if (!edwork_check_proof_of_work(edwork, payload, payload_size, is_encrypted ? 48 : 16, timestamp, EDWORK_WANT_WORK_LEVEL, EDWORK_WANT_WORK_PREFIX, who_am_i)) {
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
            int size = edfs_reply_chunk(edfs_context, ino, chunk, buffer + 32, sizeof(buffer));
            if (size > 0) {
                // unsigned char additional_data[32];
                unsigned char *additional_data = buffer;
                *(uint64_t *)additional_data = htonll(ino);
                *(uint64_t *)(additional_data + 8) = htonll(chunk);
                *(uint64_t *)(additional_data + 16) = htonll(microseconds());
                *(uint64_t *)(additional_data + 24) = htonll(size);

                if (is_encrypted) {
                    if (payload_size < 96) {
                        log_warn("WAN4 packet to small");
                        return;
                    }
                    unsigned char shared_secret[32];
                    
                    curve25519(shared_secret, edfs_context->key.secret, payload + 16) ;

                    unsigned char buf2[BLOCK_SIZE_MAX];
                    memcpy(buf2, edfs_context->key.pk, 32);

                    int size2 = edwork_encrypt(edfs_context, buffer, size + 32, buf2 + 32, who_am_i, edwork_who_i_am(edwork), shared_secret);
                    if (edwork_send_to_peer(edwork, "dat4", buf2, size2 + 32, clientaddr, clientaddrlen) <= 0)
                        log_error("error sending DAT4");
                    else
                        log_info("DAT4 sent");

                } else
                if (!memcmp(type, "wan3", 4)) {
                    unsigned char buf2[BLOCK_SIZE_MAX];
                    int size2 = edwork_encrypt(edfs_context, buffer, size + 32, buf2, who_am_i, edwork_who_i_am(edwork), NULL);
                    if (edwork_send_to_peer(edwork, "dat3", buf2, size2, clientaddr, clientaddrlen) <= 0)
                        log_error("error sending DAT3");
                    else
                        log_info("DAT3 sent");
                } else {
                    if (edwork_send_to_peer(edwork, "dat2", buffer, size + 32, clientaddr, clientaddrlen) <= 0)
                        log_error("error sending DAT2");
                    else
                        log_info("DAT2 sent");
                }
            }
        }
        return;
    } 
    if (!memcmp(type, "list", 4)) {
        log_info("ADDR request received (non-signed) (%s)", edwork_addr_ipv4(clientaddr));
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

        int size = BLOCK_SIZE;
        int records = edwork_get_node_list(edwork, buffer, &size, (unsigned int)offset, time(NULL) - 3600);
        if (records > 0) {
            if (edwork_send_to_peer(edwork, "addr", buffer, size, clientaddr, clientaddrlen) <= 0) {
                log_warn("error sending address list");
            }
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        return;
    }
    if (!memcmp(type, "desc", 4)) {
        log_info("DESC received (%s)", edwork_addr_ipv4(clientaddr));
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        // json payload
        uint64_t ino;
        int err = edwork_process_json(edfs_context, payload, payload_size, &ino);
        *(uint64_t *)buffer = htonll(ino);
        if (err > 0) {
            if (edwork_send_to_peer(edwork, "ack\x00", buffer, sizeof(uint64_t), clientaddr, clientaddrlen) <= 0) {
                log_error("error sending ACK");
                return;
            }
            log_info("DESC acknoledged");
            // rebroadcast without ack 3 seconds
            if (timestamp > now - 3000000UL)
                edwork_broadcast_except(edwork, "desc", payload, payload_size, 0, EDWORK_NODES, clientaddr, clientaddrlen, timestamp, ino);
        } else {
            if (!err) {
                if (edwork_send_to_peer(edwork, "nack", buffer, sizeof(uint64_t), clientaddr, clientaddrlen) <= 0) {
                    log_error("error sending NACK");
                    return;
                }
            }
            log_warn("invalid data received");
        }
        return;
    }
    if (!memcmp(type, "data", 4)) {
        log_info("DATA received (%s)", edwork_addr_ipv4(clientaddr));
        int err;
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        if (EDFS_DATA_BROADCAST_ENCRYPTED) {
            int size = edwork_decrypt(edfs_context, payload, payload_size, buffer, who_am_i, NULL, NULL);
            if (size <= 0) {
                log_warn("error decrypting DATA packet");
                return;
            }
            err = edwork_process_data(edfs_context, buffer, size, 1, NULL, 0);
        }  else
            err = edwork_process_data(edfs_context, payload, payload_size, 1, NULL, 0);
        if (err > 0) {
#ifndef EDWORK_NO_ACK_DATA
            *(uint64_t *)buffer = htonll(sequence);
            if (edwork_send_to_peer(edwork, "ack\x00", buffer, sizeof(uint64_t), clientaddr, clientaddrlen) <= 0) {
                log_error("error sending ACK");
                return;
            }
            log_info("DATA acknoledged");
#endif
        } else {
            if (!err) {
                // refused to write
                if (edwork_send_to_peer(edwork, "nack", buffer, sizeof(uint64_t), clientaddr, clientaddrlen) <= 0) {
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
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        int err = edwork_process_data(edfs_context, payload, payload_size, 0, clientaddr, clientaddrlen);
        if (err <= 0)
            log_warn("DAT2: will not write data block");
        return;
    }
    if (!memcmp(type, "dat3", 4)) {
        log_info("DAT3 received (%s)", edwork_addr_ipv4(clientaddr));
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        int size = edwork_decrypt(edfs_context, payload, payload_size, buffer, who_am_i, edwork_who_i_am(edwork), NULL);
        int err = edwork_process_data(edfs_context, buffer, size, 0, clientaddr, clientaddrlen);
        if (err <= 0)
            log_warn("DAT3: will not write data block");
        return;
    }
    if (!memcmp(type, "dat4", 4)) {
        log_info("DAT4 received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 32) {
            log_error("DAT4 packet to small");
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);

        unsigned char shared_secret[32];
        curve25519(shared_secret, edfs_context->key.secret, payload);

        int size = edwork_decrypt(edfs_context, payload + 32, payload_size - 32, buffer, who_am_i, edwork_who_i_am(edwork), shared_secret);
        int err = edwork_process_data(edfs_context, buffer, size, 0, clientaddr, clientaddrlen);
        if (err <= 0)
            log_warn("DAT4: will not write data block");
        return;
    }
    if (!memcmp(type, "del\x00", 4)) {
        log_info("DEL received (%s)", edwork_addr_ipv4(clientaddr));
        uint64_t ino;
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        if (edwork_delete(edfs_context, payload, payload_size, &ino)) {
            *(uint64_t *)buffer = htonll(sequence);
            if (edwork_send_to_peer(edwork, "ack\x00", buffer, sizeof(uint64_t), clientaddr, clientaddrlen) <= 0) {
                log_error("error sending ACK");
                return;
            }
            log_info("DEL acknoledged");
            // rebroadcast without acks 3 seconds
            if (timestamp > now - 3000000UL)
                edwork_broadcast_except(edwork, "del\x00", payload, payload_size, 0, EDWORK_NODES, clientaddr, clientaddrlen, timestamp, ino);
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

        edwork_resync(edfs_context, clientaddr, clientaddrlen);
        *(uint64_t *)buffer = htonll(1);
        edwork_send_to_peer(edwork, "ack\x00", buffer, sizeof(uint64_t), clientaddr, clientaddrlen);
        log_info("ROOT acknoledged");
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
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
        edwork_resync_desc(edfs_context, ntohll(*(uint64_t *)payload), clientaddr, clientaddrlen);
        usleep(500);
        edwork_resync_dir_desc(edfs_context, ntohll(*(uint64_t *)payload), clientaddr, clientaddrlen);
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
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
        edwork_resync_desc(edfs_context, ntohll(*(uint64_t *)payload), clientaddr, clientaddrlen);
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        return;
    }
    if (!memcmp(type, "hash", 4)) {
        log_info("HASH request received (%s)", edwork_addr_ipv4(clientaddr));
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

        void *clientinfo = edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);

        if (randomly_ignore) {
            log_info("randomly ignoring request");
            return;
        }

        if ((!payload) || (payload_size < 96)) {
            log_warn("HASH packet to small");
            return;
        }

        uint64_t ino = ntohll(*(uint64_t *)payload);
        uint64_t chunk = ntohll(*(uint64_t *)(payload + 8));

        if (!edwork_check_proof_of_work(edwork, payload, payload_size, 48, timestamp, EDWORK_WANT_WORK_LEVEL, EDWORK_WANT_WORK_PREFIX, who_am_i)) {
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
            int size = edfs_reply_hash(edfs_context, ino, chunk, buffer + 32, sizeof(buffer));
            if (size > 0) {
                // unsigned char additional_data[32];
                unsigned char *additional_data = buffer;
                *(uint64_t *)additional_data = htonll(ino);
                *(uint64_t *)(additional_data + 8) = htonll(chunk);
                *(uint64_t *)(additional_data + 16) = htonll(microseconds());
                *(uint64_t *)(additional_data + 24) = htonll(size);


                unsigned char shared_secret[32];                    
                curve25519(shared_secret, edfs_context->key.secret, payload + 16) ;

                unsigned char buf2[BLOCK_SIZE_MAX];
                memcpy(buf2, edfs_context->key.pk, 32);

                int size2 = edwork_encrypt(edfs_context, buffer, size + 32, buf2 + 32, who_am_i, edwork_who_i_am(edwork), shared_secret);
                if (edwork_send_to_peer(edwork, "dati", buf2, size2 + 32, clientaddr, clientaddrlen) <= 0)
                    log_error("error sending DATI");
                else
                    log_info("DATI sent");
            }
        }
        return;
    }
    if (!memcmp(type, "wand", 4)) {
        if (payload_size < 8) {
            log_warn("WAND packet to small");
            return;
        }

       if (!edwork_check_proof_of_work(edwork, payload, payload_size, 8, timestamp, EDWORK_WANT_WORK_LEVEL, EDWORK_WANT_WORK_PREFIX, who_am_i)) {
            log_warn("no valid proof of work");
            return;
        }

        uint64_t ino = ntohll(*(uint64_t *)payload);
        if ((!ino) || (ino == 1)) {
            log_warn("invalid WAND request");
            return;
        }

        char b64name[MAX_B64_HASH_LEN];
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);
        int len = edfs_read_file(edfs_context, edfs_context->working_directory, computename(ino, b64name), buffer, EDWORK_PACKET_SIZE, ".json", 0, 0, 0, NULL, 0);
        if (len > 0) {
            if (edwork_send_to_peer(edfs_context->edwork, "desc", buffer, len, clientaddr, clientaddrlen) <= 0)
                log_error("error sending DESC");
            else
                log_info("DESC sent");
        }
        return;
    }
    if (!memcmp(type, "dati", 4)) {
        log_info("DATI received (%s)", edwork_addr_ipv4(clientaddr));
        if (payload_size < 32) {
            log_error("DATI packet to small");
            return;
        }
        edwork_ensure_node_in_list(edwork, clientaddr, clientaddrlen);

        unsigned char shared_secret[32];
        curve25519(shared_secret, edfs_context->key.secret, payload);

        int size = edwork_decrypt(edfs_context, payload + 32, payload_size - 32, buffer, who_am_i, edwork_who_i_am(edwork), shared_secret);
        int err = edwork_process_hash(edfs_context, buffer, size, clientaddr, clientaddrlen);
        if (err <= 0)
            log_warn("DATI: will not write data block");
        return;
    }
    log_error("unsupported message type received: %s", type);
}

void edwork_save_nodes(struct edfs *edfs_context) {
    unsigned char buffer[BLOCK_SIZE];
    int size = BLOCK_SIZE;
    unsigned int offset = 0;
    int records = edwork_get_node_list(edfs_context->edwork, buffer, &size, (unsigned int)offset ++, 0);

    if (records > 0) {
        FILE *out = fopen(edfs_context->nodes_file, "wb");
        if (out) {
            do {
                uint32_t size_data = htonl(size);
                fwrite(&size_data, 1, sizeof(uint32_t), out);
                fwrite(buffer, 1, size, out);
                records = edwork_get_node_list(edfs_context->edwork, buffer, &size, offset ++, 0);
            } while (records);
        }
        fclose(out);
    }
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
                    if (port <= 0)
                        port = EDWORK_PORT;
                    if ((host) && (host[0]))
                        edwork_add_node(edfs_context->edwork, host, port);
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
                DEBUG_PRINT("ERROR LOADING NODE LIST (block size)");
                break;
            }
            if (fread(buffer, 1, size, in) != size) {
                DEBUG_PRINT("ERROR LOADING NODE LIST");
                break;
            }
            edwork_add_node_list(edfs_context->edwork, buffer, size);
        }
        fclose(in);
    }
    uint32_t offset = htonl(edfs_context->list_offset);
    notify_io(edfs_context, "list", (const unsigned char *)&offset, sizeof(uint32_t), NULL, 0, 0, 0, 0, edfs_context->edwork, EDWORK_LIST_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
    edfs_context->list_offset ++;
    edfs_context->list_timestamp = time(NULL);
}

void flush_queue(struct edfs *edfs_context) {
    while (edfs_context->queue) {
        if (edfs_context->mutex_initialized)
            thread_mutex_lock(&edfs_context->lock);
        struct edwork_io *fsio = (struct edwork_io *)edfs_context->queue;
        edfs_context->queue = (struct edwork_io *)edfs_context->queue->next;
        if (edfs_context->mutex_initialized)
            thread_mutex_unlock(&edfs_context->lock);
        if (fsio) {
            switch (fsio->ack) {
                case 3:
                    edwork_broadcast(edfs_context->edwork, fsio->type, fsio->buffer, fsio->size, 0, EDWORK_DATA_NODES, fsio->ino);
                    break;
                case 2:
                    edwork_broadcast(edfs_context->edwork, fsio->type, fsio->buffer, fsio->size, 1, EDWORK_NODES, fsio->ino);
                    break;
                default:
                    edwork_broadcast(edfs_context->edwork, fsio->type, fsio->buffer, fsio->size, fsio->ack ? EDWORK_NODES : 0, EDWORK_NODES, fsio->ino);
                    break;
            }
            free(fsio);
        }
    }
}

int string_ends_with(const char * str, const char *suffix, int suffix_len) {
    int str_len = strlen(str);
    return (str_len >= suffix_len) && (0 == strcmp(str + (str_len-suffix_len), suffix));
}

unsigned int edwork_resync(struct edfs *edfs_context, void *clientaddr, int clientaddrlen) {
    tinydir_dir dir;
    
    if (tinydir_open(&dir, edfs_context->working_directory)) {
        log_error("error opening edfs directory %s", edfs_context->working_directory);
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
            if ((string_ends_with(file.name, ".json", 5)) && (strcmp(file.name, "AAAAAAAAAAE.json"))) {
                unsigned char buffer[EDWORK_PACKET_SIZE];
                int len = edfs_read_file(edfs_context, edfs_context->working_directory, file.name, buffer, EDWORK_PACKET_SIZE, NULL, 0, 0, 0, NULL, 0);
                if (len > 0) {
                    if ((clientaddr) && (clientaddrlen)) {
                        edwork_send_to_peer(edfs_context->edwork, "desc", buffer, len, clientaddr, clientaddrlen);
                        usleep(200);
                    } else
                        edwork_broadcast(edfs_context->edwork, "desc", buffer, len, 0, EDWORK_NODES, 0);
                } else
                    log_debug("error");
            }
        }
        tinydir_next(&dir);
    }
    tinydir_close(&dir);
    return rebroadcast_count;
}

unsigned int edwork_resync_desc(struct edfs *edfs_context, uint64_t inode, void *clientaddr, int clientaddrlen) {
    unsigned char buffer[EDWORK_PACKET_SIZE];
    char b64name[MAX_B64_HASH_LEN];

    int len = edfs_read_file(edfs_context, edfs_context->working_directory, computename(inode, b64name), buffer, EDWORK_PACKET_SIZE, ".json", 0, 0, 0, NULL, 0);
    if (len > 0) {
        if ((clientaddr) && (clientaddrlen))
            edwork_send_to_peer(edfs_context->edwork, "desc", buffer, len, clientaddr, clientaddrlen);
        else
            edwork_broadcast(edfs_context->edwork, "desc", buffer, len, 0, EDWORK_NODES, 0);
        return 1;
    } else
        log_debug("error");
    return 0;
}

unsigned int edwork_resync_dir_desc(struct edfs *edfs_context, uint64_t inode, void *clientaddr, int clientaddrlen) {
    unsigned char buffer[EDWORK_PACKET_SIZE];
    char b64name[MAX_B64_HASH_LEN];
    char path[MAX_PATH_LEN];

    tinydir_dir dir;

    snprintf(path, sizeof(path), "%s/%s", edfs_context->working_directory, computename(inode, b64name));
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
            int len = edfs_read_file(edfs_context, edfs_context->working_directory, file.name, buffer, EDWORK_PACKET_SIZE, ".json", 0, 0, 0, NULL, 0);
            if (len > 0) {
                if ((clientaddr) && (clientaddrlen)) {
                    edwork_send_to_peer(edfs_context->edwork, "desc", buffer, len, clientaddr, clientaddrlen);
                    usleep(500);
                } else
                    edwork_broadcast(edfs_context->edwork, "desc", buffer, len, 0, EDWORK_NODES, 0);
            } else
                log_debug("error");
        }
        tinydir_next(&dir);
    }
    tinydir_close(&dir);
    return rebroadcast_count;
}

int edwork_thread(void *userdata) {
    edwork_init();
    struct edfs *edfs_context = (struct edfs *)userdata;
    if (edfs_context->port <= 0)
        edfs_context->port = EDWORK_PORT;

    if (!edfs_context->pub_loaded) {
        EDFS_THREAD_LOCK(edfs_context);
        edfs_context->pub_len = read_signature(edfs_context->signature, edfs_context->pubkey, 1, &edfs_context->key_type, NULL);
        EDFS_THREAD_UNLOCK(edfs_context);
    }

    struct edwork_data *edwork = edwork_create(edfs_context->port, edfs_context->cache_directory, edfs_context->pubkey);
    if (!edwork) {
        log_fatal("error creating network node");
        edfs_context->network_done = 1;
        return 0;
    }

    edfs_context->edwork = edwork;

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
            edwork_add_node(edwork, host_and_port, add_port);
        else
            log_error("error parsing url: %s", host_and_port);
    }

    edwork_load_nodes(edfs_context);
    time_t ping = 0;
    time_t write_nodes = time(NULL);
    time_t rebroadcast = 0;
    time_t startup = time(NULL);
    time_t resync_timestamp = time(NULL);
    int broadcast_offset = 0;
    while (!edfs_context->network_done) {
        if (((edfs_context->resync) && (time(NULL) - startup > EDWORK_INIT_INTERVAL)) || (time(NULL) - resync_timestamp > EDWORK_RESYNC_INTERVAL)) {
            uint64_t ack = htonll(1);
            notify_io(edfs_context, "root", (const unsigned char *)&ack, sizeof(uint64_t), NULL, 0, 2, 0, 1, edwork, EDWORK_ROOT_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
            edfs_context->resync = 0;
            resync_timestamp = time(NULL);
        }
        if ((edfs_context->force_rebroadcast) && (time(NULL) - startup > EDWORK_INIT_INTERVAL)) {
            edwork_resync(edfs_context, NULL, 0);
            edfs_context->force_rebroadcast = 0;
        }
        if (time(NULL) - ping > EDWORK_PING_INTERVAL) {
            edwork_broadcast(edwork, "ping", NULL, 0, 0, EDWORK_NODES, 0);
            ping = time(NULL);
        }

        if (time(NULL) - edfs_context->list_timestamp > EDWORK_LIST_INTERVAL) {
            edfs_context->list_offset = 0;
            uint32_t offset = htonl(edfs_context->list_offset);
            notify_io(edfs_context, "list", (const unsigned char *)&offset, sizeof(uint32_t), NULL, 0, 0, 0, 0, edwork, EDWORK_LIST_WORK_LEVEL, 0, NULL, 0, NULL, NULL);
            edfs_context->list_offset ++;
            edfs_context->list_timestamp = time(NULL);
        }

        if (time(NULL) - write_nodes > EDWORK_NODE_WRITE_INTERVAL) {
            edwork_save_nodes(edfs_context);
            write_nodes = time(NULL);
        }
        if (time(NULL) - rebroadcast > EDWORK_REBROADCAST_INTERVAL) {
            int count = edwork_rebroadcast(edwork, EDWORK_REBROADCAST, broadcast_offset);
            if (count)
                log_info("rebroadcasted %i edwork blocks, offset %i", count, broadcast_offset);
            if (count < EDWORK_REBROADCAST)
                broadcast_offset = 0;
            else
                broadcast_offset += count;
            rebroadcast = time(NULL);
        }

        flush_queue(edfs_context);
        edwork_dispatch(edwork, edwork_callback, 100, edfs_context);
    }


    flush_queue(edfs_context);
    edwork_save_nodes(edfs_context);

    edfs_context->edwork = NULL;
    edwork_destroy(edwork);

    edwork_done();
    return 0;
}

uint64_t pathtoinode(const char *path, uint64_t *parentinode, const char **nameptr) {
    if (parentinode)
        *parentinode = 0;
    if (nameptr)
        *nameptr = NULL;
    if (!path)
        return 1;
    int len = strlen(path);
    if (!len)
        return 1;

    int i;
    int chunk_len;
    uint64_t inode = 1;
    int start = 0;

    if (path[start] == '/')
        start ++;

    for (i = start; i < len; i++) {
        if ((path[i] == '/') || (path[i] == '\\')) {
            chunk_len = i - start;
            if (chunk_len > 0) {
                if (parentinode)
                    *parentinode = inode;
                inode = computeinode2(inode, path + start, chunk_len);
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
        inode = computeinode2(inode, path + start, chunk_len);
        if (nameptr)
            *nameptr = path + start;
        start = i + 1;
    }
    return inode;
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

        thread_mutex_init(&edfs_context->io_lock);
        thread_mutex_lock(&edfs_context->io_lock);
#ifdef EDFS_MULTITHREADED
        thread_mutex_init(&edfs_context->thread_lock);
#endif
        thread_mutex_init(&edfs_context->ino_cache_lock);

        edfs_context->mutex_initialized = 1;
        edfs_context->network_thread = thread_create(edwork_thread, (void *)edfs_context, "edwork", 8192 * 1024);

        thread_mutex_unlock(&edfs_context->io_lock);
        thread_mutex_unlock(&edfs_context->lock);
    } else
        log_error("edwork already initialized");
}

void edfs_edwork_done(struct edfs *edfs_context) {
    if (!edfs_context)
        return;

    if (!edfs_context->mutex_initialized) {
        log_error("edwork not initialized");
        return;
    }
    if (edfs_context->network_thread) {
        log_info("waiting for edwork thread to finish ...");
        edfs_context->network_done = 1;
        thread_join(edfs_context->network_thread);
        thread_destroy(edfs_context->network_thread);
        log_info("edwork done");
    }
    edfs_context->mutex_initialized = 0;
    thread_mutex_term(&edfs_context->io_lock);
    thread_mutex_term(&edfs_context->lock);
#ifdef EDFS_MULTITHREADED
    thread_mutex_term(&edfs_context->thread_lock);
#endif
    thread_mutex_term(&edfs_context->ino_cache_lock);
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

int edfs_init(struct edfs *edfs_context) {
    if (!edfs_context)
        return -1;

    recursive_mkdir(edfs_context->working_directory);
    recursive_mkdir(edfs_context->cache_directory);

    if (!edfs_context->read_only_fs) {
        if (signature_allows_write(edfs_context))
            edfs_context->read_only_fs = 0;
        else
            edfs_context->read_only_fs = 1;
    }
    if (edfs_context->read_only_fs) {
        log_info("read-only filesytem");
    } else {
        // init root foloder
        read_file_json(edfs_context, 1, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL);
    }
    return 0;
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

        edfs_context->working_directory = edfs_add_to_path(use_working_directory, "inode");
        edfs_context->cache_directory = edfs_add_to_path(use_working_directory, "cache");
        edfs_context->signature = edfs_add_to_path(use_working_directory, "signature.json");
        edfs_context->nodes_file = edfs_add_to_path(use_working_directory, "nodes");
        edfs_context->default_nodes = edfs_add_to_path(use_working_directory, "default_nodes.json");
        edfs_context->forward_chunks = 5;
        edfs_make_key(edfs_context);

        avl_initialize(&edfs_context->ino_cache, ino_compare, avl_ino_destructor);
    }
    return edfs_context;
}

void edfs_destroy_context(struct edfs *edfs_context) {
    if (!edfs_context)
        return;

    avl_destroy(&edfs_context->ino_cache, avl_ino_key_data_destructor);

    free(edfs_context->working_directory);
    free(edfs_context->cache_directory);
    free(edfs_context->signature);
    free(edfs_context->nodes_file);
    free(edfs_context->default_nodes);
    free(edfs_context->host_and_port);
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

const char *edfs_signature_path(struct edfs *edfs_context) {
    if (!edfs_context)
        return NULL;
    return edfs_context->signature;
}

int edwork_readonly(struct edfs *edfs_context) {
    if (!edfs_context)
        return 1;
    return edfs_context->read_only_fs;
}

void edfs_set_initial_friend(struct edfs *edfs_context, const char *peer) {
    if ((!edfs_context) || (!peer))
        return;

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
