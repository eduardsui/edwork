#ifndef EDFS_KEY_DATA
#define EDFS_KEY_DATA

#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include "avl.h"
#include "blockchain.h"

#define MAX_KEY_SIZE                8192
#define MAX_PROOF_INODES        300

struct edfs_key_data {
    unsigned char pubkey[MAX_KEY_SIZE];
    unsigned char sigkey[MAX_KEY_SIZE];

    unsigned char key_id[32];
    uint64_t key_id_xxh64_be;

    char *working_directory;
    char *cache_directory;
    char *signature;
    char *blockchain_directory;

    avl_tree_t ino_cache;
    thread_mutex_t ino_cache_lock;

    avl_tree_t ino_checksum_mismatch;
    avl_tree_t ino_sync_file;

    avl_tree_t notify_write;
    thread_mutex_t notify_write_lock;

    unsigned char proof_of_time[40];
    uint64_t proof_inodes[MAX_PROOF_INODES];
    int proof_inodes_len;
    struct block *chain;

    size_t pub_len;
    int pubkey_size;
    int key_type;
    int sign_key_type;
    int signature_size;
    size_t sig_len;

    uint64_t top_broadcast_timestamp;
    uint64_t client_top_broadcast_timestamp;

    uint32_t chain_errors;

    int block_timestamp;

    unsigned char hblk_scheduled;

    unsigned char key_loaded;
    unsigned char pub_loaded;

    unsigned char read_only;

    int opened_files;

    int mining_flag;

    void *next_key;
};


int edfs_key_data_init(struct edfs_key_data *key_data, char *use_working_directory);
void edfs_key_data_deinit(struct edfs_key_data *key_data);

#endif
