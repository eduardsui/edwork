#include "edfs_key_data.h"

char *edfs_add_to_path(const char *path, const char *subpath);

static int avl_ino_compare(void *a1, void *a2) {
    if (a1 < a2)
        return -1;

    if (a1 > a2)
        return 1;

    return 0;
}

static void avl_key_data_destroy(void *key, void *data) {
    free(data);
}

void avl_dummy_destructor(void *key, void *data) {
    // nothing
}

void avl_dummy_key_destructor(void *key) {
    // nothing
}

int edfs_key_data_init(struct edfs_key_data *key_data, char *use_working_directory) {
    memset(key_data, 0, sizeof(struct edfs_key_data));

    thread_mutex_init(&key_data->ino_cache_lock);
    thread_mutex_init(&key_data->notify_write_lock);

    avl_initialize(&key_data->ino_cache, avl_ino_compare, avl_dummy_key_destructor);
    avl_initialize(&key_data->ino_checksum_mismatch, avl_ino_compare, avl_dummy_key_destructor);
    avl_initialize(&key_data->ino_sync_file, avl_ino_compare, avl_dummy_key_destructor);
    avl_initialize(&key_data->notify_write, avl_ino_compare, avl_dummy_key_destructor);

    key_data->working_directory = edfs_add_to_path(use_working_directory, "inode");
    key_data->cache_directory = edfs_add_to_path(use_working_directory, "cache");
    key_data->signature = edfs_add_to_path(use_working_directory, "signature.json");
    key_data->blockchain_directory = edfs_add_to_path(use_working_directory, "blockchain");

    return 0;
}

void edfs_key_data_deinit(struct edfs_key_data *key_data) {
    if (!key_data)
        return;

    avl_destroy(&key_data->notify_write, avl_dummy_destructor);
    avl_destroy(&key_data->ino_cache, avl_key_data_destroy);
    avl_destroy(&key_data->ino_checksum_mismatch, avl_dummy_destructor);
    avl_destroy(&key_data->ino_sync_file, avl_dummy_destructor);
    blockchain_free(key_data->chain);

    free(key_data->working_directory);
    free(key_data->cache_directory);
    free(key_data->signature);
    free(key_data->blockchain_directory);

    thread_mutex_term(&key_data->notify_write_lock);
    thread_mutex_term(&key_data->ino_cache_lock);
}
