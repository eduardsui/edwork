#include <stdlib.h>
#include <stdio.h>

#include "log.h"
#include "edfs_key_data.h"

#ifdef _WIN32
    #include <windows.h>
#endif

char *edfs_add_to_path(const char *path, const char *subpath);
int edfs_file_exists(const char *name);
const char *computename(uint64_t inode, char *out);

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

int edfs_key_data_init(struct edfs_key_data *key_data, const char *use_working_directory) {
    memset(key_data, 0, sizeof(struct edfs_key_data));

    thread_mutex_init(&key_data->ino_cache_lock);
    thread_mutex_init(&key_data->notify_write_lock);
#ifndef EDFS_NO_JS
    thread_mutex_init(&key_data->js_lock);
#endif

    avl_initialize(&key_data->ino_cache, avl_ino_compare, avl_dummy_key_destructor);
    avl_initialize(&key_data->ino_checksum_mismatch, avl_ino_compare, avl_dummy_key_destructor);
    avl_initialize(&key_data->ino_sync_file, avl_ino_compare, avl_dummy_key_destructor);
    avl_initialize(&key_data->notify_write, avl_ino_compare, avl_dummy_key_destructor);
    avl_initialize(&key_data->allow_data, avl_ino_compare, avl_dummy_key_destructor);

    key_data->working_directory = edfs_add_to_path(use_working_directory, "inode");
    key_data->cache_directory = edfs_add_to_path(use_working_directory, "cache");
    key_data->signature = edfs_add_to_path(use_working_directory, "signature.json");
    key_data->blockchain_directory = edfs_add_to_path(use_working_directory, "blockchain");
#ifndef EDFS_NO_JS
    key_data->js_working_directory = strdup(use_working_directory);
#endif
    return 0;
}

#ifndef EDFS_NO_JS
void edfs_key_data_js_lock(struct edfs_key_data *key_data, int lock) {
    if (!key_data)
        return;

    if (lock) {
        if (key_data->js_thread_lock != thread_current_thread_id()) {
            thread_mutex_lock(&key_data->js_lock);
            key_data->js_thread_lock = thread_current_thread_id();
            key_data->js_dry_locks = 0;
        } else
            key_data->js_dry_locks ++;
    } else {
        if (key_data->js_thread_lock == thread_current_thread_id()) {
            if (key_data->js_dry_locks > 0) {
                key_data->js_dry_locks --;
            } else {
                key_data->js_thread_lock = NULL;
                thread_mutex_unlock(&key_data->js_lock);
            }
        }
    }
}

struct edfs_key_data *edfs_key_data_get_from_js(duk_context *js) {
    if (!js)
        return NULL;

    duk_memory_functions funcs;
    duk_get_memory_functions(js, &funcs);

    return (struct edfs_key_data *)funcs.udata;
}

static void edfs_js_log_error(void *key_data, const char *msg) {
    if ((msg) && (key_data)) {
        free(((struct edfs_key_data *)key_data)->js_last_error);
        ((struct edfs_key_data *)key_data)->js_last_error = strdup(msg);
    }
    log_error("JS engine error: %s", msg);
    edfs_js_error(((struct edfs_key_data *)key_data)->js, msg);
    exit(-1);
}

static duk_context *edfs_key_data_get_js(struct edfs_key_data *key_data) {
    if (!key_data)
        return NULL;

    if (!key_data->js) {
        key_data->js = duk_create_heap(NULL, NULL, NULL, key_data, edfs_js_log_error);
        key_data->js_exit = 0;
        edfs_js_register_all(key_data->js);
    }

    return key_data->js;
}

int edfs_key_data_load_js(struct edfs_key_data *key_data, const char *js_data) {
    if ((!js_data) || (!js_data[0]))
        return 0;

    edfs_key_data_js_lock(key_data, 1);
    duk_context *js = edfs_key_data_get_js(key_data);
    if (!js) {
        edfs_key_data_js_lock(key_data, 0);
        return -1;
    }
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;
    if (duk_peval_string(js, js_data) != 0) {
        key_data->js_last_error = strdup(duk_safe_to_string(js, -1));
        log_error("JS engine error: %s", key_data->js_last_error);
        edfs_js_error(((struct edfs_key_data *)key_data)->js, key_data->js_last_error);
        key_data->js_exit = 1;
    }
    duk_pop(js);
    edfs_key_data_js_lock(key_data, 0);
    if (key_data->js_exit) {
        edfs_key_data_reset_js(key_data);
        key_data->js_exit = 0;
    } else {
        edfs_key_js_call(key_data, "edwork.events.onlaunch", NULL);
    }
    return 0;
}

void edfs_key_data_reset_js(struct edfs_key_data *key_data) {
    if (!key_data)
        return;

    edfs_key_data_js_lock(key_data, 1);

    if (key_data->js) {
        duk_destroy_heap(key_data->js);
        key_data->js = NULL;
    }
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;

    edfs_key_data_js_lock(key_data, 0);
}

const char *edfs_key_data_js_error(struct edfs_key_data *key_data) {
    if (!key_data)
        return NULL;
    return key_data->js_last_error;
}

void edfs_key_data_js_loop(struct edfs_key_data *key_data) {
    if ((!key_data) || (!key_data->js))
        return;

    edfs_key_data_js_lock(key_data, 1);
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;
    duk_eval_string_noresult(key_data->js, "try { edwork.__edfs_loop(); } catch (e) { console.error(e.toString()); }");
    // duktape documentation:
    // You may want to call this function twice to ensure even objects with finalizers are collected.
    duk_gc(key_data->js, 0);
    duk_gc(key_data->js, 0);
    edfs_key_data_js_lock(key_data, 0);
}

int edfs_key_js_call(struct edfs_key_data *key_data, const char *jscall, ... ) {
    if ((!key_data) || (!key_data->js))
        return -1;

    edfs_key_data_js_lock(key_data, 1);
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;

    duk_push_string(key_data->js, jscall);
    duk_peval(key_data->js);

    va_list ap;
    va_start(ap, jscall);
    int arg_count = 0;
    while (1) {
        const char *str = va_arg(ap, const char *);
        if (!str)
            break;
        duk_push_string(key_data->js, str);
        arg_count ++;
    }
    va_end(ap);

    duk_pcall(key_data->js, arg_count);
    int ret_val = duk_get_int(key_data->js, -1);
    duk_pop(key_data->js);

    edfs_key_data_js_lock(key_data, 0);
    return ret_val;
}

int edfs_key_js_call_args(struct edfs_key_data *key_data, const char *jscall, const char *fmt, ...) {
    if ((!key_data) || (!key_data->js))
        return -1;

    edfs_key_data_js_lock(key_data, 1);
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;

    duk_push_string(key_data->js, jscall);
    duk_peval(key_data->js);

    int len_fmt = fmt ? strlen(fmt) : 0;

    va_list ap;
    va_start(ap, fmt);
    int arg_count = 0;
    for (arg_count = 0; arg_count < len_fmt; arg_count ++) {
        char buffer[0x200];
        switch (fmt[arg_count]) {
            case '_':
                buffer[0] = 0;
                computename(va_arg(ap, uint64_t), buffer);
                duk_push_string(key_data->js, buffer);
                break;
            case 'u':
                duk_push_number(key_data->js, (double)va_arg(ap, unsigned int));
                break;
            case 'i':
                duk_push_number(key_data->js, (double)va_arg(ap, int));
                break;
            case 'f':
                duk_push_number(key_data->js, va_arg(ap, double));
                break;
            case 'x':
                snprintf(buffer, sizeof(buffer), "%" PRIx64, va_arg(ap, uint64_t));
                duk_push_string(key_data->js, buffer);
                break;
            case 's':
                snprintf(buffer, sizeof(buffer), "%s", va_arg(ap, const char *));
                duk_push_string(key_data->js, buffer);
                break;
            case 'b':
                duk_push_boolean(key_data->js, va_arg(ap, int));
                break;
            default:
                log_error("invalid format specifier");
                break;
        }
    }
    va_end(ap);

    duk_pcall(key_data->js, arg_count);
    int ret_val = duk_get_boolean(key_data->js, -1);
    duk_pop(key_data->js);

    edfs_key_data_js_lock(key_data, 0);
    return ret_val;
}
#endif

int edfs_key_data_up_vote(struct edfs_key_vote_data *vote_data, const unsigned char *vote, int vote_size) {
    if (vote_data->timeout > time(NULL)) {
        log_warn("voted too late");
        return -1;
    }
    int i;
    for (i = 0; i < vote_data->vote_size; i ++) {
        if (!memcmp(vote_data->votes[i].vote_key, vote, vote_size)) {
            vote_data->votes[i].count ++;
            return 0;
        }
    }
    
    struct edfs_key_vote_item *old_votes = vote_data->votes;
    vote_data->votes = (struct edfs_key_vote_item *)realloc(vote_data->votes, (vote_data->vote_size + 1) * sizeof(struct edfs_key_vote_item));
    if (!vote_data->votes) {
        vote_data->votes = old_votes;
        log_error("error allocating memory");
        return -1;
    }
    memset(&vote_data->votes[vote_data->vote_size], 0, sizeof(struct edfs_key_vote_item));
    memcmp(vote_data->votes[vote_data->vote_size].vote_key, vote, vote_size);
    vote_data->votes[vote_data->vote_size].count = 1;

    vote_data->vote_size ++;
    return 1;
}

int edfs_key_data_vote(struct edfs_key_data *key_data, const unsigned char *subject, int subject_size, const unsigned char *vote, int vote_size, int timeout) {
    if ((!key_data) || (subject_size < 0) || (subject_size > 0xFF) || (vote_size <= 0) || (vote_size > 0xFF)) {
        log_error("invalid vote parameters");
        return -1;
    }

    int i;
    struct edfs_key_vote_data *vote_data;

    for (i = 0; i < key_data->vote_size; i ++) {
        vote_data = &key_data->votes[i];
        if (!memcmp(vote_data->subject, subject, subject_size))
            return edfs_key_data_up_vote(vote_data, vote, vote_size);
    }
    struct edfs_key_vote_data *old_votes = key_data->votes;
    key_data->votes = (struct edfs_key_vote_data *)realloc(key_data->votes, (key_data->vote_size + 1) * sizeof(struct edfs_key_vote_data));
    if (!key_data->votes) {
        key_data->votes = old_votes;
        log_error("error allocating memory");
        return -1;
    }

    vote_data = &key_data->votes[key_data->vote_size];
    memset(vote_data, 0, sizeof(struct edfs_key_vote_data));
    vote_data->timeout = time(NULL) + timeout + 1;
    memcpy(vote_data->subject, subject, subject_size);

    key_data->vote_size ++;

    return edfs_key_data_up_vote(vote_data, vote, vote_size);
}

int edfs_key_data_vote_winner(struct edfs_key_data *key_data, const unsigned char *subject, int subject_size, unsigned char *vote, int vote_size) {
    if ((!key_data) || (subject_size < 0) || (subject_size > 0xFF) || (!vote) || (vote_size <= 0)) {
        log_error("invalid vote parameters");
        return -1;
    }

    int i;
    int j;

    for (i = 0; i < key_data->vote_size; i ++) {
        struct edfs_key_vote_data *vote_data = &key_data->votes[i];
        if (!memcmp(vote_data->subject, subject, subject_size)) {
            int max_votes = -1;
            int index = -1;
            for (j = 0; i < vote_data->vote_size; j ++) {
                if (!memcmp(vote_data->votes[j].vote_key, vote, vote_size)) {
                    if ((vote_data->votes[j].count > max_votes) || ((vote_data->votes[j].count == max_votes) && (memcmp(vote_data->votes[j].vote_key, vote_data->votes[index].vote_key, 0xFF) == 1))) {
                        max_votes = vote_data->votes[j].count;
                        index = j;
                    }
                }
            }
            if (index >= 0)
                memcpy(vote, vote_data->votes[j].vote_key, vote_size <= 0xFF ? vote_size : 0xFF);

            free(vote_data->votes);
            vote_data->votes = NULL;
            vote_data->vote_size = 0;

            key_data->vote_size --;
            if (key_data->vote_size) {
                memmove(vote_data, vote_data + 1, (key_data->vote_size - i) * sizeof(struct edfs_key_vote_data));
            } else {
                free(key_data->votes);
                key_data->votes = NULL;
            }
            if (index >= 0)
                return 1;
            return 0;
        }
    }

    return 0;
}

void edfs_key_data_deinit(struct edfs_key_data *key_data) {
    if (!key_data)
        return;

#ifndef EDFS_NO_JS
    if (key_data->js)
        duk_destroy_heap(key_data->js);
    free(key_data->js_last_error);
#endif
    avl_destroy(&key_data->allow_data, avl_dummy_destructor);
    avl_destroy(&key_data->notify_write, avl_dummy_destructor);
    avl_destroy(&key_data->ino_cache, avl_key_data_destroy);
    avl_destroy(&key_data->ino_checksum_mismatch, avl_dummy_destructor);
    avl_destroy(&key_data->ino_sync_file, avl_dummy_destructor);
    blockchain_free(key_data->chain);

    if (key_data->votes) {
        int i;
        for (i = 0; i < key_data->vote_size; i ++)
            free(key_data->votes[i].votes);
        free(key_data->votes);
        key_data->vote_size = 0;
        key_data->votes = NULL;
    }

    free(key_data->working_directory);
    free(key_data->cache_directory);
    free(key_data->signature);
    free(key_data->blockchain_directory);
#ifndef EDFS_NO_JS
    free(key_data->js_working_directory);
#endif

    thread_mutex_term(&key_data->notify_write_lock);
    thread_mutex_term(&key_data->ino_cache_lock);
#ifndef EDFS_NO_JS
    thread_mutex_term(&key_data->js_lock);
#endif
}
