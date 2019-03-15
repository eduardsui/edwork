#include <stdlib.h>
#include <stdio.h>

#include "log.h"
#include "edfs_key_data.h"

#ifdef _WIN32
    #include <windows.h>
#endif

char *edfs_add_to_path(const char *path, const char *subpath);
int edfs_file_exists(const char *name);

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
struct edfs_key_data *edfs_key_data_get_from_js(duk_context *js) {
    if (!js)
        return NULL;

    duk_memory_functions funcs;
    duk_get_memory_functions(js, &funcs);

    return (struct edfs_key_data *)funcs.udata;
}

const char *duk_push_string_file_raw(duk_context *js, const char *path) {
	FILE *f = NULL;
	char *buf;
	long sz;  /* ANSI C typing */

	if (!path) {
		goto fail;
	}
	f = fopen(path, "rb");
	if (!f) {
		goto fail;
	}
	if (fseek(f, 0, SEEK_END) < 0) {
		goto fail;
	}
	sz = ftell(f);
	if (sz < 0) {
		goto fail;
	}
	if (fseek(f, 0, SEEK_SET) < 0) {
		goto fail;
	}
	buf = (char *) duk_push_fixed_buffer(js, (duk_size_t) sz);
	if ((size_t) fread(buf, 1, (size_t) sz, f) != (size_t) sz) {
		duk_pop(js);
		goto fail;
	}
	(void) fclose(f);  /* ignore fclose() error */
	return duk_buffer_to_string(js, -1);

 fail:
	if (f) {
		(void) fclose(f);  /* ignore fclose() error */
	}

	duk_push_undefined(js);
	return NULL;
}

static duk_int_t duk_peval_file(duk_context *js, const char *path) {
	duk_int_t rc;

	duk_push_string_file_raw(js, path);
	duk_push_string(js, path);
	rc = duk_pcompile(js, DUK_COMPILE_EVAL);
	if (rc != 0)
		return rc;

	duk_push_global_object(js); 
	rc = duk_pcall_method(js, 0);
	return rc;
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

    thread_mutex_lock(&key_data->js_lock);
    if (!key_data->js) {
        key_data->js = duk_create_heap(NULL, NULL, NULL, key_data, edfs_js_log_error);
        key_data->js_exit = 0;
        edfs_js_register_all(key_data->js);
    }
    thread_mutex_unlock(&key_data->js_lock);

    return key_data->js;
}

int edfs_key_data_load_js(struct edfs_key_data *key_data, const char *js_data) {
    if ((!js_data) || (!js_data[0]))
        return 0;

    duk_context *js = edfs_key_data_get_js(key_data);
    if (!js)
        return -1;

    thread_mutex_lock(&key_data->js_lock);
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;
    unsigned char old_js_lock = key_data->no_js_lock;
    key_data->no_js_lock = 1;
    if (duk_peval_string(js, js_data) != 0) {
        key_data->js_last_error = strdup(duk_safe_to_string(js, -1));
        log_error("JS engine error: %s", key_data->js_last_error);
        edfs_js_error(((struct edfs_key_data *)key_data)->js, key_data->js_last_error);
        key_data->js_exit = 1;
    }
    key_data->no_js_lock = old_js_lock;
    duk_pop(js);
    thread_mutex_unlock(&key_data->js_lock);
    if (key_data->js_exit) {
        edfs_key_data_reset_js(key_data);
        key_data->js_exit = 0;
    }
    return 0;
}

int edfs_key_data_load_js_file(struct edfs_key_data *key_data, const char *js_filename) {
    char filename_buf[8192];
    snprintf(filename_buf, sizeof(filename_buf), "%s/%s", key_data->js_working_directory, js_filename);
    if (!edfs_file_exists(filename_buf))
        return -1;

    duk_context *js = edfs_key_data_get_js(key_data);
    if (!js)
        return -1;

    thread_mutex_lock(&key_data->js_lock);
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;
    if (duk_peval_file(js, filename_buf)) {
        thread_mutex_unlock(&key_data->js_lock);
        return -1;
    }
    duk_pop(js);
    thread_mutex_unlock(&key_data->js_lock);

    return 0;
}

void edfs_key_data_reset_js(struct edfs_key_data *key_data) {
    if (!key_data)
        return;

    thread_mutex_lock(&key_data->js_lock);

    if (key_data->js) {
        duk_destroy_heap(key_data->js);
        key_data->js = NULL;
    }
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;

    thread_mutex_unlock(&key_data->js_lock);
}

const char *edfs_key_data_js_error(struct edfs_key_data *key_data) {
    if (!key_data)
        return NULL;
    return key_data->js_last_error;
}

void edfs_key_data_js_loop(struct edfs_key_data *key_data) {
    if ((!key_data) || (!key_data->js))
        return;

    if (!key_data->no_js_lock)
        thread_mutex_lock(&key_data->js_lock);
    free(key_data->js_last_error);
    key_data->js_last_error = NULL;
    duk_eval_string_noresult(key_data->js, "try { edwork.__edfs_loop(); } catch (e) { console.error(e.toString()); }");
    // duktape documentation:
    // You may want to call this function twice to ensure even objects with finalizers are collected.
    duk_gc(key_data->js, 0);
    duk_gc(key_data->js, 0);
    if (!key_data->no_js_lock)
        thread_mutex_unlock(&key_data->js_lock);
}

int edfs_key_js_call(struct edfs_key_data *key_data, const char *jscall, ... ) {
    if ((!key_data) || (!key_data->js))
        return -1;

    if (!key_data->no_js_lock)
        thread_mutex_lock(&key_data->js_lock);
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

    unsigned char old_js_lock = key_data->no_js_lock;
    key_data->no_js_lock = 1;
    duk_pcall(key_data->js, arg_count);
    key_data->no_js_lock = old_js_lock;
    int ret_val = duk_get_int(key_data->js, -1);
    duk_pop(key_data->js);

    if (!key_data->no_js_lock)
        thread_mutex_unlock(&key_data->js_lock);
    return ret_val;
}

int edfs_key_js_call_safe(struct edfs_key_data *key_data, const char *jscall, ... ) {
    if ((!key_data) || (!key_data->js))
        return -1;

    thread_mutex_lock(&key_data->js_lock);
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

    key_data->no_js_lock = 1;
    duk_pcall(key_data->js, arg_count);
    key_data->no_js_lock = 0;
    int ret_val = duk_get_int(key_data->js, -1);
    duk_pop(key_data->js);

    thread_mutex_unlock(&key_data->js_lock);
    return ret_val;
}
#endif

void edfs_key_data_deinit(struct edfs_key_data *key_data) {
    if (!key_data)
        return;

#ifndef EDFS_NO_JS
    if (key_data->js)
        duk_destroy_heap(key_data->js);
    free(key_data->js_last_error);
#endif
    avl_destroy(&key_data->notify_write, avl_dummy_destructor);
    avl_destroy(&key_data->ino_cache, avl_key_data_destroy);
    avl_destroy(&key_data->ino_checksum_mismatch, avl_dummy_destructor);
    avl_destroy(&key_data->ino_sync_file, avl_dummy_destructor);
    blockchain_free(key_data->chain);

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
