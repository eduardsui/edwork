#ifndef __EDWORK_H
#define __EDWORK_H

#include <inttypes.h>
#include <time.h>

struct edwork_data;

typedef void (*edwork_dispatch_callback)(struct edwork_data *edwork, uint64_t sequence, uint64_t timestamp, const char *type, const unsigned char *payload, unsigned int payload_size, void *clientaddr, int clientaddrlen, const unsigned char *who_am_i, void *userdata);

#ifdef _WIN32
    void usleep(uint64_t usec);
#endif

void edwork_init();

uint64_t edwork_random();
int edwork_random_bytes(unsigned char *destination, int len);

struct edwork_data *edwork_create(int port, const char *log_dir);
void edwork_confirm_seq(struct edwork_data *data, uint64_t sequence, int acks);
void edwork_add_node(struct edwork_data *data, const char *node, int port);
int edworks_data_pending(struct edwork_data* data, int timeout_ms);
int edwork_dispatch(struct edwork_data* data, edwork_dispatch_callback callback, int timeout_ms, void *userdata);
int edwork_dispatch_data(struct edwork_data* data, edwork_dispatch_callback callback, unsigned char *buffer, int n, void *clientaddr, int clientaddrlen, void *userdata);
int edwork_send_to_peer(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, void *clientaddr, int clientaddrlen);
int edwork_broadcast(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, uint64_t ino);
int edwork_broadcast_except(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, const void *except, int except_len, uint64_t force_timestamp, uint64_t ino);
unsigned int edwork_rebroadcast(struct edwork_data *data, unsigned int max_count, unsigned int offset);
int edwork_get_node_list(struct edwork_data *data, unsigned char *buf, int *buf_size, unsigned int offset, time_t threshold);
int edwork_add_node_list(struct edwork_data *data, const unsigned char *buf, int buf_size);
void *edwork_ensure_node_in_list(struct edwork_data *data, void *clientaddr, int clientaddrlen);
int edwork_get_info(void *clientinfo, uint64_t *last_ino, uint64_t *last_chunk, uint64_t *last_msg_timestamp);
int edwork_set_info(void *clientinfo, uint64_t last_ino, uint64_t last_chunk, uint64_t last_msg_timestamp);
unsigned int edwork_magnitude(struct edwork_data *data);
const unsigned char *edwork_who_i_am(struct edwork_data *data);
int edwork_try_spend(struct edwork_data *data, const unsigned char *proof_of_work, int proof_of_work_size);
const char *edwork_addr_ipv4(void *clientaddr_ptr);
void edwork_destroy(struct edwork_data *data);

void edwork_done();

#endif // __EDWORK_H
