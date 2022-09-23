#ifndef __EDWORK_H
#define __EDWORK_H

#include <inttypes.h>
#include <time.h>

#include "edfs_key_data.h"

// 1 second ttl
#define EDWORK_SCTP_TTL                 1000
#define SCTP_UDP_ENCAPSULATION
#define EDWORK_SCTP_UDP_TUNNELING_PORT  4884
#define EDWORK_PEER_DISCOVERY_SERVICE
#define EDWORK_LAST_SEEN_TIMEOUT        120

struct edwork_data;

typedef void (*edwork_dispatch_callback)(struct edwork_data *edwork, uint64_t sequence, uint64_t timestamp, const char *type, const unsigned char *payload, unsigned int payload_size, struct edfs_key_data *key_data, void *clientaddr, int clientaddrlen, const unsigned char *who_am_i, const unsigned char *blockhash, void *userdata, int is_sctp, int is_listen_socket);
typedef struct edfs_key_data *(*edwork_find_key_callback)(uint64_t key, void *userdata);

#ifdef _WIN32
    void usleep(uint64_t usec);
#endif

void edwork_init();

uint64_t edwork_random();
int edwork_random_bytes(unsigned char *destination, int len);

struct edwork_data *edwork_create(int port, edwork_find_key_callback key_callback);
void edwork_confirm_seq(struct edwork_data *data, struct edfs_key_data *key, uint64_t sequence, int acks);
void edwork_add_node(struct edwork_data *data, const char *node, int port, int is_listen_socket, int sctp, unsigned short encapsulation_port, time_t timestamp);
int edworks_data_pending(struct edwork_data* data, int timeout_ms);
int edwork_dispatch(struct edwork_data* data, edwork_dispatch_callback callback, int timeout_ms, void *userdata);
int edwork_dispatch_data(struct edwork_data* data, edwork_dispatch_callback callback, unsigned char *buffer, int n, void *clientaddr, int clientaddrlen, void *userdata, int is_sctp, int is_listen_socket);
int edwork_send_to_peer(struct edwork_data *data, struct edfs_key_data *key, const char type[4], const unsigned char *buf, int len, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket, int ttl);
int edwork_broadcast(struct edwork_data *data, struct edfs_key_data *key, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, uint64_t ino, int force_udp, time_t threshold);
int edwork_broadcast_client(struct edwork_data *data, struct edfs_key_data *key, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, uint64_t ino, const void *clientaddr, int clientaddr_len);
int edwork_broadcast_except(struct edwork_data *data, struct edfs_key_data *key, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, const void *except, int except_len, uint64_t force_timestamp, uint64_t ino);
unsigned int edwork_rebroadcast(struct edwork_data *data, struct edfs_key_data *key, unsigned int max_count, unsigned int offset);
int edwork_get_node_list(struct edwork_data *data, unsigned char *buf, int *buf_size, unsigned int offset, time_t threshold, int with_timestamp);
int edwork_debug_node_list(struct edwork_data *data, char *buf, int buf_size, unsigned int offset, time_t threshold, int html);
int edwork_add_node_list(struct edwork_data *data, const unsigned char *buf, int buf_size);
void *edwork_ensure_node_in_list(struct edwork_data *data, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket);
int edwork_get_info(void *clientinfo, uint64_t *last_ino, uint64_t *last_chunk, uint64_t *last_msg_timestamp);
int edwork_set_info(void *clientinfo, uint64_t last_ino, uint64_t last_chunk, uint64_t last_msg_timestamp);
unsigned int edwork_magnitude(struct edwork_data *data);
const unsigned char *edwork_who_i_am(struct edwork_data *data);
int edwork_try_spend(struct edwork_data *data, const unsigned char *proof_of_work, int proof_of_work_size);
int edwork_unspend(struct edwork_data *data, const unsigned char *proof_of_work, int proof_of_work_size);
int edwork_udp_socket(struct edwork_data *data);
#ifdef WITH_SCTP
int edwork_is_sctp(struct edwork_data *data, const void *clientaddr_ptr);
void edwork_force_sctp(struct edwork_data *data, int force_sctp);
int edwork_reconnect(struct edwork_data *data, int seconds);
#endif
const char *edwork_addr_ipv4(const void *clientaddr_ptr);
void edwork_close(struct edwork_data *data);
void edwork_destroy(struct edwork_data *data);
void edwork_callback_lock(struct edwork_data *data, int lock);
void edwork_reset_id(struct edwork_data *data);

void edwork_done();

#endif // __EDWORK_H
