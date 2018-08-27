#include "edwork.h"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#ifdef _WIN32
    #define socklen_t int
    #define _WIN32_WINNT    0x501
    #include <windows.h>
    #include <io.h>
    #include <winsock2.h>
    #include <wincrypt.h>

    void usleep(uint64_t usec) { 
        HANDLE timer; 
        LARGE_INTEGER ft; 

        ft.QuadPart = -(10*usec);

        timer = CreateWaitableTimer(NULL, TRUE, NULL); 
        SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0); 
        WaitForSingleObject(timer, INFINITE); 
        CloseHandle(timer); 
    }
#else
    #include <signal.h>
    #include <netdb.h>
    #include <sys/types.h> 
    #include <sys/socket.h>
    #include <sys/poll.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#include "thread.h"
#include "tinydir.h"
#include "sha256.h"
#include "avl.h"
#include "log.h"

uint64_t microseconds();
uint64_t switchorder(uint64_t input);

#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : switchorder(x))
#endif

#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : switchorder(x))
#endif

// half a second
#define MAX_US_OFFSET                   500000
#define MAX_EDWORK_SYNC_BLOCK_SIZE      0x12000
// one week
#define EDWORK_SYNC_MAX_TTL             604800
// 16MB buffer
#define EDWORK_SOCKET_BUFFER            0x1000000

#define EDWORK_MAX_SPENT_DB             0x10000

// max 128 bytes
#define EDWOR_MAX_LAN_BROADCAST_SIZE    128

struct client_data {
    struct sockaddr_in clientaddr;
    int clientlen;
    uint64_t last_ino;
    uint64_t last_chunk;
    uint64_t last_msg_timestamp;
    time_t last_seen;
};

struct edwork_data {
    int socket;

    unsigned char i_am[32];
    unsigned char key_id[32];
    char *log_dir;
    uint64_t sequence;

    struct client_data *clients;
    unsigned int clients_count;

    avl_tree_t tree;
    avl_tree_t spent;
    int spent_count;

    unsigned int magnitude;
    time_t magnitude_stamp;

    thread_mutex_t sock_lock;
#ifdef EDFS_MULTITHREADED
    thread_mutex_t thread_lock;
#endif
};

#ifdef EDFS_MULTITHREADED
    #define EDWORK_THREAD_LOCK(data)    thread_mutex_lock(&data->thread_lock);
    #define EDWORK_THREAD_UNLOCK(data)  thread_mutex_unlock(&data->thread_lock);
#else
    #define EDWORK_THREAD_LOCK(data)
    #define EDWORK_THREAD_UNLOCK(data)
#endif

const char *edwork_addr_ipv4(const void *clientaddr_ptr) {
    struct sockaddr_in *clientaddr = (struct sockaddr_in *)clientaddr_ptr;
    static char str_addr[sizeof("255.255.255.255:65535")];
    if (!clientaddr)
        return "";

    const unsigned char *sin_addr = (const unsigned char *)&clientaddr->sin_addr;
    snprintf(str_addr, sizeof(str_addr), "%i.%i.%i.%i:%i", (int)sin_addr[0], (int)sin_addr[1], (int)sin_addr[2], (int)sin_addr[3], (int)ntohs(clientaddr->sin_port));
    return str_addr;
}

static int sockaddr_compare(void *k1, void *k2) {
    struct sockaddr_in *a1 = (struct sockaddr_in *)k1;
    struct sockaddr_in *a2 = (struct sockaddr_in *)k2;

    if (a1->sin_addr.s_addr < a2->sin_addr.s_addr)
        return -1;

    if (a1->sin_addr.s_addr > a2->sin_addr.s_addr)
        return 1;

    if (a1->sin_port < a2->sin_port)
        return -1;

    if (a1->sin_port > a2->sin_port)
        return 1;

    return 0;
}

static int spent_compare(void *k1, void *k2) {
    return strcmp((const char *)k1, (const char *)k2);
}

void avl_key_destructor(void *key) {
    free(key);
}

void avl_spent_key_destructor(void *key) {
    free(key);
}

void avl_key_data_destructor(void *key, void *data) {
    avl_key_destructor(key);
}

void avl_spent_key_data_destructor(void *key, void *data) {
    avl_spent_key_destructor(key);
}

void edwork_init() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
}

void edwork_done() {
#ifdef _WIN32
    WSACleanup();
#endif
}

ssize_t safe_sendto(struct edwork_data *data, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    thread_mutex_lock(&data->sock_lock);
    ssize_t err = sendto(data->socket, (const char *)buf, len, flags, dest_addr, addrlen);
    thread_mutex_unlock(&data->sock_lock);
    return err;
}

ssize_t safe_recvfrom(struct edwork_data *data, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    thread_mutex_lock(&data->sock_lock);
    ssize_t err = recvfrom(data->socket, (char *)buf, len, flags, src_addr, addrlen);
    thread_mutex_unlock(&data->sock_lock);
    return err;
}

int edwork_random_bytes(unsigned char *destination, int len) {
#ifdef _WIN32
    HCRYPTPROV prov;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))  {
        return 0;
    }

    if (!CryptGenRandom(prov, len, destination))  {
        CryptReleaseContext(prov, 0);
        return 0;
    }

    CryptReleaseContext(prov, 0);
#else
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        return 0;
    }

    fread(destination, 1, len, f);
    fclose(f);
#endif
    return 1;
}

uint64_t edwork_random() {
    uint64_t seed;
    edwork_random_bytes((unsigned char *)&seed, sizeof(uint64_t));
    return seed;
}


struct edwork_data *edwork_create(int port, const char *log_dir, const unsigned char *key) {
    int optval;
    struct sockaddr_in serveraddr;

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) 
        return NULL;

#ifdef _WIN32
    // windows UDP bug
    #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)

    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    if (WSAIoctl(sockfd, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL))
        log_error("error patching windows UDP socket");
#endif

    optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(int));

    optval = EDWORK_SOCKET_BUFFER;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&optval, sizeof(optval)))
        log_warn("error setting send buffer to %i bytes", optval);

    optval = EDWORK_SOCKET_BUFFER;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *)&optval, sizeof(optval)))
        log_warn("error setting recv buffer to %i bytes", optval);

#ifdef _WIN32
    optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&optval, sizeof(optval)))
        log_warn("error setting sendto timeout");
#else
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 2000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv,sizeof(tv)) < 0)
        log_warn("error setting sendto timeout");
#endif

    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const char *)&optval, sizeof(optval)) < 0)
        log_warn("error setting broadcast option");

    memset((char *)&serveraddr, 0, sizeof(serveraddr));

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);

    if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return NULL;
    }

    struct edwork_data *data = (struct edwork_data *)malloc(sizeof(struct edwork_data));
    memset(data, 0, sizeof(struct edwork_data));

    data->socket = sockfd;

    int len = log_dir ? strlen(log_dir) : 0;
    data->log_dir = (char *)malloc(len + 1);
    memcpy(data->log_dir, log_dir, len);
    data->log_dir[len] = 0;

    unsigned char random[32];
    uint64_t rand = edwork_random();
    memcpy(random, &rand, sizeof(uint64_t));
    rand = edwork_random();
    memcpy(random + 8, &rand, sizeof(uint64_t));
    rand = edwork_random();
    memcpy(random + 16, &rand, sizeof(uint64_t));
    rand = edwork_random();
    memcpy(random + 24, &rand, sizeof(uint64_t));

    sha256(random, 32, data->i_am);

    data->sequence = edwork_random();

    // my version (1.0)
    data->i_am[0] = 0x01;
    data->i_am[1] = 0x00;

    avl_initialize(&data->tree, sockaddr_compare, avl_key_destructor);
    avl_initialize(&data->spent, spent_compare, avl_spent_key_destructor);
    data->spent_count = 0;

    data->magnitude = 0;
    data->magnitude_stamp = 0;

    if (key)
        sha256(key, 32, data->key_id);

    thread_mutex_init(&data->sock_lock);
#ifdef EDFS_MULTITHREADED
    thread_mutex_init(&data->thread_lock);
#endif
    edwork_add_node(data, "255.255.255.255", port);

    return data;
}

int edwork_try_spend(struct edwork_data *data, const unsigned char *proof_of_work, int proof_of_work_size) {
    char *proof = (char *)malloc(proof_of_work_size + 1);
    if (!proof)
        return 0;
    memcpy(proof, proof_of_work, proof_of_work_size);
    proof[proof_of_work_size] = 0;

    void *exists = avl_search(&data->spent, proof);
    if (exists) {
        free(proof);
        return 0;
    }

    if (data->spent_count >= EDWORK_MAX_SPENT_DB) {
        // reset spent
        avl_destroy(&data->spent, avl_spent_key_data_destructor);
        avl_initialize(&data->spent, spent_compare, avl_spent_key_destructor);
        data->spent_count = 0;
    }

    avl_insert(&data->spent, proof, (void *)1);
    data->spent_count ++;
    return 1;
}

unsigned char *make_packet(struct edwork_data *data, const char type[4], const unsigned char *data_buffer, int *len, int confirmed_acks, uint64_t force_timestamp, uint64_t ino) {
    unsigned char *buf = (unsigned char *)malloc(128 + *len);
    // static const char reserved_buf[40] = { 0 };
    if (!buf)
        return NULL;

    memcpy(buf, data->i_am, 32);
    uint64_t sequence = htonll(data->sequence);
    uint32_t size = htonl((uint32_t)*len);
    memcpy(buf + 32, &sequence, sizeof(uint64_t));
    memcpy(buf + 40, type, 4);
    uint64_t timestamp = force_timestamp;
    if (!timestamp)
        timestamp = microseconds();
    timestamp = htonll(timestamp);
    memcpy(buf + 44, &timestamp, sizeof(timestamp));
    // reserved bytes for future use
    edwork_random_bytes(buf + 52, 40);
    // memcpy(buf + 52, reserved_buf, sizeof(reserved_buf));
    hmac_sha256(data->key_id, 32, buf, 92, data_buffer, *len, buf + 92); 

    memcpy(buf + 124, &size, sizeof(uint32_t));
    if (data_buffer)
        memcpy(buf + 128, data_buffer, *len);

    *len += 128;

    if (confirmed_acks > 0) {
        char buf_path[4096];
        buf_path[0] = 0;
        snprintf(buf_path, 4096, "%s/%" PRIu64, data->log_dir, ino);
        FILE *f = fopen(buf_path, "wb");
        if (f) {
            uint32_t acks_buffer = htonl(confirmed_acks);
            fwrite(&acks_buffer, 1, sizeof(acks_buffer), f);
            // second one is "original acks"
            fwrite(&acks_buffer, 1, sizeof(acks_buffer), f);
            if (fwrite(buf, 1, *len, f) != *len) {
                fclose(f);
                errno = EIO;
                return NULL;
            }
            fclose(f);
        } else {
            free(buf);
            *len = 0;
            return NULL;
        }
    }
    data->sequence ++;
    return buf;
}

void edwork_confirm_seq(struct edwork_data *data, uint64_t sequence, int acks) {
    if (!acks)
        return;

    char buf_path[4096];
    buf_path[0] = 0;
    snprintf(buf_path, 4096, "%s/%" PRIu64, data->log_dir, sequence);
    if (acks < 0) {
        log_debug("forcefully deleted edwork block %", buf_path);
        if (unlink(buf_path))
            log_warn("error deleting %s, errno: %i", buf_path, errno);
        return;
    }

    FILE *f = fopen(buf_path, "r+b");
    if (f) {
        uint32_t acks_buffer;
        if (fread(&acks_buffer, 1, sizeof(uint32_t), f) != sizeof(uint32_t)) {
            fclose(f);
            return;
        }
        acks_buffer = ntohl(acks_buffer);
        if ((acks_buffer) && (acks_buffer > acks)) {
            acks_buffer --;
            acks_buffer = htonl(acks_buffer);
            fseek(f, 0, SEEK_SET);
            if (fwrite(&acks_buffer, 1, sizeof(uint32_t), f) != sizeof(uint32_t))
                log_error("error writing ACKs buffer");
        } else {
            log_debug("marked edwork block %s for delete (%i/%i)", buf_path, acks_buffer, acks);
            acks_buffer = 0;
        }

        fclose(f);

        if (!acks_buffer)
            unlink(buf_path);
    }
}

const unsigned char *edwork_who_i_am(struct edwork_data *data) {
    if (!data)
        return NULL;

    return data->i_am;
}

int edwork_get_info(void *clientinfo, uint64_t *last_ino, uint64_t *last_chunk, uint64_t *last_msg_timestamp) {
    struct client_data *data = (struct client_data *)clientinfo;
    if (data) {
        if (last_ino)
            *last_ino = data->last_ino;
        if (last_chunk)
            *last_chunk = data->last_chunk;
        if (last_msg_timestamp)
            *last_msg_timestamp = data->last_msg_timestamp;
        return 1;
    }
    return 0;
}

int edwork_set_info(void *clientinfo, uint64_t last_ino, uint64_t last_chunk, uint64_t last_msg_timestamp) {
    struct client_data *data = (struct client_data *)clientinfo;
    if (data) {
        data->last_ino = last_ino;
        data->last_chunk = last_chunk;
        data->last_msg_timestamp = last_msg_timestamp;
        return 1;
    }
    return 0;
}


void *add_node(struct edwork_data *data, struct sockaddr_in *sin, int client_len, int update_seen, int return_old_peer) {
    if ((!sin) || (client_len <= 0) || (sin->sin_addr.s_addr == 0) || (sin->sin_port == 0))
        return 0;

    EDWORK_THREAD_LOCK(data);
    struct client_data *peer = NULL;
    uintptr_t data_index = (uintptr_t)avl_search(&data->tree, sin);
    if (data_index > 0)
        peer = &data->clients[data_index - 1];

    if (peer) {
        if (update_seen)
            peer->last_seen = time(NULL);
        EDWORK_THREAD_UNLOCK(data);
        if (return_old_peer)
            return peer;
        return 0;
    }

    // rewrite this (slow)
    data->clients = (struct client_data *)realloc(data->clients, sizeof(struct client_data) * (data->clients_count + 1));
    if (!data->clients) {
        data->clients_count = 0;
        return 0;
    }
    memcpy(&data->clients[data->clients_count].clientaddr, sin, client_len);
    memset(&data->clients[data->clients_count].clientaddr + client_len, 0, sizeof(data->clients[data->clients_count].clientaddr) - client_len);
    data->clients[data->clients_count].clientlen = client_len;
    data->clients[data->clients_count].last_ino = 0;
    data->clients[data->clients_count].last_chunk = 0;
    data->clients[data->clients_count].last_msg_timestamp = 0;
    data->clients[data->clients_count].last_seen = time(NULL);

    data->clients_count ++;

    struct sockaddr_in *addr_key = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if (addr_key) {
        memcpy(addr_key, sin, sizeof(struct sockaddr_in));
        avl_insert(&data->tree, addr_key, (void *)(uintptr_t)data->clients_count);
    }

    EDWORK_THREAD_UNLOCK(data);
    return &data->clients[data->clients_count - 1];
}

void *edwork_ensure_node_in_list(struct edwork_data *data, void *clientaddr, int clientaddrlen) {
    if ((!data) || (!clientaddr) || (!clientaddrlen))
        return 0;

    return add_node(data, (struct sockaddr_in *)clientaddr, clientaddrlen, 1, 1);
}

void edwork_add_node(struct edwork_data *data, const char *node, int port) {
    struct sockaddr_in sin;
    struct hostent     *hp;

    if (!data)
        return;

    if ((hp = gethostbyname(node)) == 0)
        return;

    // add ipv6
    memset(&sin, 0, sizeof(sin));
    sin.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons((int)port);

    if (add_node(data, &sin, sizeof(sin), 0, 0))
        log_info("added node %s:%i", node, port);
}

int edwork_private_broadcast(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, int buf_is_packet, const void *except, int except_len, uint64_t force_timestamp, uint64_t ino, const void *clientaddr, int clientaddr_len, int sleep_us) {
    if (!data)
        return -1;

    if (!data->clients_count) {
        log_warn("no nodes to broadcast to");
        return 0;
    }

    EDWORK_THREAD_LOCK(data);

    unsigned char *packet = NULL;
    const unsigned char *ptr = buf;
    if (buf_is_packet) {
        ptr = buf;
    } else {
        log_trace("broadcasting %.4s", type);
        packet = make_packet(data, type, buf, &len, confirmed_acks, force_timestamp, ino);
        ptr = packet;
    }
    uint64_t rand = edwork_random() % data->clients_count;
    int wrapped_to_first = 0;
    time_t threshold = time(NULL) - 120;
    if ((ptr) && (len > 0)) {
        unsigned int i;
        if ((clientaddr) && (clientaddr_len > 0)) {
            if (safe_sendto(data, (const char *)ptr, len, 0, (const struct sockaddr *)clientaddr, clientaddr_len) <= 0) {
#ifdef _WIN32
                log_trace("error %i in sendto (%s)", (int)WSAGetLastError(), edwork_addr_ipv4(clientaddr));
#else
                log_trace("error %i in sendto (%s)", (int)errno, edwork_addr_ipv4(clientaddr));
#endif
                // fallback sending to other clients
            } else {
                EDWORK_THREAD_UNLOCK(data);
                free(packet);
                return 0;
            }
        }
        int lan_broadcast = 1;
        // exclude data and large packages from broadcast
        if ((len > EDWOR_MAX_LAN_BROADCAST_SIZE) || ((type[0] == 'd') && (type[1] == 'a') && (type[2] == 't')))
            lan_broadcast = 0;
        if ((data->clients_count < max_nodes) || (max_nodes <= 0)) {
            i = rand % data->clients_count;
            unsigned int send_to = 0;
            while (send_to < data->clients_count) {
                if ((i) || (lan_broadcast)) {
                    if ((except) && (except_len == data->clients[i].clientlen) && (!memcmp(except, &data->clients[i].clientaddr, except_len))) {
                        log_debug("not broadcasting to same client");
                    } else
                    if ((data->clients[i].last_seen >= threshold) || (i == 0)) { // i == 0 => means first addres (broadcast address)
                        if (safe_sendto(data, (const char *)ptr, len, 0, (struct sockaddr *)&data->clients[i].clientaddr, data->clients[i].clientlen) <= 0) {
#ifdef _WIN32
                            log_trace("error %i in sendto (client #%i: %s)", (int)WSAGetLastError(), i, edwork_addr_ipv4(&data->clients[i].clientaddr));
#else
                            log_trace("error %i in sendto (client #%i: %s)", (int)errno, i, edwork_addr_ipv4(&data->clients[i].clientaddr));
#endif
                            data->clients[i].last_seen = threshold - 1;
                        }
                    }
                }
                i ++;
                if (i >= data->clients_count) {
                    i = 0;
                    if (wrapped_to_first)
                        break;
                    wrapped_to_first = 1;
                }
                send_to ++;
                if (sleep_us > 0)
                    usleep(sleep_us);
            }
        } else {
            int sent_to = 0;
            i = (unsigned int)rand;
            do {
                if ((i) || (lan_broadcast)) {
                    if ((except) && (except_len == data->clients[i].clientlen) && (!memcmp(except, &data->clients[i].clientaddr, except_len))) {
                        sent_to ++;
                        log_debug("not broadcasting to same client");
                    } else
                    if ((data->clients[i].last_seen >= threshold) || (i == 0)) { // i == 0 => means first addres (broadcast address)
                        if (safe_sendto(data, (const char *)ptr, len, 0, (struct sockaddr *)&data->clients[i].clientaddr, data->clients[i].clientlen) > 0) {
                            sent_to ++;
                        } else {
#ifdef _WIN32
                            log_trace("error %i in sendto (client #%i: %s)", (int)WSAGetLastError(), i, edwork_addr_ipv4(&data->clients[i].clientaddr));
#else
                            log_trace("error %i in sendto (client #%i: %s)", (int)errno, i, edwork_addr_ipv4(&data->clients[i].clientaddr));
#endif
                            data->clients[i].last_seen = threshold - 1;
                        }
                    }
                }

                i ++;
                if (i >= data->clients_count) {
                    i = 0;
                    // already sent to first one
                    if (wrapped_to_first)
                        break;
                    wrapped_to_first = 1;
                }
                if (sleep_us > 0)
                    usleep(sleep_us);
            } while (sent_to < max_nodes);
        }
    }
    EDWORK_THREAD_UNLOCK(data);
    free(packet);
    return 0;
}

int edwork_broadcast(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, uint64_t ino) {
    return edwork_private_broadcast(data, type, buf, len, confirmed_acks, max_nodes, 0, NULL, 0, 0, ino, NULL, 0, 500);
}

int edwork_broadcast_client(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, uint64_t ino, const void *clientaddr, int clientaddr_len) {
    return edwork_private_broadcast(data, type, buf, len, confirmed_acks, max_nodes, 0, NULL, 0, 0, ino, clientaddr, clientaddr_len, 0);
}

int edwork_broadcast_except(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, const void *except, int except_len, uint64_t force_timestamp, uint64_t ino) {
    return edwork_private_broadcast(data, type, buf, len, confirmed_acks, max_nodes, 0, except, except_len, force_timestamp, ino, NULL, 0, 0);
}

unsigned int edwork_jumbo(struct edwork_data *data, unsigned char *jumbo_buf, unsigned int max_jumbo_size, unsigned int jumbo_size, unsigned char *buf, int buf_size) {
    if ((jumbo_size + buf_size + 2 >= max_jumbo_size) && (jumbo_size)) {
        edwork_private_broadcast(data, "jmbo", jumbo_buf, jumbo_size, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0);
        jumbo_size = 0;
    }
    unsigned short size_short = htons((unsigned short)buf_size);
    memcpy(jumbo_buf + jumbo_size, &size_short, 2);
    memcpy(jumbo_buf + jumbo_size + 2, buf, buf_size);
    jumbo_size += buf_size + 2;

    return jumbo_size;
}

unsigned int edwork_rebroadcast(struct edwork_data *data, unsigned int max_count, unsigned int offset) {
    if (!data)
        return 0;

    tinydir_dir dir;
    
    if (tinydir_open(&dir, data->log_dir)) {
        log_error("error opening log directory %s", data->log_dir);
        return 0;
    }
    unsigned int rebroadcast_count = 0;
    // unsigned char jumbo_buf[0xA000];
    // unsigned int jumbo_size = 0;
    while (dir.has_next) {
        tinydir_file file;
        tinydir_readfile(&dir, &file);

        if (!file.is_dir) {
            if (offset) {
                offset --;
                tinydir_next(&dir);
                continue;
            }
            char buf_path[4096];
            buf_path[0] = 0;
            snprintf(buf_path, 4096, "%s/%s", data->log_dir, file.name);
            FILE *f = fopen(buf_path, "rb");
            if (f) {
                unsigned char buf[MAX_EDWORK_SYNC_BLOCK_SIZE];
                int size = fread(buf, 1, MAX_EDWORK_SYNC_BLOCK_SIZE, f);
                int invalid = 1;
                if (size >= 136) {
                    invalid = 0;
                    uint64_t timestamp = ntohll(*(uint64_t *)(buf + 52));
                    uint64_t now = microseconds();
                    if (timestamp - MAX_US_OFFSET > now) {
                        log_warn("edwork block %s has timestamp in the future, dropping", file.name);
                    } else
                    if (timestamp < now - (uint64_t)EDWORK_SYNC_MAX_TTL * (uint64_t)1000000) {
                        log_warn("edwork block %s is too old, dropping (timestamp %i, now %i)", file.name, timestamp, now);
                        fclose(f);
                        unlink(buf_path);
                        tinydir_next(&dir);
                        continue;
                    } else {
                        // re-id (maybe restarted the service)
                        memcpy(buf + 8, data->i_am, 32);
                        // re-timestamp
                        *(uint64_t *)(buf + 52) = htonll(microseconds());

                        hmac_sha256(data->key_id, 32, buf + 8, 92, buf + 136, size - 136, buf + 100);
                        
                        // jumbo_size = edwork_jumbo(data, jumbo_buf, sizeof(jumbo_buf), jumbo_size, buf + 8, size - 8);
                        edwork_private_broadcast(data, NULL, buf + 8, size - 8, 0, 0, 1, NULL, 0, 0, 0, NULL, 0, 0);
                        rebroadcast_count ++;
                    }
                } else
                    log_warn("error reading edwork block %s, read size: %i , errno %i", size, file.name, errno);
                fclose(f);
                if (invalid) {
                    log_info("invalid edwork block %s, deleting block", file.name);
                    if (unlink(buf_path))
                        log_warn("error deleting %s, errno: %i", file.name, errno);
                }
            } else {
                log_warn("error opening edwork block %s", file.name);
            }
            if ((max_count) && (rebroadcast_count >= max_count))
                break;
        }
        tinydir_next(&dir);
    }
    tinydir_close(&dir);
    // if (jumbo_size)
    //     edwork_private_broadcast(data, "jmbo", jumbo_buf, jumbo_size, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0);
    return rebroadcast_count;
}

int edworks_data_pending(struct edwork_data* data, int timeout_ms) {
    if (!data)
        return -1;

#ifdef _WIN32
    struct timeval timeout;
    timeout.tv_sec = 0;
    if (timeout_ms < 0)
        timeout.tv_usec = 0;
    else
        timeout.tv_usec = (int)timeout_ms * 1000;
    fd_set socks;

    FD_ZERO(&socks);
    FD_SET(data->socket, &socks);

    int sel_val = select(FD_SETSIZE, &socks, 0, 0, &timeout);
    return (sel_val != 0);
#else
    struct pollfd ufds[1];
    ufds[0].fd     = data->socket;
    ufds[0].events = POLLIN;

    if (timeout_ms < 0)
        timeout_ms = 0;

    return poll(ufds, 1, (int)timeout_ms);
#endif
}

int edwork_send_to_peer(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, void *clientaddr, int clientaddrlen) {
    unsigned char *packet = make_packet(data, type, buf, &len, 0, 0, 0);
    int sent = -1;
    if ((packet) && (len > 0)) {
        if ((data) && (clientaddr) && (clientaddrlen))
            sent = safe_sendto(data, (const char *)packet, len, 0, (struct sockaddr *)clientaddr, clientaddrlen);
        if (sent < 0)
            log_error("error in sendto (peer)");
    }
    free(packet);
    return sent;
}

int edwork_remove_addr(struct edwork_data *data, void *sin, int client_len) {
    EDWORK_THREAD_LOCK(data);
    uintptr_t index = (uintptr_t)avl_search(&data->tree, sin);
    if ((!index) || (index == 1)) {
        EDWORK_THREAD_UNLOCK(data);
        return 0;
    }
    
    if ((data->clients_count > 1) && (index <= data->clients_count)) {
        avl_remove(&data->tree, sin);
        memmove(&data->clients[index - 1], &data->clients[index], sizeof(struct client_data) * (data->clients_count - index));
        int i;
        data->clients_count --;

        for (i = index - 1; i < data->clients_count; i++) {
            avl_remove(&data->tree, sin);

            struct sockaddr_in *addr_key = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
            if (addr_key) {
                memcpy(addr_key, &data->clients[index].clientaddr, sizeof(struct sockaddr_in));
                avl_insert(&data->tree, addr_key, (void *)(uintptr_t)(i + 1));
            }

        }
    }
    EDWORK_THREAD_UNLOCK(data);
    return 1;
}

int edwork_dispatch_data(struct edwork_data* data, edwork_dispatch_callback callback, unsigned char *buffer, int n, void *clientaddr, int clientaddrlen, void *userdata) {
    if (n < 0)
        return -1;

    // invalid message, drop it
    if (n < 128)
        return 0;

    const unsigned char *who_am_i = buffer;
    if (!memcmp(who_am_i, data->i_am, 32)) {
        log_trace("dropping message, it is mine (%s)", edwork_addr_ipv4((struct sockaddr_in *)clientaddr));
        edwork_remove_addr(data, clientaddr, clientaddrlen);
        return 0;
    }

    if ((who_am_i[0] != 0x01) && (who_am_i[1] != 0x00)) {
        log_warn("dropping message, unsupported version (%s)", edwork_addr_ipv4((struct sockaddr_in *)clientaddr));
        edwork_remove_addr(data, clientaddr, clientaddrlen);
        return 0;
    }

    uint64_t sequence = htonll(data->sequence);
    char type[5];
    uint64_t timestamp;
    uint32_t size;

    memcpy(&sequence, buffer + 32, sizeof(uint64_t));
    sequence = ntohll(sequence);

    memcpy(type, buffer + 40, 4);
    type[4] = 0;

    memcpy(&timestamp, buffer + 44, sizeof(uint64_t));
    timestamp = ntohll(timestamp);

    memcpy(&size, buffer + 124, sizeof(uint32_t));
    size = ntohl(size);

    const unsigned char *payload = buffer + 128;

    if (n != size + 128) {
        log_error("a message of invalid size was received %i/%i", n, size);
        return 0;
    }

    unsigned char hmac[32];
    hmac_sha256(data->key_id, 32, buffer, 92, payload, size, hmac);
    if (memcmp(hmac, buffer + 92, 32)) {
        log_warn("HMAC verify failed for type %s (%s)", type, edwork_addr_ipv4(clientaddr));
        return 0;
    }

    if ((callback) && (!memcmp(type, "jmbo", 4))) {
        log_info("JMBO received");
        unsigned char *ptr = buffer + 128;
        while (size > 2) {
            unsigned short size_short = ntohs(*(unsigned short *)ptr);
            ptr += 2;
            size -= 2;
            unsigned char old_char = ptr[size_short];
            if (size_short <= size)
                edwork_dispatch_data(data, callback, ptr, size_short, clientaddr, clientaddrlen, userdata);
            else
                break;
            ptr[size_short] = old_char;
            ptr += size_short;
            size -= size_short;
        }
        return 1;
    }

    if (callback) {
        // ensure json is 0 terminated
        buffer[n] = 0;
        callback(data, sequence, timestamp, type, payload, size, clientaddr, clientaddrlen, who_am_i, userdata);
    }

    return 1;
}

int edwork_dispatch(struct edwork_data* data, edwork_dispatch_callback callback, int timeout_ms, void *userdata) {
    if (!data)
        return -1;

    if (!edworks_data_pending(data, timeout_ms))
        return 0;

    unsigned char buffer[0xFFFF];
    struct sockaddr_in clientaddr;
    do {
        socklen_t clientlen = sizeof(clientaddr);
        int n = safe_recvfrom(data, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *) &clientaddr, &clientlen);
        if (n <= 0) {
    #ifdef _WIN32
            log_error("error in recvfrom: %i", (int)WSAGetLastError());
    #else
            log_error("error in recvfrom: %i", (int)errno);
    #endif
            return 0;
        }
        if (edwork_dispatch_data(data, callback, buffer, n, &clientaddr, clientlen, userdata) <= 0)
            break;
    } while (edworks_data_pending(data, 0));
    return 1;
}

int edwork_get_node_list(struct edwork_data *data, unsigned char *buf, int *buf_size, unsigned int offset, time_t threshold) {
    if (!data)
        return -1;

    int records = 0;
    unsigned int i;
    // active in last 72 hours
    EDWORK_THREAD_LOCK(data);
    for (i = offset; i < data->clients_count; i++) {
        if (*buf_size < 7)
            break;

        if (data->clients[i].last_seen >= threshold) {
            *buf ++ = 6;
            memcpy(buf, &data->clients[i].clientaddr.sin_addr, 4);
            buf += 4;
            memcpy(buf, &data->clients[i].clientaddr.sin_port, 2);
            buf += 2;
            *buf_size -= 7;
            records ++;
        }
    }
    EDWORK_THREAD_UNLOCK(data);
    *buf_size = records * 7;
    return records;
}

int edwork_add_node_list(struct edwork_data *data, const unsigned char *buf, int buf_size) {
    if (!data)
        return -1;

    int records = 0;
    char buffer[32];
    while (buf_size >= 7) {
        int size = *buf ++;
        if (size > buf_size)
            break;

        if (size == 6) {
            // ipv4
            buffer[0] = 0;
            snprintf(buffer, sizeof(buffer), "%i.%i.%i.%i", (int)buf[0], (int)buf[1], (int)buf[2], (int)buf[3]);

            unsigned short port;
            memcpy(&port, buf + 4, 2);
            port = ntohs(port);

            edwork_add_node(data, buffer, port);
        }

        buf_size -= size;
        buf += size;
    }
    return records;
}

unsigned int edwork_magnitude(struct edwork_data *data) {
    if ((!data) || (!data->clients_count))
        return 0;

    unsigned int magnitude = 0;
    unsigned int i;
    time_t threshold = time(NULL) - 1200;
    if ((data->magnitude_stamp > threshold) && (data->magnitude > 0))
        return data->magnitude;

    EDWORK_THREAD_LOCK(data);
    for (i = 0; i < data->clients_count; i++) {
        if (data->clients[i].last_seen > threshold) {
            magnitude ++;
            if (magnitude > 1000)
                break;
        }
    }
    data->magnitude_stamp = time(NULL);
    data->magnitude = magnitude;
    EDWORK_THREAD_UNLOCK(data);

    return magnitude;
}

void edwork_destroy(struct edwork_data* data) {
    if (!data)
        return;

    avl_destroy(&data->spent, avl_spent_key_data_destructor);
    avl_destroy(&data->tree, avl_key_data_destructor);
    thread_mutex_term(&data->sock_lock);
#ifdef EDFS_MULTITHREADED
    thread_mutex_init(&data->thread_lock);
#endif

    free(data->log_dir);
    free(data->clients);
    free(data);
}
