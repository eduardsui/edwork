#include "edwork.h"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#if defined(WITH_USRSCTP) && !defined(WITH_SCTP)
    #define WITH_SCTP
#endif

#ifdef _WIN32
    #define _WIN32_WINNT    0x502
    #include <winsock2.h>
    #include <windows.h>
    #include <io.h>
    #include <wincrypt.h>
    #include <ws2tcpip.h>

    void usleep(uint64_t usec) { 
        HANDLE timer; 
        LARGE_INTEGER ft; 

        ft.QuadPart = -(10*usec);

        timer = CreateWaitableTimer(NULL, TRUE, NULL); 
        SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0); 
        WaitForSingleObject(timer, INFINITE); 
        CloseHandle(timer); 
    }
    #ifdef WITH_SCTP
        #define WITH_USRSCTP
    #endif
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
#ifdef WITH_SCTP
    #ifdef WITH_USRSCTP
        #include <usrsctp.h>

        #define SCTP_SOCKET_TYPE    struct socket *
        #define SCTP_socket(domain, type, protocol)                     usrsctp_socket(domain, type, protocol, edwork_sctp_receive, NULL, 0, data)
        #define SCTP_setsockopt(socket, level, optname, optval, optlen) usrsctp_setsockopt(socket, level, optname, optval, optlen)
        #define SCTP_bind(socket, addr, addrlen)                        usrsctp_bind(socket, addr, addrlen)
        #define SCTP_listen(socket, backlog)                            usrsctp_listen(socket, backlog)
        #define SCTP_accept(socket, addr, addrlen)                      usrsctp_accept(socket, addr, addrlen)
        #define SCTP_connect(socket, addr, addrlen)                     usrsctp_connect(socket, (struct sockaddr *)addr, addrlen)
        #define SCTP_set_non_blocking(socket, nb)                       usrsctp_set_non_blocking(socket, nb)
        #define SCTP_send(socket, buf, len, flags, dest_addr, addrlen)  usrsctp_sendv(socket, buf, len, (struct sockaddr *)dest_addr, dest_addr ? 1 : 0, &info, sizeof(info), SCTP_SENDV_PRINFO, flags)
        #define SCTP_recv(socket, buf, len, flags, src_addr, addrlen)   usrsctp_recvv(socket, buf, len, src_addr, addrlen, &rcv_info, &infolen, &infotype, &flags)
        #define SCTP_getpaddrs(socket, assoc_id, addrs)                 usrsctp_getpaddrs(socket, assoc_id, addrs)
        #define SCTP_freepaddrs(addrs)                                  usrsctp_freepaddrs(addrs)
        #define SCTP_getassocid(socket, sa)                             usrsctp_getassocid(socket, (struct sockaddr *)sa)
        #define SCTP_shutdown(socket, how)                              usrsctp_shutdown(socket, how)
        #define SCTP_close(socket)                                      usrsctp_close(socket)
    #else
        #include <netinet/sctp.h>

        sctp_assoc_t sctp_getassocid(int sock, const struct sockaddr *sa) {
	        struct sctp_paddrinfo sp;
	        socklen_t siz;
	        size_t sa_len;
	        switch (sa->sa_family) {
	            case AF_INET:
		            sa_len = sizeof(struct sockaddr_in);
		            break;
	            case AF_INET6:
		            sa_len = sizeof(struct sockaddr_in6);
		            break;
	            default:
		            return ((sctp_assoc_t) 0);
	        }
	        memcpy(&sp.spinfo_address, sa, sa_len);
	        if (getsockopt(sock, IPPROTO_SCTP, SCTP_GET_PEER_ADDR_INFO, &sp, &siz) != 0)
		        return ((sctp_assoc_t) 0);

	        return sp.spinfo_assoc_id;
        } 

        #define SCTP_SOCKET_TYPE    int
        #define SCTP_socket(domain, type, protocol)                     socket(domain, type, protocol)
        #define SCTP_setsockopt(socket, level, optname, optval, optlen) setsockopt(socket, level, optname, optval, optlen)
        #define SCTP_bind(socket, addr, addrlen)                        bind(socket, addr, addrlen)
        #define SCTP_listen(socket, backlog)                            listen(socket, backlog)
        #define SCTP_accept(socket, addr, addrlen)                      accept(socket, addr, addrlen)
        #define SCTP_connect(socket, addr, addrlen)                     connect(socket, addr, addrlen)
        #define SCTP_set_non_blocking(socket, nb)                       
        #define SCTP_send(socket, buf, len, flags, dest_addr, addrlen)  sctp_sendmsg(socket, buf, len, (struct sockaddr *)dest_addr, addrlen, 0, flags, 0, EDWORK_SCTP_TTL, 0)
        #define SCTP_recv(socket, buf, len, flags, src_addr, addrlen)   sctp_recvmsg(socket, buf, len, src_addr, addrlen, NULL, &flags)
        #define SCTP_getpaddrs(socket, assoc_id, addrs)                 sctp_getpaddrs(socket, assoc_id, addrs)
        #define SCTP_freepaddrs(addrs)                                  sctp_freepaddrs(addrs)
        #define SCTP_getassocid(socket, sa)                             sctp_getassocid(socket, sa)
        #define SCTP_shutdown(socket, how)                              shutdown(socket, how)
        #define SCTP_close(socket)                                      close(socket)

    #endif
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

#define EDWORK_SCTP_EVENTS              { SCTP_ASSOC_CHANGE }

struct client_data {
    struct sockaddr_in clientaddr;
    int clientlen;
#ifdef WITH_SCTP
    SCTP_SOCKET_TYPE socket;
#endif
    uint64_t last_ino;
    uint64_t last_chunk;
    uint64_t last_msg_timestamp;
    time_t last_seen;

    unsigned char is_listen_socket;
    unsigned char sctp_socket;
#ifdef WITH_SCTP
    time_t sctp_timestamp;
    time_t sctp_reconnect_timestamp;
    unsigned char is_sctp;
#endif
};

struct edwork_data {
    int socket;
#ifdef WITH_SCTP
    SCTP_SOCKET_TYPE sctp_socket;

    void *sctp_last_addr;
    sctp_assoc_t sctp_last_assoc_id;
#endif

    unsigned char i_am[32];
    unsigned char key_id[32];
    unsigned char chain[32];

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
    thread_mutex_t clients_lock;
    thread_mutex_t lock;
    thread_mutex_t callback_lock;
#ifdef EDFS_MULTITHREADED
    thread_mutex_t thread_lock;
#endif

#ifdef WITH_SCTP
    time_t sctp_timestamp;
    #ifdef WITH_USRSCTP
        edwork_dispatch_callback callback;
        void *userdata;
    #else
        struct pollfd *ufds;
        int ufds_len;
    #endif
    int force_sctp;
#endif
};

#ifdef EDFS_MULTITHREADED
    #define EDWORK_THREAD_LOCK(data)    thread_mutex_lock(&data->thread_lock);
    #define EDWORK_THREAD_UNLOCK(data)  thread_mutex_unlock(&data->thread_lock);
#else
    #define EDWORK_THREAD_LOCK(data)
    #define EDWORK_THREAD_UNLOCK(data)
#endif

#ifdef WITH_SCTP
int edwork_send_to_sctp_socket(struct edwork_data *data, SCTP_SOCKET_TYPE socket, const char type[4], const unsigned char *buf, int len, void *clientaddr, int clientaddrlen, int ttl);
static SCTP_SOCKET_TYPE edwork_sctp_connect(struct edwork_data *data, const struct sockaddr *addr, int addr_len);
#endif
int edwork_remove_addr(struct edwork_data *data, void *sin, int client_len);


const char *edwork_addr_ipv4(const void *clientaddr_ptr) {
    struct sockaddr_in *clientaddr = (struct sockaddr_in *)clientaddr_ptr;
    static char str_addr[sizeof("255.255.255.255:65535")];
    if (!clientaddr)
        return "";

    if (clientaddr->sin_family == AF_INET) {
        const unsigned char *sin_addr = (const unsigned char *)&clientaddr->sin_addr;
        snprintf(str_addr, sizeof(str_addr), "%i.%i.%i.%i:%i", (int)sin_addr[0], (int)sin_addr[1], (int)sin_addr[2], (int)sin_addr[3], (int)ntohs(clientaddr->sin_port));
        return str_addr;
    }
    if (clientaddr->sin_family == AF_INET6) {
        // to do
        return "(ipv6addr)";
    }
    return "(unknown socket type)";
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
#if defined(WITH_SCTP) && defined(WITH_USRSCTP)
    #ifdef SCTP_UDP_ENCAPSULATION
        usrsctp_init(EDWORK_SCTP_UDP_TUNNELING_PORT, NULL, NULL);
    #else
        usrsctp_init(0, NULL, NULL);
    #endif
    usrsctp_sysctl_set_sctp_sendspace(0x2000000);
    usrsctp_sysctl_set_sctp_recvspace(0x2000000);
    usrsctp_sysctl_set_sctp_rto_max_default(100);
    usrsctp_sysctl_set_sctp_rto_min_default(50);
    usrsctp_sysctl_set_sctp_rto_initial_default(50);
    usrsctp_sysctl_set_sctp_init_rto_max_default(30000);
    usrsctp_sysctl_set_sctp_sack_freq_default(1);
    usrsctp_sysctl_set_sctp_delayed_sack_time_default(50);
    usrsctp_sysctl_set_sctp_max_burst_default(1);
    usrsctp_sysctl_set_sctp_enable_sack_immediately(1);
    usrsctp_sysctl_set_sctp_nat_friendly(1);
    usrsctp_sysctl_set_sctp_mobility_base(1);
    usrsctp_sysctl_set_sctp_mobility_fasthandoff(1);
    usrsctp_sysctl_set_sctp_blackhole(2);
    usrsctp_sysctl_set_sctp_default_frag_interleave(2);
    usrsctp_sysctl_set_sctp_ecn_enable(1);
#endif
}

void edwork_done() {
#ifdef _WIN32
    WSACleanup();
#endif
#if defined(WITH_SCTP) && defined(WITH_USRSCTP)
    int max_loop = 50;
    while (usrsctp_finish() != 0) {
        usleep(100000);
        if (--max_loop <= 0) {
            log_error("usrsctp_finish timed out");
            break;
        }
    }
#endif
}

#ifdef WITH_SCTP

#ifdef WITH_USRSCTP
static void edwork_sctp_update_socket(struct edwork_data *edwork, struct socket *sock) {
    if ((!edwork) || (!sock) || (sock == edwork->sctp_socket))
        return;

    int i;
    thread_mutex_lock(&edwork->clients_lock);
    for (i = 0; i < edwork->clients_count; i++) {
        if ((edwork->clients[i].socket) && (edwork->clients[i].socket == sock)) {
            edwork->clients[i].is_sctp = 1;
            edwork->clients[i].sctp_socket |= 1;
            edwork->clients[i].sctp_timestamp = time(NULL);
            edwork->clients[i].last_seen = time(NULL);
            edwork->sctp_timestamp = edwork->clients[i].sctp_timestamp;
            break;
        }
    }
    thread_mutex_unlock(&edwork->clients_lock);
}

static void edwork_sctp_notification(struct edwork_data *edwork, struct socket *sock, union sctp_notification *notif, size_t n, struct sctp_rcvinfo *rcvinfo) {
    if (notif->sn_header.sn_length != (uint32_t)n) {
        log_error("sctp notification error");
        return;
    }
    return;
    int i;
    int reset = 0;
    struct sockaddr *addrs = NULL;
    switch (notif->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE:
            switch (notif->sn_assoc_change.sac_state) {
                case SCTP_COMM_UP:
                case SCTP_RESTART:
                    {
                        log_trace("SCTP_COMM_UP/SCTP_RESTART");
                        if ((SCTP_getpaddrs(sock, rcvinfo->rcv_assoc_id, &addrs) <= 0) || (!addrs)) {
                            log_error("error in sctp_getpaddrs (%i)", errno);
                        } else {
                            if (addrs->sa_family == AF_INET6)
                                edwork_send_to_sctp_socket(edwork, sock, "helo", NULL, 0, addrs, sizeof(struct sockaddr_in6), 0);
                            else
                            if (addrs->sa_family == AF_INET) {
                                log_trace("SCTP_COMM_UP (%s)", edwork_addr_ipv4(addrs));
                                edwork_send_to_sctp_socket(edwork, sock, "helo", NULL, 0, addrs, sizeof(struct sockaddr_in), 0);
                            }
                        }
                        edwork_sctp_update_socket(edwork, sock);
                    }
                    break;

                /* case SCTP_COMM_LOST:
                    log_trace("SCTP_COMM_LOST");
                    reset = 2;
                    break;

                case SCTP_SHUTDOWN_COMP:
                    log_trace("SCTP_SHUTDOWN_COMP");
                    reset = 1;
                    break;

                case SCTP_CANT_STR_ASSOC:
                    if ((notif->sn_assoc_change.sac_state != SCTP_COMM_UP) && (notif->sn_assoc_change.sac_state != SCTP_RESTART)) {
                        log_trace("SCTP_CANT_STR_ASSOC, STATE: %i", (int)notif->sn_assoc_change.sac_state);
                        reset = 3;
                    }
                    break;

                default:
                    log_trace("SCTP_ASSOC_CHANGE, STATE: %i", (int)notif->sn_assoc_change.sac_state);
                    break; */
            }
            break;
        case SCTP_PEER_ADDR_CHANGE:
            log_trace("SCTP_PEER_ADDR_CHANGE");
            switch (notif->sn_paddr_change.spc_state) {
                case SCTP_ADDR_AVAILABLE:
                    log_trace("ADDRESS AVAILABLE");
                    edwork_sctp_update_socket(edwork, sock);
                    break;
                case SCTP_ADDR_UNREACHABLE:
                    log_trace("ADDRESS UNREACHABLE");
                    break;
                case SCTP_ADDR_REMOVED:
                    log_trace("ADDRESS REMOVED");
                    break;
                case SCTP_ADDR_ADDED:
                    log_trace("ADDRESS ADDED");
                    edwork_sctp_update_socket(edwork, sock);
                    break;
                case SCTP_ADDR_MADE_PRIM:
                    log_trace("ADDRESS MADE PRIMARY");
                    edwork_sctp_update_socket(edwork, sock);
                    break;
                case SCTP_ADDR_CONFIRMED:
                    log_trace("ADDRESS CONFIRMED");
                    edwork_sctp_update_socket(edwork, sock);
                    break;
                default:
                    log_trace("SCTP_PEER_ADDR_CHANGE, STATE: %i", (int)notif->sn_paddr_change.spc_state);
            }
            break;
        case SCTP_REMOTE_ERROR:
            log_trace("SCTP_REMOTE_ERROR");
            reset = 1;
            break;
        case SCTP_SHUTDOWN_EVENT:
            log_trace("SCTP_SHUTDOWN_EVENT");
            reset = 1;
            break;
        case SCTP_ADAPTATION_INDICATION:
            log_trace("SCTP_ADAPTATION_INDICATION");
            break;
        case SCTP_PARTIAL_DELIVERY_EVENT:
            log_trace("SCTP_PARTIAL_DELIVERY_EVENT");
            break;
        case SCTP_AUTHENTICATION_EVENT:
            log_trace("SCTP_AUTHENTICATION_EVENT");
            break;
        case SCTP_SENDER_DRY_EVENT:
            log_trace("SCTP_SENDER_DRY_EVENT");
            break;
        case SCTP_NOTIFICATIONS_STOPPED_EVENT:
            log_trace("SCTP_NOTIFICATIONS_STOPPED_EVENT");
            break;
        case SCTP_SEND_FAILED_EVENT:
            log_trace("SCTP_SEND_FAILED_EVENT");
            break;
        case SCTP_SEND_FAILED:
            log_trace("SCTP_SEND_FAILED");
            break;
        case SCTP_STREAM_RESET_EVENT:
            log_trace("SCTP_STREAM_RESET_EVENT");
            break;
        case SCTP_ASSOC_RESET_EVENT:
            log_trace("SCTP_ASSOC_RESET_EVENT");
            break;
        case SCTP_STREAM_CHANGE_EVENT:
            log_trace("SCTP_STREAM_CHANGE_EVENT");
            break;
        default:
            log_trace("SCTP: unknown event");
            break;
    }
    if (reset) {
        if (sock != edwork->sctp_socket) {
            thread_mutex_lock(&edwork->clients_lock);
            for (i = 0; i < edwork->clients_count; i++) {
                if ((edwork->clients[i].socket) && (edwork->clients[i].socket == sock)) {
                    if ((reset == 3) && (edwork->clients[i].sctp_timestamp)) {
                        edwork->clients[i].last_seen = time(NULL);
                        break;
                    }

                    if ((SCTP_getpaddrs(sock, rcvinfo->rcv_assoc_id, &addrs) > 0) && (addrs))
                        log_trace("SCTP connection reset %s", edwork_addr_ipv4(addrs));

                    SCTP_close(edwork->clients[i].socket);

                    edwork->clients[i].socket = 0;
                    edwork->clients[i].is_sctp = 0;
                    edwork->clients[i].sctp_timestamp = 0;
                    edwork->clients[i].is_listen_socket = 0;
                    if (reset == 2) {
                        if (addrs->sa_family == AF_INET6)
                            edwork->clients[i].socket = edwork_sctp_connect(edwork, (const struct sockaddr *)addrs, sizeof(struct sockaddr_in6));
                        else
                        if (addrs->sa_family == AF_INET)
                            edwork->clients[i].socket = edwork_sctp_connect(edwork, (const struct sockaddr *)addrs, sizeof(struct sockaddr_in));
                        if (edwork->clients[i].socket) {
                            edwork->clients[i].sctp_reconnect_timestamp = time(NULL);
                            edwork->clients[i].last_seen = time(NULL);
                        } else
                            edwork->clients[i].sctp_reconnect_timestamp = 0;
                    } else {
                        if (edwork->clients[i].sctp_timestamp == edwork->sctp_timestamp)
                            edwork->sctp_timestamp = 0;
                    }
                    break;
                }
            }
            thread_mutex_unlock(&edwork->clients_lock);
        } else
        if (reset != 3) {
            if ((SCTP_getpaddrs(sock, rcvinfo->rcv_assoc_id, &addrs) > 0) && (addrs))
                log_trace("SCTP connection reset %s", edwork_addr_ipv4(addrs));

            struct sockaddr *addrs = NULL;
            int n = SCTP_getpaddrs(sock, rcvinfo->rcv_assoc_id, &addrs);
            if (n > 0) {
                if (addrs->sa_family == AF_INET6)
                    edwork_remove_addr(edwork, addrs, sizeof(struct sockaddr_in6));
                else
                if (addrs->sa_family == AF_INET)
                    edwork_remove_addr(edwork, addrs, sizeof(struct sockaddr_in));
            }
        }
    }
}

static int edwork_sctp_receive(struct socket *sock, union sctp_sockstore addr, void *data, size_t datalen, struct sctp_rcvinfo rcvinfo, int flags, void *ulp_info) {
    struct edwork_data *edwork = (struct edwork_data *)ulp_info;
    if ((flags & MSG_NOTIFICATION) || (!data) || (!edwork)) {
        if (flags & MSG_NOTIFICATION)
            edwork_sctp_notification(edwork, sock, (union sctp_notification *)data, datalen, &rcvinfo);
        free(data);
        return 1;
    }

    if (edwork->callback) {
        struct sockaddr *addrs = NULL;
        int n = SCTP_getpaddrs(sock, rcvinfo.rcv_assoc_id, &addrs);
        if (n <= 0) {
            log_error("error in sctp_getpaddrs (%i)", errno);
        } else {
            log_trace("SCTP dispatch");
            edwork->sctp_last_addr = addrs;
            edwork->sctp_last_assoc_id = rcvinfo.rcv_assoc_id;
            unsigned char *data_copy = (unsigned char *)malloc(datalen + 1);
            if (data_copy) {
                // it is important for data to be null-terminated!!!
                memcpy(data_copy, data, datalen);
                data_copy[datalen] = 0;
                edwork_dispatch_data(edwork, edwork->callback, (unsigned char *)data_copy, datalen, addrs, sizeof(struct sockaddr_in), edwork->userdata, 1, sock == edwork->sctp_socket);
                free(data_copy);
            }
            SCTP_freepaddrs(addrs);
        }
    }    
    free(data);
    return 1;
}
#else
static void edwork_add_poll_socket(struct edwork_data *data, int socket) {
    data->ufds = (struct pollfd *)realloc(data->ufds, sizeof(struct pollfd) * (data->ufds_len + 1));
    data->ufds[data->ufds_len].fd = socket;
    data->ufds[data->ufds_len].events = POLLIN;
    data->ufds_len ++;
}

static void edwork_remove_poll_socket(struct edwork_data *data, int offset) {
    int i;

    if ((offset < 0) || (offset >= data->ufds_len))
        return;

    if (offset > 0)
        SCTP_close(data->ufds[offset].fd);
    else
        close(data->ufds[offset].fd);
    int limit = data->ufds_len - 1;
    memmove(&data->ufds[offset], &data->ufds[offset + 1], (data->ufds_len - offset - 1) * sizeof(struct pollfd));
    data->ufds_len --;
}
#endif

static SCTP_SOCKET_TYPE edwork_sctp_connect(struct edwork_data *data, const struct sockaddr *addr, int addr_len) {
    SCTP_SOCKET_TYPE peer_socket = SCTP_socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (!peer_socket)
        return 0;

    SCTP_set_non_blocking(peer_socket, 1);
    
    int opt = 1;
    SCTP_setsockopt(peer_socket, IPPROTO_SCTP, SCTP_NODELAY, (const char *)&opt, sizeof(opt));
#ifdef SCTP_UDP_ENCAPSULATION
    #ifdef WITH_USRSCTP
	    uint16_t event_types[] = EDWORK_SCTP_EVENTS;
        struct sctp_event evt;
        int i;

	    memset(&evt, 0, sizeof(struct sctp_event));
	    evt.se_assoc_id = SCTP_ALL_ASSOC;
	    evt.se_on = 1;

        for (i = 0; i < sizeof(event_types) / sizeof(uint16_t); i++) {
            evt.se_type = event_types[i];
            SCTP_setsockopt(peer_socket, IPPROTO_SCTP, SCTP_EVENT, &evt, sizeof(evt));
        }

        struct sctp_udpencaps encaps;
	    memset(&encaps, 0, sizeof(struct sctp_udpencaps));
	    encaps.sue_address.ss_family = AF_INET;
	    encaps.sue_port = htons(EDWORK_SCTP_UDP_TUNNELING_PORT);

        if (SCTP_setsockopt(peer_socket, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, &encaps, sizeof(struct sctp_udpencaps)))
            log_error("error in SCTP_setsockopt %i", errno);
    #else
        // todo
    #endif
#endif
    int optval = EDWORK_SOCKET_BUFFER;
    if (SCTP_setsockopt(data->sctp_socket, SOL_SOCKET, SO_SNDBUF, (const char *)&optval, sizeof(optval)))
        log_warn("error setting send buffer to %i bytes", optval);

    optval = EDWORK_SOCKET_BUFFER;
    if (SCTP_setsockopt(data->sctp_socket, SOL_SOCKET, SO_RCVBUF, (const char *)&optval, sizeof(optval)))
        log_warn("error setting recv buffer to %i bytes", optval);

    struct sctp_initmsg initmsg;
    memset(&initmsg, 0, sizeof(struct sctp_initmsg));
    initmsg.sinit_num_ostreams = 2;
    initmsg.sinit_max_instreams = 2;
    initmsg.sinit_max_attempts = 6;

    SCTP_setsockopt(peer_socket, IPPROTO_SCTP, SCTP_INITMSG, (const char *)&initmsg, sizeof(struct sctp_initmsg));

    int err = SCTP_connect(peer_socket, addr, addr_len);
    if (!err)
        return peer_socket;

    SCTP_close(peer_socket);
    return 0;
}

static SCTP_SOCKET_TYPE edwork_sctp_connect_hostname(struct edwork_data *data, const char *hostname, int port) {
    struct sockaddr_in sin;
    struct hostent     *hp;

    if ((hp = gethostbyname(hostname)) == 0)
        return 0;

    // add ipv6
    memset(&sin, 0, sizeof(sin));
    sin.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons((int)port);

    return edwork_sctp_connect(data, (struct sockaddr *)&sin, sizeof(sin));
}

ssize_t safe_sctp_sendto(struct edwork_data *data, SCTP_SOCKET_TYPE socket, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen, int ttl) {
    if (!data->sctp_socket)
        return -1;

#ifdef WITH_USRSCTP
    struct sctp_prinfo info;
    info.pr_policy = SCTP_PR_SCTP_TTL;
    info.pr_value = ttl;
#endif
    thread_mutex_lock(&data->sock_lock);
    ssize_t err = SCTP_send(socket, (const char *)buf, len, flags, dest_addr, addrlen);
    thread_mutex_unlock(&data->sock_lock);
    return err;
}

ssize_t safe_sctp_recvfrom(struct edwork_data *data, SCTP_SOCKET_TYPE socket, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
#ifdef WITH_USRSCTP
    socklen_t infolen;
	struct sctp_rcvinfo rcv_info;
	unsigned int infotype; 
#endif
    if (!socket)
        return -1;
    thread_mutex_lock(&data->sock_lock);
    ssize_t err = SCTP_recv(socket, (char *)buf, len, flags, src_addr, addrlen);
    thread_mutex_unlock(&data->sock_lock);
    return err;
}
#endif

#ifdef WITH_SCTP
int edwork_is_sctp(struct edwork_data *data, const void *clientaddr_ptr) {
    int is_sctp = 0;
    thread_mutex_lock(&data->clients_lock);
    uintptr_t data_index = (uintptr_t)avl_search(&data->tree, (void *)clientaddr_ptr);
    if (data_index > 1)
        is_sctp = data->clients[data_index - 1].is_sctp;
    thread_mutex_unlock(&data->clients_lock);
    return is_sctp;
}
#endif

ssize_t safe_sendto(struct edwork_data *data, struct client_data *peer_data, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen, int try_sctp) {
#ifdef WITH_SCTP
    if ((data->sctp_socket) && (try_sctp)) {
        SCTP_SOCKET_TYPE socket = 0;
        int is_sctp = 0;
        if (peer_data) {
            socket = peer_data->socket;
            is_sctp = peer_data->is_sctp;
        } else {
            uintptr_t data_index = (uintptr_t)avl_search(&data->tree, (void *)dest_addr);
            if (data_index > 0) {
                peer_data = &data->clients[data_index - 1];
                if (peer_data) {
                    socket = peer_data->socket;
                    is_sctp = peer_data->is_sctp;
                }
            }
        }
        if (data->force_sctp)
            is_sctp = 1;
        if ((socket) && (is_sctp))
            return safe_sctp_sendto(data, socket, buf, len, flags | SCTP_UNORDERED, dest_addr, addrlen, EDWORK_SCTP_TTL);
        else
        if (((peer_data) && (peer_data->is_sctp)) || (data->sctp_last_addr == dest_addr) || (SCTP_getassocid(data->sctp_socket, dest_addr) > 0))
            return safe_sctp_sendto(data, data->sctp_socket, buf, len, flags | SCTP_UNORDERED, dest_addr, addrlen, EDWORK_SCTP_TTL);
    }
#endif
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
#ifdef WITH_SCTP
    #ifndef WITH_USRSCTP
        edwork_add_poll_socket(data, data->socket);
    #endif
    data->sctp_socket = SCTP_socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (data->sctp_socket) {
        optval = 1;
        SCTP_setsockopt(data->sctp_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(int));
        SCTP_setsockopt(data->sctp_socket, IPPROTO_SCTP, SCTP_NODELAY, (const char *)&optval, sizeof(int));

#ifdef SCTP_UDP_ENCAPSULATION
        #ifdef WITH_USRSCTP
	        uint16_t event_types[] = EDWORK_SCTP_EVENTS;
            struct sctp_event evt;
            int i;

	        memset(&evt, 0, sizeof(struct sctp_event));
	        evt.se_assoc_id = SCTP_ALL_ASSOC;
	        evt.se_on = 1;

            for (i = 0; i < sizeof(event_types) / sizeof(uint16_t); i++) {
                evt.se_type = event_types[i];
                SCTP_setsockopt(data->sctp_socket, IPPROTO_SCTP, SCTP_EVENT, &evt, sizeof(evt));
            }

            struct sctp_udpencaps encaps;
            memset(&encaps, 0, sizeof(struct sctp_udpencaps));
            encaps.sue_address.ss_family = AF_INET;
            encaps.sue_port = htons(EDWORK_SCTP_UDP_TUNNELING_PORT);

            if (SCTP_setsockopt(data->sctp_socket, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, &encaps, sizeof(struct sctp_udpencaps)))
                log_error("error in SCTP_setsockopt %i", errno);
        #endif

        optval = EDWORK_SOCKET_BUFFER;
        if (SCTP_setsockopt(data->sctp_socket, SOL_SOCKET, SO_SNDBUF, (const char *)&optval, sizeof(optval)))
            log_warn("error setting send buffer to %i bytes", optval);

        optval = EDWORK_SOCKET_BUFFER;
        if (SCTP_setsockopt(data->sctp_socket, SOL_SOCKET, SO_RCVBUF, (const char *)&optval, sizeof(optval)))
            log_warn("error setting recv buffer to %i bytes", optval);
#endif

        struct sctp_initmsg initmsg;
        memset(&initmsg, 0, sizeof(struct sctp_initmsg));
        initmsg.sinit_num_ostreams = 2;
        initmsg.sinit_max_instreams = 2;
        initmsg.sinit_max_attempts = 6;

        SCTP_setsockopt(data->sctp_socket, IPPROTO_SCTP, SCTP_INITMSG, (const char *)&initmsg, sizeof(struct sctp_initmsg));

        memset((char *)&serveraddr, 0, sizeof(serveraddr));

        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
        serveraddr.sin_port = htons((unsigned short)port);

        if (SCTP_bind(data->sctp_socket, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
            log_error("error binding SCTP socket");
            SCTP_close(data->sctp_socket);
            data->sctp_socket = 0;
        } else
        if (SCTP_listen(data->sctp_socket, 128) < 0) {
            log_error("error in listen (SCTP socket)");
            SCTP_close(data->sctp_socket);
            data->sctp_socket = 0;
        }
#ifdef WITH_USRSCTP
        log_info("SCTP socket created (usrsctp)");
#else
        log_info("SCTP socket created (native)");
        edwork_add_poll_socket(data, data->sctp_socket);
#endif
    } else
        log_error("error creating SCTP socket");
#endif

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
    thread_mutex_init(&data->clients_lock);
    thread_mutex_init(&data->lock);
#ifdef EDFS_MULTITHREADED
    thread_mutex_init(&data->thread_lock);
#endif
    thread_mutex_init(&data->callback_lock);
    edwork_add_node(data, "255.255.255.255", port, 0, 0);

    return data;
}

void edwork_update_chain(struct edwork_data *data, unsigned char *hash) {
    if ((!data) || (!hash))
        return;
    memcpy(data->chain, hash, 32);
}

int edwork_try_spend(struct edwork_data *data, const unsigned char *proof_of_work, int proof_of_work_size) {
    char *proof = (char *)malloc(proof_of_work_size + 1);
    if (!proof)
        return 0;
    memcpy(proof, proof_of_work, proof_of_work_size);
    proof[proof_of_work_size] = 0;
    thread_mutex_lock(&data->lock);
    void *exists = avl_search(&data->spent, proof);
    if (exists) {
        thread_mutex_unlock(&data->lock);
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
    thread_mutex_unlock(&data->lock);
    return 1;
}

int edwork_unspend(struct edwork_data *data, const unsigned char *proof_of_work, int proof_of_work_size) {
    char *proof = (char *)malloc(proof_of_work_size + 1);
    if (!proof)
        return 0;
    memcpy(proof, proof_of_work, proof_of_work_size);
    proof[proof_of_work_size] = 0;
    thread_mutex_lock(&data->lock);
    void *exists = avl_remove(&data->spent, proof);
    if (exists)
        data->spent_count --;
    thread_mutex_unlock(&data->lock);

    free(proof);

    if (exists)
        return 1;

    return 0;
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
    memcpy(buf + 52, data->chain, 32);
    edwork_random_bytes(buf + 84, 8);
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


#ifdef WITH_SCTP
int edwork_send_to_sctp_socket(struct edwork_data *data, SCTP_SOCKET_TYPE socket, const char type[4], const unsigned char *buf, int len, void *clientaddr, int clientaddrlen, int ttl) {
    if (!socket)
        return -1;
    unsigned char *packet = make_packet(data, type, buf, &len, 0, 0, 0);
    int sent = -1;
    if ((packet) && (len > 0)) {
        if (data)
            sent = safe_sctp_sendto(data, socket, (const char *)packet, len, SCTP_UNORDERED, (struct sockaddr *)clientaddr, clientaddrlen, ttl);
        if (sent < 0)
            log_error("error in sendto (sctp, peer), errno: %i", errno);
    }
    free(packet);
    return sent;
}
#endif

void *add_node(struct edwork_data *data, struct sockaddr_in *sin, int client_len, int update_seen, int return_old_peer, int is_sctp, int is_listen_socket) {
    if ((!sin) || (client_len <= 0) || (sin->sin_addr.s_addr == 0) || (sin->sin_port == 0))
        return 0;

    thread_mutex_lock(&data->clients_lock);
    struct client_data *peer = NULL;
    uintptr_t data_index = (uintptr_t)avl_search(&data->tree, sin);
    if (data_index > 0)
        peer = &data->clients[data_index - 1];

    if (peer) {
        if (update_seen)
            peer->last_seen = time(NULL);
        // opt in or out sctp
#ifdef WITH_SCTP
        if (data_index != 1) {
            if (data->force_sctp)
                peer->is_sctp = 1;
            if ((is_sctp & 1) && (is_listen_socket)) {
                peer->sctp_timestamp = time(NULL);
                data->sctp_timestamp = peer->sctp_timestamp;
            }
            if (is_sctp & 1)
                peer->sctp_socket |= 1;
            else
                peer->sctp_socket |= 2;
        }
#endif
        thread_mutex_unlock(&data->clients_lock);
        if (return_old_peer)
            return peer;
        return 0;
    }

    // rewrite this (slow)
    data->clients = (struct client_data *)realloc(data->clients, sizeof(struct client_data) * (data->clients_count + 1));
    if (!data->clients) {
        data->clients_count = 0;
        thread_mutex_unlock(&data->clients_lock);
        return 0;
    }
    memcpy(&data->clients[data->clients_count].clientaddr, sin, client_len);
    memset(&data->clients[data->clients_count].clientaddr + client_len, 0, sizeof(data->clients[data->clients_count].clientaddr) - client_len);
    data->clients[data->clients_count].clientlen = client_len;
    data->clients[data->clients_count].last_ino = 0;
    data->clients[data->clients_count].last_chunk = 0;
    data->clients[data->clients_count].last_msg_timestamp = 0;
    data->clients[data->clients_count].last_seen = time(NULL);
    if (is_listen_socket)
        data->clients[data->clients_count].is_listen_socket = 1;
    else
        data->clients[data->clients_count].is_listen_socket = 0;
#ifdef WITH_SCTP
    // no sctp for broadcast address
    data->clients[data->clients_count].socket = 0;
    data->clients[data->clients_count].sctp_reconnect_timestamp = 0;
    if ((is_sctp & 1) && (!is_listen_socket) && (data->clients_count == 0)) {
        struct sockaddr addr2;
        memcpy(&addr2, sin, client_len);
        if (addr2.sa_family == AF_INET)
            ((struct sockaddr_in *)&addr2)->sin_port = ntohs(((struct sockaddr_in *)&addr2)->sin_port);

        data->clients[data->clients_count].socket = edwork_sctp_connect(data, (const struct sockaddr *)&addr2, client_len);
        if (data->clients[data->clients_count].socket)
            data->clients[data->clients_count].sctp_reconnect_timestamp = time(NULL);
        else
            data->clients[data->clients_count].sctp_reconnect_timestamp = 0;
    }

    if ((data->force_sctp) && (data->clients_count))
        data->clients[data->clients_count].is_sctp = 1;
    else
        data->clients[data->clients_count].is_sctp = is_sctp & 1;
    if ((is_sctp & 1) && (is_listen_socket)) {
        data->clients[data->clients_count].sctp_timestamp = time(NULL);
        data->sctp_timestamp = data->clients[data->clients_count].sctp_timestamp;
    } else
        data->clients[data->clients_count].sctp_timestamp = 0;
#endif

    data->clients[data->clients_count].sctp_socket = is_sctp;
    data->clients_count ++;

    struct sockaddr_in *addr_key = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if (addr_key) {
        memcpy(addr_key, sin, sizeof(struct sockaddr_in));
        avl_insert(&data->tree, addr_key, (void *)(uintptr_t)data->clients_count);
    }

    thread_mutex_unlock(&data->clients_lock);
    return &data->clients[data->clients_count - 1];
}

void *edwork_ensure_node_in_list(struct edwork_data *data, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket) {
    if ((!data) || (!clientaddr) || (!clientaddrlen))
        return 0;

    return add_node(data, (struct sockaddr_in *)clientaddr, clientaddrlen, 1, 1, is_sctp, is_listen_socket);
}

void edwork_add_node(struct edwork_data *data, const char *node, int port, int is_listen_socket, int sctp_socket) {
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
#ifdef HAVE_SIN_LEN
    sin.sin_len         = sizeof(sin);
#endif

    if (add_node(data, &sin, sizeof(sin), 0, 0, sctp_socket, is_listen_socket)) {
        if (sctp_socket & 1)
            log_info("added stateful node %s:%i", node, port);
        else
            log_info("added node %s:%i", node, port);
    }
}

int edwork_private_broadcast(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, int buf_is_packet, const void *except, int except_len, uint64_t force_timestamp, uint64_t ino, const void *clientaddr, int clientaddr_len, int sleep_us, int force_udp) {
    if (!data)
        return -1;

    if (!data->clients_count) {
        log_warn("no nodes to broadcast to");
        return 0;
    }

    thread_mutex_lock(&data->clients_lock);

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
    time_t threshold = time(NULL) - 180;
#ifdef WITH_SCTP
    time_t sctp_threshold = time(NULL) - 10;
#endif
    if ((ptr) && (len > 0)) {
        unsigned int i;
        if ((clientaddr) && (clientaddr_len > 0)) {
            if (safe_sendto(data, NULL, (const char *)ptr, len, 0, (const struct sockaddr *)clientaddr, clientaddr_len, 1) <= 0) {
#ifdef _WIN32
                log_trace("error %i in sendto (%s)", (int)WSAGetLastError(), edwork_addr_ipv4(clientaddr));
#else
                log_trace("error %i in sendto (%s)", (int)errno, edwork_addr_ipv4(clientaddr));
#endif
                // fallback sending to other clients
            } else {
                thread_mutex_unlock(&data->clients_lock);
                free(packet);
                return 0;
            }
        }
        int lan_broadcast = 1;
        // exclude data and large packages from broadcast
        if ((len > EDWOR_MAX_LAN_BROADCAST_SIZE) || ((type[0] == 'd') && (type[1] == 'a') && (type[2] == 't')))
            lan_broadcast = 0;
        i = rand % data->clients_count;
        unsigned int start_i = i;
        unsigned int send_to = 0;
        while (send_to < max_nodes) {
            if ((i) || (lan_broadcast)) {
#ifdef WITH_SCTP
                if ((!data->force_sctp) || ((data->clients[i].is_sctp) && ((data->sctp_timestamp < sctp_threshold) || (data->clients[i].sctp_timestamp >= sctp_threshold)))) {
#endif
                if ((except) && (except_len == data->clients[i].clientlen) && (!memcmp(except, &data->clients[i].clientaddr, except_len))) {
                    log_debug("not broadcasting to same client");
                } else
                if ((data->clients[i].last_seen >= threshold) || (i == 0) || (force_udp)) { // i == 0 => means first addres (broadcast address)
                    if (safe_sendto(data, &data->clients[i], (const char *)ptr, len, 0, (struct sockaddr *)&data->clients[i].clientaddr, data->clients[i].clientlen, 1) <= 0) {
#ifdef _WIN32
                        log_trace("error %i in sendto (client #%i: %s)", (int)WSAGetLastError(), i, edwork_addr_ipv4(&data->clients[i].clientaddr));
#else
                        log_trace("error %i in sendto (client #%i: %s)", (int)errno, i, edwork_addr_ipv4(&data->clients[i].clientaddr));
#endif
#ifdef WITH_SCTP
                        if (data->clients[i].is_sctp) {
                            if ((errno != 11) && (errno != 35)) {
                                data->clients[i].is_sctp = 0;
                                if (data->clients[i].socket) {
                                    SCTP_close(data->clients[i].socket);
                                    data->clients[i].socket = edwork_sctp_connect(data, (struct sockaddr *)&data->clients[i].clientaddr, data->clients[i].clientlen);
                                    if (data->clients[i].socket)
                                        log_trace("reconnecting SCTP socket");
                                }
                            }
                        } else
                        if (errno != 11)
#endif
                            data->clients[i].last_seen = threshold - 1;
                    } else {
                        send_to ++;
#ifdef WITH_SCTP
                        if ((force_udp) && (data->clients[i].is_sctp) && (!data->clients[i].is_listen_socket))
                            safe_sendto(data, &data->clients[i], (const char *)ptr, len, 0, (struct sockaddr *)&data->clients[i].clientaddr, data->clients[i].clientlen, 0);

                        if ((sleep_us > 0) && (!data->clients[i].is_sctp))
                            usleep(sleep_us);
#else
                        if (sleep_us > 0)
                            usleep(sleep_us);
#endif
                    }
                }
#ifdef WITH_SCTP
                }
#endif
            }
            i ++;
            if (i >= data->clients_count) {
                i = 0;
                if (wrapped_to_first)
                    break;
                wrapped_to_first = 1;
            }
            if (i == start_i)
                break;
        }
    }
    thread_mutex_unlock(&data->clients_lock);
    free(packet);
    return 0;
}

int edwork_broadcast(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, uint64_t ino, int force_udp) {
    return edwork_private_broadcast(data, type, buf, len, confirmed_acks, max_nodes, 0, NULL, 0, 0, ino, NULL, 0, 0, force_udp);
}

int edwork_broadcast_client(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, uint64_t ino, const void *clientaddr, int clientaddr_len) {
    return edwork_private_broadcast(data, type, buf, len, confirmed_acks, max_nodes, 0, NULL, 0, 0, ino, clientaddr, clientaddr_len, 0, 0);
}

int edwork_broadcast_except(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, int confirmed_acks, int max_nodes, const void *except, int except_len, uint64_t force_timestamp, uint64_t ino) {
    return edwork_private_broadcast(data, type, buf, len, confirmed_acks, max_nodes, 0, except, except_len, force_timestamp, ino, NULL, 0, 0, 0);
}

unsigned int edwork_jumbo(struct edwork_data *data, unsigned char *jumbo_buf, unsigned int max_jumbo_size, unsigned int jumbo_size, unsigned char *buf, int buf_size) {
    if ((jumbo_size + buf_size + 2 >= max_jumbo_size) && (jumbo_size)) {
        edwork_private_broadcast(data, "jmbo", jumbo_buf, jumbo_size, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0);
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
                        edwork_private_broadcast(data, NULL, buf + 8, size - 8, 0, 0, 1, NULL, 0, 0, 0, NULL, 0, 0, 0);
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


#if defined(WITH_SCTP) && !defined(WITH_USRSCTP)
static int edworks_data_pending_sctp(struct edwork_data *data, int timeout_ms) {
    return poll(data->ufds, data->ufds_len, (int)timeout_ms);
}
#endif

int edworks_data_pending(struct edwork_data *data, int timeout_ms) {
    if (!data)
        return -1;

#if defined(WITH_SCTP) && defined(WITH_USRSCTP)
    if (data->force_sctp) {
        usleep(timeout_ms * 1000);
        return 0;
    }
#endif
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
#if defined(WITH_SCTP) && !defined(WITH_USRSCTP)
    return edworks_data_pending_sctp(data, timeout_ms);
#endif
    struct pollfd ufds[1];
    ufds[0].fd     = data->socket;
    ufds[0].events = POLLIN;

    if (timeout_ms < 0)
        timeout_ms = 0;

    return poll(ufds, 1, (int)timeout_ms);
#endif
}

int edwork_send_to_peer(struct edwork_data *data, const char type[4], const unsigned char *buf, int len, void *clientaddr, int clientaddrlen, int is_sctp, int is_listen_socket, int ttl) {
#ifdef WITH_SCTP
    if (is_sctp) {
        if (is_listen_socket)
            return edwork_send_to_sctp_socket(data, data->sctp_socket, type, buf, len, clientaddr, clientaddrlen, EDWORK_SCTP_TTL);
        uintptr_t data_index = (uintptr_t)avl_search(&data->tree, clientaddr);
        SCTP_SOCKET_TYPE socket = 0;
        if (data_index > 0) {
            thread_mutex_lock(&data->clients_lock);
            struct client_data *peer_data = &data->clients[data_index - 1];
            if (peer_data)
                socket = peer_data->socket;
            thread_mutex_unlock(&data->clients_lock);
        }
        return edwork_send_to_sctp_socket(data, socket ? socket : data->sctp_socket, type, buf, len, clientaddr, clientaddrlen, EDWORK_SCTP_TTL);
    }
#endif
    unsigned char *packet = make_packet(data, type, buf, &len, 0, 0, 0);
    int sent = -1;
    if ((packet) && (len > 0)) {
        if ((data) && (clientaddr) && (clientaddrlen))
            sent = safe_sendto(data, NULL, (const char *)packet, len, 0, (struct sockaddr *)clientaddr, clientaddrlen, 0);
        if (sent < 0)
            log_error("error in sendto (peer)");
    } else
        log_error("invalid packet");
    free(packet);
    return sent;
}

int edwork_remove_addr(struct edwork_data *data, void *sin, int client_len) {
    thread_mutex_lock(&data->clients_lock);
    uintptr_t index = (uintptr_t)avl_search(&data->tree, sin);
    if ((!index) || (index == 1)) {
        thread_mutex_unlock(&data->clients_lock);
        return 0;
    }
    
    if ((data->clients_count > 1) && (index <= data->clients_count)) {
#ifdef WITH_SCTP
        if (data->clients[index - 1].socket) {
            SCTP_close(data->clients[index - 1].socket);
            data->clients[index - 1].socket = 0;
        }
#endif
        avl_remove(&data->tree, sin);
        memmove(&data->clients[index - 1], &data->clients[index], sizeof(struct client_data) * (data->clients_count - index));
        int i;
        data->clients_count --;

        for (i = index - 1; i < data->clients_count; i++) {
            struct sockaddr_in *addr_key = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
            if (addr_key) {
                memcpy(addr_key, &data->clients[index].clientaddr, sizeof(struct sockaddr_in));
                avl_insert(&data->tree, addr_key, (void *)(uintptr_t)(i + 1));
            }

        }
    }
    thread_mutex_unlock(&data->clients_lock);
    return 1;
}

int edwork_dispatch_data(struct edwork_data *data, edwork_dispatch_callback callback, unsigned char *buffer, int n, void *clientaddr, int clientaddrlen, void *userdata, int is_sctp, int is_listen_socket) {
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

    const unsigned char *blockhash = buffer + 52;
    
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
        // invalid hmac
#ifdef EDWORK_PEER_DISCOVERY_SERVICE
        if ((memcmp(type, "disc", 4)) && (memcmp(type, "add2", 4))) {
#endif
            log_warn("HMAC verify failed for type %s (%s)", type, edwork_addr_ipv4(clientaddr));
            return 0;
#ifdef EDWORK_PEER_DISCOVERY_SERVICE
        }
#endif
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
                edwork_dispatch_data(data, callback, ptr, size_short, clientaddr, clientaddrlen, userdata, is_sctp, is_listen_socket);
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
        thread_mutex_lock(&data->callback_lock);
        callback(data, sequence, timestamp, type, payload, size, clientaddr, clientaddrlen, who_am_i, blockhash, userdata, is_sctp, is_listen_socket);
        thread_mutex_unlock(&data->callback_lock);        
    }

    return 1;
}

int edwork_dispatch(struct edwork_data *data, edwork_dispatch_callback callback, int timeout_ms, void *userdata) {
    if (!data)
        return -1;

#if defined(WITH_SCTP) && defined(WITH_USRSCTP)
    data->callback = callback;
    data->userdata = userdata;
#endif
    if (!edworks_data_pending(data, timeout_ms))
        return 0;

    unsigned char buffer[0xFFFF];
    struct sockaddr_in clientaddr;
    do {
        socklen_t clientlen = sizeof(clientaddr);
#if defined(WITH_SCTP) && !defined(WITH_USRSCTP)
        if ((data->ufds) && (data->ufds[0].revents)) {
#endif
            int n = safe_recvfrom(data, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *) &clientaddr, &clientlen);
            if (n <= 0) {
        #ifdef _WIN32
                log_error("error in recvfrom: %i", (int)WSAGetLastError());
        #else
                log_error("error in recvfrom: %i", (int)errno);
        #endif
                return 0;
            }
            if (edwork_dispatch_data(data, callback, buffer, n, &clientaddr, clientlen, userdata, 0, 0) <= 0)
                break;
#if defined(WITH_SCTP) && !defined(WITH_USRSCTP)
        }
        int i;
        for (i = 1; i < data->ufds_len; i++) {
            if (data->ufds[i].revents) {
                clientlen = sizeof(clientaddr);
                int n = safe_sctp_recvfrom(data, data->ufds[i].fd, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *) &clientaddr, &clientlen);
                if (n <= 0) {
                    log_error("error in SCTP_recvmsg: %i", (int)errno);
                    if (i > 1) {
                        // do not remove server socket
                        edwork_remove_poll_socket(data, i);
                    }
                }
                if (edwork_dispatch_data(data, callback, buffer, n, &clientaddr, clientlen, userdata, 1, (i == 1)) <= 0)
                    break;
            }
        }
#endif
    } while (edworks_data_pending(data, 0));
    return 1;
}

int edwork_get_node_list(struct edwork_data *data, unsigned char *buf, int *buf_size, unsigned int offset, time_t threshold) {
    if (!data)
        return -1;

    int records = 0;
    unsigned int i;
    // active in last 72 hours
    thread_mutex_lock(&data->clients_lock);
    unsigned int found = 0;
    for (i = 0; i < data->clients_count; i++) {
        if (*buf_size < 8)
            break;
#if defined(WITH_SCTP) && defined(SCTP_UDP_ENCAPSULATION)
        if ((!data->force_sctp) && (data->clients[i].is_sctp))
            continue;
#endif
        if (data->clients[i].last_seen >= threshold) {
            if (found >= offset) {
                records ++;
                if (data->clients[i].sctp_socket)
                    *buf ++ = 7;
                else
                    *buf ++ = 6;
                memcpy(buf, &data->clients[i].clientaddr.sin_addr, 4);
                buf += 4;
                if (data->clients[i].is_listen_socket) {
                    unsigned short port = htons(4848);
                    memcpy(buf, &port, 2);
                } else
                    memcpy(buf, &data->clients[i].clientaddr.sin_port, 2);
                buf += 2;
                if (data->clients[i].sctp_socket) {
                    *buf ++ = data->clients[i].sctp_socket;
                    *buf_size -= 8;
                } else
                    *buf_size -= 7;
            }
            found ++;
        }
    }
    thread_mutex_unlock(&data->clients_lock);
    *buf_size = records * 7;
    return records;
}

int edwork_add_node_list(struct edwork_data *data, const unsigned char *buf, int buf_size) {
    if (!data)
        return 0;

    int records = 0;
    char buffer[32];
    while (buf_size >= 7) {
        int size = *buf ++;
        buf_size --;
        if ((size > buf_size) || (!size))
            break;

        if ((size == 6) || (size == 7)) {
            // ipv4
            buffer[0] = 0;
            snprintf(buffer, sizeof(buffer), "%i.%i.%i.%i", (int)buf[0], (int)buf[1], (int)buf[2], (int)buf[3]);

            unsigned short port;
            memcpy(&port, buf + 4, 2);
            port = ntohs(port);
            int sctp = 0;
            if (size == 7)
                sctp = buf[6];
            edwork_add_node(data, buffer, port, 0, sctp);
            records ++;
        } else
            log_warn("invalid record size (%i)", size);

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

    thread_mutex_lock(&data->clients_lock);
    for (i = 0; i < data->clients_count; i++) {
        if (data->clients[i].last_seen > threshold) {
            magnitude ++;
            if (magnitude > 1000)
                break;
        }
    }
    data->magnitude_stamp = time(NULL);
    data->magnitude = magnitude;
    thread_mutex_unlock(&data->clients_lock);

    return magnitude;
}

#ifdef WITH_SCTP
void edwork_force_sctp(struct edwork_data *data, int force_sctp) {
    if (!data)
        return;
    data->force_sctp = force_sctp;
}
#endif

void edwork_callback_lock(struct edwork_data *data, int lock) {
    if (lock)
        thread_mutex_lock(&data->callback_lock);
    else
        thread_mutex_unlock(&data->callback_lock);
}

void edwork_close(struct edwork_data *data) {
    if (!data)
        return;

    if (data->socket) {
        thread_mutex_lock(&data->sock_lock);
#ifdef _WIN32
        closesocket(data->socket);
#else
        close(data->socket);
#endif
        data->socket = 0;
        thread_mutex_unlock(&data->sock_lock);
    }

#ifdef WITH_SCTP
    if (data->sctp_socket) {
        SCTP_shutdown(data->sctp_socket, SHUT_RDWR);
        thread_mutex_lock(&data->callback_lock);
        SCTP_close(data->sctp_socket);
        data->sctp_socket = 0;
        thread_mutex_unlock(&data->callback_lock);
    }
    int i;
    thread_mutex_lock(&data->clients_lock);
    for (i = 0; i < data->clients_count; i++) {
        SCTP_SOCKET_TYPE socket = data->clients[i].socket;
        data->clients[i].is_sctp = 0;
        if (socket) {
            data->clients[i].socket = 0;
            SCTP_shutdown(socket, SHUT_RDWR);
            SCTP_close(socket);
        }
    }
    thread_mutex_unlock(&data->clients_lock);
#endif
}

void edwork_destroy(struct edwork_data *data) {
    if (!data)
        return;
    avl_destroy(&data->spent, avl_spent_key_data_destructor);
    avl_destroy(&data->tree, avl_key_data_destructor);
    thread_mutex_term(&data->sock_lock);
    thread_mutex_term(&data->clients_lock);
    thread_mutex_init(&data->lock);
#ifdef EDFS_MULTITHREADED
    thread_mutex_term(&data->thread_lock);
#endif
    thread_mutex_term(&data->callback_lock);

    free(data->log_dir);
    free(data->clients);
    free(data);
}
