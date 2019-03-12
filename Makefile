CC = gcc
RM = rm
USRSCTP_CFLAGS = -DSCTP_SIMPLE_ALLOCATOR -DSCTP_PROCESS_LEVEL_LOCKS -D__Userspace__ -D__Userspace_os_Linux -DINET -D_LIB -Isrc/usrsctp
CFLAGS = -pthread -O3 -D_FILE_OFFSET_BITS=64 -DEDFS_DEFAULT_HOST=\"discovery.gyrogears.com:4848\" -DWITH_SCTP -DWITH_USRSCTP $(USRSCTP_CFLAGS)
LIBS = -lfuse -lm
BUILDFLAGS= -o edfs_mount

USRSCTP_SRC = src/usrsctp/user_environment.c src/usrsctp/user_mbuf.c src/usrsctp/user_recv_thread.c src/usrsctp/user_socket.c src/usrsctp/netinet/sctputil.c src/usrsctp/netinet/sctp_asconf.c src/usrsctp/netinet/sctp_auth.c src/usrsctp/netinet/sctp_bsd_addr.c src/usrsctp/netinet/sctp_callout.c src/usrsctp/netinet/sctp_cc_functions.c src/usrsctp/netinet/sctp_crc32.c src/usrsctp/netinet/sctp_indata.c src/usrsctp/netinet/sctp_input.c src/usrsctp/netinet/sctp_output.c src/usrsctp/netinet/sctp_pcb.c src/usrsctp/netinet/sctp_peeloff.c src/usrsctp/netinet/sctp_sha1.c src/usrsctp/netinet/sctp_ss_functions.c src/usrsctp/netinet/sctp_sysctl.c src/usrsctp/netinet/sctp_timer.c src/usrsctp/netinet/sctp_userspace.c src/usrsctp/netinet/sctp_usrreq.c src/usrsctp/netinet6/sctp6_usrreq.c
DUKTAPE_SRC = src/duktape.c src/edfs_js.c
SRC = $(USRSCTP_SRC) $(DUKTAPE_SRC) src/sha256.c src/xxhash.c src/base64.c src/base32.c src/parson.c src/edd25519.c src/avl.c src/chacha.c src/log.c src/sha3.c src/curve25519.c src/sort.c src/blockchain.c src/edfs_key_data.c src/edwork.c src/edfs_core.c src/edfs_fuse.c
OBJS = $(SRC: .c=.o)

edfs: ${OBJS}
	${CC} ${BUILDFLAGS} ${CFLAGS} ${OBJS} ${LIBS}

%.o:
	${CC} ${CFLAGS} -c $<

.PHONY: clean
clean:
	@echo all cleaned up!
