# edwork
edwork is a lightweight decentralized, distributed read-write filesystem. It uses the UDP protocol for node sync. For now, it should not be used in production.

How it works
------------

After compiling you will get either an `edfs_mount`(if built with fuse or dokany) or `edfs_console`. This is a node. Every node is the same (no master). The difference is that some nodes may have a full key pair (public-private) and some have only the public key, that can be only used for checking signatures.

The nodes discover each other by using 3 strategies:
1. using the -use parameter to explicitly set the first node (eg.: `./edfs_mount -use someserver:4848`)
2. hardcoding a node (by defining EDFS_DEFAULT_HOST at compile time)
3. exchanging lists of addresses between them

Note that for now, the content is randomly encrypted (about 25% of all the packages). In the early tests, I've noticed that some hops refused to forward some explicit UDP datagrams (I guess firewalls or other middleboxes). This was solved by randomly encrypting some packages using chacha20.

Every file has an unique 64-bit id, computed as:
```
file_id = xxhash(sha256(parent_id || filename))
```

There is some collision probability on deployments with lots of file. This could be mediated by using larger file ids. 64bit id's were used for compatibility with fuse's `ino_t` type.

After the file id is computed, the file content is split into 57k chunks (in order to fit in a UDP datagram). Each chunk is optionally compressed (compression is enabled by default). Note that when encryption will be available, compression will be disabled by default. Compression and encryption don't mix well. If you compress then encrypt, the door will be opened to at least some theoretical attacks. If you encrypt the compress, the compression will be useless, due to the indistinguishable from random property of most encryption algorithms.

Every user will have the full inode list, but not every fily chunk. The inode list is sent when receiving a `ROOT` request.

File chunks are sent "on-needed" by broadcasting a ``WANT`` request. In order to avoid flooding the edwork nodes, a cost function (proof of work) function was added. It is closely related with hashcash original specification, but instead of sha-1, it uses sha3-256. For every chunk (57k or less) a node must compute a hash begining with 12 zero bits. A `ROOT` request needs a 14 zero bit  proof of work.

The filesystem supports most of the I/O operations except rename. This is because the `file_id` is dependent of its name.

Compiling
------------

edwork may be compiled stand-alone (with no dependencies), with fuse or with dokany-fuse compatibility layer.

On Linux (fuse):
```
$ make
```

Linux, FreeBSD, OS X, without fuse:
```
$ make -f Makefile.console
```

Windows (dokany):
```
make -f Makefile.win32
```

Windows (console):
```
make -f Makefile.console.win32
```

Work in progress
------------
Not that this is work in progress, protocol and API may change. For now, is not suitable for production use.
