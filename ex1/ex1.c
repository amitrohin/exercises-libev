/* 1. Реализовать на Си программу, использующую event loop (можно взять
 * любую библиотеку, желательно libev).
 * На вход программе передают 1 аргумент - номер порта.
 * На данном порте открыть слушающий TCP сокет, и на все входящие пакеты
 * отсылать их обратно в неизменном виде.
 * Тестировать функционал можно с помощью telnet.
 *
 * $Id: ex1.c,v 1.4 2022/09/03 18:33:49 swp Exp $
 */

#include <stddef.h>
#include <stdlib.h>
#include <locale.h>
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <err.h>
#include <sys/queue.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <ev.h>


#ifndef NDEBUG
#define dlog(fmt, ...)  printf("  DEBUG: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define dlog(fmt, ...)
#endif
#define elog(fmt, ...)  printf("  ERROR: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define wlog(fmt, ...)  printf("WARNING: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ilog(fmt, ...)  printf("   INFO: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)

struct iob {
    int inuse;  /* кол-во данных в буфере */
    int pos;    /* индекс начала свободного места в буфере */
    char buf[0x1000];
};
static inline void iob_init(struct iob *iob) {
    iob->inuse = iob->pos = 0;
}
static inline void iob_fini(struct iob *iob) {
    iob->inuse = iob->pos = 0;
}
static inline int iob_nfree(struct iob *iob) {
    return sizeof iob->buf - iob->inuse;
}
static inline int iob_nused(struct iob *iob) {
    return iob->inuse;
}
static void iob_iov_init_(int *n_iov, struct iovec iov[2], int cap, char buf[cap], int pos, int len) {
    int end = pos + len;
    if (end > cap) {
        iov[0].iov_base = buf + pos;
        iov[0].iov_len = cap - pos;
        iov[1].iov_base = buf;
        iov[1].iov_len = end % cap;
        *n_iov = 2;
    } else {
        iov[0].iov_base = buf + pos;
        iov[0].iov_len = end - pos;
        *n_iov = 1;
    }
}
static int iob_read(struct iob *iob, int fd) {
    ssize_t n;
    struct iovec iov[2];
    int n_iov;

    iob_iov_init_(&n_iov, iov, sizeof iob->buf, iob->buf, iob->pos, iob_nfree(iob));
    n = readv(fd, iov, n_iov);
    if (n > 0) {
        iob->pos = (iob->pos + n) % sizeof iob->buf;
        iob->inuse += n;
    }
    return n;
}
static int iob_write(struct iob *iob, int fd) {
    ssize_t n;
    struct iovec iov[2];
    int n_iov, e;

    iob_iov_init_(&n_iov, iov, sizeof iob->buf, iob->buf, (iob->pos + iob_nfree(iob)) % sizeof iob->buf, iob->inuse);
    n = writev(fd, iov, n_iov);
    if (n > 0)
        iob->inuse -= n;
    return n;
}

/* [!] подразумеваем, что структура всегда выделяется malloc()-ом */
struct io {
    LIST_ENTRY(io) ent;
    struct ev_io evr, evw;
    struct iob iob;
    struct sockaddr_in addr;
};
static LIST_HEAD(, io) ioq[1] = { LIST_HEAD_INITIALIZER(ioq[0]) };

static void io_r_cb(EV_P_ ev_io *w, int revents);
static void io_w_cb(EV_P_ ev_io *w, int revents);
static struct io *io_create(int fd, struct sockaddr_in *addr, socklen_t addrlen) {
    struct io *io;

    if (io = malloc(sizeof(struct io)), !io) {
        elog("malloc(): %s.\n", strerror(errno));
        return NULL;
    }
    ev_io_init(&io->evr, io_r_cb, fd, EV_READ);
    ev_io_init(&io->evw, io_w_cb, fd, EV_WRITE);
    iob_init(&io->iob);
    io->addr = *addr;
    LIST_INSERT_HEAD(ioq, io, ent);
    dlog("%p\n", io);
    return io;
}
static void io_destroy(struct io *io) {
    LIST_REMOVE(io, ent);
    if (ev_is_active(&io->evr))
        ev_io_stop(EV_DEFAULT_UC, &io->evr);
    if (ev_is_active(&io->evw))
        ev_io_stop(EV_DEFAULT_UC, &io->evw);
    close(io->evr.fd);
    free(io);
    dlog("%p\n", io);
}

static void io_r_cb(EV_P_ struct ev_io *w, int revents) {
    struct io *io = (struct io *) (((char *)w) - offsetof(struct io, evr));
    for (;;) {
        int n = iob_nfree(&io->iob);
        if (!n) {
            if (ev_is_active(&io->evr))
                ev_io_stop(EV_A_ &io->evr);
            break;
        }
    L_retry:
        n = iob_read(&io->iob, io->evr.fd);
        if (n < 0) {
            if (errno == EINTR)
                goto L_retry;
            if (errno == EAGAIN)
                break;
            elog("fd %d: %s.\n", w->fd, strerror(errno));
            ev_io_stop(EV_A_ &io->evr);
            if (!iob_nused(&io->iob))
                io_destroy(io);
            break;
        }
        if (!n) {
            ev_io_stop(EV_A_ &io->evr);
            if (!iob_nused(&io->iob))
                io_destroy(io);
            break;
        }
        if (!ev_is_active(&io->evw))
            ev_io_start(EV_A_ &io->evw);
    }
}
static void io_w_cb(EV_P_ struct ev_io *w, int revents) {
    struct io *io = (struct io *) (((char *)w) - offsetof(struct io, evw));
    for (;;) {
        int n = iob_nused(&io->iob);
        if (!n) {
            if (ev_is_active(&io->evw))
                ev_io_stop(EV_A_ &io->evw);
            break;
        }
    L_retry:
        n = iob_write(&io->iob, io->evw.fd);
        if (n < 0) {
            if (errno == EINTR)
                goto L_retry;
            if (errno == EAGAIN)
                break;
            elog("fd %d: %s.\n", w->fd, strerror(errno));
            io_destroy(io);
            break;
        }
        if (!n) {
            dlog("??? unreachable ???\n");
            ev_io_stop(EV_A_ &io->evr);
            if (!iob_nused(&io->iob)) {
                ev_io_stop(EV_A_ &io->evw);
                io_destroy(io);
            }
            break;
        }
        if (!ev_is_active(&io->evr))
            ev_io_start(EV_A_ &io->evr);
    }
}

static void accept_cb(EV_P_ struct ev_io *w, int revents) {
    int fd;
    struct sockaddr_in addr;
    socklen_t addrlen;
    struct io *io;

    for (;;) {
        addrlen = sizeof addr;
        fd = accept(w->fd, (struct sockaddr *)&addr, &addrlen);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                return;
            elog("accept(): %s.\n", strerror(errno));
            break;
        }
        
        dlog("accepted connection from %s:%hu.\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
            elog("fcntl(+O_NONBLOCK): %s.\n", strerror(errno));
            close(fd);
            continue;
        }
        io = io_create(fd, &addr, addrlen);
        if (!io) {
            close(fd);
            dlog("unable to create io.\n");
            continue;
        }
        ev_io_start(EV_A_ &io->evr);
    }
    ev_io_stop(EV_A_ w);
    dlog("work complete.\n");
    //ev_break(EV_A_ EVBREAK_ALL);
}

static void watchdog_cb(EV_P_ struct ev_periodic *w, int revents) {
    static int i = 0;
    static const char s[] = {'-', '\\', '|', '/'};
    i = (i + 1) % sizeof s/sizeof s[0];
    fprintf(stderr, "%c\b", s[i]);
}

static void signal_cb(EV_P_ struct ev_signal *w, int revents) {
    ev_signal_stop(EV_DEFAULT_UC_ w);
    dlog("exit.\n");
    ev_break(EV_DEFAULT_UC_ EVBREAK_ALL);
}

static const char *progname;
static void usage(FILE *fp) {
    fprintf(fp, "usage: %s [-h] tcp_listen_port\n", progname);
}
int main(int argc, char *argv[]) {
    progname = ({
        char *p = strrchr(argv[0], '/');
        p ? p+1 : argv[0];
    });

    for (int c; (c = getopt(argc, argv, "h")) != -1; ) {
        switch (c) {
            case 'h':
                usage(stdout);
                exit(0);
            case '?':
            default:
                usage(stderr);
                exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if (!argc) {
        usage(stderr);
        exit(1);
    }

    static int port;
    static int sock = -1;
    static struct sockaddr_in addr;

    port = ({
        char *e;
        long n;

        n = strtol(argv[0], &e, 10);
        while (isspace(*e))
            e++;
        if (n < 1 || n > 65535 || *e) {
            elog("\"%s\": invalid value for port number.", argv[0]);
            exit(1);
        }
        n;
    });

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        err(1, "socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (int [1]){1}, sizeof(int)) < 0)
        err(1, "setsockopt(): SO_REUSEPORT");

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr *)&addr, sizeof addr) < 0)
        err(1, "bind(0.0.0.0:%d)", port);

    if (listen(sock, -1) < 0)
        err(1, "listen()");

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0)
        err(1, "fcntl(+O_NONBLOCK)");

    static struct ev_io accept_ev[1];
    static struct ev_periodic watchdog_ev[1];
    static struct ev_signal signal_ev[1];
    struct ev_loop *loop = EV_DEFAULT;

    ev_periodic_init(watchdog_ev, watchdog_cb, 0, 0.1, NULL);
    ev_periodic_start(EV_DEFAULT_UC_ watchdog_ev);
    ev_io_init(accept_ev, accept_cb, sock, EV_READ);
    ev_io_start(EV_DEFAULT_UC_ accept_ev);
    ev_signal_init(signal_ev, signal_cb, SIGINT);
    ev_signal_start(EV_DEFAULT_UC_ signal_ev);
    ev_run(EV_DEFAULT_UC_ 0);

    if (ev_is_active(accept_ev))
        ev_io_stop(EV_DEFAULT_UC_ accept_ev);
    close(sock);
    for (struct io *p; p = LIST_FIRST(ioq), p; )
        io_destroy(p);
    if (ev_is_active(watchdog_ev))
        ev_periodic_stop(EV_DEFAULT_UC_ watchdog_ev);

    ev_loop_destroy(EV_DEFAULT_UC);

    return 0;
}

// vi: ts=4:sts=4:sw=4:et
