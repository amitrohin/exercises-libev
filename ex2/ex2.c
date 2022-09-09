/* 2) В программу добавить 1 поток (всего будет 2 потока включая 1 главный
 * поток).
 * В потоке должен быть свой event loop. Перенести TCP сокет в этот поток.
 * Приняв пакет, нужно переслать его на обработку в главный поток.
 * Главный поток должен что-то сделать с пакетом, например перевернуть все
 * данные в нем задом наперед.
 * После этого пакет передается обратно в поток и там отсылается обратно
 * клиенту.
 *
 * $Id: ex2.c,v 1.5 2022/09/08 13:55:15 swp Exp $
 */

/* 
 * thr1_sock_async_ev/thr1_sock_async_cb()
 *      - принимаем соединения и ставим дескриптор в циклическую очередь sockq.
 *      - сигнализируем thr2 о готовности события thr2_sock_async_ev.
 * thr2_sock_async_ev/thr2_sock_async_cb()
 *      - забираем из очереди сокеты и создаем объекты io. делаем активными события
 *        io.evr/EV_READ.
 * thr2_io_r_ev/thr2_io_r_cb()
 *      - когда срабатывает io.evr/EV_READ, вычитываем данные в iob и ставим в очередь 
 *        iobq[0]. iob - это кусок прочитанных данных, в нем есть ссылка на io, из
 *        которого данные получены.
 *      - сигнализируем thr1 о готовности thr1_data_async_ev. т.е. что данные поставлены
 *        в очередь на обработку для thr1.
 * thr1_data_async_ev/thr1_data_async_cb()
 *      - забираем данные из очереди.
 *      - для каждого блока данных iob, выполняем "полезную работу" (переворачиваем данные).
 *      - помещаем iob в очередь iobq[1].
 *      - сигнализируем thr2 о готовности thr2_data_async_ev, т.е. необходимости 
 *        отправить данные в сокет (iob->io.evw.fd).
 *
 * [!] сделано специально так, что с io работает только thr2. thr1 будет подбирать 
 * незакрытые io, только после завершения thr2, когда никаких race conditions уже нет.
 * это позволяет не использовать блокировки и делает программу быстрее и проще.
 *
 * thr2_data_async_ev/thr2_data_async_ev()
 *      - перемещаем iob в свой io (т.е. в очередь iob->io->wq) и запускаем событие
 *        iob->io.evw/EV_WRITE (т.е. событие на ожидание готовности на запись данных 
 *        обратно в сокет).
 * thr2_io_w_ev/thr2_io_w_cb()
 *      - когда срабатывает io.evw/EV_WRITE, записываем данные в сокет.
 *      - если нет пакетов, которые мы вычитали из нашего сокета, и ещё не отправили
 *        (т.е. счётчик io.iob_inp == 0), и при этом событие io.evr не активно, то
 *        закрывается соединение с удалённой стороной (уничтожается io).
 *
 * thr2_exit_async_ev
 *      используется основным потоком (thr1), чтобы просигнализировать второму (thr2)
 *      о необходимости завершить свою работу (т.е. выполнить ev_break()).
 * thr1_exit_signal_ev
 *      thr1 ловит сигнал и завершается (делает ev_break()) в обработчике этого события.
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
#include <pthread.h>
#include <assert.h>
#include <stdarg.h>
#include <ev.h>

#ifndef NDEBUG
#define dlog(fmt, ...)  printf("  DEBUG: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define dlog(fmt, ...)
#endif
#define elog(fmt, ...)  printf("  ERROR: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define wlog(fmt, ...)  printf("WARNING: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ilog(fmt, ...)  printf("   INFO: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)


struct io;
struct iob {
    STAILQ_ENTRY(iob) ent;
    struct io *io;
    int len;
    int offset;
    char buf[0x1000];
};
static pthread_mutex_t iobq_mtx[2] = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER};
static STAILQ_HEAD(iobq, iob) iobq[2] = {STAILQ_HEAD_INITIALIZER(iobq[0]), STAILQ_HEAD_INITIALIZER(iobq[1])};
struct io {
    struct ev_io evr, evw;
    int iob_inp;    /* кол-во прочитанных, но ещё не записанных блоков iob */
    struct iobq wq;
    int nref;
    LIST_ENTRY(io) ent;
};
/* все io создаются и удаляются только во втором потоке. первый (основной) поток 
 * подчищает io только при завершении программы, после join-а второго потока.
 * т.е. нет необходимости защищать очередь мутексом.
 */
static LIST_HEAD(ioq, io) ioq = LIST_HEAD_INITIALIZER(ioq);

static struct io *          io_create(int fd, 
                                void (*rcb)(struct ev_loop *, struct ev_io *, int),
                                void (*wcb)(struct ev_loop *, struct ev_io *, int));
static inline struct io *   io_attach(struct io *io);
static void                 io_detach(struct io *io);

static struct iob *         iob_create();
static void                 iob_destroy(struct iob *iob);
static int                  iob_read(struct iob **iob, struct io *io);
static int                  iob_write(struct iob **iob);

static inline void          iobq_init(struct iobq *iobq);
static void                 iobq_fini(struct iobq *iobq);
static void                 iobq_destroy(struct iobq *iobq);
static inline void          iobq_enqueue(struct iobq *iobq, struct iob *iob);
static inline struct iob *  iobq_dequeue(struct iobq *iobq);
static inline void          iobq_undequeue(struct iobq *iobq, struct iob *iob);
static inline void          iobq_swap(struct iobq *q1, struct iobq *q2);
static inline void          iobq_concat(struct iobq *q1, struct iobq *q2);
static inline struct iob *  iobq_first(struct iobq *q);
static inline int           iobq_isempty(struct iobq *q);

static void                 io_dump(struct io *io, const char *fmt, ...) 
                                    __attribute__((__format__(printf,2,3)));
static void                 iob_dump(struct iob *iob, const char *fmt, ...)
                                    __attribute__((__format__(printf,2,3)));

static pthread_t thr2;
static struct ev_io         thr1_accept_ev[1];
static struct ev_periodic   thr1_watchdog_ev[1];
static struct ev_signal     thr1_signal_ev[1];
static struct ev_loop *     thr1_loop;
static struct ev_async      thr1_sock_async_ev[1];
static struct ev_async      thr1_data_async_ev[1];

static struct ev_loop *     thr2_loop;
static struct ev_async      thr2_sock_async_ev[1];
static struct ev_async      thr2_data_async_ev[1];
static struct ev_async      thr2_exit_async_ev[1];


static pthread_mutex_t sockq_mtx[1] = {PTHREAD_MUTEX_INITIALIZER};
static int sockq_b = 0, sockq_e = 0, sockq_len = 0;
static int sockq[0x10];

static void                 sockq_lock();
static void                 sockq_unlock();
static inline int           sockq_nfree();
static int                  sockq_enqueue(int fd);
static int                  sockq_dequeue(int *fd);
static void                 sockq_dump(const char *fmt, ...) __attribute__((__format__(printf, 1, 2)));

static void                 thr1_accept_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static void                 thr2_io_r_cb(struct ev_loop *loop, ev_io *w, int revents);
static void                 thr2_io_w_cb(struct ev_loop *loop, ev_io *w, int revents);

static void *thr2_routine(void *arg) {
    dlog("thr2 start\n");
    ev_run(thr2_loop, 0);
    dlog("thr2 exit\n");
    return NULL;
}
static void thr2_sock_async_cb(struct ev_loop *loop, struct ev_async *w, int revents);
static void thr1_sock_async_cb(struct ev_loop *loop, struct ev_async *w, int revents);
static void thr1_data_async_cb(struct ev_loop *loop, struct ev_async *w, int revents);
static void thr2_data_async_cb(struct ev_loop *loop, struct ev_async *w, int revents);

static void thr2_exit_async_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    ev_async_stop(thr2_loop, thr2_exit_async_ev);
    dlog("loop break\n");
    ev_break(thr2_loop, EVBREAK_ALL);
}

static void thr1_watchdog_cb(struct ev_loop *loop, struct ev_periodic *w, int revents) {
    static int i = 0;
    static const char s[] = {'-', '\\', '|', '/'};
    i = (i + 1) % sizeof s/sizeof s[0];
    fprintf(stderr, "%c\b", s[i]);
}
static void thr1_signal_cb(struct ev_loop *loop, struct ev_signal *w, int revents) {
    ev_signal_stop(thr1_loop, thr1_signal_ev);
    dlog("loop break\n");
    ev_break(thr1_loop, EVBREAK_ALL);
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

    thr1_loop = EV_DEFAULT;
    ev_periodic_init(thr1_watchdog_ev, thr1_watchdog_cb, 0, 0.1, NULL);
    ev_periodic_start(thr1_loop, thr1_watchdog_ev);
    ev_io_init(thr1_accept_ev, thr1_accept_cb, sock, EV_READ);
    ev_io_start(thr1_loop, thr1_accept_ev);
    ev_signal_init(thr1_signal_ev, thr1_signal_cb, SIGINT);
    ev_signal_start(thr1_loop, thr1_signal_ev);
    ev_async_init(thr1_sock_async_ev, thr1_sock_async_cb);
    ev_async_start(thr1_loop, thr1_sock_async_ev);
    ev_async_init(thr1_data_async_ev, thr1_data_async_cb);
    ev_async_start(thr1_loop, thr1_data_async_ev);

    thr2_loop = ev_loop_new(0);
    assert(thr2_loop);
    ev_async_init(thr2_sock_async_ev, thr2_sock_async_cb);
    ev_async_start(thr2_loop, thr2_sock_async_ev);
    ev_async_init(thr2_data_async_ev, thr2_data_async_cb);
    ev_async_start(thr2_loop, thr2_data_async_ev);
    ev_async_init(thr2_exit_async_ev, thr2_exit_async_cb);
    ev_async_start(thr2_loop, thr2_exit_async_ev);

    do { int ecode = pthread_create(&thr2, NULL, thr2_routine, NULL); 
        if (ecode) errx(1, "pthread_create(): %s.", strerror(ecode)); } while (0);

    ev_run(thr1_loop, 0);

    ev_async_send(thr2_loop, thr2_exit_async_ev);
    do { int ecode = pthread_join(thr2, NULL); 
        if (ecode) dlog("pthread_join(): %s.\n", strerror(ecode)); } while (0);

    if (ev_is_active(thr2_data_async_ev))
        ev_async_stop(thr2_loop, thr2_data_async_ev);
    if (ev_is_active(thr2_sock_async_ev))
        ev_async_stop(thr2_loop, thr2_sock_async_ev);

    if (ev_is_active(thr1_signal_ev))
        ev_signal_stop(thr1_loop, thr1_signal_ev);
    if (ev_is_active(thr1_data_async_ev))
        ev_async_stop(thr1_loop, thr1_data_async_ev);
    if (ev_is_active(thr1_accept_ev))
        ev_io_stop(thr1_loop, thr1_accept_ev);
    close(sock);
    for (struct io *p; p = LIST_FIRST(&ioq), p; )
        io_detach(p);
    if (ev_is_active(thr1_watchdog_ev))
        ev_periodic_stop(thr1_loop, thr1_watchdog_ev);

    ev_loop_destroy(thr2_loop);
    ev_loop_destroy(thr1_loop);

    return 0;
}

static struct io *
io_create(int fd, void (*rcb)(struct ev_loop *, struct ev_io *, int revents),
                  void (*wcb)(struct ev_loop *, struct ev_io *, int revents))
{
    struct io *io;

    if (io = malloc(sizeof(struct io)), !io) {
        elog("malloc(): %s.\n", strerror(errno));
    } else {
        io->nref = 1;
        ev_io_init(&io->evr, rcb, fd, EV_READ);
        ev_io_init(&io->evw, wcb, fd, EV_WRITE);
        iobq_init(&io->wq);
        LIST_INSERT_HEAD(&ioq, io, ent);
    }
    //io_dump(io, "%s(),%d: ", __func__, __LINE__);
    dlog("%p\n", io);
    return io;
}
static inline struct io *io_attach(struct io *io) {
    assert(io->nref > 0);
    io->nref++;
    dlog("%p\n", io);
    return io;
}
static void io_detach(struct io *io) {
    assert(io->nref > 0);
    //io_dump(io, "%s(),%d -> ", __func__, __LINE__);
    if (!--io->nref) {
        LIST_REMOVE(io, ent);
        if (ev_is_active(&io->evr))
            ev_io_stop(thr2_loop, &io->evr);
        if (ev_is_active(&io->evw))
            ev_io_stop(thr2_loop, &io->evw);
        close(io->evr.fd);
        free(io);
        dlog("%p destroyed.\n", io);
    } else
        dlog("%p\n", io);
}
static void io_dump(struct io *io, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (!io)
        printf("%p{}", io);
    else
        printf("%p{evr{%s,%d},evw{%s,%d},iob_inp:%d,wq:???,nref:%d}\n", 
            io, ev_is_active(&io->evr) ? "act" : "ina", io->evr.fd, 
                ev_is_active(&io->evw) ? "act" : "ina", io->evw.fd,
            io->iob_inp, io->nref);
}

static struct iob *iob_create() {
    struct iob *iob;

    if (iob = malloc(sizeof(struct iob)), !iob) {
        elog("malloc(): %s.\n", strerror(errno));
        return NULL;
    }
    iob->io = NULL;
    iob->len = iob->offset = 0;
    //dlog("%p\n", iob);
    return iob;
}
static void iob_destroy(struct iob *iob) {
    if (iob->io) {
        assert(iob->io->iob_inp > 0);
        iob->io->iob_inp--;
        io_detach(iob->io);
    }
    free(iob);
    //dlog("%p\n", iob);
}
static int iob_read(struct iob **iob, struct io *io) {
    struct iob *b = iob_create();
    ssize_t n = read(io->evr.fd, b->buf, sizeof b->buf);
    if (n > 0) {
        b->len = n;
        b->io = io_attach(io);
        io->iob_inp++;
        assert(io->iob_inp > 0);
        *iob = b;
    } else {
        iob_destroy(b);
        *iob = NULL;
    }
    return n;
}
static int iob_write(struct iob **iob) {
    assert(*iob);
    assert((*iob)->io);
    ssize_t n = write((*iob)->io->evw.fd, (*iob)->buf + (*iob)->offset, (*iob)->len);
    if (n > 0) {
        (*iob)->len -= n;
        (*iob)->offset += n;
        if (!(*iob)->len) {
            iob_destroy(*iob);
            *iob = NULL;
        }
    }
    return n;
}
static void iob_dump(struct iob *iob, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("%p{", iob);
    io_dump(iob->io, "io:");
    printf("len:%d,offset:%d,buf:%p{%s}}\n",
        iob->len, iob->offset, iob->buf, iob->buf);
}

static inline void iobq_init(struct iobq *iobq) {
    STAILQ_INIT(iobq);
}
static void iobq_fini(struct iobq *iobq) {
    struct iob *iob;
    while (1) {
        iob = STAILQ_FIRST(iobq);
        if (!iob)
            break;
        STAILQ_REMOVE_HEAD(iobq, ent);
        iob_destroy(iob);
    }
}
static inline void iobq_enqueue(struct iobq *iobq, struct iob *iob) {
    STAILQ_INSERT_TAIL(iobq, iob, ent);
}
static inline struct iob *iobq_dequeue(struct iobq *iobq) {
    struct iob *iob = STAILQ_FIRST(iobq);
    if (iob)
        STAILQ_REMOVE_HEAD(iobq, ent);
    return iob;
}
static inline void iobq_undequeue(struct iobq *iobq, struct iob *iob) {
    STAILQ_INSERT_HEAD(iobq, iob, ent);
}
static inline void iobq_swap(struct iobq *q1, struct iobq *q2) {
    STAILQ_SWAP(q1, q2, iob);
}
static inline void iobq_concat(struct iobq *q1, struct iobq *q2) {
    STAILQ_CONCAT(q1, q2);
}
static inline struct iob *iobq_first(struct iobq *q) {
    return STAILQ_FIRST(q);
}
static inline int iobq_isempty(struct iobq *q) {
    return STAILQ_EMPTY(q);
}


static void sockq_lock() {
    int ecode = pthread_mutex_lock(sockq_mtx);
    assert(!ecode);
}
static void sockq_unlock() {
    int ecode = pthread_mutex_unlock(sockq_mtx);
    assert(!ecode);
}
static inline int sockq_nfree() {
    int n = sizeof sockq / sizeof sockq[0] - sockq_len;
    assert(n >= 0);
    return n;
}
/* 0 - success */
static int sockq_enqueue(int fd) {
    int rc = -1;
    if (sockq_len < sizeof sockq / sizeof sockq[0]) {
        sockq[sockq_e] = fd;
        sockq_e = (sockq_e + 1) % (sizeof sockq / sizeof sockq[0]);
        sockq_len++;
        rc = 0;
    }
    return rc;
}
static int sockq_dequeue(int *fd) {
    int rc = -1;
    if (sockq_len) {
        if (fd)
            *fd = sockq[sockq_b];
        sockq_b = (sockq_b + 1) % (sizeof sockq / sizeof sockq[0]);
        sockq_len--;
        rc = 0;
    }
    return rc;
}
static void __attribute__((format(printf, 1, 2))) sockq_dump(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf(": {sockq_len:%d, sockq_b:%d, sockq_e:%d} -> ", sockq_len, sockq_b, sockq_e);
    if (sockq_len) {
        printf("%d", sockq[sockq_b]);
        for (int i = 1; i < sockq_len; i++)
            printf(",%d", sockq[(sockq_b + i) % (sizeof sockq/sizeof sockq[0])]);
    }
    printf("}\n");
}


static void thr1_accept_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    int fd;
    struct sockaddr_in addr;
    socklen_t addrlen;

    sockq_lock();
    for (;;) {
        if (!sockq_nfree()) {
            ev_io_stop(thr1_loop, w);
            break;
        }
        addrlen = sizeof addr;
        fd = accept(w->fd, (struct sockaddr *)&addr, &addrlen);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                break;
            elog("accept(): %s.\n", strerror(errno));
            ev_io_stop(thr1_loop, w);
            break;
        }
        dlog("accepted connection from %s:%hu.\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
            elog("fcntl(+O_NONBLOCK): %s.\n", strerror(errno));
            close(fd);
            continue;
        }
        sockq_enqueue(fd);
    }
    sockq_unlock();
    ev_async_send(thr2_loop, thr2_sock_async_ev);
}
static void thr2_sock_async_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    int fd;
    struct io *io;
    assert(loop == thr2_loop);

    sockq_lock();
    while (!sockq_dequeue(&fd)) {
        io = io_create(fd, thr2_io_r_cb, thr2_io_w_cb);
        assert(io);
        ev_io_start(loop, &io->evr);
    }
    sockq_unlock();
    ev_async_send(thr1_loop, thr1_sock_async_ev);
}
static void thr1_sock_async_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    sockq_lock();
    if (sockq_nfree())
        ev_io_start(thr1_loop, thr1_accept_ev);
    sockq_unlock();
}

static void thr2_io_r_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct io *io = (struct io *) (((char *)w) - offsetof(struct io, evr));
    struct iobq q[1] = {STAILQ_HEAD_INITIALIZER(q[0])};
    struct iob *iob = NULL;
    int n;

    for (;;) {
    L_retry:
        n = iob_read(&iob, io);
        //dlog("io:%p, iob_inp:%d\n", io, io->iob_inp);
        if (n < 0) {
            assert(!iob);
            if (errno == EINTR)
                goto L_retry;
            if (errno == EAGAIN)
                break;
            elog("fd %d: %s.\n", w->fd, strerror(errno));
            ev_io_stop(loop, &io->evr);
            if (!io->iob_inp)
                io_detach(io);
            break;
        }
        if (!n) {
            assert(!iob);
            ev_io_stop(loop, &io->evr);
            if (!io->iob_inp)
                io_detach(io);
            break;
        }
        assert(iob);
        iobq_enqueue(q, iob);
        iob = NULL;
    }
    if (!iobq_isempty(q)) {
        pthread_mutex_lock(iobq_mtx + 0);
        iobq_concat(iobq + 0, q);
        pthread_mutex_unlock(iobq_mtx + 0);
        ev_async_send(thr1_loop, thr1_data_async_ev);
    }
}
static void thr1_data_async_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    struct iobq q[2][1] = {
        {STAILQ_HEAD_INITIALIZER(q[0][0])},
        {STAILQ_HEAD_INITIALIZER(q[1][0])}
    };

    pthread_mutex_lock(iobq_mtx + 0);
    iobq_swap(iobq + 0, q[0]);
    pthread_mutex_unlock(iobq_mtx + 0);

    while (1) {
        struct iob *iob = iobq_dequeue(q[0]);
        if (!iob)
            break;
        //iob_dump(iob, "%s(),%d: iob := ", __func__, __LINE__);
        
        /* "полезная" работа, по обработке данных пакета.
         * XXX: в общем случае формулировка задачи не корректна, т.к. tcp это поток и прочитанные программой
         * данные могут ни разу не совпадать c порцией данных одного пакета tcp.
         */
        char *b = iob->buf + iob->offset, *e = b + iob->len - 1;
        while (b < e) {
            int x = *b; *b = *e; *e = x;
            b++;
            e--;
        }
        iobq_enqueue(q[1], iob);
    }

    pthread_mutex_lock(iobq_mtx + 1);
    iobq_concat(iobq + 1, q[1]);
    pthread_mutex_unlock(iobq_mtx + 1);
    ev_async_send(thr2_loop, thr2_data_async_ev);
}
static void thr2_data_async_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    struct iobq q[1] = {STAILQ_HEAD_INITIALIZER(q[0])};

    pthread_mutex_lock(iobq_mtx + 1);
    iobq_swap(iobq + 1, q);
    pthread_mutex_unlock(iobq_mtx + 1);
    for (struct iob *iob; iob = iobq_dequeue(q), iob; ) {
        assert(iob->io);
        iobq_enqueue(&iob->io->wq, iob);
        if (!ev_is_active(&iob->io->evw))
            ev_io_start(thr2_loop, &iob->io->evw);
    }
}

static void thr2_io_w_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct io *io = (struct io *) (((char *)w) - offsetof(struct io, evw));
    struct iob *iob;
    int n;

    for (;;) {
        iob = iobq_dequeue(&io->wq);
        if (!iob) {
            if (!io->iob_inp && !ev_is_active(&io->evr))
                io_detach(io);
            break;
        }
    L_retry:
        n = iob_write(&iob);
        assert(n);
        if (n < 0) {
            assert(iob);
            if (errno == EINTR)
                goto L_retry;
            if (errno == EAGAIN) {
                iobq_undequeue(&io->wq, iob);
                break;
            }
            elog("fd %d: %s.\n", w->fd, strerror(errno));
            iob_destroy(iob);
            break;
        }
        if (iob) {
            /* запись успешная, но не все данные записаны */
            goto L_retry;
        }
        /* все записали и iob удалилось */
    }
}

// vi: ts=4:sts=4:sw=4:et
