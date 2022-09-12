/* 3) Вместо порта на вход передаются имена входящего и выходящего сетевых
 * интерфейсов (например eth0, eth1).
 * В потоке нужно ловить все входящие UDP пакеты на входящем интерфейсе (в
 * сыром виде, с L2 заголовками).
 * Далее пакет также передается в основной поток, UDP payload
 * переворачивается задом наперед, и пакет передается обратно в поток на
 * отправку.
 * Отправка осуществляется тоже в сыром виде в выходящий интерфейс, с
 * формированием L2 заголовков, подсчетом сумм итд.
 *
 * $Id: ex3.c,v 1.3 2022/09/12 07:56:06 swp Exp $
 */

#include <stddef.h>
#include <stdlib.h>
#include <locale.h>
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
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
#include <pcap.h>

#ifndef NDEBUG
#define dlog(fmt, ...)  printf("  DEBUG: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define dlog(fmt, ...)
#endif
#define elog(fmt, ...)  printf("  ERROR: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define wlog(fmt, ...)  printf("WARNING: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ilog(fmt, ...)  printf("   INFO: %s(),%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)

struct pcb {
    STAILQ_ENTRY(pcb) ent;
    struct timeval ts;
    int len;
    uint8_t pkt[];
};
STAILQ_HEAD(pcbq, pcb);

static pthread_mutex_t pcbq_mtx[2][1] = {{PTHREAD_MUTEX_INITIALIZER}, {PTHREAD_MUTEX_INITIALIZER}};
static struct pcbq pcbq[2][1] = {{STAILQ_HEAD_INITIALIZER(pcbq[0][0])}, {STAILQ_HEAD_INITIALIZER(pcbq[1][0])}};

static struct pcb *         pcb_create(struct timeval *ts, int len, const u_char pkt[len]);
static void                 pcb_destroy(struct pcb *pcb);

static inline void          pcbq_init(struct pcbq *pcbq);
static void                 pcbq_fini(struct pcbq *pcbq);
static void                 pcbq_destroy(struct pcbq *pcbq);
static inline void          pcbq_enqueue(struct pcbq *pcbq, struct pcb *pcb);
static inline struct pcb *  pcbq_dequeue(struct pcbq *pcbq);
static inline void          pcbq_undequeue(struct pcbq *pcbq, struct pcb *pcb);
static inline void          pcbq_swap(struct pcbq *q1, struct pcbq *q2);
static inline void          pcbq_concat(struct pcbq *q1, struct pcbq *q2);
static inline struct pcb *  pcbq_first(struct pcbq *q);
static inline int           pcbq_isempty(struct pcbq *q);

static pthread_t thr2;
static struct ev_loop *     thr1_loop;
static struct ev_periodic   thr1_watchdog_ev[1];
static struct ev_signal     thr1_signal_ev[1];
static struct ev_io         thr1_precv_ev[1];
static struct ev_io         thr1_psend_ev[1];
static struct ev_async      thr1_pcbq_async_ev[1];

static struct ev_loop *     thr2_loop;
static struct ev_async      thr2_exit_async_ev[1];
static struct ev_async      thr2_pcbq_async_ev[1];

static void                 thr1_precv_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static void                 thr1_psend_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static void                 thr1_pcbq_async_cb(struct ev_loop *loop, struct ev_async *w, int revents);
static void                 thr2_pcbq_async_cb(struct ev_loop *loop, struct ev_async *w, int revents);

static void                 thr1_watchdog_cb(struct ev_loop *loop, struct ev_periodic *w, int revents);
static void                 thr1_signal_cb(struct ev_loop *loop, struct ev_signal *w, int revents);
static void                 thr2_exit_async_cb(struct ev_loop *loop, struct ev_async *w, int revents);

static int                  pcb_mangle(struct pcb *);

static void *thr2_routine(void *arg) {
    dlog("thr2 start\n");
    ev_run(thr2_loop, 0);
    dlog("thr2 exit\n");
    return NULL;
}

static const char *progname;
static void usage(FILE *fp) {
    fprintf(fp, "usage: %s [-h] recvif sendif udpfltr\n", progname);
}

static const char *ifname[2]; 
static char udpfltr_default[] = "udp", *udpfltr = udpfltr_default;
static struct bpf_program fpbuf, *fp;
static pcap_t *ifcap[2];
static int fdcap[2] = {-1, -1};
static char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char *argv[]) {
    progname = ({ char *p = strrchr(argv[0], '/'); p ? p+1 : argv[0]; });

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
    if (argc < 2 || argc > 3) {
        usage(stderr); 
        exit(1);
    }

    ifname[0] = argv[0];
    ifname[1] = argv[1];

    if (argc == 3) {
        char *s = malloc(sizeof "udp and " + strlen(argv[2]));
        if (!s) {
            elog("malloc(): %s.\n", strerror(errno));
            exit(1);
        }
        sprintf(s, "udp and %s", argv[2]);
        udpfltr = s;
    }

    for (int i = 0; i < sizeof ifname/sizeof ifname[0]; i++) {
        ifcap[i] = pcap_open_live(ifname[i], 65536, 1, 100, errbuf);
        if (!ifcap[i]) {
            elog("pcap_open_live(%s): %s\n", ifname[i], errbuf);
            goto L_err;
        }
        if (pcap_datalink(ifcap[i]) != DLT_EN10MB) {
            elog("%s: ethernet interface expected.\n", ifname[i]);
            goto L_err;
        }
        if (pcap_setnonblock(ifcap[i], 1, errbuf) == PCAP_ERROR) {
            elog("pcap_setnonblock(%s): %s\n", ifname[i], errbuf);
            goto L_err;
        }
        int fd = pcap_get_selectable_fd(ifcap[i]);
        if (fd == PCAP_ERROR) {
            elog("pcap_get_selectable_fd(%s): unsupported event driven io.\n", ifname[0]);
            goto L_err;
        }
        fdcap[i] = fd;
        // dlog("fdcap[%d]: %d\n", i, fdcap[i]);
    }
    if (pcap_compile(ifcap[0], &fpbuf, udpfltr, 0, 0) == PCAP_ERROR) {
        elog("pcap_compile(): %s: %s\n", udpfltr, pcap_geterr(ifcap[0]));
        goto L_err;
    }
    fp = &fpbuf;
    if (pcap_setfilter(ifcap[0], fp) == PCAP_ERROR) {
        elog("pcap_setfilter(): %s\n", pcap_geterr(ifcap[0]));
        goto L_err;
    }
    if (pcap_setdirection(ifcap[0], PCAP_D_IN) == PCAP_ERROR) {
        elog("pcap_setdirection(%s, PCAP_D_IN): %s\n", ifname[0], pcap_geterr(ifcap[0]));
        goto L_err;
    }
    if (pcap_setdirection(ifcap[1], 0) == PCAP_ERROR) {
        elog("pcap_setdirection(%s, 0): %s\n", ifname[1], pcap_geterr(ifcap[1]));
        goto L_err;
    }

    thr1_loop = ev_default_loop(EVBACKEND_SELECT);
    assert(thr1_loop);
    ev_periodic_init(thr1_watchdog_ev, thr1_watchdog_cb, 0, 0.1, NULL);
    ev_periodic_start(thr1_loop, thr1_watchdog_ev);
    ev_signal_init(thr1_signal_ev, thr1_signal_cb, SIGINT);
    ev_signal_start(thr1_loop, thr1_signal_ev);
    ev_async_init(thr1_pcbq_async_ev, thr1_pcbq_async_cb);
    ev_async_start(thr1_loop, thr1_pcbq_async_ev);
    ev_io_init(thr1_precv_ev, thr1_precv_cb, fdcap[0], EV_READ);
    ev_io_start(thr1_loop, thr1_precv_ev);
    ev_io_init(thr1_psend_ev, thr1_psend_cb, fdcap[1], EV_WRITE);

    thr2_loop = ev_loop_new(EVBACKEND_SELECT);
    assert(thr2_loop);
    ev_async_init(thr2_exit_async_ev, thr2_exit_async_cb);
    ev_async_start(thr2_loop, thr2_exit_async_ev);
    ev_async_init(thr2_pcbq_async_ev, thr2_pcbq_async_cb);
    ev_async_start(thr2_loop, thr2_pcbq_async_ev);

    do {
        int ecode = pthread_create(&thr2, NULL, thr2_routine, NULL); 
        if (ecode) {
            elog("pthread_create(): %s.\n", strerror(ecode));
            goto L_err2;
        }
    } while (0);

    ev_run(thr1_loop, 0);

    ev_async_send(thr2_loop, thr2_exit_async_ev);
    do { int ecode = pthread_join(thr2, NULL); 
        if (ecode) dlog("pthread_join(): %s.\n", strerror(ecode)); } while (0);
    if (ev_is_active(thr2_pcbq_async_ev))
        ev_async_stop(thr2_loop, thr2_pcbq_async_ev);
    if (ev_is_active(thr1_watchdog_ev))
        ev_periodic_stop(thr1_loop, thr1_watchdog_ev);
    if (ev_is_active(thr1_signal_ev))
        ev_signal_stop(thr1_loop, thr1_signal_ev);
    if (ev_is_active(thr1_pcbq_async_ev))
        ev_async_stop(thr1_loop, thr1_pcbq_async_ev);
    for (int i = 0; i < sizeof pcbq/sizeof pcbq[0]; i++)
        for (struct pcb *pcb; (pcb = pcbq_dequeue(pcbq[i])) != NULL; )
            pcb_destroy(pcb);
    ev_loop_destroy(thr2_loop);
    ev_loop_destroy(thr1_loop);
    for (int i = 0; i < sizeof ifcap/sizeof ifcap[0]; i++)
        pcap_close(ifcap[i]);
    if (fp)
        pcap_freecode(fp);
    if (udpfltr != udpfltr_default)
        free(udpfltr);
    return 0;

L_err2:
    if (ev_is_active(thr2_pcbq_async_ev))
        ev_async_stop(thr2_loop, thr2_pcbq_async_ev);

    if (ev_is_active(thr1_watchdog_ev))
        ev_periodic_stop(thr1_loop, thr1_watchdog_ev);
    if (ev_is_active(thr1_signal_ev))
        ev_signal_stop(thr1_loop, thr1_signal_ev);
    if (ev_is_active(thr1_pcbq_async_ev))
        ev_async_stop(thr1_loop, thr1_pcbq_async_ev);
    for (int i = 0; i < sizeof pcbq/sizeof pcbq[0]; i++)
        for (struct pcb *pcb; (pcb = pcbq_dequeue(pcbq[i])) != NULL; )
            pcb_destroy(pcb);
L_err:
    if (thr2_loop)
        ev_loop_destroy(thr2_loop);
    if (thr1_loop)
        ev_loop_destroy(thr1_loop);
    for (int i = 0; i < sizeof ifcap/sizeof ifcap[0]; i++) {
        if (ifcap[i])
            pcap_close(ifcap[i]);
    }
    if (fp)
        pcap_freecode(fp);
    if (udpfltr != udpfltr_default)
        free(udpfltr);
    return 1;
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
static void thr2_exit_async_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    ev_async_stop(thr2_loop, thr2_exit_async_ev);
    dlog("loop break\n");
    ev_break(thr2_loop, EVBREAK_ALL);
}

static struct pcb *pcb_create(struct timeval *ts, int len, const u_char pkt[len]) {
    struct pcb *pcb;

    int n = offsetof(struct pcb, pkt) + len;
    if (pcb = malloc(n), !pcb) {
        elog("malloc(%d): %s.\n", n, strerror(errno));
        return NULL;
    }
    pcb->len = len;
    memcpy(pcb->pkt, pkt, len);
    dlog("%p\n", pcb);
    return pcb;
}
static void pcb_destroy(struct pcb *pcb) {
    dlog("%p\n", pcb);
    free(pcb);
}

static inline void pcbq_init(struct pcbq *pcbq) {
    STAILQ_INIT(pcbq);
}
static void pcbq_fini(struct pcbq *pcbq) {
    struct pcb *pcb;
    while (1) {
        pcb = STAILQ_FIRST(pcbq);
        if (!pcb)
            break;
        STAILQ_REMOVE_HEAD(pcbq, ent);
        pcb_destroy(pcb);
    }
}
static inline void pcbq_enqueue(struct pcbq *pcbq, struct pcb *pcb) {
    STAILQ_INSERT_TAIL(pcbq, pcb, ent);
}
static inline struct pcb *pcbq_dequeue(struct pcbq *pcbq) {
    struct pcb *pcb = STAILQ_FIRST(pcbq);
    if (pcb)
        STAILQ_REMOVE_HEAD(pcbq, ent);
    return pcb;
}
static inline void pcbq_undequeue(struct pcbq *pcbq, struct pcb *pcb) {
    STAILQ_INSERT_HEAD(pcbq, pcb, ent);
}
static inline void pcbq_swap(struct pcbq *q1, struct pcbq *q2) {
    STAILQ_SWAP(q1, q2, pcb);
}
static inline void pcbq_concat(struct pcbq *q1, struct pcbq *q2) {
    STAILQ_CONCAT(q1, q2);
}
static inline struct pcb *pcbq_first(struct pcbq *q) {
    return STAILQ_FIRST(q);
}
static inline int pcbq_isempty(struct pcbq *q) {
    return STAILQ_EMPTY(q);
}

static void thr1_precv_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct pcbq q[1] = {STAILQ_HEAD_INITIALIZER(q[0])};

    for (;;) {
        struct pcap_pkthdr *ph;
        const u_char *pd;
        int rc;

        switch (rc = pcap_next_ex(ifcap[0], &ph, &pd), rc) {
            case PCAP_ERROR_BREAK:
                ev_io_stop(loop, w);
                dlog("loop break (pcap_next_ex(): PCAP_ERROR_BREAK).\n");
                ev_break(loop, EVBREAK_ALL);
                break;
            case PCAP_ERROR:
                ev_io_stop(loop, w);
                dlog("loop break (pcap_next_ex(): PCAP_ERROR: %s).\n", pcap_geterr(ifcap[0]));
                ev_break(loop, EVBREAK_ALL);
                break;
            case 0: /* EAGAIN */
                goto L_endloop;
            case 1: do {
                    struct pcb *pcb = pcb_create(&ph->ts, ph->caplen, pd);
                    if (!pcb) {
                        elog("packet dropped.\n");
                        break;
                    }
                    pcbq_enqueue(q, pcb);
                } while (0);
                break;
            default:
                elog("pcap_next_ex(): Unexpected return value %d.\n", rc);
                abort();
        }
    }
L_endloop:
    if (!pcbq_isempty(q)) {
        pthread_mutex_lock(pcbq_mtx[0]);
        pcbq_concat(pcbq[0], q);
        pthread_mutex_unlock(pcbq_mtx[0]);
        ev_async_send(thr2_loop, thr2_pcbq_async_ev);
    }
}
static void thr2_pcbq_async_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    struct pcbq q[2][1] = {
        {STAILQ_HEAD_INITIALIZER(q[0][0])},
        {STAILQ_HEAD_INITIALIZER(q[1][0])}
    };
    pthread_mutex_lock(pcbq_mtx[0]);
    pcbq_swap(pcbq[0], q[0]);
    pthread_mutex_unlock(pcbq_mtx[0]);
    for (struct pcb *pcb; (pcb = pcbq_dequeue(q[0])) != NULL; ) {
        if (pcb_mangle(pcb)) {
            pcb_destroy(pcb);
            continue;
        }
        pcbq_enqueue(q[1], pcb);
    }
    pthread_mutex_lock(pcbq_mtx[1]);
    pcbq_concat(pcbq[1], q[1]);
    pthread_mutex_unlock(pcbq_mtx[1]);
    ev_async_send(thr1_loop, thr1_pcbq_async_ev);
}
static void thr1_pcbq_async_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    if (!ev_is_active(thr1_psend_ev))
        ev_io_start(thr1_loop, thr1_psend_ev);
}
static void thr1_psend_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    static struct pcbq q[1] = {STAILQ_HEAD_INITIALIZER(q[0])};

    if (pcbq_isempty(q)) {
        pthread_mutex_lock(pcbq_mtx[1]);
        pcbq_concat(q, pcbq[1]);
        pthread_mutex_unlock(pcbq_mtx[1]);
    }
    for (struct pcb *pcb;;) {
        pcb = pcbq_dequeue(q);
        if (!pcb) {
            ev_io_stop(loop, w);
            break;
        }
        if (pcap_inject(ifcap[1], pcb->pkt, pcb->len) == PCAP_ERROR)
            elog("pcap_inject(): %s.\n", pcap_geterr(ifcap[1]));
        pcb_destroy(pcb);
        break;
    }
}

static inline void memswap(void *a, void *b, int n) {
    for (uint8_t *A = a, *B = b; n; n--, A++, B++) {
        int x = *A; *A = *B; *B = x;
    }
}

/* rfc1071 */
static uint16_t calc_csum(int count, uint8_t *addr) {
    /* Compute Internet Checksum for "count" bytes
    *         beginning at location "addr".
    */
    uint32_t sum = 0;

    while (count > 1) {
        sum += *(uint16_t *)addr;
        addr += 2;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0)
        sum += *addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int pcb_mangle(struct pcb *pcb) {
    dlog("pcb->len: %d\n", pcb->len);
    if (pcb->len < 14 + 20 + 8) {
        dlog("runt: %d bytes.\n", pcb->len);
        goto L_err;
    }
    uint8_t *p          = pcb->pkt;
    uint8_t *ehb        = p;
    uint8_t *ehb_daddr  = ehb;
    uint8_t *ehb_saddr  = ehb + 6;
    uint8_t *ehb_etype  = ehb + 12;
    uint16_t etype;
    uint8_t *ehb_vtags  = NULL;
    uint8_t *ipb;
    uint8_t *ipb_ttl;
    uint16_t *ipb_hcsum;
    uint32_t *ipb_saddr, *ipb_daddr;
    uint8_t *uhb;
    uint16_t *uhb_sport, *uhb_dport, *uhb_len, *uhb_csum;

    dlog("===> ehb_daddr[6]: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx -> ehb_saddr[6]: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
        ehb_daddr[0], ehb_daddr[1], ehb_daddr[2], ehb_daddr[3], ehb_daddr[4], ehb_daddr[5], 
        ehb_saddr[0], ehb_saddr[1], ehb_saddr[2], ehb_saddr[3], ehb_saddr[4], ehb_saddr[5]);

    p = ehb_etype;
    etype = ntohs(*(uint16_t *)ehb_etype);
    switch (etype) {
        case 0x0800:
            p += 2;
            break;
        case 0x8100:
            ehb_vtags = ehb_etype;
            do {
                p += 4;
                if (p > pcb->pkt + pcb->len - 2) {
                    dlog("runt: %d bytes.\n", pcb->len);
                    goto L_err;
                }
                etype = ntohs(*(uint16_t *)p);
            } while (etype == 0x8100);
            if (etype == 0x0800) {
                ehb_etype = p;
                p += 2;
                for (uint8_t *q = ehb_vtags; q < ehb_etype; q += 4) {
                    uint16_t u16[2] = {
                        ntohs(*(uint16_t *)q), 
                        ntohs(*(uint16_t *)(q + 2)) 
                    };
                    dlog("----> etype: 0x%04" PRIx16 ", vlan: %u, cbit: %u, cos: %u\n", 
                        u16[0], u16[1] & 0x0fff, u16[1] & 0x01000, u16[1] >> 13);
                }
                break;
            }
            /* fall through */
        default:
            dlog("ethertype is %04" PRIx16 ". ethernet_ii or ethernet_802.1p frame expected.\n", etype);
            goto L_err;
    }
    dlog("----> etype: 0x%04" PRIx16 "\n", ntohs(*(uint16_t *)ehb_etype));

    ipb = ((uint8_t *)ehb_etype) + 2;
    assert(p == ipb);

    dlog("ipb - ehb: %zd, 0x%02x\n", ipb - ehb, *ipb);

    if (p > pcb->pkt + pcb->len - 20 - 8) {
        dlog("[!] not enough space for ip + udp headers.\n");
        goto L_err;
    }

    if ((*ipb >> 4) != 4) {
        dlog("[!] not ipv4: %d\n", *ipb >> 4);
        goto L_err;
    }

    p += (*ipb & 0x0f) * 4;  /* skip ip header */

    if (p > pcb->pkt + pcb->len - 8) {
        dlog("[!] not enough space for udp header.\n");
        goto L_err;
    }

    {
        int ip_dlen = ntohs(*(uint16_t *)(ipb + 2));
        if (pcb->len < ipb - pcb->pkt + ip_dlen) {
            dlog("ip length wrong? frame = %d, ip_dlen = %" PRIu16 ".\n", pcb->len, ip_dlen);
            goto L_err;
        }
    }

    {
        int ip_proto = ipb[9];
        if (ip_proto != 17) {
            dlog("skip ip proto: %d\n", ip_proto);
            goto L_err;
        }
    }

    ipb_ttl = ipb + 8;
    if (*ipb_ttl <= 1) {
        dlog("[!] ip ttl expired.\n");
        goto L_err;
    }

    ipb_hcsum = (uint16_t *)(ipb + 10);
    ipb_saddr = (uint32_t *)(ipb + 12);
    ipb_daddr = (uint32_t *)(ipb + 16);

    {
        uint8_t *s = (uint8_t *)ipb_saddr, *d = (uint8_t *)ipb_daddr;
        dlog("------> srcip: %hhu.%hhu.%hhu.%hhu, dstip: %hhu.%hhu.%hhu.%hhu, ttl: %hhu\n", 
            s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3], *ipb_ttl);
    }

    uhb = p;
    uhb_sport = (uint16_t *)uhb;
    uhb_dport = (uint16_t *)(uhb + 2);
    uhb_len = (uint16_t *)(uhb + 4);
    uhb_csum = (uint16_t *)(uhb + 6);

    int udp_len = pcb->len - (uhb - pcb->pkt);
    int udp_len_orig = ntohs(*uhb_len);
    if (udp_len_orig != udp_len) {
        dlog("udp len wrong? %" PRIu16 ", must be %d. fix it.\n", udp_len_orig, udp_len);
        *uhb_len = udp_len;
    }

    p += 8;     /* data */

    uint16_t ip_hcsum_orig = *ipb_hcsum;
    *ipb_hcsum = 0;
    uint16_t ip_hcsum = calc_csum(uhb - ipb, ipb);
    if (ip_hcsum != ip_hcsum_orig) {
        elog("ip header csum mismatch.\n");
        goto L_err;
    }

    /* уродуем исходный пакет для отправки назад */

    memswap(ehb_daddr, ehb_saddr, 6);
    *ipb_ttl = 64;
    memswap(ipb_saddr, ipb_daddr, 4);
    memswap(uhb_sport, uhb_dport, 2);
    for (uint8_t *b = p, *e = pcb->pkt + pcb->len - 1; b < e; b++, e--) {
        uint8_t x = *b; *b = *e; *e = x;
    }

    *ipb_hcsum = calc_csum(uhb - ipb, ipb);

    /* UDP checksum computation is optional for IPv4. If a checksum is not used it 
     * should be set to the value zero.
     */
    *uhb_csum = 0;

    dlog("OK\n");
    return 0;

L_err:
    dlog("WRONG\n");
    return -1;
}

// vi: ts=4:sts=4:sw=4:et
