/***************************************************************************
 *  Copyright (C) 2007 by Saritha Kalyanam                                 *
 *  kalyanamsaritha@gmail.com                                              *
 *                                                                         *
 *  This program is free software: you can redistribute it and/or modify   *
 *  it under the terms of the GNU Affero General Public License as         *
 *  published by the Free Software Foundation, either version 3 of the     *
 *  License, or (at your option) any later version.                        *
 *                                                                         *
 *  This program is distributed in the hope that it will be useful,        *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *  GNU Affero General Public License for more details.                    *
 *                                                                         *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.  *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <errno.h>
extern int errno;

#include <signal.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "tinydht.h"
#include "dht_types.h"
#include "dht.h"
#include "pkt.h"
#include "debug.h"
#include "types.h"
#include "crypto.h"
#include "stun.h"
#include "queue.h"
#include "float.h"

extern int h_errno;

/*--------------- Global Variables -----------------*/

char rpc_ifname[IFNAMSIZ];
int n_rpc_ifs = 0;
struct dht_net_if rpc_if[MAX_DHT_NET_IF];

int n_svc_fds = 0;
int svc_fds[MAX_SERVICE_FD];

int n_dhts = 0;
struct dht *dht[MAX_DHT_INSTANCE];

TAILQ_HEAD(task_list_head, task) task_list;

int n_poll_fds = 0;
int poll_fd[MAX_POLL_FD];

u64 n_rx_tx = 0;

/*--------------- Private Functions -----------------*/

int tinydht_init(void);
void tinydht_exit(void);
int tinydht_init_sighandlers(void);
static void tinydht_signal_handler(int signum);
int tinydht_usage(const char *cmd);

int tinydht_get_intf_ip_addrs(const char *ifname, 
                            struct dht_net_if *nif, int *n_if, int max_if);
int tinydht_get_intf_ext_ip_addr(struct dht_net_if *nif);

int tinydht_init_service(void);

int tinydht_add_dht(unsigned int type, struct dht_net_if *nif);

int tinydht_poll_loop(void);
int tinydht_task_schedule(void);

bool tinydht_is_service_fd(int fd);
struct dht * tinydht_find_dht_from_fd(int fd);

int tinydht_decode_request(int sock, struct sockaddr_storage *from, 
                            size_t fromlen, u8 *data, int len);
int tinydht_put(struct tinydht_msg *msg);
int tinydht_get(struct tinydht_msg *msg);

/*--------------- Implementation -----------------*/

int
main(int argc, char *argv[])
{
    int ret;
    int c;
    int index;

    if (argc < 2) {
        tinydht_usage(argv[0]);
        return EXIT_FAILURE;
    }

    opterr = 0;

    while ((c = getopt(argc, argv, "i:")) != -1) {
        switch (c) {
            case 'i':
                bzero(rpc_ifname, sizeof(rpc_ifname));
                memcpy(rpc_ifname, optarg, sizeof(rpc_ifname)-1);
                break;
            default:
                tinydht_usage(argv[0]);
                return EXIT_FAILURE;
        }

        for (index = optind; index < argc; index++) {
            printf ("Non-option argument %s\n", argv[index]);
            tinydht_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    ret = tinydht_init();
    if (ret != SUCCESS) {
        ERROR("TinyDHT initialization failed!\n");
        return EXIT_FAILURE;
    }

    /* the main poll loop */
    tinydht_poll_loop();

    /* we should never be here!
     * but if we do, cleanup */
    tinydht_exit();

    return EXIT_SUCCESS;
}

int
tinydht_init(void)
{
    int ret;
    int i;
    int count = 0;
    
    /* initialize the signal handlers */
    ret = tinydht_init_sighandlers();
    if (ret != SUCCESS) {
        return ret;
    }

    /* initialize the prng */
    srandom(dht_get_current_time());

    /* initialize the crypto engine */
    ret = crypto_init();
    if (ret != SUCCESS) {
        return ret;
    }

    /* get local ip addr */
    ret = tinydht_get_intf_ip_addrs(rpc_ifname, rpc_if, 
                                        &n_rpc_ifs, MAX_DHT_NET_IF); 
    if (ret != SUCCESS) {
        return EXIT_FAILURE;
    }

    count = 0;

    for (i = 0; i < n_rpc_ifs; i++) {
        ret = tinydht_get_intf_ext_ip_addr(&rpc_if[i]);
        if (ret != SUCCESS) {
            /* FIXME: should we abort here? */
            continue;
        }
        count++;
    }

    if (count == 0) {
        ERROR("No interfaces can reach public Internet!\n");
        return FAILURE;
    }

    /* initialize the task list */
    TAILQ_INIT(&task_list);
    
    /* instantiate a dht for each rpc intf */
    for (i = 0; i < n_rpc_ifs; i++) {
        ret = tinydht_add_dht(DHT_TYPE_AZUREUS, &rpc_if[i]);
        if (ret != SUCCESS) {
            return EXIT_FAILURE;
        }
    }

    /* initialize the tinydht service */
    ret = tinydht_init_service();
    if (ret != SUCCESS) {
        return EXIT_FAILURE;
    }

    return SUCCESS;
}

void
tinydht_exit(void)
{
    int i;

    INFO("TinyDHT exiting ...\n");

    /* shutdown service fds */
    for (i = 0; i < n_svc_fds; i++) {
        close(svc_fds[i]);
    }

#if 0
    /* FIXME: shutdown the dht instances */
    for (i = 0; i < n_dhts; i++) {
        dht[i]->exit(&dht[i]);
    }
#endif

    return;
}

int
tinydht_init_sighandlers(void)
{
    struct sigaction sigact;

    /* setup signal handlers */
    sigact.sa_handler = tinydht_signal_handler;
    sigemptyset (&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction (SIGINT, &sigact, NULL);
    sigaction (SIGTERM, &sigact, NULL);
    sigaction (SIGHUP, &sigact, NULL);
//    sigaction (SIGSEGV, &sigact, NULL);
    sigaction (SIGABRT, &sigact, NULL);
    sigaction (SIGTRAP, &sigact, NULL);

    return SUCCESS;
}

static void
tinydht_signal_handler(int signum)
{
    INFO("signal %d received\n", signum);
        
    switch (signum) {/* exited?      */

        case SIGSEGV:   /* crash?       */
        case SIGABRT:   /* crash?       */
        case SIGTRAP:   /* crash?       */
            exit(0);    /* we cannot trust our memory */

        case SIGALRM:   /* timer?       */
            tinydht_exit();
            break;

        case SIGHUP:    /* restart      */
            /* FIXME: ?? */
            tinydht_init_sighandlers();
            tinydht_poll_loop();
            break;

        case SIGINT:    /* exited?      */
        case SIGTERM:   /* exited?      */
            tinydht_exit();
            break;

        default:
            ERROR("unhandled signal %d\n", signum);
            break;
    }

    return;
}
int
tinydht_get_intf_ip_addrs(const char *ifname, 
                            struct dht_net_if *nif, int *n_if, int max_if)
{
    struct ifaddrs *ifap = NULL, *ifa = NULL;
    bool found = FALSE;
    int ret;

    if (getifaddrs(&ifap) != 0) {
        return FAILURE;
    }

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {

        if (*n_if >= max_if) {
            break;
        }

        if (strncmp(ifa->ifa_name, ifname, IFNAMSIZ) != 0)
            continue;

        if (!(ifa->ifa_addr != NULL))
            continue;

        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        switch (ifa->ifa_addr->sa_family) {
            case AF_INET:
                found = TRUE;
                ret = dht_net_if_new(&nif[*n_if], ifname, 
                                    (struct sockaddr *)ifa->ifa_addr, 
                                    sizeof(struct sockaddr_in));
                if (ret != SUCCESS) {
                    goto err;
                }
                (*n_if)++;
                break;

            case AF_INET6:
                found = TRUE;
                ret = dht_net_if_new(&nif[*n_if], ifname, 
                                    (struct sockaddr *)ifa->ifa_addr, 
                                    sizeof(struct sockaddr_in6));
                if (ret != SUCCESS) {
                    goto err;
                }
                (*n_if)++;
                break;

            default:
                break;
        }
    }

    freeifaddrs(ifap);
    
    if (!found) {
        ERROR("%s - not a working intf\n", ifname);
        return FAILURE;
    }

    return SUCCESS;

err:
    freeifaddrs(ifap);
    
    return FAILURE;
}

int
tinydht_get_intf_ext_ip_addr(struct dht_net_if *nif)
{
    int sa_family;
    struct stun_nat_info nat_info;
    int ret;

    sa_family = ((struct sockaddr *)&nif->int_addr)->sa_family;

    switch (sa_family) {
        case AF_INET:
            bzero(&nat_info, sizeof(struct stun_nat_info));
            memcpy(&nat_info.internal, &nif->int_addr, 
                            sizeof(struct sockaddr_in));

            /* use STUN to find out the external address */
            ret = stun_get_nat_info(&nat_info);
            if (ret != SUCCESS) {
                return ret;
            }

            /* a DHT is useless behind a firewall */
            if (nat_info.nat_type == STUN_FIREWALLED) {
                INFO("UDP Firewall blocking packets!\n");
                return FAILURE;
            }

            INFO("TinyDHT RPC Public IP %s\n", 
                    inet_ntoa(((struct sockaddr_in *)
                                    &nat_info.external)->sin_addr));

            memcpy(&nif->ext_addr, &nat_info.external, 
                            sizeof(struct sockaddr_storage));

            break;


        case AF_INET6:
            /* FIXME: no STUN support for IPv6? */
            goto err;

        default:
            goto err;
    }
   
    return SUCCESS;

err:
    return FAILURE;
}

int
tinydht_add_dht(unsigned int type, struct dht_net_if *nif)
{
    struct dht *d = NULL;
    unsigned short port;
    int ret = FAILURE;
    int i;
    bool unique_port;

    do {
        unique_port = TRUE;
        ret = dht_get_rnd_port((u16 *)&port);
        if (ret != SUCCESS) {
            return ret;
        }

        for (i = 0; i < n_dhts; i++) {
            /* don't pick the tinydht service port */
            if (port == TINYDHT_SERVICE) {
                unique_port = FALSE;
                break;
            }
       
            /* don't pick some other dht instance's port */
            if (dht[i]->port == port) {
                unique_port = FALSE;
                break;
            }
        }

    } while (!unique_port);

    for (i = 0; (i < MAX_DHT_TYPE) && dht_table[i]; i++) {
        if (dht_table[i]->type == type) {
            d = dht_table[i]->constructor(nif, htons(port));
            if (!d) {
                /* FIXME: should we abort here? */
                ret = SUCCESS;
                break;
            }
            dht[n_dhts] = d;
            n_dhts++;
            ret = SUCCESS;
            break;
        }
    }

    return ret;
}

int
tinydht_init_service(void)
{
    int sock;
    int ret;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    /* setup for ipv4 */
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        /* FIXME: should we abort here? */
        goto err;
    }
    bzero(&addr4, sizeof(struct sockaddr_in));
    ret = inet_pton(AF_INET, "127.0.0.1", &addr4.sin_addr);
    if (ret < 0) {
        ERROR("inet_pton() - %s\n", strerror(errno));
        goto err;
    }
    addr4.sin_port = htons(TINYDHT_SERVICE);
    ret = bind(sock, (struct sockaddr *)&addr4, 
            sizeof(struct sockaddr_in));
    if (ret < 0) {
        ERROR("bind() - %s\n", strerror(errno));
        goto err;
    }

    ret = tinydht_add_poll_fd(sock);
    if (ret != SUCCESS) {
        goto err;
    }

    ret = listen(sock, 10);
    if (ret != SUCCESS) {
        ERROR("listen() - %s\n", strerror(errno));
        goto err;
    }

    svc_fds[n_svc_fds] = sock;
    n_svc_fds++;

    INFO("TinyDHT IPv4 service listening on port %hu fd %d\n", 
            TINYDHT_SERVICE, sock);


    /* setup for ipv6 */
    sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        /* FIXME: should we abort here? */
        goto err;
    }
    bzero(&addr6, sizeof(struct sockaddr_in6));
    ret = inet_pton(AF_INET6, "::1", &addr6.sin6_addr);
    if (ret < 0) {
        ERROR("inet_pton() - %s\n", strerror(errno));
        goto err;
    }
    addr6.sin6_port = htons(TINYDHT_SERVICE);
    ret = bind(sock, (struct sockaddr *)&addr6, 
            sizeof(struct sockaddr_in6));
    if (ret < 0) {
        ERROR("bind() - %s\n", strerror(errno));
        goto err;
    }

    ret = tinydht_add_poll_fd(sock);
    if (ret != SUCCESS) {
        goto err;
    }

    ret = listen(sock, 10);
    if (ret != SUCCESS) {
        ERROR("listen() - %s\n", strerror(errno));
        goto err;
    }

    svc_fds[n_svc_fds] = sock;
    n_svc_fds++;

    INFO("TinyDHT IPv6 service listening on port %hu fd %d\n", 
            TINYDHT_SERVICE, sock);

    return SUCCESS;

err:
    return FAILURE;
}

int
tinydht_add_poll_fd(int fd)
{
    if (n_poll_fds >= MAX_POLL_FD) {
        return FAILURE;
    }

    DEBUG("TinyDHT added fd %d to poll\n", fd);

    poll_fd[n_poll_fds] = fd;
    n_poll_fds++;

    return SUCCESS;
}

struct dht *
tinydht_find_dht_from_fd(int fd)
{
    int i;

    for (i = 0; i < n_dhts; i++) {
        if ((dht[i]->net_if.sock == fd)) {
            return dht[i];
        }
    }

    return NULL;
}

bool
tinydht_is_service_fd(int fd)
{
    int i;

    for (i = 0; i < n_svc_fds; i++) {
        if (svc_fds[i] == fd) {
            return TRUE;
        }
    }

    return FALSE;
}

int
tinydht_poll_loop(void)
{
    struct pollfd fds[MAX_POLL_FD];
    int i;
    int ret;
    bool data_avail;
    bool fd_found;
    struct dht *dht = NULL;
    u8 buf[2048];
    struct sockaddr_storage from;
    size_t fromlen;
    int len = 0;
    int sock;

    INFO("TinyDHT polling %d fds\n", n_poll_fds);

    bzero(fds, sizeof(fds));

    for (i = 0; i < n_poll_fds; i++) {
        fds[i].fd = poll_fd[i];
        fds[i].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    }

    while (TRUE) {

        /* call the task_scheduler */
        tinydht_task_schedule();
        
        data_avail = FALSE;
        errno = 0;

        ret = poll(fds, n_poll_fds, MAX_POLL_TIMEOUT);

        switch (ret) {
            case -1:        /* error */
                if (errno == EINTR) {
                    continue;
                }
                ERROR("poll() - %s\n", strerror(errno));
                return FAILURE;
            case 0:         /* timeout */
                continue;
            default:        /* some data is ready */
                data_avail = TRUE;
                break;
        }

        if (!data_avail) {
            continue;
        }

        fd_found = FALSE;
        for (i = 0; i < n_poll_fds; i++) {
            if (fds[i].revents & POLLIN) {
                fd_found = TRUE;
                break;
            }
        }

        if (data_avail && !fd_found) {
            return FAILURE;
        }

        DEBUG("TinyDHT reading fd %d\n", poll_fd[i]);

        if (tinydht_is_service_fd(poll_fd[i])) {

            bzero(&from, sizeof(from));
            fromlen = sizeof(from);

            sock = accept(poll_fd[i], (struct sockaddr *)&from, &fromlen);
            if (sock < 0) {
                ERROR("accept() - %s\n", strerror(errno));
                continue;
            }

            len = recv(sock, buf, sizeof(buf), 0);
            if (len <= 0) {
                ERROR("recv() - %s\n", strerror(errno));
                continue;
            }

            ret = tinydht_decode_request(sock, &from, fromlen, buf, len);
            if (ret < 0) {
                continue;
            }

        } else {

            /* read the data */
            fromlen = sizeof(struct sockaddr_storage);
            len = recvfrom(poll_fd[i], buf, sizeof(buf), 0, 
                    (struct sockaddr *)&from, &fromlen);
            if (len <= 0) {
                ERROR("recvfrom() - %s\n", strerror(errno));
                continue;
            }

            INFO("received %d bytes from %s:%hu\n", len,
                    inet_ntoa((((struct sockaddr_in *)&from)->sin_addr)), 
                    ntohs(((struct sockaddr_in *)&from)->sin_port));

            /* has it arrived on a dht instance? */
            dht = tinydht_find_dht_from_fd(poll_fd[i]);
            if (!dht) {
                ERROR("No DHT found for fd %d\n", poll_fd[i]);
                return FAILURE;
            }

            ret = dht->rpc_rx(dht, &from, fromlen, 
                                buf, len, dht_get_current_time());
            if (ret != SUCCESS) {
                continue;
            }
        }
    }

    return FAILURE;
}

int
tinydht_task_schedule(void)
{
    static int index = 0;

    /* give every dht instance a time slice */
    dht[index]->task_schedule(dht[index]);
    index = (index + 1) % n_dhts;

    return SUCCESS;
}

int
tinydht_decode_request(int sock, struct sockaddr_storage *from, 
                        size_t fromlen, u8 *data, int len)
{
    struct tinydht_msg_req req;
    struct tinydht_msg *msg = NULL;
    int ret;
    bool action = FAILURE;

    bzero(&req, sizeof(req));
    memcpy(&req, data, len);
    req.key_len = htonl(req.key_len);
    req.val_len = htonl(req.val_len);

    msg = (struct tinydht_msg *) malloc(sizeof(struct tinydht_msg));
    if (!msg) {
        ERROR("%s\n", strerror(errno));
        goto err;
    }

    bzero(msg, sizeof(struct tinydht_msg));
    memcpy(&msg->req, &req, sizeof(req));
    msg->sock = sock;
    memcpy(&msg->from, from, fromlen);
    msg->fromlen = fromlen;

    switch (req.action) {
        case TINYDHT_ACTION_PUT:
            DEBUG("PUT received\n");
            ret = tinydht_put(msg);
            if (ret != SUCCESS) {
                break;
            }

            action = SUCCESS;
            break;

        case TINYDHT_ACTION_GET:
            DEBUG("GET received\n");
            ret = tinydht_get(msg);
            if (ret != SUCCESS) {
                break;
            }

            action = SUCCESS;
            break;

        default:
            ERROR("unknown action %d\n", req.action);
            free(msg);
            goto err;
    }

    if (action != SUCCESS) {
        msg->rsp.status = TINYDHT_RESPONSE_FAILURE;
    } else {
        msg->rsp.status = TINYDHT_RESPONSE_SUCCESS;
    }

    ret = send(sock, &msg->rsp, sizeof(msg->rsp), 0);
    if (ret < 0) {
        ERROR("send() - %s\n", strerror(errno));
    }

    close(sock);
    free(msg);

    return SUCCESS;

err:
    return FAILURE;
}

int
tinydht_put(struct tinydht_msg *msg)
{
    int i;
    bool found = FALSE;
    int ret;

    if ((msg->req.key_len <= 0) || (msg->req.key_len > MAX_KEY_LEN) ||
            (msg->req.val_len <= 0) || (msg->req.val_len > MAX_VAL_LEN)) {
        return FAILURE;
    }

    for (i = 0; i < n_dhts; i++) {
        ret = dht[i]->put(dht[i], msg);
        if (ret != SUCCESS) {
            continue;
        }
        found = TRUE;
    }

    if (found) {
        DEBUG("at least one PUT was successful\n");
        return SUCCESS;
    } 

    return FAILURE;
}

int
tinydht_get(struct tinydht_msg *msg)
{
    int i;
    bool found = FALSE;
    int ret;

    if ((msg->req.key_len <= 0) || (msg->req.key_len > MAX_KEY_LEN)) {
        return FAILURE;
    }

    for (i = 0; i < n_dhts; i++) {
        ret = dht[i]->get(dht[i], msg);
        if (ret != SUCCESS) {
            continue;
        }
        found = TRUE;
    }

    if (found) {
        DEBUG("at least one GET was successful\n");
        return SUCCESS;
    } 

    return FAILURE;
}

int
tinydht_usage(const char *cmd)
{
    printf("usage: %s -i <interface>\n", cmd);
    return SUCCESS;
}

/* Rate-limiting */
void
tinydht_rate_limit_update(size_t size)
{
    n_rx_tx += size;
}

bool
tinydht_rate_limit_allow(void)
{
    static u64 prev_time = 0;
    u64 curr_time = 0;
    u64 elapsed = 0;

    curr_time = dht_get_current_time();

    if (prev_time == 0) {
        prev_time = curr_time;
        return TRUE;
    }

    elapsed = (curr_time - prev_time)/1000;

    // DEBUG("elapsed %lld size %lld\n", elapsed, n_rx_tx);
    // DEBUG("result %lld\n", (elapsed*(RATE_LIMIT_BITS_PER_SEC/1000)));

    if ((elapsed*(RATE_LIMIT_BITS_PER_SEC/1000)) < (n_rx_tx*8)) {
        return FALSE;
    }

    return TRUE;
}
