/**
 * (C) 2007-18 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#ifndef _N2N_H_
#define _N2N_H_

 /* Moved here to define _CRT_SECURE_NO_WARNINGS before all the including takes place */
#ifdef WIN32
#ifndef CMAKE_BUILD
//#include "config.h" /* Visual C++ */
#else
#include "win32/winconfig.h"
#endif
#define N2N_CAN_NAME_IFACE 1
#undef N2N_HAVE_DAEMON
#undef N2N_HAVE_TCP           /* as explained on https://github.com/ntop/n2n/pull/627#issuecomment-782093706 */
#undef N2N_HAVE_SETUID
#else
#ifndef CMAKE_BUILD
//#include "config.h"
#endif
#endif



#define PACKAGE_BUILDDATE (__DATE__ " " __TIME__)

#include <time.h>
#include <ctype.h>
#include <stdlib.h>

#ifndef WIN32
#include <netdb.h>
#endif

#ifndef _MSC_VER
#include <getopt.h>
#endif /* #ifndef _MSC_VER */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <pthread.h>

#ifdef __linux__
#define N2N_CAN_NAME_IFACE 1
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif /* #ifdef __linux__ */

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#endif /* #ifdef __FreeBSD__ */

#include <syslog.h>
#include <sys/wait.h>

#ifdef HAVE_LIBZSTD
#include <zstd.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <stdint.h>
#if defined (HAVE_OPENSSL_1_1)
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#endif

#define closesocket(a) close(a)
#endif /* #ifndef WIN32 */




#include "minilzo.h"
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include "lzoconf.h"
#include "uthash.h"


#ifdef WIN32
#include <winsock2.h>           /* for tcp */
#define SHUT_RDWR   SD_BOTH     /* for tcp */
#include "win32/wintap.h"
#include <sys/stat.h>
#else
#include <pwd.h>
#endif /* #ifdef WIN32 */

#include <Cedar/CedarPch.h>
#include "n2n_define.h"
#include "n2n_typedefs.h"

#include "n2n_wire.h"
#include "random_numbers.h"
#include "pearson.h"
#include "portable_endian.h"
#include "cc20.h"

/* ************************************** */

#ifndef TRACE_ERROR
#define TRACE_ERROR       0, __FILE__, __LINE__
#define TRACE_WARNING     1, __FILE__, __LINE__
#define TRACE_NORMAL      2, __FILE__, __LINE__
#define TRACE_INFO        3, __FILE__, __LINE__
#define TRACE_DEBUG       4, __FILE__, __LINE__
#endif



/* extern TWOFISH *tf; */

extern int traceLevel;
extern int useSyslog;
extern n2n_log				logfunc;
extern n2n_progress_notify notifyfunc;
extern n2n_edge_t 			client;
extern const uint8_t broadcast_addr[6];
extern const uint8_t multicast_addr[6];

/* Functions */
extern int  tuntap_open(tuntap_dev *device, char *dev, char *device_ip, char *device_mask, const char * device_mac, int mtu);
extern int  tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len);
extern int  tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len);
extern void tuntap_close(struct tuntap_dev *tuntap);
extern void tuntap_get_address(struct tuntap_dev *tuntap);
extern void tuntap_set_address(struct tuntap_dev *device, char* new_ip);

extern SOCKET open_socket(int local_port, int bind_any, uint8_t type);

/* n2n.c */
extern void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...);
extern char* intoa(uint32_t addr, char* buf, uint16_t buf_len);
extern char* macaddr_str(macstr_t buf, const n2n_mac_t mac);
extern int   str2mac(uint8_t * outmac /* 6 bytes */, const char * s);
extern char *trim (char *s);
extern char * sock_to_cstr(n2n_sock_str_t out, const n2n_sock_t * sock);
extern int sock_equal(const n2n_sock_t * a, const n2n_sock_t * b);
struct peer_info * find_peer_by_mac(struct peer_info * list, const n2n_mac_t mac);
struct peer_info* find_peer_by_id(struct peer_info* list, uint8_t id);
void   peer_list_add(struct peer_info * * list,
	struct peer_info * newp);
size_t peer_list_size(const struct peer_info * list);
void peer_list_remove(struct peer_info** list, uint8_t id);
size_t purge_peer_list(struct peer_info ** peer_list,
	time_t purge_before);
size_t clear_peer_list(struct peer_info ** peer_list);
size_t purge_expired_registrations(struct peer_info ** peer_list);
void random_device_mac(char*);
int is_empty_ip_address(const n2n_sock_t * sock);
extern uint8_t is_multi_broadcast(const uint8_t * dest_mac);
extern char* msg_type2str(uint16_t msg_type);
extern void hexdump(const uint8_t * buf, size_t len);
int ip_search(uint32_t ip4, ip_set *sortedIP4Sets, int count);


extern void open_firewall();
extern void write_run_initscript(int port);


void print_n2n_version();

/* version.c */
extern char *n2n_sw_version, *n2n_sw_osName, *n2n_sw_buildDate;

/* egde_utils.c */
int edge_init(n2n_edge_t * eee, vpn_conf_t *conf);

void supernode2addr(n2n_sock_t * sn, const n2n_sn_name_t addrIn);

uint8_t generateEmptyId(n2n_sn_t * sss);
bool verify_handshake(n2n_sn_t * server, n2n_REGISTER_SUPER_t* reg, uint8_t id);


void readFromTAPSocket(n2n_edge_t * eee);
void readFromServerTAPSocket(n2n_sn_t * eee);
int is_ip6_discovery(const void * buf, size_t bufsize);
int is_ethMulticast(const void * buf, size_t bufsize);

void supernode_disconnect(n2n_edge_t *eee);
void server_send_packet2net(n2n_sn_t * server, uint8_t *tap_pkt, size_t len);
void edge_send_packet2net(n2n_edge_t * eee, 	uint8_t *tap_pkt, size_t len);
ssize_t sendto_sock(n2n_edge_t *eee, const void * buf, size_t len, const n2n_sock_t * dest);
//static ssize_t server_sendto_sock(n2n_sn_t * sss, const n2n_sock_t * sock, const uint8_t * pktbuf, size_t pktsize);
static ssize_t server_sendto_sock(n2n_sn_t * sss, SOCKET socket_fd, const struct sockaddr *socket, const uint8_t * pktbuf, size_t pktsize);

const char * supernode_ip(const n2n_edge_t * eee);

int run_edge_loop(n2n_edge_t * eee, int *keep_running);
int handshake_loop(n2n_edge_t * eee, int *keep_running);
void edge_term(n2n_edge_t * eee);

int n2n_transop_cc20_init(const u_char*encrypt_key, n2n_trans_op_t *ttt);
int transop_encode_cc20 (n2n_trans_op_t *arg, uint8_t *outbuf, size_t out_len, const uint8_t *inbuf, size_t in_len, const uint8_t *peer_mac);

//n2n_connection.c
int supernode_connect(n2n_edge_t *eee);
void ping_to_server(n2n_edge_t * eee, time_t nowTime);
void update_supernode_reg(n2n_edge_t * eee, time_t nowTime);
void handshake(n2n_edge_t* edge, time_t nowTime);

//client.c
void startVpn(vpn_conf_t *conf);
void startVpn_test(const char* token, const char* server_info,  n2n_log ptr, n2n_progress_notify notify, void* v);

//routing.c
void restoreRouting(n2n_edge_t* edge, ROUTE_TRACKING *t);

#endif /* _N2N_H_ */
