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

 /* Supernode for n2n-2.x */

#include "n2n.h"

#ifdef WIN32
#include "win32/installation.h"
#include <signal.h>
#endif
#include "jwt.h"
#include "ECDH/curve25519.h"
#define VIRTUALHOSTIP "192.168.137.1"
#define VIRTUALHOSTSUBNET "255.255.255.0"
#define N2N_SN_LPORT_DEFAULT 8888
#define N2N_SN_PKTBUF_SIZE   2048

#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
#define IP4_DSTOFFSET 16

#define N2N_SN_MGMT_PORT                5645

#define TESTMODE

struct n2n_allowed_communities {
	char  community[N2N_COMMUNITY_SIZE];
	UT_hash_handle   hh; /* makes this structure hashable */
};

static struct n2n_allowed_communities *allowed_communities = NULL;

static int try_forward(n2n_sn_t * sss, const n2n_common_t * cmn, struct peer_info *  scan,
	const uint8_t * pktbuf, size_t pktsize);

static int try_broadcast(n2n_sn_t * sss, const n2n_common_t * cmn, const n2n_mac_t srcMac,
	uint8_t * udp_buf, size_t offset, uint8_t * pktbuf, size_t pktsize);

static n2n_sn_t sss_node;

/** Initialise the supernode structure */
static int init_sn(n2n_sn_t * sss) {
#ifdef WIN32
	initWin32();
#endif
	memset(sss, 0, sizeof(n2n_sn_t));

    sss->daemon = 0; /* By defult run as a daemon. */
	sss->lport = N2N_SN_LPORT_DEFAULT;
	sss->sock = -1;
	sss->mgmt_sock = -1;
	sss->edges = NULL;
	sss->null_transop = 0;
    sss->ec.local_port = 0 /* any port */;
    sss->ec.mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
    snprintf(sss->ec.tuntap_dev_name, sizeof(sss_node.ec.tuntap_dev_name), "tun0");
    snprintf(sss->ec.netmask, sizeof(sss_node.ec.netmask), "255.255.255.0");
    sss->ec.ip_addr[0] = '\0';
    sss->ec.device_mac[0] = '\0';
    sss->device.tuntap_mode = TUN_MODE;
#ifndef WIN32
    sss->device.dev_name[0]='\0';
#else
	sss->device.dev_name = NULL;
#endif
    sss->ec.mtu = DEFAULT_MTU;
    sss->ec.got_s = 0;

#ifndef WIN32
    sss->ec.userid = 0; /* root is the only guaranteed ID */
    sss->ec.groupid = 0; /* root is the only guaranteed ID */
#endif

    Rand(sss->priv_key, N2N_AUTH_KEY_SIZE);     // generate random private key
    static const uint8_t basepoint[32] = { 9 }; // generate public key based on the random private key
	curve25519_donna(sss->pub_key, sss->priv_key, basepoint);

	return 0; /* OK */
}

/** Deinitialise the supernode structure and deallocate any memory owned by
 *  it. */
static void deinit_sn(n2n_sn_t * sss)
{
    n2n_tcp_connection_t *conn, *tmp_conn;
    struct peer_info *edge, *edge_tmp;
	if (sss->sock >= 0)
	{
		closesocket(sss->sock);
	}
	sss->sock = -1;

	if (sss->mgmt_sock >= 0)
	{
		closesocket(sss->mgmt_sock);
	}
	sss->mgmt_sock = -1;

    HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
        shutdown(conn->socket_fd, SHUT_RDWR);
        closesocket(conn->socket_fd);
        HASH_DEL(sss->tcp_connections, conn);
        free(conn);
    }
    if(sss->tcp_sock >= 0) {
        shutdown(sss->tcp_sock, SHUT_RDWR);
        closesocket(sss->tcp_sock);
    }
    sss->tcp_sock = -1;

    HASH_ITER(hh, sss->edges, edge, edge_tmp) {
        HASH_DEL(sss->edges, edge);
        if(edge->conn){// in case of tcp
            shutdown(edge->conn->socket_fd, SHUT_RDWR);
            closesocket(edge->conn->socket_fd);
        }
        free(edge);
    }
    FreeMayaqua();
}


/** Determine the appropriate lifetime for new registrations.
 *
 *  If the supernode has been put into a pre-shutdown phase then this lifetime
 *  should not allow registrations to continue beyond the shutdown point.
 */
static uint16_t reg_lifetime() {
	/* NOTE: UDP firewalls usually have a 30 seconds timeout */
	return 15;
}

uint8_t generateEmptyId(n2n_sn_t * sss)
{
	for (uint8_t i = 1; i < N2N_MAX_CLIENTS; i++)
	{
		if (sss->ids[i] == N2N_EMPTY)
			return i;
	}
	return 0;
}

static void close_edge_connection(n2n_sn_t *sss, struct peer_info* edge)
{
    HASH_DEL(sss->edges, edge);
    //HASH_DEL(sss->tcp_edges, edge);
    if(edge){
        if(edge->conn){// in case of tcp
            shutdown(edge->conn->socket_fd, SHUT_RDWR);
            closesocket(edge->conn->socket_fd);
            edge->conn->inactive = 1;
        }
        sss->ids[edge->id] = N2N_EMPTY;
        sss->ips[HOST_INDEX(edge->ip)] = N2N_EMPTY;
        free(edge); // in case of udp
        edge = NULL;
    }
}
static void close_tcp_connection(n2n_sn_t *sss, n2n_tcp_connection_t *conn) {

    struct peer_info *edge, *tmp_edge;

    if(!conn)
        return;

    HASH_ITER(hh, sss->edges, edge, tmp_edge) {
        if(edge->conn->socket_fd == conn->socket_fd) {
            // remove peer
            HASH_DEL(sss->edges, edge);
            if(edge != NULL){
                sss->ids[edge->id] = N2N_EMPTY;
                sss->ips[HOST_INDEX(edge->ip)] = N2N_EMPTY;
                free(edge);
                edge = NULL;
            }
            goto close_conn; /* break - level 2 */
        }
    }


 close_conn:
    // close the connection
    shutdown(conn->socket_fd, SHUT_RDWR);
    closesocket(conn->socket_fd);
    // forget about the connection, will be deleted later
    conn->inactive = 1;
}
uint32_t get_empty_dhcp_ip(n2n_sn_t * server, uint32_t hostip)
{
    uint32_t netmask = ( hostip << 8 )>> 8;
    uint8_t ip = hostip >> 24;
    if(ip <= 1 || ip >= N2N_MAX_CLIENTS || server->ips[ip] == N2N_ALLOCATED){
        for (uint32_t i = 2; i < N2N_MAX_CLIENTS; i++)
        {
            if (server->ips[i] == N2N_EMPTY){
                server->ips[i] = N2N_ALLOCATED;
                return netmask | (i<<24);
            }
        }
    }else{
        server->ips[ip] = N2N_ALLOCATED;
        return netmask | (ip<<24);
    }
    return 0;
}
/** Update the edge table with the details of the edge which contacted the
 *  supernode. */
static uint8_t register_edge_temp(n2n_sn_t * sss, n2n_tcp_connection_t *conn, const n2n_REGISTER_SUPER_t *reg,
	const n2n_community_t community, const n2n_sock_t * sender_sock, time_t now) {
	macstr_t            mac_buf;
	n2n_sock_str_t      sockbuf;
	struct peer_info *  scan;

	traceEvent(TRACE_DEBUG, "update_edge for %s [%s]",
		macaddr_str(mac_buf, reg->edgeMac),
		sock_to_cstr(sockbuf, sender_sock));

	if (sss->device.tuntap_mode == TAP_MODE) {
		HASH_FIND_PEER(sss->edges, reg->edgeMac, scan);
	}
	else {
        HASH_FIND_SOCK(sss->edges, sender_sock, scan);
	}
 
	if (NULL == scan) {
		/* Not known */

		scan = (struct peer_info*)calloc(1, sizeof(struct peer_info)); /* deallocated in purge_expired_registrations */

		memcpy(scan->community_name, community, sizeof(n2n_community_t));
		if (sss->device.tuntap_mode == TAP_MODE) {
			memcpy(&(scan->mac_addr), reg->edgeMac, sizeof(n2n_mac_t));
		}
		memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
        scan->ip = 0;
        scan->conn = conn;
        scan->id = generateEmptyId(sss);
        memcpy(scan->pub_key, reg->auth.token, reg->auth.toksize);
        sss->ids[scan->id] = N2N_ALLOCATED;
		if (sss->device.tuntap_mode == TAP_MODE) {
			HASH_ADD_PEER(sss->edges, scan);
		}
		else {
            HASH_ADD_SOCK(sss->edges, scan);
		}
		
		/* insert this guy at the head of the edges list */
        //scan->next = sss->edges;     /* first in list */
        //sss->edges = scan;           /* head of list points to new scan */
    }
	else {
		/* Known */
		if ((0 != memcmp(community, scan->community_name, sizeof(n2n_community_t))) ||
			(0 != sock_equal(sender_sock, &(scan->sock))))
		{
			memcpy(scan->community_name, community, sizeof(n2n_community_t));
			memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
			memcpy(scan->pub_key, reg->auth.token, reg->auth.toksize);
            scan->conn = conn;
			traceEvent(TRACE_INFO, "update_edge updated   %s ==> %s",
				macaddr_str(mac_buf, reg->edgeMac),
				sock_to_cstr(sockbuf, sender_sock));
		}
		else
		{
			traceEvent(TRACE_DEBUG, "update_edge unchanged %s ==> %s",
				macaddr_str(mac_buf, reg->edgeMac),
				sock_to_cstr(sockbuf, sender_sock));
		}

	}
	scan->verified = false;
	memset(scan->shared_key, 0, N2N_AUTH_KEY_SIZE + 1);
	curve25519_donna(scan->shared_key, sss->priv_key, scan->pub_key);
	n2n_transop_cc20_init(scan->shared_key, &scan->transop);

	scan->last_seen = now;
	return scan->id;
}

void register_edge(n2n_sn_t * sss, const n2n_REGISTER_SUPER_t *reg, const n2n_community_t community, n2n_sock_t * sender_sock,  bool verified)
{
    struct peer_info * scan;
	if (sss->device.tuntap_mode == TAP_MODE) {
		HASH_FIND_PEER(sss->edges, reg->edgeMac, scan);
	}
	else {
        HASH_FIND_SOCK(sss->edges, sender_sock, scan);
	}

	if (verified) {
		scan->verified = true;
        scan->ip = get_empty_dhcp_ip(sss, reg->edgeTapIp);
        memcpy(sender_sock->addr.v4, &(scan->ip) , IPV4_SIZE);
        //HASH_ADD_INT(sss->tcp_edges, ip, scan);
    }

    if(!verified || scan->ip == 0 ) {// no available ip
		scan->transop.deinit(&scan->transop);
		sss->ids[scan->id] = N2N_EMPTY;
        close_edge_connection(sss, scan);
        //peer_list_remove(&(sss->edges), scan->id);
	}
}

static ssize_t server_sendto_fd (n2n_sn_t *sss,
                          SOCKET socket_fd,
                          const struct sockaddr *socket,
                          const uint8_t *pktbuf,
                          size_t pktsize) {

    ssize_t sent = 0;
    n2n_tcp_connection_t *conn;

    sent = sendto(socket_fd, pktbuf, pktsize, 0 /* flags */,
                  socket, sizeof(struct sockaddr_in));

    if((sent <= 0) && (errno)) {
        char * c = strerror(errno);
        traceEvent(TRACE_ERROR, "sendto_fd failed (%d) %s", errno, c);
#ifdef WIN32
        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
        // if the erroneous connection is tcp, i.e. not the regular sock...
        if((socket_fd >= 0) && (socket_fd != sss->sock)) {
            // ...forget about the corresponding peer and the connection
            HASH_FIND_INT(sss->tcp_connections, &socket_fd, conn);
            close_tcp_connection(sss, conn);
            return -1;
        }
    } else {
            traceEvent(TRACE_DEBUG, "sendto_fd sent=%d to ", (signed int)sent);
    }

    return sent;
}

/** Send a datagram to the destination embodied in a n2n_sock_t.
 *
 *  @return -1 on error otherwise number of bytes sent
 */
static ssize_t server_sendto_sock(n2n_sn_t * sss, SOCKET socket_fd, const struct sockaddr *socket, const uint8_t * pktbuf, size_t pktsize)
{
//	n2n_sock_str_t      sockbuf;
    ssize_t sent = 0;
    int value = 0;
    // if the connection is tcp, i.e. not the regular sock...
    if((socket_fd >= 0) && (socket_fd != sss->sock)) {
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
        value = 1;
#ifdef LINUX
        setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif
        // prepend packet length...
        uint16_t pktsize16 = htobe16(pktsize);
        sent = server_sendto_fd(sss, socket_fd, socket, (uint8_t*)&pktsize16, sizeof(pktsize16));

        if(sent <= 0)
            return -1;
        // ...before sending the actual data
    }
    sent = server_sendto_fd(sss, socket_fd, socket, pktbuf, pktsize);

    // if the connection is tcp, i.e. not the regular sock...
   if((socket_fd >= 0) && (socket_fd != sss->sock)) {
       value = 1; /* value should still be set to 1 */
       setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
#ifdef __linux__
       value = 0;
       setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif
   }
   return sent;
/*
	if (AF_INET == sock->family)
	{
		struct sockaddr_in udpsock;

		udpsock.sin_family = AF_INET;
		udpsock.sin_port = htons(sock->port);
		memcpy(&(udpsock.sin_addr.s_addr), &(sock->addr.v4), IPV4_SIZE);

		traceEvent(TRACE_DEBUG, "sendto_sock %lu to [%s]",
			pktsize,
			sock_to_cstr(sockbuf, sock));

		return sendto(sss->sock, pktbuf, pktsize, 0,
			(const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in));
	}
	else
	{

		errno = EAFNOSUPPORT;
		return -1;
	}
*/
}



/** Try to forward a message to a unicast MAC. If the MAC is unknown then
 *  broadcast to all edges in the destination community.
 */
static int try_forward(n2n_sn_t * sss, const n2n_common_t * cmn, struct peer_info *  scan,
	const uint8_t * pktbuf, size_t pktsize)
{
	macstr_t            mac_buf;
	n2n_sock_str_t      sockbuf;

	//scan = find_peer_by_mac(sss->edges, dstMac);

    if (NULL != scan && AF_INET == scan->sock.family)
	{
        struct sockaddr_in socket;
        fill_sockaddr((struct sockaddr *)&socket, sizeof(socket), &(scan->sock));

        size_t data_sent_len;
        data_sent_len = server_sendto_sock(sss, (scan->conn != 0) ? scan->conn->socket_fd : sss->sock, (const struct sockaddr*)&socket, pktbuf, pktsize);
		if (data_sent_len == pktsize)
		{
			++(sss->stats.fwd);
			traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
				pktsize,
				sock_to_cstr(sockbuf, &(scan->sock)),
				macaddr_str(mac_buf, scan->mac_addr));
		}
		else
		{
			++(sss->stats.errors);
			traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
				pktsize,
				sock_to_cstr(sockbuf, &(scan->sock)),
				macaddr_str(mac_buf, scan->mac_addr),
				errno, strerror(errno));
		}
	}
	else
	{
		traceEvent(TRACE_DEBUG, "try_forward unknown MAC");
		/* Not a known MAC so drop. */
	}

	return 0;
}

/** Try and broadcast a message to all edges in the community.
 *
 *  This will send the exact same datagram to zero or more edges registered to
 *  the supernode.
 */
static int try_broadcast(n2n_sn_t * sss, const n2n_common_t * cmn, const n2n_mac_t srcMac,
	uint8_t * udp_buf, size_t offset, uint8_t * pktbuf, size_t pktsize)
{

	macstr_t            mac_buf;
	n2n_sock_str_t      sockbuf;
	traceEvent(TRACE_DEBUG, "try_broadcast");
	size_t  tmp_offset = offset;
    //scan = sss->edges;
    struct peer_info *scan, *tmp_edge;

    HASH_ITER(hh, sss->edges, scan, tmp_edge) {
        //if (0 == (memcmp(scan->community_name, cmn->community, sizeof(n2n_community_t)))
           // && (0 != memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t))))
        uint8_t is_me = ((sss->device.tuntap_mode == TUN_MODE) ? false : memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)));
        if(is_me != 0)
        {
            size_t data_sent_len;
            offset = tmp_offset;
            offset += scan->transop.fwd(&(scan->transop), udp_buf + offset, N2N_PKT_BUF_SIZE - offset,
                pktbuf, pktsize, 0);

            struct sockaddr_in socket;
            fill_sockaddr((struct sockaddr *)&socket, sizeof(socket), &(scan->sock));

            data_sent_len = server_sendto_sock(sss, (scan->conn !=0 ) ? scan->conn->socket_fd : sss->sock, (const struct sockaddr*)&socket, udp_buf, offset);

            if (data_sent_len != offset)
            {
                ++(sss->stats.errors);
                traceEvent(TRACE_WARNING, "multicast %lu to [%s] %s failed %s",
                    offset,
                    sock_to_cstr(sockbuf, &(scan->sock)),
                    macaddr_str(mac_buf, scan->mac_addr),
                    strerror(errno));
            }
            else
            {
                ++(sss->stats.broadcast);
                traceEvent(TRACE_DEBUG, "multicast %lu to [%s] %s",
                    offset,
                    sock_to_cstr(sockbuf, &(scan->sock)),
                    macaddr_str(mac_buf, scan->mac_addr));
            }
        }

    }
	
	return 0;
}

/** Check if the specified community is allowed by the
 *  supernode configuration
 *  @return 0 = community not allowed, 1 = community allowed
 *
 */
static int allowed_n2n_community(n2n_common_t *cmn) {
	if (allowed_communities != NULL) {
		struct n2n_allowed_communities *c;

		HASH_FIND_STR(allowed_communities, (const char*)cmn->community, c);
		return((c == NULL) ? 0 : 1);
	}
	else {
		/* If no allowed community is defined, all communities are allowed */
	}

	return(1);
}

/** Load the list of allowed communities. Existing/previous ones will be removed
 *
 */
static int load_allowed_n2n_communities(char *path) {
	char buffer[4096], *line;
	FILE *fd = fopen(path, "r");
	struct n2n_allowed_communities *s, *tmp;
	u_int32_t num_communities = 0;

	if (fd == NULL) {
		traceEvent(TRACE_WARNING, "File %s not found", path);
		return -1;
	}

	HASH_ITER(hh, allowed_communities, s, tmp)
		free(s);

	while ((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
		int len = strlen(line);

		if ((len < 2) || line[0] == '#')
			continue;

		len--;
		while (len > 0) {
			if ((line[len] == '\n') || (line[len] == '\r')) {
				line[len] = '\0';
				len--;
			}
			else
				break;
		}

		s = (struct n2n_allowed_communities*)malloc(sizeof(struct n2n_allowed_communities));

		if (s != NULL) {
			strncpy((char*)s->community, line, N2N_COMMUNITY_SIZE);
			HASH_ADD_STR(allowed_communities, community, s);
			num_communities++;
			traceEvent(TRACE_INFO, "Added allowed community '%s' [total: %u]",
				(char*)s->community, num_communities);
		}
	}

	fclose(fd);

	traceEvent(TRACE_NORMAL, "Loaded %u communities from %s",
		num_communities, path);

	return(0);
}
#ifdef WIN32
#define AUTH_PUBLIC_KEY_FILE "c:\\au_public-key.pem"
#else
#define AUTH_PUBLIC_KEY_FILE "/etc/au_public-key.pem"
#endif

struct peer_info* find_edge_by_id(struct peer_info *edges, uint8_t id)
{
    struct peer_info *edge, *tmp_edge;
    HASH_ITER(hh, edges, edge, tmp_edge) {
        if(edge->id == id) {
            return edge;
        }
    }
    return NULL;
}
bool verify_handshake(n2n_sn_t * server, n2n_REGISTER_SUPER_t* reg, uint8_t id) {
	n2n_auth_t auth;
	memset(&auth, 0, sizeof(n2n_auth_t));
    struct peer_info* edge = find_edge_by_id(server->edges, id);
	int ret = 1;
	if (edge != NULL) {
        edge->transop.rev(&edge->transop, auth.token, N2N_AUTH_TOKEN_SIZE,
						reg->auth.token, reg->auth.toksize, 0);
		//printf("start verifiying...\n");
		//printf("token -- %s ...\n", auth.token);
        ret = verify_jwt(AUTH_PUBLIC_KEY_FILE, (char*)(auth.token));
	}
	
	return ret == 0;
}

static void process_udp (n2n_sn_t * server,
                        const struct sockaddr_in *sender_sock,//destination
                        const SOCKET socket_fd, // socket to use for transfer
                        uint8_t * udp_buf,
                        size_t udp_size,
                        time_t now, n2n_tcp_connection_t *conn) {
	n2n_common_t        cmn; /* common fields in the packet header */

     /* Compete UDP packet */
    ssize_t             recvlen = udp_size;
	size_t              rem;
	size_t              idx;
	size_t				sdx;
	size_t              msg_type;
    n2n_sock_str_t      sockbuf;
    char                buf[32];
//    struct sn_community *comm, *tmp;
    uint64_t            stamp;
    int                 skip_add;
	ether_hdr_t *		eh;
	size_t              i;

	// handling dhcp
	/*
	uint8_t *eth_pkt;
	ssize_t             len;
	len = VirtualGetNextPacket(server->n->Virtual, &eth_pkt);
	if ((len > 0) && (len < N2N_PKT_BUF_SIZE))
	{
		idx = 0;
		server->cmn.pc = MSG_TYPE_PACKET;
		encode_common(udp_buf, &idx, &server->cmn);
		memcpy(udp_buf + sizeof(n2n_common_t) + sizeof(n2n_PACKET_t), eth_pkt, len);
		len += sizeof(n2n_common_t) + sizeof(n2n_PACKET_t);
		n2n_PACKET_t pkt;
		memcpy(pkt.dstMac, eth_pkt, N2N_MAC_SIZE); 
		memcpy(pkt.srcMac, server->device.mac_addr, N2N_MAC_SIZE);
		int unicast = (0 == is_multi_broadcast(pkt.dstMac));
		if (unicast)
			try_forward(server, &cmn, pkt.dstMac, udp_buf, len);
		else {
			try_broadcast(server, &cmn, pkt.srcMac, udp_buf, len);
		}
	}
*/
    if(udp_size < 24) {
        traceEvent(TRACE_DEBUG, "process_udp dropped a packet too short to be valid.");
        return;
    }
	rem = recvlen; /* Counts down bytes of packet to protect against buffer overruns. */
	idx = 0; /* marches through packet header as parts are decoded. */
	if (decode_common(&cmn, udp_buf, &rem, &idx) < 0) {
		traceEvent(TRACE_ERROR, "Failed to decode common section");
		return; /* failed to decode packet */
	}

	msg_type = cmn.pc; /* packet code */

	if (msg_type == MSG_TYPE_PACKET) {
        struct peer_info *edge = find_edge_by_id(server->edges, cmn.id);
        if (edge == NULL || edge->verified != true)
			return;
		/* pkt will be modified in place and recoded to an output of potentially
		* different size due to addition of the socket.*/
		n2n_PACKET_t                    pkt;
		int                             unicast; /* non-zero if unicast */

		//memcpy(&pkt, udp_buf + idx, sizeof(pkt));
		decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);
		sdx = idx;

		uint8_t* payload = udp_buf + idx;
		//ether_hdr_t * eh = (ether_hdr_t*)(eth_payload);
		size_t psize = recvlen - idx;
		
		uint8_t decodebuf[N2N_PKT_BUF_SIZE];
        uint8_t* eth_payload = decodebuf;

		size_t eth_size;

		eth_size = edge->transop.rev(&edge->transop, eth_payload, N2N_PKT_BUF_SIZE,
            payload, psize, pkt.srcMac);
		if (eth_size > N2N_PKT_BUF_SIZE)// decryption error
            return;
        //uint8_t* eth_payload = payload;
        //eth_size = psize;
		++(edge->transop.rx_cnt); /* stats */
		uint32_t *dst;
		if (server->device.tuntap_mode == TAP_MODE) {
			eh = (ether_hdr_t*)eth_payload;
			if (memcmp(pkt.dstMac, server->device.mac_addr, 6) == 0) {  //routing to NAT
				tuntap_write(&(server->device), eth_payload, eth_size);
				return;
			}
			if (ntohs(eh->type) == 0x0800) {        // transfered to ME(Server)
				dst = (uint32_t*)&eth_payload[ETH_FRAMESIZE + IP4_DSTOFFSET];
				/* Note: all elements of the_ip are in network order */
				if (*dst == server->device.ip_addr) {
					tuntap_write(&(server->device), eth_payload, eth_size);
					return;
				}
			}
			unicast = (0 == is_multi_broadcast(pkt.dstMac));
		}
        else {
            int ipver = (eth_payload[0] >> 4) & 0xf;
            if(ipver == 6 || eth_size < 16)
                return;//ipv6

            dst = (uint32_t*)&eth_payload[IP4_DSTOFFSET];
            if (*dst == server->device.ip_addr) {
				tuntap_write(&(server->device), eth_payload, eth_size);
				return;
			}
			unicast = true;// think it later
		}

		/* Common section to forward the final product. */
        edge = NULL;
		if (server->device.tuntap_mode == TAP_MODE) {
			HASH_FIND_PEER(server->edges, pkt.dstMac, edge);
		}
		else {
            struct peer_info* edge0, *tmp_edge;
//            HASH_FIND_INT(server->tcp_edges, dst, edge0);
//            if(edge0 != NULL){
//                edge = edge0;
//            }
            unicast = true;
            HASH_ITER(hh, server->edges, edge0, tmp_edge){
                if(edge0->ip == *dst){
                    edge = edge0;
                    break;
                }
            }
		}
		if (unicast && edge) {
			sdx += edge->transop.fwd(&(edge->transop), udp_buf + sdx, N2N_PKT_BUF_SIZE - sdx,
				eth_payload, eth_size, 0);
			try_forward(server, &cmn, edge, udp_buf, sdx);
		} else {
			//sdx += eth_size;
			//memcpy(udp_buf + sdx, eth_payload, eth_size);
            if(server->device.tuntap_mode == TAP_MODE)
                try_broadcast(server, &cmn, pkt.srcMac, udp_buf, sdx, eth_payload, eth_size);
            tuntap_write(&(server->device), eth_payload, eth_size);
		}

	}/* MSG_TYPE_PACKET */
    else if(msg_type == MSG_TYPE_PING_REQUEST){
        n2n_PING_SERVER_t            reg;
        n2n_PING_SERVER_t            ack;
        n2n_common_t                    cmn2;
        uint8_t                         ackbuf[N2N_PKT_BUF_SIZE];
        size_t                          encx = 0;
        memset(&reg, 0, sizeof(n2n_PING_SERVER_t));
        memset(&ack, 0, sizeof(n2n_PING_SERVER_t));
        //printf("registering...\n");
        decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);

        if (allowed_n2n_community(&cmn)) {
            uint8_t id = cmn.id;
            struct peer_info* edge = find_edge_by_id(server->edges, id);
            if(edge && edge->verified){
                cmn2.pc = MSG_TYPE_PING_ACK;
                cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
                cmn2.flags |= (( server->device.tuntap_mode == TAP_MODE ) ? N2N_FLAGS_TAP : N2N_FLAGS_TUN);
                memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));
                memcpy(&(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t));
                encode_PING_SUPER(ackbuf, &encx, &cmn2, &ack);
                server_sendto_sock(server, socket_fd, (struct sockaddr*)sender_sock, ackbuf, encx);
            }
        }
    }/*
	else if (msg_type == MSG_TYPE_REGISTER_SUPER) {
		n2n_REGISTER_SUPER_t            reg;
		n2n_REGISTER_SUPER_ACK_t        ack;
		n2n_common_t                    cmn2;
		uint8_t                         ackbuf[N2N_PKT_BUF_SIZE];
		size_t                          encx = 0;
		memset(&reg, 0, sizeof(n2n_REGISTER_SUPER_t));
		memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));
		//printf("registering...\n");
		decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);

		if (allowed_n2n_community(&cmn)) {
			memset(server->cmn.community, 0, N2N_COMMUNITY_SIZE);
            //strncpy((char*)(server->cmn.community), (char*)(cmn.community), (size_t)N2N_COMMUNITY_SIZE);
            uint8_t id = cmn.id;
            struct peer_info* edge = find_edge_by_id(server->edges, id);
            if(edge && edge->verified){
                memcpy(&(edge->mac_addr), reg.edgeMac, sizeof(n2n_mac_t));

                cmn2.pc = MSG_TYPE_REGISTER_SUPER_ACK;
                cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
                memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));
                memcpy(&(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t));
                cmn2.flags |= ((server->device.tuntap_mode == TAP_MODE) ? N2N_FLAGS_TAP : N2N_FLAGS_TUN);
                ack.sock.family = AF_INET;
                // Create a new entry
                uint32_t ip = 0;
                edge->ip = edge_id + 1;
                memcpy(ack.sock.addr.v4, &ip, IPV4_SIZE); //dhcp ip response
                encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack);
                server_sendto_sock(server, socket_fd, (struct sockaddr*)&server->sock, ackbuf, encx);
            }
		}
		else {
			traceEvent(TRACE_INFO, "Discarded registration: unallowed community '%s'",
				(char*)cmn.community);
		}
    }*/
	else if (msg_type == MSG_TYPE_HANDSHAKE_START) {
#ifdef TESTMODE
        traceEvent(TRACE_NORMAL, "AAAAAA_received MSG_TYPE_HANDSHAKE_START request \n");
#endif
		n2n_REGISTER_SUPER_t            reg;
		n2n_REGISTER_SUPER_ACK_t        ack;
		n2n_common_t                    cmn2;
		uint8_t                         ackbuf[N2N_PKT_BUF_SIZE];
		size_t                          encx = 0;
		memset(&reg, 0, sizeof(n2n_REGISTER_SUPER_t));
		memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));
		//printf("handshake starting...\n");
		decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);
		if (allowed_n2n_community(&cmn)) {
			//printf("handshake 1111...\n");
			memset(server->cmn.community, 0, N2N_COMMUNITY_SIZE);
            strncpy((char*)(server->cmn.community), (char*)(cmn.community), N2N_COMMUNITY_SIZE);
			cmn2.pc = MSG_TYPE_HANDSHAKE_START_ACK;
			cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
			memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));
			ack.sock.family = AF_INET;
            ack.sock.port = ntohs(sender_sock->sin_port);
            memcpy(ack.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);
            cmn2.id = register_edge_temp(server, conn, &reg, cmn.community, &(ack.sock), now);
            cmn2.flags |= ((server->device.tuntap_mode == TAP_MODE) ? N2N_FLAGS_TAP : N2N_FLAGS_TUN);
			memcpy(ack.auth.token, server->pub_key, N2N_AUTH_KEY_SIZE);
			ack.auth.toksize = N2N_AUTH_KEY_SIZE;
			memcpy(&(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t));
            //memcpy(ack.edgeMac, reg.edgeMac, sizeof(n2n_mac_t));
			encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack);
            server_sendto_sock(server, socket_fd, (const struct sockaddr*)sender_sock, ackbuf, encx);

#ifdef TESTMODE
        traceEvent(TRACE_NORMAL, "AAAAAA_sent MSG_TYPE_HANDSHAKE_START_ACK response \n");
#endif
		}
	}
	else if (msg_type == MSG_TYPE_HANDSHAKE_VERIFY) {
#ifdef TESTMODE
        traceEvent(TRACE_NORMAL, "AAAAAA_received MSG_TYPE_HANDSHAKE_START request \n");
#endif
		//printf("handshake verifying...\n");
		n2n_REGISTER_SUPER_t            reg;
		n2n_REGISTER_SUPER_ACK_t        ack;
		n2n_common_t                    cmn2;
		uint8_t                         ackbuf[N2N_PKT_BUF_SIZE];
		size_t                          encx = 0;
		memset(&reg, 0, sizeof(n2n_REGISTER_SUPER_t));
		memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));
		decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);
		if (allowed_n2n_community(&cmn)) {
			//printf("handshake 3333...\n");
			memset(server->cmn.community, 0, N2N_COMMUNITY_SIZE);
            strncpy((char*)(server->cmn.community), (char*)(cmn.community), N2N_COMMUNITY_SIZE);
            bool verified = verify_handshake(server, &reg, cmn.id);
            /*
            if(verified)
                printf("handshake succeeded...\n");
            else
                printf("handshake failed...\n");
                */
			cmn2.pc = verified ? MSG_TYPE_HANDSHAKE_SUCCESS : MSG_TYPE_HANDSHAKE_FAIL;
			cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
            cmn2.flags |= ((server->device.tuntap_mode == TAP_MODE) ? N2N_FLAGS_TAP : N2N_FLAGS_TUN);
			memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));
			memcpy(&(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t));
			ack.num_sn = 0; /* No backup */
			memset(&(ack.sn_bak), 0, sizeof(n2n_sock_t));
            /*
            ack.sock.family = AF_INET;

			uint32_t ip = ServeDhcpDiscover(server->n->Virtual, reg.edgeMac, reg.edgeTapIp);
			// Create a new entry
			if (ip != reg.edgeTapIp) {
				DHCP_LEASE *d = NewDhcpLease(server->n->Virtual->DhcpExpire, reg.edgeMac, ip, server->n->Virtual->DhcpMask, "host");
				d->Id = ++server->n->Virtual->DhcpId;
				Add(server->n->Virtual->DhcpLeaseList, d);
            }*/
            ack.sock.family = AF_INET;
            ack.sock.port = ntohs(sender_sock->sin_port);
            memcpy(ack.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);
            register_edge(server, &reg, cmn.community, &(ack.sock), verified);
            if(verified){
                encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack);
                server_sendto_sock(server, socket_fd, (struct sockaddr*)sender_sock, ackbuf, encx);
#ifdef TESTMODE
        traceEvent(TRACE_NORMAL, "AAAAAA_sent MSG_TYPE_HANDSHAKE_SUCCESS response \n");
#endif
            }
			//update ack.sock.addr.v4 into dhcp ip response
            //memcpy(ack.sock.addr.v4, &ip, IPV4_SIZE); //dhcp ip response
		}
	}
	else {
		traceEvent(TRACE_WARNING, "unknown type packet");
	}
}


/* *************************************************** */

/** Help message to print if the command line arguments are not valid. */
static void help() {
	print_n2n_version();

	printf("supernode <config file> (see supernode.conf)\n"
		"or\n"
	);
	printf("supernode ");
	printf("-l <lport> ");
	printf("-c <path> ");
	printf("[-f] ");
	printf("[-v] ");
	printf("\n\n");

	printf("-l <lport>\tSet UDP main listen port to <lport>\n");
	printf("-c <path>\tFile containing the allowed communities.\n");
#if defined(N2N_HAVE_DAEMON)
	printf("-f        \tRun in foreground.\n");
#endif /* #if defined(N2N_HAVE_DAEMON) */
	printf("-v        \tIncrease verbosity. Can be used multiple times.\n");
	printf("-h        \tThis help message.\n");
	printf("\n");

	exit(1);
}

/* *************************************************** */

static int run_loop(n2n_sn_t * sss, int* keep_running);

/* *************************************************** */

static int setOption(int optkey, char *_optarg, n2n_sn_t *sss) {
	//traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, _optarg ? _optarg : "");

	switch (optkey) {
	case 'l': /* local-port */
		sss->lport = atoi(_optarg);
		break;

	case 'c': /* community file */
		load_allowed_n2n_communities(optarg);
		break;

	case 'f': /* foreground */
		sss->daemon = 0;
		break;

	case 'h': /* help */
		help();
		break;

	case 'v': /* verbose */
		traceLevel = 4; /* DEBUG */
		break;

	default:
		traceEvent(TRACE_WARNING, "Unknown option -%c: Ignored.", (char)optkey);
		return(-1);
	}

	return(0);
}

/* *********************************************** */

static const struct option long_options[] = {
  { "communities",     required_argument, NULL, 'c' },
  { "foreground",      no_argument,       NULL, 'f' },
  { "local-port",      required_argument, NULL, 'l' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};

/* *************************************************** */

/* read command line options */
static int loadFromCLI(int argc, char * const argv[], n2n_sn_t *sss) {
	u_char c;

	while ((c = getopt_long(argc, argv, "fl:c:vh",
		long_options, NULL)) != '?') {
		if (c == 255) break;
		setOption(c, optarg, sss);
	}

	return 0;
}

/* *************************************************** */

/* parse the configuration file */
static int loadFromFile(const char *path, n2n_sn_t *sss) {
	char buffer[4096], *line, *key, *value;
	u_int line_len, opt_name_len;
	FILE *fd;
	const struct option *opt;

	fd = fopen(path, "r");

	if (fd == NULL) {
		traceEvent(TRACE_WARNING, "Config file %s not found", path);
		return -1;
	}

	while ((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {

		line = trim(line);
		value = NULL;

		if ((line_len = strlen(line)) < 2 || line[0] == '#')
			continue;

		if (!strncmp(line, "--", 2)) { /* long opt */
			key = &line[2], line_len -= 2;

			opt = long_options;
			while (opt->name != NULL) {
				opt_name_len = strlen(opt->name);

				if (!strncmp(key, opt->name, opt_name_len)
					&& (line_len <= opt_name_len
						|| key[opt_name_len] == '\0'
						|| key[opt_name_len] == ' '
						|| key[opt_name_len] == '=')) {
					if (line_len > opt_name_len)	  key[opt_name_len] = '\0';
					if (line_len > opt_name_len + 1) value = trim(&key[opt_name_len + 1]);

					// traceEvent(TRACE_NORMAL, "long key: %s value: %s", key, value);
					setOption(opt->val, value, sss);
					break;
				}

				opt++;
			}
		}
		else if (line[0] == '-') { /* short opt */
			key = &line[1], line_len--;
			if (line_len > 1) key[1] = '\0';
			if (line_len > 2) value = trim(&key[2]);

			// traceEvent(TRACE_NORMAL, "key: %c value: %s", key[0], value);
			setOption(key[0], value, sss);
		}
		else {
			traceEvent(TRACE_WARNING, "Skipping unrecognized line: %s", line);
			continue;
		}
	}

	fclose(fd);

	return 0;
}

/* *************************************************** */

static void dump_registrations(int signo) {
	struct peer_info * list = sss_node.edges;
	char buf[32];
	time_t now = time(NULL);
	u_int num = 0;

	traceEvent(TRACE_NORMAL, "====================================");

	while (list != NULL) {
		if (list->sock.family == AF_INET)
			traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: %u.%u.%u.%u:%u][community: %s][last seen: %u sec ago]",
				++num, macaddr_str(buf, list->mac_addr),
				list->sock.addr.v4[0], list->sock.addr.v4[1], list->sock.addr.v4[2], list->sock.addr.v4[3],
				list->sock.port,
				(char*)list->community_name,
				now - list->last_seen);
		else
			traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: IPv6:%u][community: %s][last seen: %u sec ago]",
				++num, macaddr_str(buf, list->mac_addr), list->sock.port,
				(char*)list->community_name,
				now - list->last_seen);

		list = list->next;
	}

	traceEvent(TRACE_NORMAL, "====================================");
}

static int keep_running;

#if defined(__linux__) || defined(WIN32)
#ifdef WIN32
BOOL WINAPI term_handler (DWORD sig)
#else
    static void term_handler(int sig)
#endif
{
    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "Ok I am leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "Shutting down...");
        called = 1;
    }

    keep_running = 0;
#ifdef WIN32
    return(TRUE);
#endif
}
#endif /* defined(__linux__) || defined(WIN32) */

/* *************************************************** */

/** Main program entry point from kernel. */
int main(int argc, char * const argv[]) {

#ifdef WIN32
    BOOL isRebootRequired = false;
	BOOL ret = InstallOrUpdate(&isRebootRequired);
#endif

#ifndef WIN32
    struct passwd *pw = NULL;
#endif
	int rc;

	init_sn(&sss_node);

#ifndef WIN32
	if ((argc >= 2) && (argv[1][0] != '-')) {
		rc = loadFromFile(argv[1], &sss_node);
		if (argc > 2)
			rc = loadFromCLI(argc, argv, &sss_node);
	}
	else
#endif
		rc = loadFromCLI(argc, argv, &sss_node);

	if (rc < 0)
		return(-1);

    InitMayaqua(false, true, 0, NULL);
#ifdef __linux__ 
    //write_run_initscript(sss_node.lport);
#endif
#if defined(N2N_HAVE_DAEMON)
	if (sss_node.daemon) {
		useSyslog = 1; /* traceEvent output now goes to syslog. */

		if (-1 == daemon(0, 0)) {
			traceEvent(TRACE_ERROR, "Failed to become daemon.");
			exit(-5);
        }
	}
#endif /* #if defined(N2N_HAVE_DAEMON) */

#ifndef WIN32
  /* If running suid root then we need to setuid before using the force. */
  setuid(0);
  /* setgid(0); */
#endif

  
  if (tuntap_open(&(sss_node.device), sss_node.ec.tuntap_dev_name, VIRTUALHOSTIP, VIRTUALHOSTSUBNET, sss_node.ec.device_mac, sss_node.ec.mtu) < 0)
  {
      traceEvent(TRACE_ERROR, "Failed to open tuntap device.");
	  return(-1);
  }

    //eee.n = SnNewSecureNAT();
	IP tap_ip;
	if (StrToIP(&tap_ip, VIRTUALHOSTIP) == false)
	{
		return false;
	}

	VH_OPTION *o = ZeroMalloc(sizeof(VH_OPTION));
	NiSetDefaultVhOption(o);
	SetIP(&o->Ip, tap_ip.addr[0], tap_ip.addr[1], tap_ip.addr[2], tap_ip.addr[3]);
	SetIP(&o->DhcpGatewayAddress, tap_ip.addr[0], tap_ip.addr[1], tap_ip.addr[2], tap_ip.addr[3]);
	SetIP(&o->DhcpDnsServerAddress, tap_ip.addr[0], tap_ip.addr[1], tap_ip.addr[2], tap_ip.addr[3]);
	o->UseDhcp = true;
	StrToIP(&o->DhcpLeaseIPStart, "192.168.137.100");
	StrToIP(&o->DhcpLeaseIPEnd, "192.168.137.200");
	StrToIP(&o->DhcpGatewayAddress, "255.255.255.0");
	sss_node.n = SnNewSecureNATWithVHOption(o);
	traceEvent(TRACE_NORMAL, "traceLevel is %d", traceLevel);

    sss_node.sock = open_socket(sss_node.lport, 1 /*bind ANY*/, 0);
    if (-1 == sss_node.sock) {
		traceEvent(TRACE_ERROR, "Failed to open main socket. %s", strerror(errno));
		exit(-2);
	}
	else {
		traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (main)", sss_node.lport);
	}
    sss_node.tcp_sock = open_socket(sss_node.lport, 1 /*bind ANY*/, 1 /* TCP */);
    if(-1 == sss_node.tcp_sock) {
        traceEvent(TRACE_ERROR, "Failed to open auxiliary TCP socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode opened TCP %u (aux)", sss_node.lport);
    }

    if(-1 == listen(sss_node.tcp_sock, N2N_TCP_BACKLOG_QUEUE_SIZE)) {
        traceEvent(TRACE_ERROR, "Failed to listen on auxiliary TCP socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on TCP %u (aux)", sss_node.lport);
    }

    sss_node.mgmt_sock = open_socket(N2N_SN_MGMT_PORT, 0 /* bind LOOPBACK */, 0);
	if (-1 == sss_node.mgmt_sock) {
		traceEvent(TRACE_ERROR, "Failed to open management socket. %s", strerror(errno));
		exit(-2);
	}
	else
		traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (management)", N2N_SN_MGMT_PORT);

#ifndef WIN32
    if(((pw = getpwnam ("n2n")) != NULL) || ((pw = getpwnam ("nobody")) != NULL)) {
        sss_node.userid = sss_node.userid == 0 ? pw->pw_uid : 0;
        sss_node.groupid = sss_node.groupid == 0 ? pw->pw_gid : 0;
    }
    if((sss_node.userid != 0) || (sss_node.groupid != 0)) {
        traceEvent(TRACE_NORMAL, "Dropping privileges to uid=%d, gid=%d",
                     (signed int)sss_node.userid, (signed int)sss_node.groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if((setgid(sss_node.groupid) != 0) || (setuid(sss_node.userid) != 0)) {
            traceEvent(TRACE_ERROR, "Unable to drop privileges [%u/%s]", errno, strerror(errno));
            exit(1);
        }
    }

    if((getuid() == 0) || (getgid() == 0)) {
        traceEvent(TRACE_WARNING, "Running as root is discouraged, check out the -u/-g options");
    }
#endif
	traceEvent(TRACE_NORMAL, "supernode started");

#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
	signal(SIGHUP, dump_registrations);
#endif

    keep_running = 1;
    return run_loop(&sss_node, &keep_running);
}

void server_send_packet2net(n2n_sn_t * server, uint8_t *tap_pkt, size_t len) {

	n2n_mac_t destMac;
    uint32_t *destIp;
	n2n_common_t cmn;
	n2n_PACKET_t pkt;

	uint8_t pktbuf[N2N_PKT_BUF_SIZE];
	size_t idx = 0;
	size_t tx_transop_idx = 0;

	ether_hdr_t eh;

	/* tap_pkt is not aligned so we have to copy to aligned memory */

	memset(&cmn, 0, sizeof(cmn));
	//cmn.ttl = N2N_DEFAULT_TTL;
	cmn.pc = MSG_TYPE_PACKET;
    cmn.flags = N2N_FLAGS_FROM_SUPERNODE; /* no options, not from supernode, no socket */
	memcpy(cmn.community, server->cmn.community, N2N_COMMUNITY_SIZE);

	//encode_common(pktbuf, &idx, &cmn);

	memset(&pkt, 0, sizeof(pkt));
	struct peer_info* edge;

    bool unicast = false;
	if (server->device.tuntap_mode == TAP_MODE) {
		memcpy(&eh, tap_pkt, sizeof(ether_hdr_t));
		memcpy(destMac, tap_pkt, N2N_MAC_SIZE); /* dest MAC is first in ethernet header */
		memcpy(pkt.srcMac, server->device.mac_addr, N2N_MAC_SIZE);
		memcpy(pkt.dstMac, destMac, N2N_MAC_SIZE);
		cmn.flags |= N2N_FLAGS_TAP;
		HASH_FIND_PEER(server->edges, destMac, edge);
		unicast = (0 == is_multi_broadcast(pkt.dstMac));
	}
	else {
        int ipver = (tap_pkt[0] >> 4) & 0xf;
        if(ipver == 6) //ipv6
            return;
        destIp = (uint32_t*)&tap_pkt[IP4_DSTOFFSET];

		cmn.flags |= N2N_FLAGS_TUN;
        struct peer_info* edge0, *tmp_edge;
        HASH_ITER(hh, server->edges, edge0, tmp_edge){
            if(edge0->ip == *destIp){
                edge = edge0;
                unicast = true;
                break;
            }
        }
        if(edge0 == NULL)
            return;
	}
	
	pkt.sock.family = 0; /* do not encode sock */

	idx = 0;
	encode_PACKET(pktbuf, &idx, &cmn, &pkt);
	traceEvent(TRACE_DEBUG, "encoded PACKET header of size=%u transform %u (idx=%u)",
	(unsigned int)idx, (unsigned int)pkt.transform, (unsigned int)tx_transop_idx);

	/* Common section to forward the final product. */
	//traceEvent(TRACE_NORMAL, "Trying to send A PACKET through tap\n");
	if (unicast && edge) {
		idx += edge->transop.fwd(&(edge->transop), pktbuf + idx, N2N_PKT_BUF_SIZE - idx,
			tap_pkt, len, pkt.dstMac);
		try_forward(server, &cmn, edge, pktbuf, idx);
	}else {
		try_broadcast(server, &cmn, pkt.srcMac, pktbuf, idx, tap_pkt, len);
	}
	//traceEvent(TRACE_NORMAL, "Sent A PACKET through tap\n");
}

/** Read a single packet from the TAP interface, process it and write out the
*  corresponding packet to the cooked socket.
*/
void readFromServerTAPSocket(n2n_sn_t * server) {
	/* tun -> remote */
	uint8_t             eth_pkt[N2N_PKT_BUF_SIZE];
	macstr_t            mac_buf;
	ssize_t             len;

#ifdef __ANDROID_NDK__
	if (uip_arp_len != 0) {
		len = uip_arp_len;
		memcpy(eth_pkt, uip_arp_buf, MIN(uip_arp_len, N2N_PKT_BUF_SIZE));
		traceEvent(TRACE_DEBUG, "ARP reply packet to send");
	}
	else
	{
#endif /* #ifdef __ANDROID_NDK__ */
		len = tuntap_read(&(server->device), eth_pkt, N2N_PKT_BUF_SIZE);
#ifdef __ANDROID_NDK__
	}
#endif /* #ifdef __ANDROID_NDK__ */

	if ((len <= 0) || (len > N2N_PKT_BUF_SIZE))
	{
		traceEvent(TRACE_WARNING, "read()=%d [%d/%s]",
			(signed int)len, errno, strerror(errno));
	}else{
		const uint8_t * mac = eth_pkt;
        server_send_packet2net(server, eth_pkt, len);
	}
}




#ifdef WIN32
static DWORD tunReadThread(LPVOID lpArg) {
    n2n_sn_t *eee = (n2n_sn_t*)lpArg;

	while (1)
		readFromServerTAPSocket(eee);

	return((DWORD)NULL);
}

/* ************************************** */

/** Start a second thread in Windows because TUNTAP interfaces do not expose
*  file descriptors. */
static void startTunReadThread(n2n_sn_t *eee) {
	HANDLE hThread;
	DWORD dwThreadId;

	hThread = CreateThread(NULL,         /* security attributes */
		0,            /* use default stack size */
		(LPTHREAD_START_ROUTINE)tunReadThread, /* thread function */
        (void*)eee,   /* argument to thread function */
		0,            /* thread creation flags */
		&dwThreadId); /* thread id out */
}
#endif

/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
static int run_loop(n2n_sn_t * sss, int *keep_running) {
    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
#ifdef WIN32
	startTunReadThread(sss);
#endif

    sss->start_time = time(NULL);

    while (keep_running) {
        int rc;
        ssize_t bread;
        int max_sock = 0;
        fd_set socket_mask;
        struct timeval wait_time;
        n2n_tcp_connection_t *conn, *next, *tmp_conn;
        time_t before, now = 0;
        SOCKET tmp_sock;
        n2n_sock_str_t sockbuf;

        FD_ZERO(&socket_mask);
        FD_SET(sss->sock, &socket_mask);
        FD_SET(sss->tcp_sock, &socket_mask);
        FD_SET(sss->mgmt_sock, &socket_mask);
        max_sock = MAX(MAX(sss->sock, sss->mgmt_sock), sss->tcp_sock);
#ifndef WIN32
        FD_SET(sss->device.fd, &socket_mask);
        max_sock = MAX(max_sock, sss->device.fd);
#endif
        HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
            //socket descriptor
            FD_SET(conn->socket_fd, &socket_mask);
            if(conn->socket_fd > max_sock)
                max_sock = conn->socket_fd;
        }

        wait_time.tv_sec = 10; wait_time.tv_usec = 0;
        before = time(NULL);
        rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);
        now = time(NULL);
        if (rc > 0) {
            if(FD_ISSET(sss->sock, &socket_mask)) {
                struct sockaddr_in sender_sock;
                socklen_t i;

                i = sizeof(sender_sock);
                bread = recvfrom(sss->sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0 /*flags*/,
                                 (struct sockaddr *)&sender_sock, (socklen_t *)&i);

                if((bread < 0)
#ifdef WIN32
                   && (WSAGetLastError() != WSAECONNRESET)
#endif
                  ) {
                    /* For UDP bread of zero just means no data (unlike TCP). */
                    /* The fd is no good now. Maybe we lost our interface. */
                    traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef WIN32
                    traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
                    *keep_running = 0;
                    break;
                }

                // we have a datagram to process...
                if(bread > 0) {
                    // ...and the datagram has data (not just a header)
                    process_udp(sss, &sender_sock, sss->sock, pktbuf, bread, now, 0);
                }
            }

            // the so far known tcp connections

            // beware: current conn and other items of the connection list may be found
            // due for deletion while processing packets. Even OTHER connections, e.g. if
            // forwarding to another edge node fails. connections due for deletion will
            // not immediately be deleted but marked 'inactive' for later deletion
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
                // do not process entries that have been marked inactive, those will be deleted
                // immediately after this loop
                if(conn->inactive)
                    continue;

                if(FD_ISSET(conn->socket_fd, &socket_mask)) {

                    struct sockaddr_in sender_sock;
                    socklen_t i;

                    i = sizeof(sender_sock);
                    bread = recvfrom(conn->socket_fd,
                                     conn->buffer + conn->position, conn->expected - conn->position, 0 /*flags*/,
                                     (struct sockaddr *)&sender_sock, (socklen_t *)&i);

                    if((bread <= 0) && (errno)) {
                        traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef WIN32
                        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
                        close_tcp_connection(sss, conn);
                        continue;
                    }
                    conn->position += bread;

                    if(conn->position == conn->expected) {
                        if(conn->position == sizeof(uint16_t)) {
                            // the prepended length has been read, preparing for the packet
                            conn->expected += be16toh(*(uint16_t*)(conn->buffer));
                            if(conn->expected > N2N_SN_PKTBUF_SIZE) {
                                traceEvent(TRACE_ERROR, "too many bytes in tcp packet expected");
                                close_tcp_connection(sss, conn);
                                continue;
                            }
                        } else {
                            // full packet read, handle it
                            process_udp(sss, (struct sockaddr_in*)&(conn->sock), conn->socket_fd,
                                             conn->buffer + sizeof(uint16_t), conn->position - sizeof(uint16_t), now, conn);

                            // reset, await new prepended length
                            conn->expected = sizeof(uint16_t);
                            conn->position = 0;

                        }
                    }
                }
            }

            // remove inactive / already closed tcp connections from list
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
                if(conn->inactive) {
                    HASH_DEL(sss->tcp_connections, conn);
                    free(conn);
                }
            }
            // accept new incoming tcp connection
            if(FD_ISSET(sss->tcp_sock, &socket_mask)) {
                struct sockaddr_in sender_sock;
                socklen_t i;

                i = sizeof(sender_sock);
                if((HASH_COUNT(sss->tcp_connections) + 4) < FD_SETSIZE) {
                    tmp_sock = accept(sss->tcp_sock, (struct sockaddr *)&sender_sock, (socklen_t *)&i);
                    if(tmp_sock >= 0) {
                        conn = (n2n_tcp_connection_t*)malloc(sizeof(n2n_tcp_connection_t));
                        if(conn) {
                            conn->socket_fd = tmp_sock;
                            memcpy(&(conn->sock), &sender_sock, sizeof(struct sockaddr_in));
                            conn->inactive = 0;
                            conn->expected = sizeof(uint16_t);
                            conn->position = 0;
                            HASH_ADD_INT(sss->tcp_connections, socket_fd, conn);
                            traceEvent(TRACE_DEBUG, "run_sn_loop accepted incoming TCP connection from %s",
                                                    sock_to_cstr(sockbuf, (n2n_sock_t*)&sender_sock));
                        }
                    }
                } else {
                        // no space to store the socket for a new connection, close immediately
                        traceEvent(TRACE_DEBUG, "run_sn_loop denied incoming TCP connection from %s due to max connections limit hit",
                                                sock_to_cstr(sockbuf, (n2n_sock_t*)&sender_sock));
                }
            }
#ifdef __ANDROID_NDK__
              if (uip_arp_len != 0) {
				  readFromServerTAPSocket(sss);
                    uip_arp_len = 0;
              }
#endif /* #ifdef __ANDROID_NDK__ */

#ifndef WIN32
              if(FD_ISSET(sss->device.fd, &socket_mask)) {
                    /* Read an ethernet frame from the TAP socket. Write on the IP
                     * socket. */
                    readFromServerTAPSocket(sss);
              }
#endif
        }
        else {
            if(((now - before) < wait_time.tv_sec) && (*keep_running)){
                // this is no real timeout, something went wrong with one of the tcp connections (probably)
                // close them all, edges will re-open if they detect closure
                HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn)
                    close_tcp_connection(sss, conn);
                traceEvent(TRACE_DEBUG, "falsly claimed timeout, assuming issue with tcp connection, closing them all");
            } else
                traceEvent(TRACE_DEBUG, "timeout");
            }

		//purge_expired_registrations(&(sss->edges));

	} /* while */

	deinit_sn(sss);

	return 0;
}
