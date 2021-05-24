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

#pragma warning(disable:4996)

#include "n2n.h"
#include "htree.h"
#include "ECDH/curve25519.h"
#ifdef WIN32
#include <process.h>
#endif

#ifdef __ANDROID_NDK__
#include "android/edge_android.h"
#include <tun2tap/tun2tap.h>
#endif /* __ANDROID_NDK__ */


// Get hash of MAC table entry
uint32_t GetHashFilterTable(void *p)
{
	FILTER_TABLE_ENTRY *e = p;

	if (e == NULL)
	{
		return 0;
	}

	return e->ip;
}

// Comparison function of the MAC table entries
int CmpFilterTable(void *p1, void *p2)
{
	FILTER_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(FILTER_TABLE_ENTRY **)p1;
	e2 = *(FILTER_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	
	int r = COMPARE_RET(e1->ip, e2->ip);
	if (r != 0)
	{
		return r;
	}

	return 0;
}



char* get_conf_path()
{
#ifdef WIN32
	
#else

#endif
	return "settings.conf";
}
int read_conf_file(n2n_edge_t * eee, char* path)
{
	char buffer[4096], *line;
    FILE *fd;

    fd = fopen(path, "r");

    if(fd == NULL) {
        return -1;
    }

    while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
        line = trim(line);

        if(strlen(line) < 2 || line[0] == '#')
            continue;
		
		char* token = strtok(line, ":");
		if(token == NULL){
			fclose(fd);
			return -1;
		}
		strncpy(eee->conf->ip_addr_str, token, strlen(token));
		token = strtok(NULL, ":");
		if(token == NULL){
			fclose(fd);
			return -1;
		}
		strncpy(eee->conf->netmask_str, token, strlen(token));
		token = strtok(NULL, ":");
		if(token == NULL){
			fclose(fd);
			return -1;
		}
		strncpy(eee->conf->device_mac_str, token, strlen(token));
    	break;
    }

    fclose(fd);
    return 1;
}
int write_conf_file(n2n_edge_t * eee, char* path)
{
	char buffer[1024];
	memset(buffer, 0, 1024);
    FILE *fd;

    fd = fopen(path, "w");

    if(fd == NULL) {
        return -1;
    }
    snprintf(buffer, "%s:%s:%s", eee->conf->ip_addr_str, eee->conf->netmask_str, eee->conf->device_mac_str);
    fputs(buffer, fd);
    fclose(fd);
    return 1;
}

void load_filter_list(n2n_edge_t * eee)
{
    int count = 0;
	char ipsets[strlen(eee->conf->ipsets)+1];
	memset(ipsets, 0, strlen(eee->conf->ipsets)+1);
	strcpy(ipsets, eee->conf->ipsets);
	
	char ips[strlen(eee->conf->ips)+1];
	memset(ips, 0, strlen(eee->conf->ips)+1);
	strcpy(ips, eee->conf->ips);
	
	char domains[strlen(eee->conf->domains)+1];
	memset(domains, 0, strlen(eee->conf->domains)+1);
	strcpy(domains, eee->conf->domains);
	
	char* ctx1;
	char* ctx2;
	
	char* line = STRTOKS(ipsets, "\r\n", &ctx1);

	char* lo, *hi;
    while (line) {
		lo = STRTOKS(line, "|", &ctx2);
		hi = STRTOKS(NULL, "|", &ctx2);
		eee->ip_sets[count].lo = atoi(lo);
		eee->ip_sets[count].hi = atoi(hi);
		line = STRTOKS(NULL, "\r\n", &ctx1);
		count++;
    }
    
    eee->ip_set_count = count;
    
    FILTER_TABLE_ENTRY *e;
    line = strtok(ips, "\r\n");
    while (line) {
        e = ZeroMalloc(sizeof(FILTER_TABLE_ENTRY));
        e->ip = strtol(line, NULL, 10);
        AddHash(eee->filter_list, e);
        line = strtok(NULL, "\r\n");
    }

    line = strtok(domains, "\r\n");
    while (line) {
        domain_find_or_add(eee->filter_dns_list, line);
        line = strtok(NULL, "\r\n");
    }
    
}
/** Initialise an edge to defaults.
 *
 */
 
int edge_init(n2n_edge_t * eee, vpn_conf_t *conf) {
#ifdef WIN32
	initWin32();
#endif

	memset(eee, 0, sizeof(n2n_edge_t));
	eee->conf = conf;
	char* path = get_conf_path();
	conf->file_op_success =	read_conf_file(eee, path);
    n2n_srand (n2n_seed());
	InitMayaqua(false, false, 0, NULL);
	
	logfunc = conf->log_func;
	notifyfunc = conf->notify;
	eee->view = conf->v;
	notifyfunc(20, eee->view);

	memcpy(eee->token.token, conf->token, strlen(conf->token));
	eee->token.toksize = strlen(conf->token);
	
	eee->start_time = time(NULL);
	eee->daemon = 1;    /* By default run in daemon mode. */
	/* keyschedule set to NULLs by memset */
	/* community_name set to NULLs by memset */
	eee->lport = 0;
	eee->sock = -1;
	eee->is_tcp = 1;
	eee->udp_multicast_sock = -1;
	eee->allow_routing = 0;
	eee->drop_multicast = 1;
	eee->last_register_req = 0;
	eee->last_sup = 0;
	eee->filter_list = NewHashList(GetHashFilterTable, CmpFilterTable, 11, true);
	eee->filter_dns_list = htree_new_node(NULL, 0);
	eee->keep_on_running = 1;
	memset(&(eee->device), 0, sizeof(tuntap_dev));
	if(eee->conf->file_op_success < 0){
		strcpy(eee->conf->ip_addr_str, "192.168.137.103");
		strcpy(eee->conf->netmask_str, "255.255.255.0");
		random_device_mac(eee->conf->device_mac_str);
	}
	eee->device.ip_addr = inet_addr(eee->conf->ip_addr_str);
	eee->device.mtu = 1500;	
	eee->device.tuntap_mode = TUN_MODE;
	str2mac(eee->device.mac_addr, eee->conf->device_mac_str);
	eee->gw_ip[0]='\0';
	//eee->device.tuntap_mode = TAP_MODE;

#ifndef WIN32
	eee->device.fd = -1;
	eee->userid = 0;
	eee->groupid = 0;
#endif
	for(int idx = 0; idx < N2N_AUTH_KEY_SIZE; ++idx) {
        eee->priv_key[idx] = n2n_rand() % 0xff;
    }
	//Rand(eee->priv_key, N2N_AUTH_KEY_SIZE);
	static const uint8_t basepoint[32] = {9};
	curve25519_donna(eee->pub_key, eee->priv_key, basepoint);
	eee->handshake_status = MSG_TYPE_HANDSHAKE_START;
	
	notifyfunc(25, eee->view);

	memset(&(eee->supernode), 0, sizeof(eee->supernode));
	eee->supernode.family = AF_INET;

	strncpy(eee->sn_ip, conf->server_info, N2N_EDGE_SN_HOST_SIZE);
	traceEvent(TRACE_NORMAL, "Adding supernode = %s\n", client.sn_ip);

	supernode2addr(&(eee->supernode), eee->sn_ip);
	load_filter_list(eee);
	return(0);
}

/* ***************************************************** */

/** Resolve the supernode IP address.
 *
 *  REVISIT: This is a really bad idea. The edge will block completely while the
 *           hostname resolution is performed. This could take 15 seconds.
 */
void supernode2addr(n2n_sock_t * sn, const n2n_sn_name_t addrIn) {
	
	n2n_sn_name_t addr;
	const char *supernode_host;

	memcpy(addr, addrIn, N2N_EDGE_SN_HOST_SIZE);

	supernode_host = strtok(addr, ":");

	if (supernode_host)
	{
		in_addr_t sn_addr;
		char *supernode_port = strtok(NULL, ":");
		const struct addrinfo aihints = { 0, PF_INET, 0, 0, 0, NULL, NULL, NULL };
		struct addrinfo * ainfo = NULL;
		int nameerr;

		if (supernode_port)
			sn->port = atoi(supernode_port);
		else
			traceEvent(TRACE_WARNING, "Bad supernode parameter (-l <host:port>) %s %s:%s",
				addr, supernode_host, supernode_port);

		nameerr = getaddrinfo(supernode_host, NULL, &aihints, &ainfo);

		if (0 == nameerr)
		{
			struct sockaddr_in * saddr;

			/* ainfo s the head of a linked list if non-NULL. */
			if (ainfo && (PF_INET == ainfo->ai_family))
			{
				/* It is definitely and IPv4 address -> sockaddr_in */
				saddr = (struct sockaddr_in *)ainfo->ai_addr;

				memcpy(sn->addr.v4, &(saddr->sin_addr.s_addr), IPV4_SIZE);
				sn->family = AF_INET;
			}
			else
			{
				/* Should only return IPv4 addresses due to aihints. */
				traceEvent(TRACE_WARNING, "Failed to resolve supernode IPv4 address for %s", supernode_host);
			}

			freeaddrinfo(ainfo); /* free everything allocated by getaddrinfo(). */
			ainfo = NULL;
		}
		else {
			traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s, assuming numeric", supernode_host);
			sn_addr = inet_addr(supernode_host); /* uint32_t */
			memcpy(sn->addr.v4, &(sn_addr), IPV4_SIZE);
			sn->family = AF_INET;
		}

	}
	else
		traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l <host:port>)");
}

// always closes the socket
void supernode_disconnect(n2n_edge_t *eee) {

    if(eee->sock >= 0) {
        closesocket(eee->sock);
        eee->sock = -1;
    }
}

/** Send a datagram to a socket file descriptor */
static ssize_t sendto_fd (n2n_edge_t *eee, const void *buf,
                            size_t len, struct sockaddr_in *dest) {

    ssize_t sent = 0;
    int rc = 1;

    // if required (tcp), wait until writeable as soket is set to O_NONBLOCK, could require
    // some wait time directly after re-opening
    if(eee->is_tcp) {
        fd_set socket_mask;
        struct timeval wait_time;

        FD_ZERO(&socket_mask);
        FD_SET(eee->sock, &socket_mask);
        wait_time.tv_sec = 0;
        wait_time.tv_usec = 500000;
        rc = select(eee->sock + 1, NULL, &socket_mask, NULL, &wait_time);
    }

    if (rc > 0) {

        sent = sendto(eee->sock, buf, len, 0 /*flags*/,
                      (struct sockaddr *)dest, sizeof(struct sockaddr_in));

        if((sent <= 0) && (errno)) {
            char * c = strerror(errno);
            traceEvent(TRACE_ERROR, "sendto_fd sendto failed (%d) %s", errno, c);
#ifdef WIN32
            traceEvent(TRACE_ERROR, "sendto_fd WSAGetLastError(): %u", WSAGetLastError());
#endif
            if(eee->is_tcp) {
                supernode_disconnect(eee);
                eee->sn_wait = 1;
                traceEvent(TRACE_DEBUG, "sendto_fd disconnected supernode due to sendto() error");
                return -1;
            }
        } else {
            traceEvent(TRACE_DEBUG, "sendto_fd sent=%d to ", (signed int)sent);
        }
    } else {
        supernode_disconnect(eee);
        eee->sn_wait = 1;
        traceEvent(TRACE_DEBUG, "sendto_fd disconnected supernode due to select() timeout");
        return -1;
    }
    return sent;
}

/* ************************************** */

/** Send a datagram to a socket defined by a n2n_sock_t */
ssize_t sendto_sock(n2n_edge_t *eee, const void * buf,
	size_t len, const n2n_sock_t * dest) {
	struct sockaddr_in peer_addr;
	ssize_t sent = 0;
   	int value = 0;

    if(!dest->family)
        // invalid socket
        return 0;

    if(eee->sock < 0)
        // invalid socket file descriptor, e.g. TCP unconnected has fd of '-1'
        return 0;

	fill_sockaddr((struct sockaddr *) &peer_addr, sizeof(peer_addr), dest);
	
	if(eee->is_tcp) {

        setsockopt(eee->sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
        value = 1;
#ifdef LINUX
        setsockopt(eee->sock, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif

        // prepend packet length...
        uint16_t pktsize16 = htobe16(len);
        sent = sendto_fd(eee, (uint8_t*)&pktsize16, sizeof(pktsize16), &peer_addr);

        if(sent <= 0)
            return -1;
        // ...before sending the actual data
    }
    sent = sendto_fd(eee, buf, len, &peer_addr);

    // if the connection is tcp, i.e. not the regular sock...
    if(eee->is_tcp) {
        value = 1; /* value should still be set to 1 */
        setsockopt(eee->sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
#ifdef LINUX
        value = 0;
        setsockopt(eee->sock, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif
    }

	return sent;
}

/** A PACKET has arrived containing an encapsulated ethernet datagram - usually
 *  encrypted. */
static int handle_PACKET(n2n_edge_t * eee,
	const n2n_common_t * cmn,
	const n2n_PACKET_t * pkt,
	//const n2n_sock_t * orig_sender,
	uint8_t * payload,
	size_t psize) {
	ssize_t             data_sent_len;
	uint8_t             from_supernode;
	uint8_t *           eth_payload = NULL;
	int                 retval = -1;
	time_t              now;
	ether_hdr_t *       eh;
	ipstr_t             ip_buf;

	now = time(NULL);

	/* hexdump(payload, psize); */

	from_supernode = cmn->flags & N2N_FLAGS_FROM_SUPERNODE;

	if (from_supernode)
	{
		++(eee->rx_sup);
		eee->last_sup = now;
	}
	else
	{
		++(eee->rx_p2p);
		eee->last_p2p = now;
	}

	/* Update the sender in peer table entry */
	//check_peer(eee, from_supernode, pkt->srcMac, orig_sender);

	/* Handle transform. */
	{
		
		uint8_t decodebuf[N2N_PKT_BUF_SIZE];
		size_t eth_size;

		eth_payload = decodebuf;
			
		eth_size = eee->transop.rev(&eee->transop,
			eth_payload, N2N_PKT_BUF_SIZE,
			payload, psize, pkt->srcMac);
		++(eee->transop.rx_cnt); /* stats */

		if(eee->device.tuntap_mode == TAP_MODE){
			eh = (ether_hdr_t*)eth_payload;
	
			if (ntohs(eh->type) == 0x0800) {
				uint32_t *dst = (uint32_t*)&eth_payload[ETH_FRAMESIZE + IP4_DSTOFFSET];
	
				/* Note: all elements of the_ip are in network order */
				if (*dst != eee->device.ip_addr) {
					/* This is a packet that needs to be routed */
					traceEvent(TRACE_INFO, "Discarding routed packet [%s]",
						intoa(ntohl(*dst), ip_buf, sizeof(ip_buf)));
					return(-1);
				}
			}
		}
		

		data_sent_len = tuntap_write(&(eee->device), eth_payload, eth_size);
		//traceEvent(TRACE_INFO, "Write success to tun device");
		if (data_sent_len == eth_size)
		{
			retval = 0;
		}

	}

	return retval;
}
/* ************************************** */

/** Read a datagram from the management UDP socket and take appropriate
 *  action. */
static void readFromMgmtSocket(n2n_edge_t * eee, int * keep_running) {

}

/* ************************************** */


/* ***************************************************** */

/** Send an ecapsulated ethernet PACKET to a destination edge or broadcast MAC
 *  address. */
static int send_packet(n2n_edge_t * eee,
	n2n_mac_t dstMac,
	const uint8_t * pktbuf,
	size_t pktlen) {

	/*ssize_t s; */
	n2n_sock_str_t sockbuf;
	n2n_sock_t destination;

	memcpy(&destination, &(eee->supernode), sizeof(struct sockaddr_in));

	traceEvent(TRACE_INFO, "send_packet to %s", sock_to_cstr(sockbuf, &destination));

	/* s = */ sendto_sock(eee, pktbuf, pktlen, &destination);

	return 0;
}

/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
void edge_send_packet2net(n2n_edge_t * eee, uint8_t *tap_pkt, size_t len) 
{
	n2n_mac_t destMac;

	n2n_common_t cmn;
	n2n_PACKET_t pkt;
	
	uint8_t pktbuf[N2N_PKT_BUF_SIZE];
	size_t idx = 0;
	size_t tx_transop_idx = 0;

	memset(&cmn, 0, sizeof(cmn));
	cmn.id = eee->id;
	cmn.pc = MSG_TYPE_PACKET;
	cmn.flags = 0; /* no options, not from supernode, no socket */
	memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

	memset(&pkt, 0, sizeof(pkt));
	if(eee->device.tuntap_mode == TAP_MODE){
		cmn.flags |= N2N_FLAGS_TAP;
		memcpy(destMac, tap_pkt, N2N_MAC_SIZE); /* dest MAC is first in ethernet header */
		memcpy(pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
		memcpy(pkt.dstMac, destMac, N2N_MAC_SIZE);
	}else{
		cmn.flags |= N2N_FLAGS_TUN;
	}

	pkt.sock.family = 0; /* do not encode sock */

	idx = 0;
	encode_PACKET(pktbuf, &idx, &cmn, &pkt);
	traceEvent(TRACE_INFO, "packet value = %d", pktbuf[0]);
	
	idx += eee->transop.fwd(&eee->transop, pktbuf + idx, N2N_PKT_BUF_SIZE - idx,
		tap_pkt, len, pkt.dstMac);

	send_packet(eee, destMac, pktbuf, idx); 
	
}

/* ************************************** */
bool g_tapthread_cycle_finish = false;
#ifdef WIN32
static DWORD tunReadThread(LPVOID lpArg) {
	n2n_edge_t *eee = (n2n_edge_t*)lpArg;

	while (eee->keep_on_running){
		g_tapthread_cycle_finish = false;
		readFromTAPSocket(eee);
		g_tapthread_cycle_finish = true;
	}


	return((DWORD)NULL);
}

/* ************************************** */

/** Start a second thread in Windows because TUNTAP interfaces do not expose
 *  file descriptors. */
static void startTunReadThread(n2n_edge_t *eee) {
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


/** Read a datagram from the main UDP socket to the internet. */
void process_udp (n2n_edge_t *eee, const struct sockaddr_in *sender_sock, const SOCKET in_sock,
                 uint8_t *udp_buf, size_t udp_size, time_t now) {
	n2n_common_t        cmn; /* common fields in the packet header */

	n2n_sock_str_t      sockbuf1;
	n2n_sock_str_t      sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */

	ssize_t             recvlen = udp_size;
	size_t              rem;
	size_t              idx;
	size_t              msg_type;
    uint8_t             via_multicast;
	n2n_sock_t          sender;
	n2n_sock_t *        orig_sender = NULL;
	ipstr_t				ip_buf;
	size_t              i;

    memset(&sender, 0, sizeof(n2n_sock_t));

    if(eee->is_tcp)
        // TCP expects that we know our comm partner and does not deliver the sender
        memcpy(&sender, &(eee->supernode), sizeof(struct sockaddr_in));
    else {
        sender.family = AF_INET; /* UDP socket was opened PF_INET v4 */
        sender.port = ntohs(sender_sock->sin_port);
        memcpy(&(sender.addr.v4), &(sender_sock->sin_addr.s_addr), IPV4_SIZE);
    }

	/* The packet may not have an orig_sender socket spec. So default to last
	 * hop as sender. */
	orig_sender = &sender;

    via_multicast = (in_sock == eee->udp_multicast_sock);
	/* hexdump(udp_buf, recvlen); */

	rem = recvlen; /* Counts down bytes of packet to protect against buffer overruns. */
	idx = 0; /* marches through packet header as parts are decoded. */
	if (decode_common(&cmn, udp_buf, &rem, &idx) < 0)
	{
		traceEvent(TRACE_ERROR, "Failed to decode common section in N2N_UDP");
		return; /* failed to decode packet */
	}

	now = time(NULL);

	msg_type = cmn.pc; /* packet code */
    uint8_t from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

    if ((from_supernode) || 0 == memcmp(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE)) {
		if (msg_type == MSG_TYPE_PACKET) {
			
			/* process PACKET - most frequent so first in list. */
			n2n_PACKET_t pkt;

			eee->last_sup = now;
			decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

			traceEvent(TRACE_INFO, "Rx PACKET from %s (%s)",
				sock_to_cstr(sockbuf1, &sender),
				sock_to_cstr(sockbuf2, orig_sender));

			handle_PACKET(eee, &cmn, &pkt, /*orig_sender,*/ udp_buf + idx, recvlen - idx);
		}else if (msg_type == MSG_TYPE_PING_ACK ){
			
			n2n_PING_SERVER_t ra;

			if (eee->sn_wait)
			{
				decode_PING_SUPER(&ra, &cmn, udp_buf, &rem, &idx);

				if (0 == memcmp(ra.cookie, eee->last_cookie, N2N_COOKIE_SIZE))
				{
					eee->last_sup = now;
					eee->sn_wait = 0;
					eee->ping_ok = true;
				}
			
			}
				
		}
		else if(msg_type == MSG_TYPE_HANDSHAKE_START_ACK){
			if (eee->sn_wait)
			{
				n2n_REGISTER_SUPER_ACK_t ra;
				decode_REGISTER_SUPER_ACK(&ra, &cmn, udp_buf, &rem, &idx);
				
				if (0 == memcmp(ra.cookie, eee->last_cookie, N2N_COOKIE_SIZE))
				{
					eee->last_sup = now;
					memcpy(eee->sn_pub_key, ra.auth.token, ra.auth.toksize);
					
					curve25519_donna(eee->encrypt_key, eee->priv_key, eee->sn_pub_key);
					n2n_transop_cc20_init(eee->encrypt_key, &eee->transop);
					eee->id = cmn.id;
					eee->handshake_status = MSG_TYPE_HANDSHAKE_VERIFY;
					handshake(eee, time(NULL));
					notifyfunc(70, eee->view);
				}
			}
		}else if(msg_type == MSG_TYPE_HANDSHAKE_SUCCESS){
			if (eee->sn_wait)
			{
				n2n_REGISTER_SUPER_ACK_t ra;
				decode_REGISTER_SUPER_ACK(&ra, &cmn, udp_buf, &rem, &idx);
				
				if (0 == memcmp(ra.cookie, eee->last_cookie, N2N_COOKIE_SIZE))
				{
					if (ra.sock.family)
					{
						memcpy(&(eee->device.ip_addr), ra.sock.addr.v4, IPV4_SIZE);
						char tmp[N2N_NETMASK_STR_SIZE];
						char* ip_addr = intoa(ntohl(eee->device.ip_addr), tmp, N2N_NETMASK_STR_SIZE);
						memset(eee->conf->ip_addr_str, 0, N2N_NETMASK_STR_SIZE);
						strncpy(eee->conf->ip_addr_str, ip_addr, strlen(ip_addr));
					}
					eee->last_sup = now;
					eee->sn_wait = 0;
					eee->handshake_status = MSG_TYPE_HANDSHAKE_SUCCESS;
					eee->ping_ok = true;
					notifyfunc(100, eee->view);

				}
			}
		}else if(msg_type == MSG_TYPE_HANDSHAKE_FAIL){
			if (eee->sn_wait)
			{
				eee->handshake_status = MSG_TYPE_HANDSHAKE_FAIL;
			}
		}
		else {
			traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored", (signed int)msg_type);
			return;
		}
	} /* if (community match) */
	else
	{
		traceEvent(TRACE_WARNING, "Received packet with invalid community");
	}
}

int fetch_and_eventually_process_data (n2n_edge_t *eee, SOCKET sock,
                                       uint8_t *pktbuf, uint16_t *expected, uint16_t *position,
                                       time_t now) {

    size_t bread = 0;

    if((!eee->is_tcp) || (sock == eee->udp_multicast_sock)) {
        // udp
        struct sockaddr_in sender_sock;
        socklen_t i;

        i = sizeof(sender_sock);
        bread = recvfrom(sock, pktbuf, N2N_PKT_BUF_SIZE, 0 /*flags*/,
                         (struct sockaddr *)&sender_sock, (socklen_t *)&i);

        if((bread < 0)
#ifdef WIN32
           && (WSAGetLastError() != WSAECONNRESET)
#endif
          ) {
            /* For UDP bread of zero just means no data (unlike TCP). */
            /* The fd is no good now. Maybe we lost our interface. */
            traceEvent(TRACE_ERROR, "fetch_and_eventually_process_data's recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef WIN32
            traceEvent(TRACE_ERROR, "fetch_and_eventually_process_data's WSAGetLastError(): %u", WSAGetLastError());
#endif
            return -1;
        }

        // we have a datagram to process...
        if(bread > 0) {
            // ...and the datagram has data (not just a header)
            process_udp(eee, &sender_sock, sock, pktbuf, bread, now);
        }

    } else {
        // tcp
        struct sockaddr_in sender_sock;
        socklen_t i;

        i = sizeof(sender_sock);
        bread = recvfrom(sock,
                         pktbuf + *position, *expected - *position, 0 /*flags*/,
                        (struct sockaddr *)&sender_sock, (socklen_t *)&i);
        if((bread <= 0) && (errno)) {
            traceEvent(TRACE_ERROR, "fetch_and_eventually_process_data's recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef WIN32
            traceEvent(TRACE_ERROR, "fetch_and_eventually_process_data's WSAGetLastError(): %u", WSAGetLastError());
#endif
            supernode_disconnect(eee);
            eee->sn_wait = 1;
            traceEvent(TRACE_DEBUG, "fetch_and_eventually_process_data disconnected supernode due to connection error");
            return -1;
        }
        *position = *position + bread;

        if(*position == *expected) {
            if(*position == sizeof(uint16_t)) {
                // the prepended length has been read, preparing for the packet
                *expected = *expected + be16toh(*(uint16_t*)(pktbuf));
                if(*expected > N2N_PKT_BUF_SIZE) {
                    supernode_disconnect(eee);
                    eee->sn_wait = 1;
                    traceEvent(TRACE_DEBUG, "run_edge_loop disconnected supernode due to too many bytes expected");
                    return -1;
                }
            } else {
                // full packet read, handle it
                process_udp(eee, (struct sockaddr_in*)&sender_sock, sock,
                                 pktbuf + sizeof(uint16_t), *position - sizeof(uint16_t), now);
                // reset, await new prepended length
                *expected = sizeof(uint16_t);
                *position = 0;
            }
        }
    }
    return 0;
}

int handshake_loop(n2n_edge_t * eee, int *keep_running){
	
	uint16_t expected = sizeof(uint16_t);
    uint16_t position = 0;
    uint8_t  pktbuf[N2N_PKT_BUF_SIZE + sizeof(uint16_t)]; /* buffer + prepended buffer length in case of tcp */

	while (*keep_running && eee->handshake_status != MSG_TYPE_HANDSHAKE_SUCCESS) {
		int rc, max_sock = 0;
		fd_set socket_mask;
		struct timeval wait_time;
		time_t nowTime;

		FD_ZERO(&socket_mask);
		FD_SET(eee->sock, &socket_mask);

		wait_time.tv_sec = 5; wait_time.tv_usec = 0;

		rc = select(eee->sock + 1, &socket_mask, NULL, NULL, &wait_time);
		nowTime = time(NULL);
		if(*keep_running == 0)
			break;

		if (rc > 0) {
			if(FD_ISSET(eee->sock, &socket_mask)) {
               	fetch_and_eventually_process_data(eee, eee->sock,
                                                           pktbuf, &expected, &position,
                                                           nowTime);
                                                           
                if(eee->is_tcp) {
                    if((expected >= N2N_PKT_BUF_SIZE) || (position >= N2N_PKT_BUF_SIZE)) {
                        // something went wrong, possibly even before
                        // e.g. connection failure/closure in the middle of transmission (between len & data)
                        supernode_disconnect(eee);
                        eee->sn_wait = 1;

                        expected = sizeof(uint16_t);
                        position = 0;
                    }
                }
            }
		}
		

		if (eee->sock > 0 && nowTime < (eee->last_register_req + HANDSHAKE_TIMEOUT_INTERVAL))
			continue; /* Too early */
		if(eee->handshake_status != MSG_TYPE_HANDSHAKE_SUCCESS){
			eee->handshake_status = MSG_TYPE_HANDSHAKE_START;
			if(eee->sock < 0){

				if(supernode_connect(eee) < 0){
#ifdef WIN32					
					sleep(3);
#endif					
				}


			}
			notifyfunc(-45, eee->view);
			handshake(&client, time(NULL));
		}

	} /* while */
	return eee->handshake_status == MSG_TYPE_HANDSHAKE_SUCCESS;
}

/* ************************************** */
int run_edge_loop(n2n_edge_t * eee, int *keep_running) {
	
	size_t numPurged;
	time_t lastIfaceCheck = 0;
	time_t lastTransop = 0;
	uint16_t expected = sizeof(uint16_t);
    uint16_t position = 0;
    uint8_t  pktbuf[N2N_PKT_BUF_SIZE + sizeof(uint16_t)]; /* buffer + prepended buffer length in case of tcp */

#ifdef __ANDROID_NDK__
	time_t lastArpPeriod = 0;
#endif

#ifdef WIN32
	startTunReadThread(eee);
#endif

	*keep_running = 1;

	/* Main loop
	 *
	 * select() is used to wait for input on either the TAP fd or the UDP/TCP
	 * socket. When input is present the data is read and processed by either
	 * readFromIPSocket() or readFromTAPSocket()
	 */

	while (*keep_running) {
		int rc, max_sock = 0;
		fd_set socket_mask;
		struct timeval wait_time;
		time_t now;

		FD_ZERO(&socket_mask);
		FD_SET(eee->sock, &socket_mask);
		FD_SET(eee->udp_multicast_sock, &socket_mask);
		max_sock = max(eee->sock, eee->udp_multicast_sock);

#ifndef WIN32
		FD_SET(eee->device.fd, &socket_mask);
		max_sock = max(max_sock, eee->device.fd);
#endif

		wait_time.tv_sec = SOCKET_TIMEOUT_INTERVAL_SECS; wait_time.tv_usec = 0;

		rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);
		now = time(NULL);

		if(rc > 0) {

            if(FD_ISSET(eee->sock, &socket_mask)) {
                if(0 != fetch_and_eventually_process_data(eee, eee->sock,
                                                           pktbuf, &expected, &position,
                                                           now)){
                	*keep_running = 0;
                    break;                                 
                }
                
                if(eee->is_tcp) {
                    if((expected >= N2N_PKT_BUF_SIZE) || (position >= N2N_PKT_BUF_SIZE)) {
                        // something went wrong, possibly even before
                        // e.g. connection failure/closure in the middle of transmission (between len & data)
                        supernode_disconnect(eee);
                        eee->sn_wait = 1;

                        expected = sizeof(uint16_t);
                        position = 0;
                        *keep_running = 0;
                    	break;
                    }
                }
            }

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
            if(FD_ISSET(eee->udp_multicast_sock, &socket_mask)) {
                if (0 != fetch_and_eventually_process_data (eee, eee->udp_multicast_sock,
                                                            pktbuf, &expected, &position,
                                                            now)) {
                    *keep_running = 0;
                    break;
                }
            }
#endif

#ifndef WIN32
            if(FD_ISSET(eee->device.fd, &socket_mask)) {
                // read an ethernet frame from the TAP socket; write on the IP socket
                readFromTAPSocket(eee);
            }
#endif
        }

		if(eee->is_tcp == 0) // in case of udp, try to ping to server.
			ping_to_server(eee, time(NULL));


#ifdef __ANDROID_NDK__
		if ((nowTime - lastArpPeriod) > ARP_PERIOD_INTERVAL) {
			uip_arp_timer();
			lastArpPeriod = nowTime;
		}
#endif /* #ifdef __ANDROID_NDK__ */
	} /* while */
                    
#ifdef WIN32
	Sleep(100);
#else
	//sleep(100);
#endif
	return(0);
}

/* ************************************** */

/** Read in a key-schedule file, parse the lines and pass each line to the
 *  appropriate trans_op for parsing of key-data and adding key-schedule
 *  entries. The lookup table of time->trans_op is constructed such that
 *  encoding can be passed to the correct trans_op. The trans_op internal table
 *  will then determine the best SA for that trans_op from the key schedule to
 *  use for encoding. */

/* ************************************** */

/** Deinitialise the edge and deallocate any owned memory. */
void edge_term(n2n_edge_t * eee) {
#ifdef WIN32
	restoreRouting(eee, eee->device.RouteState);
#endif
#ifdef __APPLE__
	char buf[256];
	memset(buf, 0, 256);
	//resore default route
	if(eee->gw_ip[0] != '\0'){
		snprintf(buf, sizeof(buf), "route delete 0.0.0.0");
	    system(buf);
	    memset(buf, 0, 256);
		snprintf(buf, sizeof(buf), "route add 0.0.0.0 %s", eee->gw_ip);
	    system(buf);
	}
	
#endif
	tuntap_close(&eee->device);

	if (eee->sock >= 0)
		closesocket(eee->sock);

	if (eee->udp_multicast_sock >= 0)
		closesocket(eee->udp_multicast_sock);

	if(eee->transop.deinit)
		eee->transop.deinit(&eee->transop);
	ReleaseHashList(eee->filter_list);
	eee->filter_list = NULL;
	htree_free(eee->filter_dns_list);
	eee->filter_dns_list = NULL;
	FreeMayaqua();
}

bool filter_packet(n2n_edge_t* edge, uint8_t *tap_pkt, size_t len) {
	bool ret = false;
	PKT * packet;
	if(edge->device.tuntap_mode == TUN_MODE){
		packet = ZeroMallocFast(sizeof(PKT));
		ParsePacketIPv4(packet, tap_pkt, len);
		PKT *p = packet;
		USHORT port_raw = Endian16(80);
		USHORT port_raw2 = Endian16(8080);
		USHORT port_raw3 = Endian16(443);
		USHORT port_raw4 = Endian16(3128);

		// Analyze if the packet is a part of HTTP
		if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) && p->TypeL4 == L4_TCP)
		{
			TCP_HEADER *tcp = p->L4.TCPHeader;
			if (tcp != NULL && (tcp->DstPort == port_raw || tcp->DstPort == port_raw2 || tcp->DstPort == port_raw4) &&
				(!((tcp->Flag & TCP_SYN) || (tcp->Flag & TCP_RST) || (tcp->Flag & TCP_FIN))))
			{
				if (p->PayloadSize >= 1)
				{
					p->HttpLog = ParseHttpAccessLog(p);
				}
			}
			if (tcp != NULL && tcp->DstPort == port_raw3 &&
				(!((tcp->Flag & TCP_SYN) || (tcp->Flag & TCP_RST) || (tcp->Flag & TCP_FIN))))
			{
				if (p->PayloadSize >= 1)
				{
					p->HttpLog = ParseHttpsAccessLog(p);
				}
			}
		}
	}else{
		packet = ParsePacket(tap_pkt, len);
	}
	
	if (packet->TypeL3 == L3_IPV4)
	{
		IPV4_HEADER* ip = packet->L3.IPv4Header;
		FILTER_TABLE_ENTRY *e = ZeroMalloc(sizeof(FILTER_TABLE_ENTRY));
		e->ip = ip->DstIP;
		FILTER_TABLE_ENTRY *entry = SearchHash(edge->filter_list, e);
		Free(e);
		ret = (entry != NULL);
		if(ret == false)
			ret = ( ip_search(ip->DstIP, edge->ip_sets, edge->ip_set_count ) >= 0 );
		if (ret == false && (packet->TypeL7 == L7_DNS || (packet->HttpLog != NULL && packet->HttpLog->IsSsl)))
		{
			char* target = packet->TypeL7 == L7_DNS ? packet->DnsQueryHost : packet->HttpLog->Hostname;
			HTREE_NODE * node = domain_match(edge->filter_dns_list, target);
			if (node == NULL) {
				ret = 0;
			}
			else if(node->sub == NULL || node->depth>2) {
				ret = 1;
			}
			else {
				ret = 0;
			}
		}
		
	}
	FreePacket(packet);
	return ret;
}

void readFromTAPSocket(n2n_edge_t * eee) {
	/* tun -> remote */
	uint8_t             eth_pkt[N2N_PKT_BUF_SIZE];
	macstr_t            mac_buf;
	ssize_t             len;

	if(eee->handshake_status != MSG_TYPE_HANDSHAKE_SUCCESS){
		return;
	}

#ifdef WIN32
#ifndef testmode	
	setDefaultRouting(eee);
#endif
#endif

#ifdef __ANDROID_NDK__
	if (uip_arp_len != 0) {
		len = uip_arp_len;
		memcpy(eth_pkt, uip_arp_buf, MIN(uip_arp_len, N2N_PKT_BUF_SIZE));
		traceEvent(TRACE_DEBUG, "ARP reply packet to send");
	}
	else
	{
#endif /* #ifdef __ANDROID_NDK__ */
		len = tuntap_read(&(eee->device), eth_pkt, N2N_PKT_BUF_SIZE);
#ifdef __ANDROID_NDK__
	}
#endif /* #ifdef __ANDROID_NDK__ */

	if ((len <= 0) || (len > N2N_PKT_BUF_SIZE))
	{
		traceEvent(TRACE_WARNING, "read()=%d [%d/%s]",
			(signed int)len, errno, strerror(errno));
	}
	else
	{
		const uint8_t *buf = NULL;
#ifdef __APPLE__
	buf = eth_pkt + 4;
	len = len - 4;
#else
	buf = eth_pkt;
#endif
		
		if (eee->drop_multicast && (is_ip6_discovery(buf, len) || is_ethMulticast(buf, len)))
		{
			traceEvent(TRACE_DEBUG, "Dropping multicast");
		}
		else
		{
			
			if (filter_packet(eee, buf, len)) {
				return;
			}
			if(eee->device.tuntap_mode == TUN_MODE){
					traceEvent(TRACE_INFO, "### Rx TAP packet (%4d) for %s",
								(signed int)len, macaddr_str(mac_buf, buf));
				int *dst = buf + IP4_DSTOFFSET;
				if(*dst == eee->device.ip_addr){
					tuntap_write(&eee->device, buf, len);
					return;
				}
			}else{
				traceEvent(TRACE_INFO, "### Rx TAP packet %d",buf[0]);
			}
			if(eee->keep_on_running)
				edge_send_packet2net(eee, buf, len);
		}
	}
}
