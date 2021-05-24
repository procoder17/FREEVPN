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

void ping_to_server(n2n_edge_t * eee, time_t nowTime){
	u_int sn_idx;

	if (nowTime < (eee->last_register_req + PING_INTERVAL) || nowTime < (eee->last_sup + PING_INTERVAL))
		return; /* Too early */

	if(!eee->ping_ok){	//ping failed. maybe disconnected.
		
		eee->handshake_status = MSG_TYPE_HANDSHAKE_START;
		notifyfunc(-45, eee->view);
		handshake(&client, time(NULL));
		
	}else if(eee->handshake_status == MSG_TYPE_HANDSHAKE_SUCCESS){	// send a ping requst
		uint8_t pktbuf[N2N_PKT_BUF_SIZE];
		size_t idx;
		/* ssize_t sent; */
		n2n_common_t cmn;
		n2n_PING_SERVER_t reg;
	
		memset(&cmn, 0, sizeof(cmn));
		memset(&reg, 0, sizeof(reg));
		cmn.id = eee->id;
		cmn.pc = MSG_TYPE_PING_REQUEST;
		cmn.flags = 0;
		cmn.flags |= (( eee->device.tuntap_mode == TAP_MODE ) ? N2N_FLAGS_TAP : N2N_FLAGS_TUN);
    	memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

		for (idx = 0; idx < N2N_COOKIE_SIZE; ++idx)
			eee->last_cookie[idx] = rand() % 0xff;
	
		memcpy(reg.cookie, eee->last_cookie, N2N_COOKIE_SIZE);
		if(eee->device.tuntap_mode == TAP_MODE){
			idx = 0;
			encode_mac(reg.edgeMac, &idx, eee->device.mac_addr);
		}

		idx = 0;
		encode_PING_SUPER(pktbuf, &idx, &cmn, &reg);
	
		int ret = sendto_sock(eee, pktbuf, idx, &(eee->supernode));
		if(ret < 0){
			eee->ping_ok = 0;
			eee->sn_wait = 1;
			ping_to_server(eee, nowTime);
		}else{
			eee->last_register_req = nowTime;
			eee->ping_ok = 0;
			eee->sn_wait = 1;
		}

	}

}
/* ************************************** */

/** Keep the known_peers list straight.
 *
 *  Ignore broadcast L2 packets, and packets with invalid public_ip.
 *  If the dst_mac is in known_peers make sure the entry is correct:
 *  - if the public_ip socket has changed, erase the entry
 *  - if the same, update its last_seen = when
 */
 
 /* ************************************** */
// open socket, close it before if TCP
// in case of TCP, 'connect()' is required
int supernode_connect(n2n_edge_t *eee) {

    int sockopt;

     if((eee->is_tcp) && (eee->sock >= 0)) {
        closesocket(eee->sock);
        eee->sock = -1;
    }

    if(eee->sock < 0) {
		eee->sock = open_socket(eee->lport, 1 /* bind ANY */, eee->is_tcp);
		if (eee->sock < 0) {
			traceEvent(TRACE_ERROR, "Failed to bind main UDP port %u", (signed int)eee->lport);
			return -1;
		}
    }
    struct sockaddr_in sock;
    sock.sin_family = AF_INET;
    sock.sin_port = htons(eee->supernode.port);
    memcpy(&(sock.sin_addr.s_addr), &(eee->supernode.addr.v4), IPV4_SIZE);

    if(eee->is_tcp) {
#ifdef WIN32
        u_long value = 1;
        ioctlsocket(eee->sock, FIONBIO, &value);
#else
		int flags;
	    flags = fcntl(eee->sock, F_GETFL, 0);
	    fcntl(eee->sock, F_SETFL, flags | O_NONBLOCK);
#endif
        int ret = connect(eee->sock, (struct sockaddr*)&(sock), sizeof(struct sockaddr));
        //int error = WSAGetLastError();;
        if( ret < 0 && (GETSOCKETERRNO() != INPROGRESS)) {
            eee->sock = -1;
            int what = errno;
            return -1;
        }
#if defined(_WIN32)
	    value = 0;
	    ioctlsocket(eee->sock, FIONBIO, &value);
#else
    	fcntl(eee->sock, F_SETFL, flags);
#endif
    }
    return 1;
}

n2n_mac_t broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static void send_handshake_super(n2n_edge_t * eee, const n2n_sock_t * supernode)
{
	uint8_t pktbuf[N2N_PKT_BUF_SIZE];
	size_t idx;
	/* ssize_t sent; */
	n2n_common_t cmn;
	n2n_REGISTER_SUPER_t reg;
	n2n_sock_str_t sockbuf;

	memset(&cmn, 0, sizeof(cmn));
	memset(&reg, 0, sizeof(reg));
	cmn.id = 0;
	cmn.pc = eee->handshake_status;
	cmn.flags = 0;
	memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

	for (idx = 0; idx < N2N_COOKIE_SIZE; ++idx)
		eee->last_cookie[idx] = rand() % 0xff;

	memcpy(reg.cookie, eee->last_cookie, N2N_COOKIE_SIZE);
	reg.auth.scheme = eee->handshake_status;
	reg.auth.toksize = 0;
	switch(eee->handshake_status){
		
		case MSG_TYPE_HANDSHAKE_START:
			memcpy(reg.auth.token, eee->pub_key, N2N_AUTH_KEY_SIZE);
			reg.auth.toksize = N2N_AUTH_KEY_SIZE;
			break;
		case MSG_TYPE_HANDSHAKE_VERIFY:
			//memcpy(reg.auth.token, eee->token.token, eee->token.toksize);

			idx = eee->transop.fwd(&eee->transop, reg.auth.token, N2N_AUTH_TOKEN_SIZE ,
				eee->token.token, eee->token.toksize, 0);
			reg.auth.toksize = idx;
			reg.edgeTapIp = eee->device.ip_addr;
			cmn.id = eee->id;

			break;
		default:
			break;
	}
	
	if(eee->device.tuntap_mode == TAP_MODE){
		idx = 0;
		encode_mac(reg.edgeMac, &idx, eee->device.mac_addr);
	}
	
	idx = 0;

	cmn.flags |= (( eee->device.tuntap_mode == TAP_MODE ) ? N2N_FLAGS_TAP : N2N_FLAGS_TUN);
    encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

	traceEvent(TRACE_INFO, "send HANDSHAKE_SUPER to %s",	sock_to_cstr(sockbuf, supernode));

	sendto_sock(eee, pktbuf, idx, supernode);
}
void handshake(n2n_edge_t* edge, time_t nowTime)
{
	send_handshake_super(edge, &(edge->supernode));
	edge->sn_wait = 1;
	edge->last_register_req = nowTime;
}
