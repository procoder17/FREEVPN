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
 * netsh interface ipv4 add neighbors "Ethernet" 192.168.100.24  00-38-70-45-79-e7
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */
 

#include "n2n.h"
#ifdef WIN32
#include <sys/stat.h>
#endif
 
n2n_log				logfunc;
n2n_progress_notify notifyfunc;

 /* *************************************************** */

 /** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH    4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH     1024

/* ***************************************************** */



/* ***************************************************** */

/** Find the address and IP mode for the tuntap device.
 *
 *  s is one of these forms:
 *
 *  <host> := <hostname> | A.B.C.D
 *
 *  <host> | static:<host> | dhcp:<host>
 *
 *  If the mode is present (colon required) then fill ip_mode with that value
 *  otherwise do not change ip_mode. Fill ip_mode with everything after the
 *  colon if it is present; or s if colon is not present.
 *
 *  ip_add and ip_mode are NULL terminated if modified.
 *
 *  return 0 on success and -1 on error
 */
static int scan_address(char * ip_addr, size_t addr_size,
	char * ip_mode, size_t mode_size,
	const char * s) {
	int retval = -1;
	char * p;

	if ((NULL == s) || (NULL == ip_addr))
	{
		return -1;
	}

	memset(ip_addr, 0, addr_size);

	p = strpbrk(s, ":");

	if (p)
	{
		/* colon is present */
		if (ip_mode)
		{
			size_t end = 0;

			memset(ip_mode, 0, mode_size);
			end = MIN(p - s, (ssize_t)(mode_size - 1)); /* ensure NULL term */
			strncpy(ip_mode, s, end);
			strncpy(ip_addr, p + 1, addr_size - 1); /* ensure NULL term */
			retval = 0;
		}
	}
	else
	{
		/* colon is not present */
		strncpy(ip_addr, s, addr_size);
	}

	return retval;
}

/* *************************************************** */


#if defined(DUMMY_ID_00001) /* Disabled waiting for config option to enable it */

static char gratuitous_arp[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Dest mac */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
  0x08, 0x06, /* ARP */
  0x00, 0x01, /* Ethernet */
  0x08, 0x00, /* IP */
  0x06, /* Hw Size */
  0x04, /* Protocol Size */
  0x00, 0x01, /* ARP Request */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
  0x00, 0x00, 0x00, 0x00, /* Src IP */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Target mac */
  0x00, 0x00, 0x00, 0x00 /* Target IP */
};

/* ************************************** */

/** Build a gratuitous ARP packet for a /24 layer 3 (IP) network. */
static int build_gratuitous_arp(char *buffer, uint16_t buffer_len) {
	if (buffer_len < sizeof(gratuitous_arp)) return(-1);

	memcpy(buffer, gratuitous_arp, sizeof(gratuitous_arp));
	memcpy(&buffer[6], device.mac_addr, 6);
	memcpy(&buffer[22], device.mac_addr, 6);
	memcpy(&buffer[28], &device.ip_addr, 4);

	/* REVISIT: BbMaj7 - use a real netmask here. This is valid only by accident
	 * for /24 IPv4 networks. */
	buffer[31] = 0xFF; /* Use a faked broadcast address */
	memcpy(&buffer[38], &device.ip_addr, 4);
	return(sizeof(gratuitous_arp));
}

/* ************************************** */

/** Called from update_supernode_reg to periodically send gratuitous ARP
 *  broadcasts. */
static void send_grat_arps(n2n_edge_t * eee, ) {
	char buffer[48];
	size_t len;

	traceEvent(TRACE_NORMAL, "Sending gratuitous ARP...");
	len = build_gratuitous_arp(buffer, sizeof(buffer));
	edge_send_packet2net(eee, buffer, len);
	edge_send_packet2net(eee, buffer, len); /* Two is better than one :-) */
}

#endif /* #if defined(DUMMY_ID_00001) */

/* ************************************** */

static void daemonize() {
#ifndef WIN32
	int childpid;

	traceEvent(TRACE_NORMAL, "Parent process is exiting (this is normal)");

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);

	if ((childpid = fork()) < 0)
		traceEvent(TRACE_ERROR, "Occurred while daemonizing (errno=%d)",
			errno);
	else {
		if (!childpid) { /* child */
			int rc;

			//traceEvent(TRACE_NORMAL, "Bye bye: I'm becoming a daemon...");
			rc = chdir("/");
			if (rc != 0)
				traceEvent(TRACE_ERROR, "Error while moving to / directory");

			setsid();  /* detach from the terminal */

			fclose(stdin);
			fclose(stdout);
			/* fclose(stderr); */

			/*
			 * clear any inherited file mode creation mask
			 */
			 //umask(0);

			 /*
			  * Use line buffered stdout
			  */
			  /* setlinebuf (stdout); */
			setvbuf(stdout, (char *)NULL, _IOLBF, 0);
		}
		else /* father */
			exit(0);
	}
#endif
}


n2n_edge_t client;

void startVpn(vpn_conf_t *conf)
{

	int     rc;
	int     i;

	if (-1 == edge_init(&client, conf)) {
		traceEvent(TRACE_ERROR, "Failed in edge_init");
		exit(1);
	}

#ifndef WIN32
	if (client.daemon) {
		useSyslog = 1; /* traceEvent output now goes to syslog. */
		//daemonize();
	}
#endif /* #ifndef WIN32 */

#ifndef WIN32
	/* If running suid root then we need to setuid before using the force. */
	setuid(0);
	/* setgid(0); */
#endif

	notifyfunc(35,client.view);
	if (client.lport > 0)
		traceEvent(TRACE_NORMAL, "Binding to local port %d", (signed int)client.lport);
	
	supernode_connect(&client);

	/* Populate the multicast group for local edge */
	client.multicast_peer.family = AF_INET;
	client.multicast_peer.port = N2N_MULTICAST_PORT;
	client.multicast_peer.addr.v4[0] = 224; /* N2N_MULTICAST_GROUP */
	client.multicast_peer.addr.v4[1] = 0;
	client.multicast_peer.addr.v4[2] = 0;
	client.multicast_peer.addr.v4[3] = 68;


	client.udp_multicast_sock = open_socket(N2N_MULTICAST_PORT, 1 /* bind ANY */, 0); //udp
	if (client.udp_multicast_sock < 0)
		return;
	else {
		/* Bind eee.udp_multicast_sock to multicast group */
		struct ip_mreq mreq;
		u_int enable_reuse = 1;

		/* allow multiple sockets to use the same PORT number */
		setsockopt(client.udp_multicast_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable_reuse, sizeof(enable_reuse));
#ifndef WIN32 /* no SO_REUSEPORT in Windows */
		setsockopt(client.udp_multicast_sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&enable_reuse, sizeof(enable_reuse));
#endif

		mreq.imr_multiaddr.s_addr = inet_addr(N2N_MULTICAST_GROUP);
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if (setsockopt(client.udp_multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char*)&mreq, sizeof(mreq)) < 0) {
			traceEvent(TRACE_ERROR, "Failed to bind to local multicast group %s:%u",
				N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
			return;
		}
	}

	traceEvent(TRACE_NORMAL, "edge started");

	notifyfunc(55, client.view);

	handshake(&client, time(NULL));
	int ret = handshake_loop(&client, &client.keep_on_running);

	if(ret){
		traceEvent(TRACE_INFO, "STARTING TUN OPEN");
		if (tuntap_open(&(client.device), client.device.dev_name, client.conf->ip_addr_str, client.conf->netmask_str, client.conf->device_mac_str, client.device.mtu) < 0)
			return;
		traceEvent(TRACE_NORMAL, "tuntap open success");
	
#ifdef WIN32
		setRoutingToServer(&client, &client.device);
#endif
		run_edge_loop(&client, &client.keep_on_running);
	}

}
