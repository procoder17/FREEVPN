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

#ifdef __APPLE__
#include "n2n.h"
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <sys/kern_event.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2
#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))


struct rtmsg {
    struct rt_msghdr m_rtm;
    char m_space[512];
};


#define TARGET_DARWIN

#if defined(TARGET_DARWIN)
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#elif defined(TARGET_NETBSD)
#define ROUNDUP(a) RT_ROUNDUP(a)
#else
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif
#define max(a,b) ((a) > (b) ? (a) : (b))

#define NEXTADDR(w, u) \
    if (rtm_addrs & (w)) { \
        l = ((struct sockaddr *)&(u))->sa_len; memmove(cp, &(u), l); cp += ROUNDUP(l); \
    }

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define CLEAR(x) memset(&(x), 0, sizeof(x))

void get_default_gateway(struct route_gateway_info *rgi)
{
    struct rtmsg m_rtmsg;
    int sockfd = -1;
    int seq, l, pid, rtm_addrs;
    unsigned int i;
    struct sockaddr so_dst, so_mask;
    char *cp = m_rtmsg.m_space;
    struct sockaddr *gate = NULL, *ifp = NULL, *sa;
    struct  rt_msghdr *rtm_aux;
    const int bufsize = 4096;
    char *buffer = NULL;
        
#define rtm m_rtmsg.m_rtm

    CLEAR(*rgi);

    /* setup data to send to routing socket */
    pid = getpid();
    seq = 0;
    rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;

    bzero(&m_rtmsg, sizeof(m_rtmsg));
    bzero(&so_dst, sizeof(so_dst));
    bzero(&so_mask, sizeof(so_mask));
    bzero(&rtm, sizeof(struct rt_msghdr));

    rtm.rtm_type = RTM_GET;
    rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_seq = ++seq;
#ifdef TARGET_OPENBSD
    rtm.rtm_tableid = getrtable();
#endif
    rtm.rtm_addrs = rtm_addrs;

    so_dst.sa_family = AF_INET;
    so_mask.sa_family = AF_INET;

#ifndef TARGET_SOLARIS
    so_dst.sa_len = sizeof(struct sockaddr_in);
    so_mask.sa_len = sizeof(struct sockaddr_in);
#endif

    NEXTADDR(RTA_DST, so_dst);
    NEXTADDR(RTA_NETMASK, so_mask);

    rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

    /* transact with routing socket */
    sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (sockfd < 0)
    {
        printf( "GDG: socket #1 failed");
        goto done;
    }
    if (write(sockfd, (char *)&m_rtmsg, l) < 0)
    {
        printf( "GDG: problem writing to routing socket");
        goto done;
    }
    do
    {
        l = read(sockfd, (char *)&m_rtmsg, sizeof(m_rtmsg));
    } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
    close(sockfd);
    sockfd = -1;

    /* extract return data from routing socket */
    rtm_aux = &rtm;
    cp = ((char *)(rtm_aux + 1));
    if (rtm_aux->rtm_addrs)
    {
        for (i = 1; i; i <<= 1)
        {
            if (i & rtm_aux->rtm_addrs)
            {
                sa = (struct sockaddr *)cp;
                if (i == RTA_GATEWAY)
                {
                    gate = sa;
                }
                else if (i == RTA_IFP)
                {
                    ifp = sa;
                }
                ADVANCE(cp, sa);
            }
        }
    }
    else
    {
        goto done;
    }

    /* get gateway addr and interface name */
    if (gate != NULL)
    {
        /* get default gateway addr */
        rgi->gateway.addr = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
        if (rgi->gateway.addr)
        {
            rgi->flags |= RGI_ADDR_DEFINED;
        }

        if (ifp)
        {
            /* get interface name */
            const struct sockaddr_dl *adl = (struct sockaddr_dl *) ifp;
            if (adl->sdl_nlen && adl->sdl_nlen < sizeof(rgi->iface))
            {
                memcpy(rgi->iface, adl->sdl_data, adl->sdl_nlen);
                rgi->iface[adl->sdl_nlen] = '\0';
                rgi->flags |= RGI_IFACE_DEFINED;
            }
        }
    }

    /* get netmask of interface that owns default gateway */
    if (rgi->flags & RGI_IFACE_DEFINED)
    {
        struct ifreq ifr;

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            printf( "GDG: socket #2 failed");
            goto done;
        }

        CLEAR(ifr);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, rgi->iface, IFNAMSIZ);

        if (ioctl(sockfd, SIOCGIFNETMASK, (char *)&ifr) < 0)
        {
            printf( "GDG: ioctl #1 failed");
            goto done;
        }
        close(sockfd);
        sockfd = -1;

        rgi->gateway.netmask = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
        rgi->flags |= RGI_NETMASK_DEFINED;
    }

    /* try to read MAC addr associated with interface that owns default gateway */
    if (rgi->flags & RGI_IFACE_DEFINED)
    {
        struct ifconf ifc;
        struct ifreq *ifr;

        buffer = (char *) malloc(bufsize);
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            printf( "GDG: socket #3 failed");
            goto done;
        }

        ifc.ifc_len = bufsize;
        ifc.ifc_buf = buffer;

        if (ioctl(sockfd, SIOCGIFCONF, (char *)&ifc) < 0)
        {
            printf( "GDG: ioctl #2 failed");
            goto done;
        }
        close(sockfd);
        sockfd = -1;

        for (cp = buffer; cp <= buffer + ifc.ifc_len - sizeof(struct ifreq); )
        {
            ifr = (struct ifreq *)cp;
#if defined(TARGET_SOLARIS)
            const size_t len = sizeof(ifr->ifr_name) + sizeof(ifr->ifr_addr);
#else
            const size_t len = sizeof(ifr->ifr_name) + max(sizeof(ifr->ifr_addr), ifr->ifr_addr.sa_len);
#endif

            if (!ifr->ifr_addr.sa_family)
            {
                break;
            }
            if (!strncmp(ifr->ifr_name, rgi->iface, IFNAMSIZ))
            {
                if (ifr->ifr_addr.sa_family == AF_LINK)
                {
                    struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr->ifr_addr;
                    memcpy(rgi->hwaddr, LLADDR(sdl), 6);
                    rgi->flags |= RGI_HWADDR_DEFINED;
                }
            }
            cp += len;
        }
    }

done:
    if (sockfd >= 0)
    {
        close(sockfd);
    }
    if(buffer != NULL)
    	free(buffer);
}

void tun_close(tuntap_dev *device);

/* ********************************** */
int open_tun_socket (tuntap_dev *device) {
	
	  struct sockaddr_ctl addr;
	  struct ctl_info info;
	  char ifname[20];
	  memset(ifname, 0, 20);
	  socklen_t ifname_len = sizeof(ifname);
	  int fd = -1;
	  int err = 0;
	
	  fd = socket (PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	  if (fd < 0) return fd;
	
	  bzero(&info, sizeof (info));
	  strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
	
	  err = ioctl(fd, CTLIOCGINFO, &info);
	  if (err != 0) goto on_error;
	
	  addr.sc_len = sizeof(addr);
	  addr.sc_family = AF_SYSTEM;
	  addr.ss_sysaddr = AF_SYS_CONTROL;
	  addr.sc_id = info.ctl_id;
	  addr.sc_unit = 3;
	
	  err = connect(fd, (struct sockaddr *)&addr, sizeof (addr));
	  if (err != 0) goto on_error;
	
	  err = getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len);
	  if (err != 0) goto on_error;
	  device->ifName = strdup(ifname);
	  // There is to close the socket,But in this case I don't need it.

	  err = fcntl(fd, F_SETFL, O_NONBLOCK);
	  if (err != 0) goto on_error;
	
	  fcntl(fd, F_SETFD, FD_CLOEXEC);
	  if (err != 0) goto on_error;
	
	on_error:
	  if (err != 0) {
	    close(fd);
	    return err;
	  }

  return fd;
}

void setRouting(tuntap_dev *device , char *device_ip, int mtu){
	
	char buf[256];
	memset(buf, 0, 256);
    
	struct route_gateway_info rgi;
	memset(&rgi, 0, sizeof(rgi));
	if(client.gw_ip[0] == '\0'){
		traceEvent(TRACE_NORMAL, "Getting Gateway address!");
		
		get_default_gateway(&rgi);
		if(rgi.gateway.addr != 0){// in case of success
			rgi.gateway.addr = htonl(rgi.gateway.addr);
			inet_ntop(AF_INET, (struct in_addr*)&rgi.gateway.addr, client.gw_ip, sizeof(client.gw_ip));
		}
	}
	if(client.gw_ip[0] != '\0'){// in case of success
			
		const char *server_ip = strtok(client.sn_ip, ":");
		
		//generate route to vpn server
		memset(buf, 0, 256);		
		snprintf(buf, sizeof(buf), "route add %s/32 %s", server_ip, client.gw_ip);
	    system(buf);
	    
	}
	
	memset(buf, 0, 256);
	snprintf(buf, sizeof(buf), "ifconfig %s down", device->ifName);
    system(buf);
    
    memset(buf, 0, 256);
	snprintf(buf, sizeof(buf), "ifconfig %s %s %s netmask 255.255.255.0 mtu %d up",
             device->ifName, device_ip, device_ip, mtu);
    system(buf);

    traceEvent(TRACE_NORMAL, "Interface %s up and running (%s)",
               device->ifName, device_ip);

	memset(buf, 0, 256);
	snprintf(buf, sizeof(buf), "route add -net 192.168.137.0 -netmask 255.255.255.0 %s", device_ip);
    system(buf);	
   
    //remove default route
	memset(buf, 0, 256);	
	snprintf(buf, sizeof(buf), "route delete 0.0.0.0");
    system(buf);
		
	//add new route
	memset(buf, 0, 256);	
	snprintf(buf, sizeof(buf), "route add 0.0.0.0 192.168.137.1");
    system(buf);
    
    snprintf(buf, sizeof(buf), "sysctl -w net.inet.ip.forwarding=1");
    system(buf);
   /*
    void *tmpfd = UnixFileCreate("/tmp/nat_rules_rt");
	if(tmpfd != NULL){
		traceEvent(TRACE_NORMAL, "Add NAT rule to firewall.");
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "rdr on utun2 from 192.168.137.103 to any -> ( en0 )\n", device->ifName);
	    UnixFileWrite(tmpfd, buf, strlen(buf));
	    UnixFileClose(tmpfd, true);
	    
	    memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "pfctl -qd 2>&1 > /dev/null || true");
	    system(buf);
	    
	    memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "pfctl -qF all 2>&1 > /dev/null || true");
	    system(buf);
	    
	    memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "pfctl -qf /tmp/nat_rules_rt -e");
	    system(buf);
	}else{
		traceEvent(TRACE_NORMAL, "Failed to write nat rule file to /tmp");
	}
*/
}

#define N2N_OSX_TAPDEVICE_SIZE 32
int tuntap_open(tuntap_dev *device /* ignored */, 
                char *dev, 
                char *device_ip, 
                char *device_mask,
                const char * device_mac,
		int mtu) {
  int i;
  char tap_device[N2N_OSX_TAPDEVICE_SIZE];

  device->fd = open_tun_socket(device);
  device->ip_addr = inet_addr(device_ip);
/*  return device->fd;
  
  for (i = 0; i < 255; i++) {
    snprintf(tap_device, sizeof(tap_device), "/dev/tap%d", i);

    device->fd = open(tap_device, O_RDWR);
    if(device->fd > 0) {
      traceEvent(TRACE_NORMAL, "Succesfully open %s", tap_device);
      break;
    }
  }
*/  
  if(device->fd < 0) {
    traceEvent(TRACE_ERROR, "Unable to open tap device %s", tap_device);
    traceEvent(TRACE_ERROR, "Please read https://github.com/ntop/n2n/blob/dev/doc/n2n_on_MacOS.txt");
    return(-1);
  } else {
	
	setRouting(device, device_ip, mtu);
   
	//randomize mac
	int i;

    

  }
  return(device->fd);
}

/* ********************************** */

int tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
  return(read(tuntap->fd, buf, len));
}

/* ********************************** */

int tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
	
	uint8_t tmpbuf[len + 4];
	tmpbuf[0] = 0;
	tmpbuf[1] = 0;
	tmpbuf[2] = 0;
	tmpbuf[3] = 2;
	memcpy(tmpbuf + 4, buf, len);
  	return(write(tuntap->fd, tmpbuf, len + 4));

}

/* ********************************** */

void tuntap_close(struct tuntap_dev *tuntap) {
  	close(tuntap->fd);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap)
{
#ifndef WIN32

#endif	
}

#endif /* __APPLE__ */
