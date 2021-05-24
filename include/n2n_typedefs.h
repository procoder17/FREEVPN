
#ifndef _N2N_TYPEDEFS_H_
#define _N2N_TYPEDEFS_H_


#if defined(_MSC_VER) || defined(__MINGW32__)
//#include "win32/getopt.h"

/* Other Win environments are expected to support stdint.h */

/* stdint.h typedefs (C99) (not present in Visual Studio) */
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

/* sys/types.h typedefs (not present in Visual Studio) */
typedef unsigned int u_int32_t;
typedef unsigned short u_int16_t;
typedef unsigned char u_int8_t;

#ifndef __MINGW32__
typedef int ssize_t;
#endif

typedef unsigned long in_addr_t;

#include "win32/n2n_win32.h"

#endif /* #if defined(_MSC_VER) || defined(__MINGW32__) */



#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <machine/endian.h>
#endif

#ifdef __OpenBSD__
#include <endian.h>
#define __BYTE_ORDER BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif /* __LITTLE_ENDIAN__ */
#else
#define __BIG_ENDIAN__
#endif/* BYTE_ORDER */
#endif/* __OPENBSD__ */


#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif
#else
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__
#endif
#endif

#ifdef WIN32
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__ 1
#endif
#endif

#if !(defined(__LITTLE_ENDIAN__) || defined(__BIG_ENDIAN__))
#if defined(__mips__)
#undef __LITTLE_ENDIAN__
#undef __LITTLE_ENDIAN
#define __BIG_ENDIAN__
#endif

/* Everything else */
#if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#else
#define __BIG_ENDIAN__
#endif
#endif

#endif

#define ETH_ADDR_LEN 6
struct ether_hdr
{
	uint8_t  dhost[ETH_ADDR_LEN];
	uint8_t  shost[ETH_ADDR_LEN];
	uint16_t type;                /* higher layer protocol encapsulated */
}GCC_PACKED;

typedef struct ether_hdr ether_hdr_t;


#ifndef WIN32

typedef struct tuntap_dev {
	int           	fd;
	int           	if_idx;
	char    	  	ip_addr_str[N2N_NETMASK_STR_SIZE];
	char    		netmask_str[N2N_NETMASK_STR_SIZE];
	char    		device_mac_str[N2N_MACNAMSIZ];
	uint8_t       	mac_addr[6];
	uint32_t      	ip_addr, device_mask;
	uint16_t      	mtu;
    char          	dev_name[256];
	char 			*ifName;
	ROUTE_TRACKING *RouteState;
	uint8_t				tuntap_mode;
} tuntap_dev;


#define SOCKET int
#endif /* #ifndef WIN32 */

 /** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[32];

/** Common type used to hold stringified MAC addresses. */
#define N2N_MACSTR_SIZE 32
typedef char macstr_t[N2N_MACSTR_SIZE];

struct FILTER_TABLE_ENTRY
{
	uint32_t	ip;
};

typedef struct FILTER_TABLE_ENTRY FILTER_TABLE_ENTRY;

typedef char n2n_sn_name_t[N2N_EDGE_SN_HOST_SIZE];

struct htree_node {
	char *label;              /* key */
	void *ptr;
	uint32_t h1;              /* from hash function 1 */
	uint32_t h2;
	struct htree_node **sub;  /* the hash table */
	unsigned sub_size;        /* size of hash table */
	int sub_count;            /* items stored in hash table */
	int sub_loadmax;          /* max items stored before upsizing sub */
	int sub_maxprobe;         /* max probes for insertion, upsizing upon reach */
	int depth;
};

typedef struct ip_set {
	int 	lo;
	int		hi;
}ip_set;

typedef struct htree_node HTREE_NODE;

struct sn_stats {
	size_t errors;              /* Number of errors encountered. */
	size_t reg_super;           /* Number of REGISTER_SUPER requests received. */
	size_t reg_super_nak;       /* Number of REGISTER_SUPER requests declined. */
	size_t fwd;                 /* Number of messages forwarded. */
	size_t broadcast;           /* Number of messages broadcast to a community. */
	time_t last_fwd;            /* Time when last message was forwarded. */
	time_t last_reg_super;      /* Time when last REGISTER_SUPER was received. */
};

typedef struct sn_stats sn_stats_t;


typedef struct {
	int     local_port;
	int     mgmt_port;
	char    tuntap_dev_name[N2N_IFNAMSIZ];
	char    ip_addr[N2N_NETMASK_STR_SIZE];
	char    ip_mode[N2N_IF_MODE_SIZE];
	char    netmask[N2N_NETMASK_STR_SIZE];
	int     mtu;
	int     got_s;
	char    device_mac[N2N_MACNAMSIZ];
	char  	encrypt_key[N2N_AUTH_KEY_SIZE];
#ifndef WIN32
	uid_t   userid;
	gid_t   groupid;
#endif
} edge_conf_t;


typedef uint8_t n2n_community_t[N2N_COMMUNITY_SIZE];
typedef uint8_t n2n_mac_t[N2N_MAC_SIZE];
typedef uint8_t n2n_cookie_t[N2N_COOKIE_SIZE];

typedef char    n2n_sock_str_t[N2N_SOCKBUF_SIZE];       /* tracing string buffer */

enum n2n_pc
{
    n2n_ping=0,                 /* Not used */
    n2n_register=1,             /* Register edge to edge */
    n2n_deregister=2,           /* Deregister this edge */
    n2n_packet=3,               /* PACKET data content */
    n2n_register_ack=4,         /* ACK of a registration from edge to edge */
    n2n_register_super=5,       /* Register edge to supernode */
    n2n_register_super_ack=6,   /* ACK from supernode to edge */
    n2n_register_super_nak=7,   /* NAK from supernode to edge - registration refused */
    n2n_federation=8,            /* Not used by edge */
    n2n_pull_filter_list=9,
    n2n_handshake_start=10,
    n2n_handshake_verify=11,
    n2n_handshake_fail=12,
    n2n_handshake_success=13
};

typedef enum n2n_pc n2n_pc_t;

typedef uint16_t n2n_flags_t;
typedef uint16_t n2n_transform_t;       /* Encryption, compression type. */
typedef uint32_t n2n_sa_t;              /* security association number */

struct n2n_sock 
{
    uint8_t     family;         /* AF_INET or AF_INET6; or 0 if invalid */
    uint16_t    port;           /* host order */
    union 
    {
    uint8_t     v6[IPV6_SIZE];  /* byte sequence */
    uint8_t     v4[IPV4_SIZE];  /* byte sequence */
    } addr;
};

typedef struct n2n_sock n2n_sock_t;

struct n2n_auth
{
    uint16_t    scheme;                         /* What kind of auth */
    uint16_t    toksize;                        /* Size of auth token */
    uint8_t     token[N2N_AUTH_TOKEN_SIZE];     /* Auth data interpreted based on scheme */
};

typedef struct n2n_auth n2n_auth_t;


struct n2n_common
{
    /* int              version; */
    uint8_t             id;
    n2n_pc_t            pc;
    n2n_flags_t         flags;
    n2n_community_t     community;
};

typedef struct n2n_common n2n_common_t;

struct n2n_REGISTER
{
    n2n_cookie_t        cookie;         /* Link REGISTER and REGISTER_ACK */
    n2n_mac_t           srcMac;         /* MAC of registering party */
    n2n_mac_t           dstMac;         /* MAC of target edge */
    n2n_sock_t          sock;           /* REVISIT: unused? */
};

typedef struct n2n_REGISTER n2n_REGISTER_t;

struct n2n_REGISTER_ACK
{
    n2n_cookie_t        cookie;         /* Return cookie from REGISTER */
    n2n_mac_t           srcMac;         /* MAC of acknowledging party (supernode or edge) */
    n2n_mac_t           dstMac;         /* Reflected MAC of registering edge from REGISTER */
    n2n_sock_t          sock;           /* Supernode's view of edge socket (IP Addr, port) */
};

typedef struct n2n_REGISTER_ACK n2n_REGISTER_ACK_t;

struct n2n_PACKET
{
    n2n_mac_t           srcMac;
    n2n_mac_t           dstMac;
    n2n_sock_t          sock;
    n2n_transform_t     transform;
};

typedef struct n2n_PACKET n2n_PACKET_t;

struct n2n_PING_SERVER
{
    n2n_cookie_t        cookie;         /* Link REGISTER_SUPER and REGISTER_SUPER_ACK */
    n2n_mac_t           edgeMac;        /* MAC to register with edge sending socket */
};

typedef struct n2n_PING_SERVER n2n_PING_SERVER_t;
/* Linked with n2n_register_super in n2n_pc_t. Only from edge to supernode. */
struct n2n_REGISTER_SUPER
{
    n2n_cookie_t        cookie;         /* Link REGISTER_SUPER and REGISTER_SUPER_ACK */
    n2n_mac_t           edgeMac;        /* MAC to register with edge sending socket */
	uint32_t            edgeTapIp;		/* byte sequence */
    n2n_auth_t          auth;           /* Authentication scheme and tokens */
};

typedef struct n2n_REGISTER_SUPER n2n_REGISTER_SUPER_t;


/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
struct n2n_REGISTER_SUPER_ACK
{
    n2n_cookie_t        cookie;         /* Return cookie from REGISTER_SUPER */
    n2n_mac_t           edgeMac;        /* MAC registered to edge sending socket */
    uint16_t            lifetime;       /* How long the registration will live */
    n2n_sock_t          sock;           /* Sending sockets associated with edgeMac */

    /* The packet format provides additional supernode definitions here. 
     * uint8_t count, then for each count there is one
     * n2n_sock_t.
     */
    uint8_t             num_sn;         /* Number of supernodes that were send
                                         * even if we cannot store them all. If
                                         * non-zero then sn_bak is valid. */
    n2n_sock_t          sn_bak;         /* Socket of the first backup supernode */
    n2n_auth_t          auth;           /* Authentication scheme and tokens */

};

typedef struct n2n_REGISTER_SUPER_ACK n2n_REGISTER_SUPER_ACK_t;


/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
struct n2n_REGISTER_SUPER_NAK
{
    n2n_cookie_t        cookie;         /* Return cookie from REGISTER_SUPER */
};

typedef struct n2n_REGISTER_SUPER_NAK n2n_REGISTER_SUPER_NAK_t;

struct n2n_buf
{
    uint8_t *   data;
    size_t      size;
};

struct n2n_trans_op;
typedef struct n2n_trans_op n2n_trans_op_t;

typedef struct n2n_tostat n2n_tostat_t;

/** This structure stores an encryption cipher spec. */
struct n2n_cipherspec
{
    n2n_transform_t     t;                      /* N2N_TRANSFORM_ID_xxx for this spec. */
    time_t              valid_from;             /* Start using the key at this time. */
    time_t              valid_until;            /* Key is valid if time < valid_until. */
    uint16_t            opaque_size;            /* Size in bytes of key. */
    uint8_t             opaque[N2N_MAX_KEYSIZE];/* Key matter. */
};

typedef struct n2n_cipherspec n2n_cipherspec_t;

typedef void(*n2n_log)(char* msg, void*);
typedef void(*n2n_progress_notify)(int, void*);
typedef int             (*n2n_transdeinit_f)( n2n_trans_op_t * arg );
typedef int             (*n2n_transaddspec_f)( n2n_trans_op_t * arg, 
                                               const n2n_cipherspec_t * cspec );
typedef n2n_tostat_t    (*n2n_transtick_f)( n2n_trans_op_t * arg, 
                                            time_t now );

typedef int             (*n2n_transform_f)( n2n_trans_op_t * arg,
                                            uint8_t * outbuf,
                                            size_t out_len,
                                            const uint8_t * inbuf,
                                            size_t in_len,
                                            const n2n_mac_t peer_mac);
struct n2n_trans_op {
  void *              priv;   /* opaque data. Key schedule goes here. */

  n2n_transform_t     transform_id;   /* link header enum to a transform */
  size_t              tx_cnt;
  size_t              rx_cnt;

  n2n_transdeinit_f   deinit; /* destructor function */
  n2n_transaddspec_f  addspec; /* parse opaque data from a key schedule file. */
  n2n_transtick_f     tick;   /* periodic maintenance */
  n2n_transform_f     fwd;    /* encode a payload */
  n2n_transform_f     rev;    /* decode a payload */
};

struct n2n_tostat {
  uint8_t             can_tx;         /* Does this transop have a valid SA for encoding. */
  n2n_cipherspec_t    tx_spec;        /* If can_tx, the spec used to encode. */
};

typedef struct n2n_buf n2n_buf_t;

struct route_gateway_address {
    in_addr_t addr;
    in_addr_t netmask;
};


struct route_gateway_info {
	
	#define RGI_ADDR_DEFINED     (1<<0)  /* set if gateway.addr defined */
	#define RGI_NETMASK_DEFINED  (1<<1)  /* set if gateway.netmask defined */
	#define RGI_HWADDR_DEFINED   (1<<2)  /* set if hwaddr is defined */
	#define RGI_IFACE_DEFINED    (1<<3)  /* set if iface is defined */
	#define RGI_OVERFLOW         (1<<4)  /* set if more interface addresses than will fit in addrs */
	#define RGI_ON_LINK          (1<<5)
    
    unsigned int flags;

    /* gateway interface */
#ifdef _WIN32
    DWORD adapter_index; /* interface or ~0 if undefined */
#else
    char iface[16]; /* interface name (null terminated), may be empty */
#endif

    /* gateway interface hardware address */
    uint8_t hwaddr[6];

    /* gateway/router address */
    struct route_gateway_address gateway;

    /* address/netmask pairs bound to interface */
#define RGI_N_ADDRESSES 8
    int n_addrs; /* len of addrs, may be 0 */
    struct route_gateway_address addrs[RGI_N_ADDRESSES]; /* local addresses attached to iface */
};

struct HASH_LIST;
struct vpn_conf;
typedef struct vpn_conf vpn_conf_t;

struct n2n_edge {
	int                 daemon;                 /**< Non-zero if edge should detach and run in the background. */
	n2n_sock_t          supernode;

	n2n_sn_name_t       sn_ip;
	uint8_t				sn_pub_key[N2N_AUTH_KEY_SIZE];
	int                 sn_wait;                /**< Whether we are waiting for a supernode response. */
	
	
	int					lport;

	n2n_community_t     community_name;         /**< The community. 16 full octets. */
	int                 sock;

	int                 udp_multicast_sock;     /**< socket for local multicast registrations. */

	tuntap_dev          device;                 /**< All about the TUNTAP device */
	int                 allow_routing;          /**< Accept packet no to interface address. */
	int                 drop_multicast;         /**< Multicast ethernet addresses. */

	n2n_trans_op_t      transop; /* one for each transform at fixed positions */
	n2n_sock_t          multicast_peer;         /**< Multicast peer group (for local edges) */
	time_t              last_register_req;      /**< Check if time to re-register with super*/
	time_t              last_p2p;               /**< Last time p2p traffic was received. */
	time_t              last_sup;               /**< Last time a packet arrived from supernode. */
	n2n_cookie_t        last_cookie;            /**< Cookie sent in last REGISTER_SUPER. */
	time_t              start_time;             /**< For calculating uptime */

	uint16_t			filterlist_version;
	struct HASH_LIST	*		filter_list;
	HTREE_NODE	*		filter_dns_list;

	int*				view;
	int					keep_on_running;
	
	uint8_t				id;
	uint8_t				priv_key[N2N_AUTH_KEY_SIZE];
	uint8_t				pub_key[N2N_AUTH_KEY_SIZE];
	uint8_t				encrypt_key[N2N_AUTH_KEY_SIZE];

	n2n_auth_t			token;
	int					handshake_status;
	uint8_t 			is_hand_shaking;
	uint8_t 			ping_ok;
	uint8_t				is_tcp;

	uint8_t				recv_buf[TUN_READER_BUF_SIZE];
	uint8_t				recv_len;
	char 				gw_ip[INET_ADDRSTRLEN];
	vpn_conf_t			*conf;
	ip_set				ip_sets[2048];
	int					ip_set_count;
#ifndef WIN32
	uid_t   userid;
	gid_t   groupid;
#endif
	
	/* Statistics */
	size_t              tx_p2p;
	size_t              rx_p2p;
	size_t              tx_sup;
	size_t              rx_sup;
};

typedef struct n2n_tcp_connection {
    int    socket_fd;       /* file descriptor for tcp socket */
    struct sockaddr sock;   /* network order socket */

    uint16_t expected;                                    /* number of bytes expected to be read */
    uint16_t position;                                    /* current position in the buffer */
    uint8_t  buffer[N2N_PKT_BUF_SIZE + sizeof(uint16_t)]; /* buffer for data collected from tcp socket incl. prepended length */
    uint8_t  inactive;                                    /* connection not be handled if set, already closed and to be deleted soon */

    UT_hash_handle hh; /* makes this structure hashable */
} n2n_tcp_connection_t;


struct n2n_sn {
	time_t              start_time;     /* Used to measure uptime. */
	sn_stats_t          stats;
	int                 daemon;         /* If non-zero then daemonise. */
	uint16_t            lport;          /* Local UDP port to bind to. */
	int                 sock;           /* Main socket for UDP traffic with edges. */
    int                 tcp_sock;
    n2n_tcp_connection_t   *tcp_connections;
	int                 mgmt_sock;      /* management socket. */
        struct peer_info *  edges;
        struct peer_info *  tcp_edges;  /* hash array for fast search in case of tcp*/
        NAT                 * n;
	tuntap_dev          device;
	n2n_common_t		cmn;
	int                 null_transop;           /**< Only allowed if no key sources defined. */
#ifndef WIN32
        uid_t               userid;
        gid_t               groupid;
#endif
	edge_conf_t			ec;
	uint8_t             ids[N2N_MAX_CLIENTS];
        uint32_t            ips[N2N_MAX_CLIENTS];
	uint8_t				priv_key[N2N_AUTH_KEY_SIZE];
	uint8_t				pub_key[N2N_AUTH_KEY_SIZE];
};
typedef struct n2n_sn n2n_sn_t;


struct peer_info {
	struct peer_info *  next;
	n2n_community_t     community_name;
	n2n_mac_t           mac_addr;
        uint32_t            ip;
	n2n_sock_t          sock;
//      SOCKET                           socket_fd;
    n2n_tcp_connection_t    *conn;
    int                              timeout;
	time_t              last_seen;
	uint8_t				id;
	uint8_t				pub_key[N2N_AUTH_KEY_SIZE];
	uint8_t				shared_key[N2N_AUTH_KEY_SIZE + 1];
	n2n_trans_op_t      transop;
	uint8_t				verified;
    UT_hash_handle     hh; /* makes this structure hashable */
};

struct n2n_edge; /* defined in edge.c */
typedef struct n2n_edge         n2n_edge_t;

struct vpn_conf {
	const char* token;
	const char* server_info;
	const char* ipsets;
	const char* domains;
	const char* ips;
	n2n_log log_func;
	n2n_progress_notify notify;
	void* v;
	char    ip_addr_str[N2N_NETMASK_STR_SIZE];
	char    netmask_str[N2N_NETMASK_STR_SIZE];
	char    device_mac_str[N2N_MACNAMSIZ];
	int 	file_op_success;
};



#endif /* _N2N_TYPEDEFS_H_ */
