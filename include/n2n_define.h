

// Routing table tracking timer
#define	TRACKING_INTERVAL_INITIAL		444		// Initial
#define	TRACKING_INTERVAL_ADD			444		// Adding value
#define	TRACKING_INTERVAL_MAX			12345	// Maximum value
#define	TRACKING_INTERVAL_MAX_RC		87654	// Maximum value (OS which change detection mechanism enabled)

#define N2N_TRANSOP_NULL_IDX    0
#define N2N_TRANSOP_TF_IDX      1
#define N2N_TRANSOP_AESCBC_IDX  2
#define N2N_TRANSOP_CHACHA20_IDX 3

#define QUICKLZ               1

/* N2N packet header indicators. */
#define MSG_TYPE_REGISTER               1
#define MSG_TYPE_DEREGISTER             2
#define MSG_TYPE_PACKET                 3
#define MSG_TYPE_REGISTER_ACK           4
/*
#define MSG_TYPE_REGISTER_SUPER         5
#define MSG_TYPE_REGISTER_SUPER_ACK     6
#define MSG_TYPE_REGISTER_SUPER_NAK     7
*/
#define MSG_TYPE_FEDERATION             8
#define MSG_TYPE_PULL_FILTER_LIST		9
#define MSG_TYPE_PULL_FILTER_LIST_SUPER_ACK     10
#define MSG_TYPE_HANDSHAKE_START		11
#define MSG_TYPE_HANDSHAKE_START_ACK	12
#define MSG_TYPE_HANDSHAKE_VERIFY		13
#define MSG_TYPE_HANDSHAKE_FAIL			14
#define MSG_TYPE_HANDSHAKE_SUCCESS		15
#define MSG_TYPE_PING_REQUEST			16
#define MSG_TYPE_PING_ACK				17
/* Set N2N_COMPRESSION_ENABLED to 0 to disable lzo1x compression of ethernet
 * frames. Doing this will break compatibility with the standard n2n packet
 * format so do it only for experimentation. All edges must be built with the
 * same value if they are to understand each other. */
#define N2N_COMPRESSION_ENABLED 1

#define DEFAULT_MTU   1400

#define HASH_ADD_PEER(head,add) \
    HASH_ADD(hh,head,mac_addr,sizeof(n2n_mac_t),add)
#define HASH_FIND_PEER(head,mac,out) \
    HASH_FIND(hh,head,mac,sizeof(n2n_mac_t),out)
#define HASH_ADD_SOCK(head,add) \
    HASH_ADD(hh,head,sock,sizeof(n2n_sock_t),add)
#define HASH_FIND_SOCK(head,sock,out) \
    HASH_FIND(hh,head,sock,sizeof(n2n_sock_t),out)


#if defined(DEBUG)
#define SOCKET_TIMEOUT_INTERVAL_SECS    5
#define REGISTER_SUPER_INTERVAL_DFL     20 /* sec */
#else  /* #if defined(DEBUG) */
#define SOCKET_TIMEOUT_INTERVAL_SECS    5
#define REGISTER_SUPER_INTERVAL_DFL     60 /* sec */
#endif /* #if defined(DEBUG) */

#define HANDSHAKE_TIMEOUT_INTERVAL      5
#define PING_INTERVAL					5  /* sec */
#define REGISTER_SUPER_INTERVAL_MIN     5    /* sec */
#define REGISTER_SUPER_INTERVAL_MAX     3600 /* sec */

#define IFACE_UPDATE_INTERVAL           (30) /* sec. How long it usually takes to get an IP lease. */
#define TRANSOP_TICK_INTERVAL           (10) /* sec */

#ifdef __ANDROID_NDK__
#define ARP_PERIOD_INTERVAL             (10) /* sec */
#endif

#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
#define IP4_DSTOFFSET 16

#define N2N_MAX_CLIENTS	250
#define N2N_ALLOCATED	1
#define N2N_EMPTY	0

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */

#define N2N_TCP_BACKLOG_QUEUE_SIZE   3

#define N2N_EDGE_SN_HOST_SIZE   48
#define N2N_EDGE_NUM_SUPERNODES 2
#define N2N_EDGE_SUP_ATTEMPTS   3       /* Number of failed attmpts before moving on to next supernode. */
#define N2N_PATHNAME_MAXLEN     256
#define N2N_MAX_TRANSFORMS      16
#define N2N_EDGE_MGMT_PORT      5644

#define N2N_IFNAMSIZ            16 /* 15 chars * NULL */
/* ************************************** */
#define N2N_PKT_VERSION                 2
#define N2N_DEFAULT_TTL                 2       /* can be forwarded twice at most */
#define N2N_COMMUNITY_SIZE              16
#define N2N_MAC_SIZE                    6
#define N2N_COOKIE_SIZE                 4
#define N2N_PKT_BUF_SIZE                2048
#define N2N_SOCKBUF_SIZE                64      /* string representation of INET or INET6 sockets */

#define N2N_MULTICAST_PORT              1968
#define N2N_MULTICAST_GROUP             "224.0.0.68"

#define N2N_FLAGS_OPTIONS               0x0080
#define N2N_FLAGS_SOCKET                0x0040
#define N2N_FLAGS_FROM_SUPERNODE        0x0020
#define N2N_FLAGS_TUN					0x0100
#define N2N_FLAGS_TAP					0x0200

/* The bits in flag that are the packet type */
#define N2N_FLAGS_TYPE_MASK             0x001f  /* 0 - 31 */
#define N2N_FLAGS_BITS_MASK             0xffe0

#define IPV4_SIZE                       4
#define IPV6_SIZE                       16

#define N2N_AUTH_PUBKEY_EXCHANGE		1
#define N2N_AUTH_TOKEN_SEND				2

#define N2N_AUTH_KEY_SIZE				32
#define N2N_AUTH_TOKEN_SIZE             256      /* bytes */

#define N2N_EUNKNOWN                    -1
#define N2N_ENOTIMPL                    -2
#define N2N_EINVAL                      -3
#define N2N_ENOSPACE                    -4

#define N2N_MAX_KEYSIZE         256             /* bytes */
#define N2N_MAX_NUM_CIPHERSPECS 8
#define N2N_KEYPATH_SIZE        256
#define N2N_KEYFILE_LINESIZE    256

#define TAP_MODE					1
#define TUN_MODE					0

#ifdef WIN32
#define INPROGRESS WSAEWOULDBLOCK
#define GETSOCKETERRNO() (WSAGetLastError())
#define STRTOKS	strtok_s
#else
#define INPROGRESS EINPROGRESS
#define GETSOCKETERRNO() (errno)
#define STRTOKS	strtok_r
#endif

#define TUN_READER_BUF_SIZE			2048
#define HOST_INDEX(ip)  (ip >> 24)

#ifndef max
#define max(a, b) ((a < b) ? b : a)
#endif

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif
