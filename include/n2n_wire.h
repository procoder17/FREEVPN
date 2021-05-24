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

#if !defined( N2N_WIRE_H_ )
#define N2N_WIRE_H_

#include <stdlib.h>

#if defined(WIN32)
#include "win32/n2n_win32.h"

#if defined(__MINGW32__)
#include <stdint.h>
#endif /* #ifdef __MINGW32__ */

#else /* #if defined(WIN32) */
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h> /* AF_INET and AF_INET6 */
#endif /* #if defined(WIN32) */


int encode_uint8( uint8_t * base, 
                  size_t * idx,
                  const uint8_t v );

int decode_uint8( uint8_t * out,
                  const uint8_t * base,
                  size_t * rem,
                  size_t * idx );

int encode_uint16( uint8_t * base, 
                   size_t * idx,
                   const uint16_t v );

int decode_uint16( uint16_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

int encode_uint32( uint8_t * base, 
                   size_t * idx,
                   const uint32_t v );

int decode_uint32( uint32_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

int encode_uint64(uint8_t * base, size_t * idx, const uint64_t v);

int decode_uint64(uint64_t * out, const uint8_t * base, size_t * rem, size_t * idx);

int encode_buf( uint8_t * base, 
                size_t * idx,
                const void * p, 
                size_t s);

int decode_buf( uint8_t * out,
                size_t bufsize,
                const uint8_t * base,
                size_t * rem,
                size_t * idx );

int encode_mac( uint8_t * base, 
                size_t * idx,
                const n2n_mac_t m );

int decode_mac( uint8_t * out, /* of size N2N_MAC_SIZE. This clearer than passing a n2n_mac_t */
                const uint8_t * base,
                size_t * rem,
                size_t * idx );

int encode_common( uint8_t * base, 
                   size_t * idx,
                   const n2n_common_t * common );

int decode_common( n2n_common_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

int encode_sock( uint8_t * base, 
                 size_t * idx,
                 const n2n_sock_t * sock );

int decode_sock( n2n_sock_t * sock,
                 const uint8_t * base,
                 size_t * rem,
                 size_t * idx );

int encode_REGISTER( uint8_t * base, 
                     size_t * idx,
                     const n2n_common_t * common, 
                     const n2n_REGISTER_t * reg );

int decode_REGISTER( n2n_REGISTER_t * pkt,
                     const n2n_common_t * cmn, /* info on how to interpret it */
                     const uint8_t * base,
                     size_t * rem,
                     size_t * idx );

int encode_REGISTER_SUPER( uint8_t * base, 
                           size_t * idx,
                           const n2n_common_t * common, 
                           const n2n_REGISTER_SUPER_t * reg );

int decode_REGISTER_SUPER( n2n_REGISTER_SUPER_t * pkt,
                           const n2n_common_t * cmn, /* info on how to interpret it */
                           const uint8_t * base,
                           size_t * rem,
                           size_t * idx );

int encode_REGISTER_ACK( uint8_t * base, 
                         size_t * idx,
                         const n2n_common_t * common, 
                         const n2n_REGISTER_ACK_t * reg );

int decode_REGISTER_ACK( n2n_REGISTER_ACK_t * pkt,
                         const n2n_common_t * cmn, /* info on how to interpret it */
                         const uint8_t * base,
                         size_t * rem,
                         size_t * idx );

int encode_REGISTER_SUPER_ACK( uint8_t * base,
                               size_t * idx,
                               const n2n_common_t * cmn,
                               const n2n_REGISTER_SUPER_ACK_t * reg );

int decode_REGISTER_SUPER_ACK( n2n_REGISTER_SUPER_ACK_t * reg,
                               const n2n_common_t * cmn, /* info on how to interpret it */
                               const uint8_t * base,
                               size_t * rem,
                               size_t * idx );
int encode_PING_SUPER( uint8_t * base, 
                           size_t * idx,
                           const n2n_common_t * common, 
                           const n2n_PING_SERVER_t * reg );
                
int decode_PING_SUPER( n2n_PING_SERVER_t * reg,
                           const n2n_common_t * cmn, /* info on how to interpret it */
                           const uint8_t * base,
                           size_t * rem,
                           size_t * idx );
                                      
int fill_sockaddr( struct sockaddr * addr, 
                   size_t addrlen, 
                   const n2n_sock_t * sock );

int encode_PACKET( uint8_t * base, 
                   size_t * idx,
                   const n2n_common_t * common, 
                   const n2n_PACKET_t * pkt );

int decode_PACKET( n2n_PACKET_t * pkt,
                   const n2n_common_t * cmn, /* info on how to interpret it */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );


#endif /* #if !defined( N2N_WIRE_H_ ) */
