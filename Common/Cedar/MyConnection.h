// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Connection.h
// Header of Connection.c

#ifndef	MYCONNECTION_H
#define	MYCONNECTION_H

// Data block
struct BLOCK
{
	BOOL Compressed;				// Compression flag
	UINT Size;						// Block size
	UINT SizeofData;				// Data size
	UCHAR *Buf;						// Buffer
	bool PriorityQoS;				// Priority packet for VoIP / QoS function
	UINT Ttl;						// TTL value (Used only in ICMP NAT of Virtual.c)
	UINT Param1;					// Parameter 1
	bool IsFlooding;				// Is flooding packet
};


BLOCK *NewBlock(void *data, UINT size, int compress);
void FreeBlock(BLOCK *b);




#endif	// CONNECTION_H
