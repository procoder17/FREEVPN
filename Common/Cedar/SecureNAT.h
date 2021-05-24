// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// SecureNAT.h
// Header of SecureNAT.c

#ifndef	SECURENAT_H
#define	SECURENAT_H

struct SNAT
{
	LOCK *lock;						// Lock
	NAT *Nat;						// NAT
};

void NiSetDefaultVhOption(VH_OPTION *o);
NAT *SnNewSecureNAT();
void SnFreeSecureNAT(NAT *s);
NAT *SnNewSecureNATWithVHOption(VH_OPTION *o);
#endif	// SECURENAT_H

