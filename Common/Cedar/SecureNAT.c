// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// SecureNAT.c
// SecureNAT code

#include "CedarPch.h"

// Release the SecureNAT
void SnFreeSecureNAT(NAT *n)
{
	// Virtual machine release
	Virtual_Free(n->Virtual);

	Lock(n->lock);
	{
		if (n->Virtual != NULL)
		{
			StopVirtualHost(n->Virtual);
			ReleaseVirtual(n->Virtual);
			n->Virtual = NULL;
		}
	}
	Unlock(n->lock);

	// Delete the object
	ReleaseEvent(n->HaltEvent);
	DeleteLock(n->lock);
}

void NiSetDefaultVhOption(VH_OPTION *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Zero(o, sizeof(VH_OPTION));
	GenMacAddress(o->MacAddress);

	// Set the virtual IP to 192.168.30.1/24
	SetIP(&o->Ip, 192, 168, 137, 1);
	SetIP(&o->Mask, 255, 255, 255, 0);
	o->UseNat = true;
	o->Mtu = 1500;
	o->NatTcpTimeout = 1800;
	o->NatUdpTimeout = 60;
	o->UseDhcp = true;
	SetIP(&o->DhcpLeaseIPStart, 192, 168, 137, 10);
	SetIP(&o->DhcpLeaseIPEnd, 192, 168, 137, 200);
	SetIP(&o->DhcpSubnetMask, 255, 255, 255, 0);
	o->DhcpExpireTimeSpan = 7200;
	o->SaveLog = true;

	SetIP(&o->DhcpGatewayAddress, 192, 168, 137, 1);
	SetIP(&o->DhcpDnsServerAddress, 192, 168, 137, 1);

	GetDomainName(o->DhcpDomainName, sizeof(o->DhcpDomainName));
}

// Create a new SecureNAT
NAT *SnNewSecureNAT()
{
	VH_OPTION *o = ZeroMalloc(sizeof(VH_OPTION));
	NiSetDefaultVhOption(o);
	
	NAT *n = ZeroMalloc(sizeof(NAT));

	n->lock = NewLock();
	Sha0(n->HashedPassword, "", 0);
	n->HaltEvent = NewEvent();
	// Initialize management port
	n->AdminPort = DEFAULT_NAT_ADMIN_PORT;

	// Offline
	n->Online = false;

	// Save the log
	n->Option.SaveLog = false;


#if	0
	// Start the operation of the virtual host
	if (n->Online && n->ClientOption != NULL)
	{
		n->Virtual = NewVirtualHostEx(n->Cedar, n->ClientOption, n->ClientAuth, &n->Option, n);
	}
	else
	{
		n->Online = false;
		n->Virtual = NULL;
	}
#else
	n->Virtual = NewVirtualHostEx(NULL, NULL, o, n);
	n->Online = true;
#endif

	// Initialize the virtual machine
	VirtualInit(n->Virtual);
	Free(o);
	return n;
}

// Create a new SecureNAT with VH_OPTHION
NAT *SnNewSecureNATWithVHOption(VH_OPTION *o)
{
	NAT *n = ZeroMalloc(sizeof(NAT));

	n->lock = NewLock();
	Sha0(n->HashedPassword, "", 0);
	n->HaltEvent = NewEvent();
	// Initialize management port
	n->AdminPort = DEFAULT_NAT_ADMIN_PORT;

	// Offline
	n->Online = false;

	// Save the log
	n->Option.SaveLog = false;


#if	0
	// Start the operation of the virtual host
	if (n->Online && n->ClientOption != NULL)
	{
		n->Virtual = NewVirtualHostEx(n->Cedar, n->ClientOption, n->ClientAuth, &n->Option, n);
	}
	else
	{
		n->Online = false;
		n->Virtual = NULL;
	}
#else
	n->Virtual = NewVirtualHostEx(NULL, NULL, o, n);
	n->Online = true;
#endif

	// Initialize the virtual machine
	VirtualInit(n->Virtual);
	Free(o);
	return n;
}

