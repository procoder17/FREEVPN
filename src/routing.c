
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
/** Read a single packet from the TAP interface, process it and write out the
 *  corresponding packet to the cooked socket.
 */
 #ifdef WIN32
void setDefaultRouting(n2n_edge_t* edge);
void setDefaultRouting(n2n_edge_t* edge)
{
	ROUTE_TRACKING *t;
	UINT64 now;
	ROUTE_TABLE *table;
	ROUTE_ENTRY *rs;
	uint8_t changed = false;
	uint8_t check = false;
	uint8_t any_modified = false;
	// Validate arguments
	if (edge == NULL)
	{
		return;
	}

	// Get the state
	t = edge->device.RouteState;
	if (t == NULL)
	{
		return;
	}

	// Current time
	PROBE_STR("RouteTrackingMain 1");
	now = Tick64();

	if (t->RouteChange != NULL)
	{
		if (t->NextRouteChangeCheckTime == 0 ||
			t->NextRouteChangeCheckTime <= now)
		{
			t->NextRouteChangeCheckTime = now + 1000ULL;

			check = IsRouteChanged(t->RouteChange);

			if (check)
			{
				Debug("*** Routing Table Changed ***\n");
				t->NextTrackingTime = 0;
			}
		}
	}
	if (t->NextTrackingTime != 0 && t->NextTrackingTime > now)
	{
		return;
	}
	PROBE_STR("RouteTrackingMain 3");

	// Get the current routing table
	table = GetRouteTable();
	rs = t->RouteToServer;
	if (table != NULL)
	{
		UINT i;
		bool route_to_server_erased = true;
		bool is_vlan_want_to_be_default_gateway = false;
		UINT vlan_default_gateway_metric = 0;
		UINT other_if_default_gateway_metric_min = INFINITE;

		// Get whether the routing table have been changed
		if (t->LastRoutingTableHash != table->HashedValue)
		{
			t->LastRoutingTableHash = table->HashedValue;
			changed = true;
		}

		//DebugPrintRouteTable(table);

		// Scan the routing table
		for (i = 0; i < table->NumEntry; i++)
		{
			ROUTE_ENTRY *e = table->Entry[i];

			if (rs != NULL)
			{
				if (CmpIpAddr(&e->DestIP, &rs->DestIP) == 0 &&
					CmpIpAddr(&e->DestMask, &rs->DestMask) == 0
					//					&& CmpIpAddr(&e->GatewayIP, &rs->GatewayIP) == 0
					//					&& e->InterfaceID == rs->InterfaceID &&
					//					e->LocalRouting == rs->LocalRouting &&
					//					e->Metric == rs->Metric
					)
				{
					// Routing entry to the server that added at the time of connection is found
					route_to_server_erased = false;
				}
			}

			// Search for the default gateway
			if (IPToUINT(&e->DestIP) == 0 &&
				IPToUINT(&e->DestMask) == 0)
			{
				Debug("e->InterfaceID = %u, t->VLanInterfaceId = %u\n",
					e->InterfaceID, t->VLanInterfaceId);

				if (e->InterfaceID == t->VLanInterfaceId)
				{
					// The virtual LAN card think that he want to be a default gateway
					is_vlan_want_to_be_default_gateway = true;
					vlan_default_gateway_metric = e->Metric;

					if (vlan_default_gateway_metric >= 2 &&
						t->OldDefaultGatewayMetric == (vlan_default_gateway_metric - 1))
					{
						// Restore because the PPP server rewrites
						// the routing table selfishly
						DeleteRouteEntry(e);
						e->Metric--;
						AddRouteEntry(e);
						Debug("** Restore metric destroyed by PPP.\n");

						any_modified = true;
					}

					// Keep this entry
					if (t->DefaultGatewayByVLan != NULL)
					{
						// Delete if there is one added last time
						FreeRouteEntry(t->DefaultGatewayByVLan);
					}

					t->DefaultGatewayByVLan = ZeroMalloc(sizeof(ROUTE_ENTRY));
					Copy(t->DefaultGatewayByVLan, e, sizeof(ROUTE_ENTRY));

					t->OldDefaultGatewayMetric = vlan_default_gateway_metric;
				}
				else
				{
					// There are default gateway other than the virtual LAN card
					// Save the metric value of the default gateway
					if (other_if_default_gateway_metric_min > e->Metric)
					{
						// Ignore the metric value of all PPP connection in the case of Windows Vista
						if (MsIsVista() == false || e->PPPConnection == false)
						{
							other_if_default_gateway_metric_min = e->Metric;
						}
						else
						{
							// a PPP is used to Connect to the network
							// in using Windows Vista
							t->VistaAndUsingPPP = true;
						}
					}
				}
			}
		}

		if (t->VistaAndUsingPPP)
		{
			if (t->DefaultGatewayByVLan != NULL)
			{
				if (is_vlan_want_to_be_default_gateway)
				{
					if (t->VistaOldDefaultGatewayByVLan == NULL || Cmp(t->VistaOldDefaultGatewayByVLan, t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY)) != 0)
					{
						ROUTE_ENTRY *e;
						// Add the route of 0.0.0.0/1 and 128.0.0.0/1
						// to the system if the virtual LAN card should be
						// the default gateway in the case of the connection
						// using PPP in Windows Vista

						if (t->VistaOldDefaultGatewayByVLan != NULL)
						{
							FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
						}

						if (t->VistaDefaultGateway1 != NULL)
						{
							DeleteRouteEntry(t->VistaDefaultGateway1);
							FreeRouteEntry(t->VistaDefaultGateway1);

							DeleteRouteEntry(t->VistaDefaultGateway2);
							FreeRouteEntry(t->VistaDefaultGateway2);
						}

						t->VistaOldDefaultGatewayByVLan = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));

						e = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));
						SetIP(&e->DestIP, 0, 0, 0, 0);
						SetIP(&e->DestMask, 128, 0, 0, 0);
						t->VistaDefaultGateway1 = e;

						e = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));
						SetIP(&e->DestIP, 128, 0, 0, 0);
						SetIP(&e->DestMask, 128, 0, 0, 0);
						t->VistaDefaultGateway2 = e;

						AddRouteEntry(t->VistaDefaultGateway1);
						AddRouteEntry(t->VistaDefaultGateway2);

						Debug("Vista PPP Fix Route Table Added.\n");

						any_modified = true;
					}
				}
				else
				{
					if (t->VistaOldDefaultGatewayByVLan != NULL)
					{
						FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
						t->VistaOldDefaultGatewayByVLan = NULL;
					}

					if (t->VistaDefaultGateway1 != NULL)
					{
						Debug("Vista PPP Fix Route Table Deleted.\n");
						DeleteRouteEntry(t->VistaDefaultGateway1);
						FreeRouteEntry(t->VistaDefaultGateway1);

						DeleteRouteEntry(t->VistaDefaultGateway2);
						FreeRouteEntry(t->VistaDefaultGateway2);

						any_modified = true;

						t->VistaDefaultGateway1 = t->VistaDefaultGateway2 = NULL;
					}
				}
			}
		}

		// If the virtual LAN card want to be the default gateway and
		// there is no LAN card with smaller metric of 0.0.0.0/0 than
		// the virtual LAN card, delete other default gateway entries
		// to elect the virtual LAN card as the default gateway
		//		Debug("is_vlan_want_to_be_default_gateway = %u, rs = %u, route_to_server_erased = %u, other_if_default_gateway_metric_min = %u, vlan_default_gateway_metric = %u\n",
		//			is_vlan_want_to_be_default_gateway, rs, route_to_server_erased, other_if_default_gateway_metric_min, vlan_default_gateway_metric);
		if (is_vlan_want_to_be_default_gateway && (rs != NULL && route_to_server_erased == false) &&
			other_if_default_gateway_metric_min >= vlan_default_gateway_metric)
		{
			// Scan the routing table again
			for (i = 0; i < table->NumEntry; i++)
			{
				ROUTE_ENTRY *e = table->Entry[i];

				if (e->InterfaceID != t->VLanInterfaceId)
				{
					if (IPToUINT(&e->DestIP) == 0 &&
						IPToUINT(&e->DestMask) == 0)
					{
						char str[64];
						// Default gateway is found
						ROUTE_ENTRY *r = ZeroMalloc(sizeof(ROUTE_ENTRY));

						Copy(r, e, sizeof(ROUTE_ENTRY));

						// Put in the queue
						InsertQueue(t->DeletedDefaultGateway, r);

						// Delete this gateway entry once
						DeleteRouteEntry(e);

						IPToStr(str, sizeof(str), &e->GatewayIP);
						Debug("Default Gateway %s Deleted.\n", str);

						any_modified = true;
					}
				}
			}
		}

		if (rs != NULL && route_to_server_erased)
		{
			// Physical entry to the server has disappeared
			Debug("Route to Server entry ERASED !!!\n");

			// Forced disconnection (reconnection enabled)
			//s->RetryFlag = true;
			//s->Halt = true;
		}

		// Release the routing table
		FreeRouteTable(table);
	}

	// Set the time to perform the next track
	if (t->NextTrackingTimeAdd == 0 || changed)
	{
		t->NextTrackingTimeAdd = TRACKING_INTERVAL_INITIAL;
	}
	else
	{
		UINT64 max_value = TRACKING_INTERVAL_MAX;
		if (t->RouteChange != NULL)
		{
			max_value = TRACKING_INTERVAL_MAX_RC;
		}

		t->NextTrackingTimeAdd += TRACKING_INTERVAL_ADD;

		if (t->NextTrackingTimeAdd >= max_value)
		{
			t->NextTrackingTimeAdd = max_value;
		}
	}
	//Debug("t->NextTrackingTimeAdd = %I64u\n", t->NextTrackingTimeAdd);
	t->NextTrackingTime = now + t->NextTrackingTimeAdd;

	if (any_modified)
	{
		// Clear the DNS cache
		Win32FlushDnsCache();
	}
}

void restoreRouting(n2n_edge_t* edge, ROUTE_TRACKING *t)
{
	ROUTE_ENTRY *e;
	ROUTE_TABLE *table;
	IP dns_ip;
	bool network_has_changed = false;
	bool do_not_delete_routing_entry = false;
	// Validate arguments
	if (edge == NULL || t == NULL)
	{
		return;
	}

	Zero(&dns_ip, sizeof(dns_ip));

	// Remove the default gateway added by the virtual LAN card
	if (MsIsVista() == false)
	{
		if (t->DefaultGatewayByVLan != NULL)
		{
			Debug("Default Gateway by VLAN was deleted.\n");
			DeleteRouteEntry(t->DefaultGatewayByVLan);
		}

		if (t->VistaOldDefaultGatewayByVLan != NULL)
		{
			FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
		}
	}

	if (t->DefaultGatewayByVLan != NULL)
	{
		FreeRouteEntry(t->DefaultGatewayByVLan);
		t->DefaultGatewayByVLan = NULL;
	}

	if (t->VistaDefaultGateway1 != NULL)
	{
		Debug("Vista PPP Fix Route Table Deleted.\n");
		DeleteRouteEntry(t->VistaDefaultGateway1);
		FreeRouteEntry(t->VistaDefaultGateway1);

		DeleteRouteEntry(t->VistaDefaultGateway2);
		FreeRouteEntry(t->VistaDefaultGateway2);
	}

	if (MsIsNt() == false)
	{
		// Only in the case of Windows 9x, release the DHCP address of the virtual LAN card
		Win32ReleaseDhcp9x(t->VLanInterfaceId, false);
	}

	// Clear the DNS cache
	Win32FlushDnsCache();

	ROUTE_TRACKING *tr = edge->device.RouteState;
	if (tr != NULL)
	{
		if (Cmp(tr->RouteToServer, t->RouteToServer, sizeof(ROUTE_ENTRY)) == 0)
		{
			do_not_delete_routing_entry = true;
		}
	}

	if (do_not_delete_routing_entry == false)
	{
		// Delete the route that is added firstly
		if (t->RouteToServerAlreadyExists == false)
		{
			DeleteRouteEntry(t->RouteToServer);
		}

		DeleteRouteEntry(t->RouteToDefaultDns);

		DeleteRouteEntry(t->RouteToNatTServer);

		DeleteRouteEntry(t->RouteToRealServerGlobal);
	}

	FreeRouteEntry(t->RouteToDefaultDns);
	FreeRouteEntry(t->RouteToServer);
	FreeRouteEntry(t->RouteToEight);
	FreeRouteEntry(t->RouteToNatTServer);
	FreeRouteEntry(t->RouteToRealServerGlobal);
	t->RouteToDefaultDns = t->RouteToServer = t->RouteToEight =
		t->RouteToNatTServer = t->RouteToRealServerGlobal = NULL;

/*
#if	0
	// Get the current DNS server
	if (GetDefaultDns(&dns_ip))
	{
		if (IPToUINT(&t->OldDnsServer) != 0)
		{
			if (IPToUINT(&t->OldDnsServer) != IPToUINT(&dns_ip))
			{
				char s1[MAX_SIZE], s2[MAX_SIZE];
				network_has_changed = true;
				IPToStr(s1, sizeof(s1), &t->OldDnsServer);
				IPToStr(s2, sizeof(s2), &dns_ip);
				Debug("Old Dns: %s, New Dns: %s\n",
					s1, s2);
			}
		}
	}

	if (network_has_changed == false)
	{
		Debug("Network: not changed.\n");
	}
	else
	{
		Debug("Network: Changed.\n");
	}

#endif
*/
	// Get the current routing table
	table = GetRouteTable();

	// Restore the routing table which has been removed so far
	while (e = GetNext(t->DeletedDefaultGateway))
	{
		bool restore = true;
		UINT i;
		// If the restoring routing entry is a default gateway and
		// the existing routing table contains another default gateway
		// on the interface, give up restoring the entry
		if (IPToUINT(&e->DestIP) == 0 && IPToUINT(&e->DestMask) == 0)
		{
			for (i = 0; i < table->NumEntry; i++)
			{
				ROUTE_ENTRY *r = table->Entry[i];
				if (IPToUINT(&r->DestIP) == 0 && IPToUINT(&r->DestMask) == 0)
				{
					if (r->InterfaceID == e->InterfaceID)
					{
						restore = false;
					}
				}
			}
			if (network_has_changed)
			{
				restore = false;
			}
		}

		if (restore)
		{
			// Routing table restoration
			AddRouteEntry(e);
		}

		// Memory release
		FreeRouteEntry(e);
	}

	// Release
	FreeRouteTable(table);
	ReleaseQueue(t->DeletedDefaultGateway);

	FreeRouteChange(t->RouteChange);

	Free(t);
}

void setRoutingToServer(n2n_edge_t* edge, tuntap_dev *device)
{
	ROUTE_TRACKING *t;
	UINT if_id = 0;
	ROUTE_ENTRY *e;
	ROUTE_ENTRY *dns = NULL;
	ROUTE_ENTRY *route_to_real_server_global = NULL;
	char tmp[64];
	UINT exclude_if_id = 0;
	bool already_exists = false;
	bool already_exists_by_other_account = false;
	IP eight;

	if (MsIsVista())
	{
		MsNormalizeInterfaceDefaultGatewaySettings(VLAN_ADAPTER_NAME_TAG, device->ifName);
	}
	
	if_id = GetVLanInterfaceID(VLAN_ADAPTER_NAME_TAG);

	if (MsIsVista())
	{
		// The routing table by the virtual LAN card body should be
		// excluded explicitly in Windows Vista
		exclude_if_id = if_id;
	}

	// Get the route to the server
	uint8_t *sIp = edge->supernode.addr.v4;
	IP serverIp;
	SetIP(&serverIp, sIp[0], sIp[1], sIp[2], sIp[3]);
	e = GetBestRouteEntryEx(&serverIp, exclude_if_id);
	if (e == NULL)
	{
		// Acquisition failure
		Debug("Failed to get GetBestRouteEntry().\n");
		return;
	}
	IPToStr(tmp, sizeof(tmp), &e->GatewayIP);
	Debug("GetBestRouteEntry() Succeed. [Gateway: %s]\n", tmp);

	// Add a route
	if (MsIsVista())
	{
		e->Metric = e->OldIfMetric;
	}
	if (AddRouteEntryEx(e, &already_exists) == false)
	{
		FreeRouteEntry(e);
		e = NULL;
	}
	Debug("already_exists: %u\n", already_exists);

	if (already_exists)
	{
		ROUTE_TRACKING *tr = edge->device.RouteState;
		if (tr != NULL && e != NULL)
		{
			if (Cmp(tr->RouteToServer, e, sizeof(ROUTE_ENTRY)) == 0)
			{
				already_exists_by_other_account = true;
			}
		}

		if (already_exists_by_other_account)
		{
			Debug("already_exists_by_other_account = %u\n", already_exists_by_other_account);
			already_exists = false;
		}
	}

	// Get the routing table to the DNS server
	// (If the DNS server is this PC itself, there's no need to get)
	/*
	if (IsZeroIP(&s->DefaultDns) == false)
	{
		if (IsMyIPAddress(&s->DefaultDns) == false)
		{
			dns = GetBestRouteEntryEx(&s->DefaultDns, exclude_if_id);
			if (dns == NULL)
			{
				// Getting failure
				Debug("Failed to get GetBestRouteEntry DNS.\n");
			}
			else
			{
				// Add a route
				if (MsIsVista())
				{
					dns->Metric = dns->OldIfMetric;

					if (AddRouteEntry(dns) == false)
					{
						FreeRouteEntry(dns);
						dns = NULL;
					}
				}
			}
		}
	}
	*/
	t = ZeroMalloc(sizeof(ROUTE_TRACKING));
	edge->device.RouteState = t;

	t->RouteToServerAlreadyExists = already_exists;
	t->RouteToServer = e;
	t->RouteToDefaultDns = dns;
	t->RouteToRealServerGlobal = route_to_real_server_global;
	t->VLanInterfaceId = if_id;
	t->NextTrackingTime = 0;
	t->DeletedDefaultGateway = NewQueue();
	t->OldDefaultGatewayMetric = 0x7fffffff;

	// Get the route to 8.8.8.8
	SetIP(&eight, 8, 8, 8, 8);
	t->RouteToEight = GetBestRouteEntryEx(&eight, exclude_if_id);

	// Get the current default DNS server to detect network changes
	GetDefaultDns(&t->OldDnsServer);

	// Clear the DNS cache
	Win32FlushDnsCache();

	// Detect a change in the routing table (for only supported OS)
	t->RouteChange = NewRouteChange();
	Debug("t->RouteChange = 0x%p\n", t->RouteChange);
}

#endif

