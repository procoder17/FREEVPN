// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Connection.c
// Connection Manager

//#include <Cedar/Connection.h>
#include <Cedar/CedarPch.h>


// Determine whether the socket is to use to send
#define	IS_SEND_TCP_SOCK(ts)		\
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode == false)))

// Determine whether the socket is to use to receive
#define	IS_RECV_TCP_SOCK(ts)		\
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode == false)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode)))


// Generate the next packet
BUF *NewKeepPacket(bool server_mode)
{
	BUF *b = NewBuf();
	char *string = KEEP_ALIVE_STRING;

	WriteBuf(b, string, StrLen(string));

	SeekBuf(b, 0, 0);

	return b;
}

// KEEP thread
void KeepThread(THREAD *thread, void *param)
{
	KEEP *k = (KEEP *)param;
	SOCK *s;
	char server_name[MAX_HOST_NAME_LEN + 1];
	UINT server_port;
	bool udp_mode;
	bool enabled;
	// Validate arguments
	if (thread == NULL || k == NULL)
	{
		return;
	}

WAIT_FOR_ENABLE:
	Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);

	// Wait until it becomes enabled
	while (true)
	{
		enabled = false;
		Lock(k->lock);
		{
			if (k->Enable)
			{
				if (StrLen(k->ServerName) != 0 && k->ServerPort != 0 && k->Interval != 0)
				{
					StrCpy(server_name, sizeof(server_name), k->ServerName);
					server_port = k->ServerPort;
					udp_mode = k->UdpMode;
					enabled = true;
				}
			}
		}
		Unlock(k->lock);
		if (enabled)
		{
			break;
		}
		if (k->Halt)
		{
			return;
		}
		Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
	}

	if (udp_mode == false)
	{
		// TCP mode
		// Try until a success to connection
		while (true)
		{
			UINT64 connect_started_tick;
			bool changed = false;
			Lock(k->lock);
			{
				if (StrCmpi(k->ServerName, server_name) != 0 ||
					k->ServerPort != server_port || k->Enable == false ||
					k->UdpMode)
				{
					changed = true;
				}
			}
			Unlock(k->lock);
			if (changed)
			{
				// Settings are changed
				goto WAIT_FOR_ENABLE;
			}

			if (k->Halt)
			{
				// Stop
				return;
			}

			// Attempt to connect to the server
			connect_started_tick = Tick64();
			s = ConnectEx2(server_name, server_port, KEEP_TCP_TIMEOUT, (bool *)&k->Halt);
			if (s != NULL)
			{
				// Successful connection
				break;
			}

			// Connection failure: Wait until timeout or the setting is changed
			while (true)
			{
				changed = false;
				if (k->Halt)
				{
					// Stop
					return;
				}
				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed)
				{
					// Settings are changed
					goto WAIT_FOR_ENABLE;
				}

				if ((Tick64() - connect_started_tick) >= KEEP_RETRY_INTERVAL)
				{
					break;
				}

				Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
			}
		}

		// Success to connect the server
		// Send and receive packet data periodically
		if (s != NULL)
		{
			UINT64 last_packet_sent_time = 0;
			while (true)
			{
				SOCKSET set;
				UINT ret;
				UCHAR buf[MAX_SIZE];
				bool changed;

				InitSockSet(&set);
				AddSockSet(&set, s);

				Select(&set, KEEP_POLLING_INTERVAL, k->Cancel, NULL);

				ret = Recv(s, buf, sizeof(buf), false);
				if (ret == 0)
				{
					// Disconnected
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
				}

				if (s != NULL)
				{
					if ((Tick64() - last_packet_sent_time) >= (UINT64)k->Interval)
					{
						BUF *b;

						// Send the next packet
						last_packet_sent_time = Tick64();

						b = NewKeepPacket(k->Server);

						ret = Send(s, b->Buf, b->Size, false);
						FreeBuf(b);

						if (ret == 0)
						{
							// Disconnected
							Disconnect(s);
							ReleaseSock(s);
							s = NULL;
						}
					}
				}

				changed = false;

				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed || s == NULL)
				{
					// Setting has been changed or disconnected
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
					goto WAIT_FOR_ENABLE;
				}
				else
				{
					if (k->Halt)
					{
						// Stop
						Disconnect(s);
						ReleaseSock(s);
						return;
					}
				}
			}
		}
	}
	else
	{
		IP dest_ip;
		// UDP mode
		// Try to create socket until it successes
		while (true)
		{
			UINT64 connect_started_tick;
			bool changed = false;
			Lock(k->lock);
			{
				if (StrCmpi(k->ServerName, server_name) != 0 ||
					k->ServerPort != server_port || k->Enable == false ||
					k->UdpMode == false)
				{
					changed = true;
				}
			}
			Unlock(k->lock);
			if (changed)
			{
				// Settings are changed
				goto WAIT_FOR_ENABLE;
			}

			if (k->Halt)
			{
				// Stop
				return;
			}

			// Attempt to create a socket
			connect_started_tick = Tick64();

			// Attempt to resolve the name first
			if (GetIP(&dest_ip, server_name))
			{
				// After successful name resolution, create a socket
				s = NewUDP(0);
				if (s != NULL)
				{
					// Creating success
					break;
				}
			}

			// Failure to create: wait until timeout or the setting is changed
			while (true)
			{
				changed = false;
				if (k->Halt)
				{
					// Stop
					return;
				}
				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed)
				{
					// Settings are changed
					goto WAIT_FOR_ENABLE;
				}

				if ((Tick64() - connect_started_tick) >= KEEP_RETRY_INTERVAL)
				{
					break;
				}

				Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
			}
		}

		// Send the packet data periodically
		if (s != NULL)
		{
			UINT64 last_packet_sent_time = 0;
			UINT num_ignore_errors = 0;
			while (true)
			{
				SOCKSET set;
				UINT ret;
				UCHAR buf[MAX_SIZE];
				bool changed;
				IP src_ip;
				UINT src_port;

				InitSockSet(&set);
				AddSockSet(&set, s);

				Select(&set, KEEP_POLLING_INTERVAL, k->Cancel, NULL);

				// Receive
				ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));
				if (ret == 0)
				{
					if (s->IgnoreRecvErr == false)
					{
LABEL_DISCONNECTED:
						// Disconnected
						Disconnect(s);
						ReleaseSock(s);
						s = NULL;
					}
					else
					{
						if ((num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS)
						{
							goto LABEL_DISCONNECTED;
						}
					}
				}

				if (s != NULL)
				{
					if ((Tick64() - last_packet_sent_time) >= (UINT64)k->Interval)
					{
						BUF *b;

						// Send the next packet
						last_packet_sent_time = Tick64();

						b = NewKeepPacket(k->Server);

						ret = SendTo(s, &dest_ip, server_port, b->Buf, b->Size);
						FreeBuf(b);

						if (ret == 0 && s->IgnoreSendErr == false)
						{
							// Disconnected
							Disconnect(s);
							ReleaseSock(s);
							s = NULL;
						}
					}
				}

				changed = false;

				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode == false)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed || s == NULL)
				{
					// Setting has been changed or disconnected
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
					goto WAIT_FOR_ENABLE;
				}
				else
				{
					if (k->Halt)
					{
						// Stop
						Disconnect(s);
						ReleaseSock(s);
						return;
					}
				}
			}
		}
	}
}

// Stop the KEEP
void StopKeep(KEEP *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	k->Halt = true;
	Set(k->HaltEvent);
	Cancel(k->Cancel);

	WaitThread(k->Thread, INFINITE);
	ReleaseThread(k->Thread);
	DeleteLock(k->lock);

	ReleaseCancel(k->Cancel);
	ReleaseEvent(k->HaltEvent);

	Free(k);
}

// Start the KEEP
KEEP *StartKeep()
{
	KEEP *k = ZeroMalloc(sizeof(KEEP));

	k->lock = NewLock();
	k->HaltEvent = NewEvent();
	k->Cancel = NewCancel();

	// Thread start
	k->Thread = NewThread(KeepThread, k);

	return k;
}

// Copy the client authentication data
CLIENT_AUTH *CopyClientAuth(CLIENT_AUTH *a)
{
	CLIENT_AUTH *ret;
	// Validate arguments
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMallocEx(sizeof(CLIENT_AUTH), true);

	ret->AuthType = a->AuthType;
	StrCpy(ret->Username, sizeof(ret->Username), a->Username);

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		// Anonymous authentication
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		// Password authentication
		Copy(ret->HashedPassword, a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		// Plaintext password authentication
		StrCpy(ret->PlainPassword, sizeof(ret->PlainPassword), a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		// Certificate authentication
		ret->ClientX = CloneX(a->ClientX);
		ret->ClientK = CloneK(a->ClientK);
		break;

	case CLIENT_AUTHTYPE_SECURE:
		// Secure device authentication
		StrCpy(ret->SecurePublicCertName, sizeof(ret->SecurePublicCertName), a->SecurePublicCertName);
		StrCpy(ret->SecurePrivateKeyName, sizeof(ret->SecurePrivateKeyName), a->SecurePrivateKeyName);
		break;
	}

	return ret;
}

// Write data to the transmit FIFO (automatic encryption)
void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// Validate arguments
	if (s == NULL || ts == NULL || data == NULL)
	{
		return;
	}

	WriteFifo(ts->SendFifo, data, size);
}

// Write data to the reception FIFO (automatic decryption)
void WriteRecvFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// Validate arguments
	if (s == NULL || ts == NULL || data == NULL)
	{
		return;
	}

	WriteFifo(ts->RecvFifo, data, size);
}

// TCP socket receive
UINT TcpSockRecv(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// Receive
	return Recv(ts->Sock, data, size, s->UseEncrypt);
}

// TCP socket send
UINT TcpSockSend(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// Transmission
	return Send(ts->Sock, data, size, s->UseEncrypt);
}

// Send the data as UDP packet
void SendDataWithUDP(SOCK *s, CONNECTION *c)
{
	UCHAR *buf;
	BUF *b;
	UINT64 dummy_64 = 0;
	UCHAR dummy_buf[16];
	UINT64 now = Tick64();
	UINT ret;
	bool force_flag = false;
	bool packet_sent = false;
	// Validate arguments
	if (s == NULL || c == NULL)
	{
		return;
	}

	// Allocate the temporary buffer in heap
	if (c->RecvBuf == NULL)
	{
		c->RecvBuf = Malloc(RECV_BUF_SIZE);
	}
	buf = c->RecvBuf;

	if (c->Udp->NextKeepAliveTime == 0 || c->Udp->NextKeepAliveTime <= now)
	{
		force_flag = true;
	}

	// Creating a buffer
	while ((c->SendBlocks->num_item > 0) || force_flag)
	{
		UINT *key32;
		UINT64 *seq;
		char *sign;

		force_flag = false;

		// Assemble a buffer from the current queue
		b = NewBuf();

		// Keep an area for packet header (16 bytes)
		WriteBuf(b, dummy_buf, sizeof(dummy_buf));

		// Pack the packets in transmission queue
		while (true)
		{
			BLOCK *block;

			if (b->Size > UDP_BUF_SIZE)
			{
				break;
			}
			block = GetNext(c->SendBlocks);
			if (block == NULL)
			{
				break;
			}

			if (block->Size != 0)
			{
				WriteBufInt(b, block->Size);
				WriteBuf(b, block->Buf, block->Size);

				c->Session->TotalSendSize += (UINT64)block->SizeofData;
				c->Session->TotalSendSizeReal += (UINT64)block->Size;
			}

			FreeBlock(block);
			break;
		}

		// Write sequence number and session key
		sign = (char *)(((UCHAR *)b->Buf));
		key32 = (UINT *)(((UCHAR *)b->Buf + 4));
		seq = (UINT64 *)(((UCHAR *)b->Buf + 8));
		Copy(sign, SE_UDP_SIGN, 4);
		*key32 = Endian32(c->Session->SessionKey32);
		*seq = Endian64(c->Udp->Seq++); // Increment the sequence number

//		InsertQueue(c->Udp->BufferQueue, b);

		packet_sent = true;
/*	}

	// Send a buffer
	while (c->Udp->BufferQueue->num_item != 0)
	{
		FIFO *f = c->Udp->BufferQueue->fifo;
		BUF **pb = (BUF**)(((UCHAR *)f->p) + f->pos);
		BUF *b = *pb;

*/		ret = SendTo(s, &c->Udp->ip, c->Udp->port, b->Buf, b->Size);
		if (ret == SOCK_LATER)
		{
			// Blocking
			Debug(".");
//			break;
		}
		if (ret != b->Size)
		{
			if (s->IgnoreSendErr == false)
			{
				// Error
				Debug("******* SendTo Error !!!\n");
			}
		}

		// Memory release
		FreeBuf(b);
//		GetNext(c->Udp->BufferQueue);
	}

	if (packet_sent)
	{
		// KeepAlive time update
		c->Udp->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
	}
}

// Write the data of the UDP packet to the connection
void PutUDPPacketData(CONNECTION *c, void *data, UINT size)
{
	BUF *b;
	char sign[4];
	// Validate arguments
	if (c == NULL || data == NULL)
	{
		return;
	}

	// Examine the protocol
	if (c->Protocol != CONNECTION_UDP)
	{
		// UDP protocol is not used
		return;
	}

	// Buffer configuration
	b = NewBuf();
	WriteBuf(b, data, size);

	SeekBuf(b, 0, 0);
	ReadBuf(b, sign, 4);

	// Signature confirmation
	if (Cmp(sign, SE_UDP_SIGN, 4) == 0)
	{
		UINT key32;

		// Session key number
		key32 = ReadBufInt(b);

		if (c->Session->SessionKey32 == key32)
		{
			UINT64 seq;

			// Read the Sequence number
			ReadBuf(b, &seq, sizeof(seq));
			seq = Endian64(seq);

			if ((UINT)(seq - c->Udp->RecvSeq - (UINT64)1))
			{
				//Debug("** UDP Seq Lost %u\n", (UINT)(seq - c->Udp->RecvSeq - (UINT64)1));
			}
			c->Udp->RecvSeq = seq;

			//Debug("SEQ: %I32u\n", seq);

			while (true)
			{
				UINT size;

				size = ReadBufInt(b);
				if (size == 0)
				{
					break;
				}
				else if (size <= MAX_PACKET_SIZE)
				{
					void *tmp;
					BLOCK *block;

					tmp = Malloc(size);
					if (ReadBuf(b, tmp, size) != size)
					{
						Free(tmp);
						break;
					}

					// Block configuration
					block = NewBlock(tmp, size, 0);

					// Insert Block
					InsertReceivedBlockToQueue(c, block, false);
				}
			}

			// Update the last communication time
			c->Session->LastCommTime = Tick64();
		}
		else
		{
			Debug("Invalid SessionKey: 0x%X\n", key32);
		}
	}

	FreeBuf(b);
}

// Add a block to the receive queue
void InsertReceivedBlockToQueue(CONNECTION *c, BLOCK *block, bool no_lock)
{
	SESSION *s;
	// Validate arguments
	if (c == NULL || block == NULL)
	{
		return;
	}

	s = c->Session;

	if (c->Protocol == CONNECTION_TCP)
	{
		s->TotalRecvSizeReal += block->SizeofData;
		s->TotalRecvSize += block->Size;
	}

	if (no_lock == false)
	{
		LockQueue(c->ReceivedBlocks);
	}

	if (c->ReceivedBlocks->num_item < MAX_STORED_QUEUE_NUM)
	{
		InsertQueue(c->ReceivedBlocks, block);
	}
	else
	{
		FreeBlock(block);
	}

	if (no_lock == false)
	{
		UnlockQueue(c->ReceivedBlocks);
	}
}

// Generate the interval to the next Keep-Alive packet
// (This should be a random number for the network load reduction)
UINT GenNextKeepAliveSpan(CONNECTION *c)
{
	UINT a, b;
	// Validate arguments
	if (c == NULL)
	{
		return INFINITE;
	}

	a = c->Session->Timeout;
	b = rand() % (a / 2);
	b = MAX(b, a / 5);

	return b;
}

// Release of the block
void FreeBlock(BLOCK *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	Free(b->Buf);
	Free(b);
}

// Create a new block
BLOCK *NewBlock(void *data, UINT size, int compress)
{
	BLOCK *b;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	b = MallocFast(sizeof(BLOCK));

	b->IsFlooding = false;

	b->PriorityQoS = b->Ttl = b->Param1 = 0;

	if (compress == 0)
	{
		// Uncompressed
		b->Compressed = FALSE;
		b->Buf = data;
		b->Size = size;
		b->SizeofData = size;
	}
	else if (compress == 1)
	{
		UINT max_size;

		// Compressed
		b->Compressed = TRUE;
		max_size = CalcCompress(size);
		b->Buf = MallocFast(max_size);
		b->Size = Compress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		// Discard old data block
		Free(data);
	}
	else
	{
		// Expand
		UINT max_size;

		b->Compressed = FALSE;
		max_size = MAX_PACKET_SIZE;
		b->Buf = MallocFast(max_size);
		b->Size = Uncompress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		// Discard old data
		Free(data);
	}

	return b;
}

// Create a TCP socket
TCPSOCK *NewTcpSock(SOCK *s)
{
	TCPSOCK *ts;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	ts = ZeroMalloc(sizeof(TCPSOCK));

	ts->Sock = s;
	AddRef(s->ref);

	ts->RecvFifo = NewFifo();
	ts->SendFifo = NewFifo();
	ts->EstablishedTick = ts->LastRecvTime = ts->LastCommTime = Tick64();

	// Unset the time-out value
	SetTimeout(s, TIMEOUT_INFINITE);

	return ts;
}

// Release of TCP socket
void FreeTcpSock(TCPSOCK *ts)
{
	// Validate arguments
	if (ts == NULL)
	{
		return;
	}

	Disconnect(ts->Sock);
	ReleaseSock(ts->Sock);
	ReleaseFifo(ts->RecvFifo);
	ReleaseFifo(ts->SendFifo);

	if (ts->SendKey)
	{
		FreeCrypt(ts->SendKey);
	}
	if (ts->RecvKey)
	{
		FreeCrypt(ts->RecvKey);
	}

	Free(ts);
}

// Exit the tunneling mode of connection
void EndTunnelingMode(CONNECTION *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Protocol
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		DisconnectTcpSockets(c);
	}
	else
	{
		// UDP
		DisconnectUDPSockets(c);
	}
}

// Generate a random value that depends on each machine
UINT GetMachineRand()
{
	char pcname[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];

	Zero(pcname, sizeof(pcname));
	GetMachineName(pcname, sizeof(pcname));
	//GenerateRandomString(pcname, sizeof(pcname));
	Sha1(hash, pcname, StrLen(pcname));

	return READ_UINT(hash);
}

// Stop the threads putting additional connection of all that are currently running
void StopAllAdditionalConnectThread(CONNECTION *c)
{
	UINT i, num;
	SOCK **socks;
	THREAD **threads;
	// Validate arguments
	if (c == NULL || c->ServerMode != false)
	{
		return;
	}

	// Disconnect the socket first
	LockList(c->ConnectingSocks);
	{
		num = LIST_NUM(c->ConnectingSocks);
		socks = ToArray(c->ConnectingSocks);
		DeleteAll(c->ConnectingSocks);
	}
	UnlockList(c->ConnectingSocks);
	for (i = 0;i < num;i++)
	{
		Disconnect(socks[i]);
		ReleaseSock(socks[i]);
	}
	Free(socks);

	// Then, wait for the suspension of the thread
	LockList(c->ConnectingThreads);
	{
		num = LIST_NUM(c->ConnectingThreads);
		Debug("c->ConnectingThreads: %u\n", num);
		threads = ToArray(c->ConnectingThreads);
		DeleteAll(c->ConnectingThreads);
	}
	UnlockList(c->ConnectingThreads);
	for (i = 0;i < num;i++)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}
	Free(threads);
}

// Stop the connection
void StopConnection(CONNECTION *c, bool no_wait)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Debug("Stop Connection: %s\n", c->Name);

	// Stop flag
	c->Halt = true;
	Disconnect(c->FirstSock);

	if (no_wait == false)
	{
		// Wait until the thread terminates
		WaitThread(c->Thread, INFINITE);
	}
}

// Close all the UDP socket
void DisconnectUDPSockets(CONNECTION *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}
	if (c->Protocol != CONNECTION_UDP)
	{
		return;
	}

	// Delete entry
	if (c->ServerMode)
	{
		//DelUDPEntry(c->Cedar, c->Session);
	}

	// Delete the UDP structure
	if (c->Udp != NULL)
	{
		if (c->Udp->s != NULL)
		{
			ReleaseSock(c->Udp->s);
		}
		if (c->Udp->BufferQueue != NULL)
		{
			// Release of the queue
			BUF *b;
			while (b = GetNext(c->Udp->BufferQueue))
			{
				FreeBuf(b);
			}
			ReleaseQueue(c->Udp->BufferQueue);
		}
		Free(c->Udp);
		c->Udp = NULL;
	}

	if (c->FirstSock != NULL)
	{
		Disconnect(c->FirstSock);
		ReleaseSock(c->FirstSock);
		c->FirstSock = NULL;
	}
}

// Close all TCP connections
void DisconnectTcpSockets(CONNECTION *c)
{
	UINT i, num;
	TCP *tcp;
	TCPSOCK **tcpsocks;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}
	if (c->Protocol != CONNECTION_TCP)
	{
		return;
	}

	tcp = c->Tcp;
	LockList(tcp->TcpSockList);
	{
		tcpsocks = ToArray(tcp->TcpSockList);
		num = LIST_NUM(tcp->TcpSockList);
		DeleteAll(tcp->TcpSockList);
	}
	UnlockList(tcp->TcpSockList);

	if (num != 0)
	{
		Debug("--- SOCKET STATUS ---\n");
		for (i = 0;i < num;i++)
		{
			TCPSOCK *ts = tcpsocks[i];
			Debug(" SOCK %2u: %u\n", i, ts->Sock->SendSize);
			FreeTcpSock(ts);
		}
	}

	Free(tcpsocks);
}

// Clean up of the connection
void CleanupConnection(CONNECTION *c)
{
	UINT i, num;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}


	switch (c->Protocol)
	{
	case CONNECTION_TCP:
		// Release of TCP connection list
		DisconnectTcpSockets(c);
		break;

	case CONNECTION_UDP:
		break;
	}

	ReleaseList(c->Tcp->TcpSockList);
	Free(c->Tcp);

	ReleaseSock(c->FirstSock);
	c->FirstSock = NULL;

	ReleaseSock(c->TubeSock);
	c->TubeSock = NULL;

	ReleaseThread(c->Thread);
	Free(c->Name);

	// Release all the receive block and send block
	if (c->SendBlocks)
	{
		LockQueue(c->SendBlocks);
		{
			BLOCK *b;
			while (b = GetNext(c->SendBlocks))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->SendBlocks);
	}
	if (c->SendBlocks2)
	{
		LockQueue(c->SendBlocks2);
		{
			BLOCK *b;
			while (b = GetNext(c->SendBlocks2))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->SendBlocks2);
	}
	if (c->ReceivedBlocks)
	{
		LockQueue(c->ReceivedBlocks);
		{
			BLOCK *b;
			while (b = GetNext(c->ReceivedBlocks))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->ReceivedBlocks);
	}

	if (c->ConnectingThreads)
	{
		THREAD **threads;
		LockList(c->ConnectingThreads);
		{
			num = LIST_NUM(c->ConnectingThreads);
			threads = ToArray(c->ConnectingThreads);
			for (i = 0; i < num; i++)
			{
				ReleaseThread(threads[i]);
			}
			Free(threads);
		}
		UnlockList(c->ConnectingThreads);
		ReleaseList(c->ConnectingThreads);
	}

	if (c->ConnectingSocks)
	{
		SOCK **socks;
		LockList(c->ConnectingSocks);
		{
			num = LIST_NUM(c->ConnectingSocks);
			socks = ToArray(c->ConnectingSocks);
			for (i = 0; i < num; i++)
			{
				Disconnect(socks[i]);
				ReleaseSock(socks[i]);
			}
			Free(socks);
		}
		UnlockList(c->ConnectingSocks);
		ReleaseList(c->ConnectingSocks);
	}

	if (c->RecvBuf)
	{
		Free(c->RecvBuf);
	}

	if (c->ServerX != NULL)
	{
		FreeX(c->ServerX);
	}

	if (c->ClientX != NULL)
	{
		FreeX(c->ClientX);
	}

	ReleaseQueue(c->ReceivedBlocks);
	ReleaseQueue(c->SendBlocks);
	ReleaseQueue(c->SendBlocks2);

	DeleteCounter(c->CurrentNumConnection);

	if (c->CipherName != NULL)
	{
		Free(c->CipherName);
	}

	Free(c);
}

// Release of the connection
void ReleaseConnection(CONNECTION *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupConnection(c);
	}
}

// Comparison of connection
int CompareConnection(void *p1, void *p2)
{
	CONNECTION *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CONNECTION **)p1;
	c2 = *(CONNECTION **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->Name, c2->Name);
}

