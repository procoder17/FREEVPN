// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Connection.c
// Connection Manager

//#include <Cedar/Connection.h>
#include <Cedar/CedarPch.h>

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
