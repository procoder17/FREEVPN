/*  htree.c Chen Wei <weichen302@gmail.com>

	Use cascade of open addressing hash tables to store config options that
	involve domain names.

					   root
						|
			 +---------------------+
			com                   org
			 |                     |
	+------------------+     +-------------+
	yahoo google twitter   debian       freebsd
	  |      |               |             |
	 www    mail          +---------+     www
						  cn jp uk us
						  |
						 ftp

	The lookup steps over domain name hierarchy top-down. All labels are stored
	in open addressing hash tables. Sub-level labels that belong to different
	parent nodes are stored separately. e.g. yahoo, google, and twitter are in
	one hash table, while debian and freebsd are in another.

	The hash table size is power of 2, two hash functions are used to compute
	hash bucket. For locating a particular label from hash table, two hash
	values are compared first, only if they are match, should the more
	expensive string comparison be used to confirm the search.


	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; version 2 dated June, 1991, or
	(at your option) version 3 dated 29 June, 2007.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program. If not, see <http://www.gnu.org/licenses/>.
*/


#include "htree.h"

#define MAXDNAME	1025		/* maximum presentation domain name */
#define OPEN_ADDRESSING_MAXPROBE 7
#define OPEN_ADDRESSING_DEFAULT_SIZE 4
#define FNV1_32A_INIT ((uint32_t)0x811c9dc5)

static char buf[MAXDNAME];

/* prototypes */
static HTREE_NODE *htree_find(HTREE_NODE *node, char *label);
static void htree_add(HTREE_NODE *node, HTREE_NODE *sub);
static void htree_upsizing(HTREE_NODE *np);
static inline void normalize_domain_name(char *dst, char *src, int len);

/* hash function 1 for double hashing
 * 32 bit Fowler/Noll/Vo hash */
static inline uint32_t dblhash_1(char *key)
{
	uint32_t hval = FNV1_32A_INIT;
	unsigned char *s = (unsigned char *)key;

	while (*s)
	{
		hval ^= (uint32_t)* s++;
		hval +=
			(hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
	}

	return hval;
}

/* hash function 2 for double hashing
 * modified Shift-Add-XOR hash, return an odd number */
static inline uint32_t dblhash_2(char *key)
{
	uint32_t h = 0;
	unsigned char *s = (unsigned char *)key;

	while (*s)
		h ^= (h << 5) + (h >> 2) + *s++;

	return h % 2 ? h : h + 1;
}

/* convert domain to lower cases, remove leading blank, leading and trailing
 * dot. End string with \0 */
static inline void normalize_domain_name(char *d, char *s, int len)
{
	int i;

	/* skip leading dot and blank */
	for (; *s != '\0' && (*s == '.' || *s == '\t' || *s == ' '); s++)
		;

	for (i = 0; i < len && *s != '\0'; i++, s++)
	{
		if (*s >= 'A' && *s <= 'Z')
			d[i] = *s + 'a' - 'A';
		else
			d[i] = *s;
	}

	/* should not happen since the source string limited to MAXDNAME */
	if (i == len)
		i--;

	for (; d[i] == '.'; i--)
		;

	if (i < (len - 1))
		d[++i] = '\0';
	else
		/* something wrong with the source string(domain name), it exceeds
		 * MAXDNAME, terminate the dst string with '\0' anyway */
		d[i] = '\0';
}

HTREE_NODE * htree_init_sub(HTREE_NODE *node)
{
	unsigned n;

	if (node->sub != NULL)
		return node;

	node->sub_size = OPEN_ADDRESSING_DEFAULT_SIZE;
	node->sub_loadmax = node->sub_size * 4 / 5;    /* max loading factor 0.8 */
	node->sub = malloc(node->sub_size * sizeof(HTREE_NODE *));
	for (n = 0; n < node->sub_size; n++)
		node->sub[n] = NULL;

	return node;
}

/* allocate and initialize a new node */
HTREE_NODE * htree_new_node(char *label, int label_len)
{
	HTREE_NODE *node;

	node = malloc(sizeof(HTREE_NODE));
	if (node == NULL)
		return NULL;

	if (label == NULL || label_len == 0)
	{
		node->h1 = 0;
		node->h2 = 0;
		node->label = NULL;
	}
	else
	{
		node->label = strdup(label);
		node->h1 = dblhash_1(label);
		node->h2 = dblhash_2(label);
	}

	node->sub_count = 0;
	node->sub_size = 0;
	node->sub_loadmax = 0;
	node->sub_maxprobe = 0;
	node->sub = NULL;
	node->ptr = NULL;
	node->depth = 0;
	return node;
}

/* double the size of hash table attached to a htree_node, it calls with
 * htree_add with each other. The table size starts with 2^2, so that the new
 * size remains 2^x, the double hash used is chosen to work with 2^n slots */
static void htree_upsizing(HTREE_NODE *np)
{
	HTREE_NODE **oldnodes;
	unsigned i, oldsize;

	oldsize = np->sub_size;
	oldnodes = np->sub;
	np->sub_size = oldsize * 2;
	np->sub_loadmax = np->sub_size * 3 / 4;
	np->sub_count = 0;
	np->sub_maxprobe = 0;
	np->sub = malloc(np->sub_size * sizeof(HTREE_NODE *));
	for (i = 0; i < np->sub_size; i++)
		np->sub[i] = NULL;

	for (i = 0; i < oldsize; i++)
	{
		if (oldnodes[i] != NULL)
		{
			htree_add(np, oldnodes[i]);
		}
	}

	free(oldnodes);
}

/* add a sub-node, upsize if needed, calls with htree_upsizing with each other */
static void htree_add(HTREE_NODE *node, HTREE_NODE *sub)
{
	int n;
	uint32_t dh, idx;

	if (node->sub == NULL)
		htree_init_sub(node);

	n = 0;
	dh = sub->h1;
	while (1)
	{
		/* eq to dh % node->sub_size, since sub_size is power of 2*/
		idx = dh & (node->sub_size - 1);
		if (node->sub[idx] == NULL)
		{
			node->sub[idx] = sub;
			node->sub_count += 1;
			sub->depth = node->depth + 1;
			break;
		}
		else
		{
			dh += sub->h2;
			n++;
		}
	}

	node->sub_maxprobe = max(n, node->sub_maxprobe);
	/*
	 * If it takes a lots of probes to find an empty slot, or the used slots
	 * close to loading max, upsize the table
	 */
	if (node->sub_maxprobe > OPEN_ADDRESSING_MAXPROBE ||
		node->sub_count > node->sub_loadmax)
	{
		htree_upsizing(node);
	}

	return;
}

HTREE_NODE *htree_find_or_add(HTREE_NODE *node, char *label)
{
	HTREE_NODE *np;

	if ((np = htree_find(node, label)) == NULL)
	{
		if (node->sub == NULL)
			htree_init_sub(node);
		np = htree_new_node(label, strlen(label));
		htree_add(node, np);
	}

	return np;
}

/* lookup the label in node's sub, return the pointer, NULL if not found */
static HTREE_NODE *htree_find(HTREE_NODE *node, char *label)
{
	uint32_t h1, h2, dh, idx;
	HTREE_NODE *np;

	/* this domain doesn't have sub-domains */
	if (node->sub == NULL)
		return NULL;

	dh = h1 = dblhash_1(label);
	h2 = dblhash_2(label);
	idx = dh & (node->sub_size - 1);
	while ((np = node->sub[idx]) != NULL)
	{
		if (np->h1 == h1 && np->h2 == h2)
			if (strcmp(np->label, label) == 0)
				return np;

		dh += h2;
		idx = dh & (node->sub_size - 1);
	}

	return NULL;
}

/* look up the whole domain pattern by step over DNS name hierarchy top down.
 * for example, if the pattern is cn.debian.org, the lookup will start with
 * org, then debian, then cn. The longest pattern wins. */
HTREE_NODE * domain_match(HTREE_NODE *root, char *domain)
{
	char *labels[MAXLABELS];
	int i, label_num;
	int len = (int) sizeof(buf);
	HTREE_NODE *node, *res;

	if (root == NULL)
		return NULL;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, domain, strlen(domain));
	//normalize_domain_name(buf, domain, len);

	for (i = 0; i < MAXLABELS; i++)
		labels[i] = NULL;

	label_num = 0;
	labels[label_num++] = &buf[0];

	/* split domain name into labels */
	for (i = 0; i < len && buf[i] != '\0'; i++)
	{
		if (buf[i] == '.')
		{
			buf[i] = '\0';
			labels[label_num++] = &buf[i + 1];
		}
	}

	node = root;
	res = NULL;
	for (i = label_num - 1; i >= 0; i--)
	{
		node = htree_find(node, labels[i]);
		if (node == NULL)
			break;

		/* repeatedly overwrite with node that has option set while walk down the
		 * domain name tree to match config option with longest pattern */
//		if (node->ptr != NULL)
		res = node;
	}

	return res;
}

/* add a domain pattern in the form of debian.org to root or find the node
 * match the domain pattern (for modify) */
HTREE_NODE *domain_find_or_add(HTREE_NODE *root, char *domain)
{
	char *labels[MAXLABELS];
	int i, label_num;
	int len = (int) sizeof(buf);
	HTREE_NODE *node;

	memset(buf, 0, sizeof(buf));
	normalize_domain_name(buf, domain, len);

	for (i = 0; i < MAXLABELS; i++)
		labels[i] = NULL;

	label_num = 0;
	labels[label_num++] = &buf[0];

	for (i = 0; i < len && buf[i] != '\0'; i++)
	{
		if (buf[i] == '.')
		{
			buf[i] = '\0';
			labels[label_num++] = &buf[i + 1];
		}
	}

	node = root;
	for (i = label_num - 1; i >= 0; i--)
		node = htree_find_or_add(node, labels[i]);

	return node;
}

/* free node and all sub-nodes recursively. Unused. */
void htree_free(HTREE_NODE *node)
{
	HTREE_NODE *np;
	unsigned i;
	if(node == NULL)
		return;
	if (node->sub_count > 0)
	{
		for (i = 0; i < node->sub_size; i++)
		{
			np = node->sub[i];
			if (np != NULL)
			{
				if (np->label != NULL)
					free(np->label);

				if (np->ptr != NULL)
					free(np->ptr);

				htree_free(np);
			}
		}
		free(node->sub);
	}

	free(node);
}


