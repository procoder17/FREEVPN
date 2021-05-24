/* dnsmasq is Copyright (c) 2000-2015 Simon Kelley
 
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "n2n.h"
#define countof(x)      (long)(sizeof(x) / sizeof(x[0]))


/* htree.c */
#define MAXLABELS 128
HTREE_NODE *htree_new_node(char *label, int len);
static HTREE_NODE *htree_find(HTREE_NODE *node, char *label);
HTREE_NODE *htree_find_or_add(HTREE_NODE *node, char *label);
HTREE_NODE *domain_match(HTREE_NODE *root, char *domain);
HTREE_NODE *domain_find_or_add(HTREE_NODE *root, char *domain);
void htree_free (HTREE_NODE *node);


