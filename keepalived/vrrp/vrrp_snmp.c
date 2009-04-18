/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        SNMP agent
 *
 * Version:     $Id$
 *
 * Author:      Vincent Bernat <bernat@luffy.cx>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#include "vrrp_snmp.h"
#include "vrrp_data.h"
#include "vrrp_track.h"
#include "vrrp_ipaddress.h"
#include "config.h"
#include "list.h"

/* Magic */
#define VRRP_SNMP_KEEPALIVEDVERSION 1
#define VRRP_SNMP_SCRIPT_INDEX 2
#define VRRP_SNMP_SCRIPT_NAME 3
#define VRRP_SNMP_SCRIPT_COMMAND 4
#define VRRP_SNMP_SCRIPT_INTERVAL 5
#define VRRP_SNMP_SCRIPT_WEIGHT 6
#define VRRP_SNMP_SCRIPT_RESULT 7
#define VRRP_SNMP_STATICADDRESS_INDEX 8
#define VRRP_SNMP_STATICADDRESS_ADDRESSTYPE 9
#define VRRP_SNMP_STATICADDRESS_VALUE 10
#define VRRP_SNMP_STATICADDRESS_BROADCAST 11
#define VRRP_SNMP_STATICADDRESS_MASK 12
#define VRRP_SNMP_STATICADDRESS_SCOPE 13
#define VRRP_SNMP_STATICADDRESS_IFINDEX 14
#define VRRP_SNMP_STATICADDRESS_IFNAME 15
#define VRRP_SNMP_STATICADDRESS_IFALIAS 16
#define VRRP_SNMP_STATICADDRESS_ISSET 17

static u_char*
vrrp_snmp_scalar(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_KEEPALIVEDVERSION:
		*var_len = strlen(VERSION_STRING) - 1;
		return (u_char *)VERSION_STRING;
	default:
		break;
        }
        return NULL;
}

static void*
header_list_table(struct variable *vp, oid *name, size_t *length,
		  int exact, size_t *var_len, WriteMethod **write_method, list dlist)
{
	element e;
	void *scr;
	unsigned int target, current;

	if (header_simple_table(vp, name, length, exact, var_len, write_method, -1))
		return NULL;

	if (LIST_ISEMPTY(dlist))
		return NULL;

	target = name[*length - 1];
	current = 0;

	for (e = LIST_HEAD(dlist); e; ELEMENT_NEXT(e)) {
		scr = ELEMENT_DATA(e);
		current++;
		if (current == target)
			/* Exact match */
			return scr;
		if (current < target)
			/* No match found yet */
			continue;
		if (exact)
			/* No exact match found */
			return NULL;
		/* current is the best match */
		name[*length - 1] = current;
		return scr;
	}
	/* No macth found at end */
	return NULL;
}

static u_char*
vrrp_snmp_script(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
        static unsigned long long_ret;
	vrrp_script *scr;

	if ((scr = (vrrp_script *)header_list_table(vp, name, length, exact,
						    var_len, write_method,
						    vrrp_data->vrrp_script)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_SCRIPT_INDEX:
                long_ret = name[*length - 1];
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_NAME:
		*var_len = strlen(scr->sname);
		return (u_char *)scr->sname;
	case VRRP_SNMP_SCRIPT_COMMAND:
		*var_len = strlen(scr->script);
		return (u_char *)scr->script;
	case VRRP_SNMP_SCRIPT_INTERVAL:
		long_ret = scr->interval;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_WEIGHT:
		long_ret = scr->weight;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_RESULT:
		long_ret = scr->result;
		return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
}

static u_char*
vrrp_snmp_staticaddress(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
        static unsigned long long_ret;
	ip_address *addr;

	if ((addr = (ip_address *)header_list_table(vp, name, length, exact,
						    var_len, write_method,
						    vrrp_data->static_addresses)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_STATICADDRESS_INDEX:
                long_ret = name[*length - 1];
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICADDRESS_ADDRESSTYPE:
		long_ret = 1;	/* ipv4 only */
		return (u_char *)&long_ret;		
	case VRRP_SNMP_STATICADDRESS_VALUE:
		*var_len = 4;
		return (u_char *)&addr->addr;
	case VRRP_SNMP_STATICADDRESS_BROADCAST:
		*var_len = 4;
		return (u_char *)&addr->broadcast;
	case VRRP_SNMP_STATICADDRESS_MASK:
		long_ret = addr->mask;
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICADDRESS_SCOPE:
		switch (addr->scope) {
		case 0: long_ret = 14; break;  /* global */
		case 255: long_ret = 0; break; /* nowhere */
		case 254: long_ret = 1; break; /* host */
		case 253: long_ret = 2; break; /* link */
		case 200: long_ret = 5; break; /* site */
		default: long_ret = 0; break;
		}
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICADDRESS_IFINDEX:
		long_ret = addr->ifindex;
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICADDRESS_IFNAME:
		*var_len = strlen(addr->ifp->ifname);
		return (u_char *)addr->ifp->ifname;
	case VRRP_SNMP_STATICADDRESS_IFALIAS:
		if (addr->label) {
			*var_len = strlen(addr->label);
			return (u_char*)addr->label;
		}
		*var_len = 0;
		return (u_char*)"";
	case VRRP_SNMP_STATICADDRESS_ISSET:
		long_ret = (addr->set == TRUE)?1:2;
		return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
}

static oid vrrp_oid[] = VRRP_OID;
static struct variable8 vrrp_vars[] = {
	/* vrrpKeepalivedVersion */
	{VRRP_SNMP_KEEPALIVEDVERSION, ASN_OCTET_STR, RONLY, vrrp_snmp_scalar, 1, {1}},
	/* vrrpScriptTable */
	{VRRP_SNMP_SCRIPT_NAME, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {2, 1, 2}},
	{VRRP_SNMP_SCRIPT_COMMAND, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {2, 1, 3}},
	{VRRP_SNMP_SCRIPT_INTERVAL, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {2, 1, 4}},
	{VRRP_SNMP_SCRIPT_WEIGHT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {2, 1, 5}},
	{VRRP_SNMP_SCRIPT_RESULT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {2, 1, 6}},
	/* vrrpStaticAddressTable */
	{VRRP_SNMP_STATICADDRESS_ADDRESSTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 2}},
	{VRRP_SNMP_STATICADDRESS_VALUE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 3}},
	{VRRP_SNMP_STATICADDRESS_BROADCAST, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 4}},
	{VRRP_SNMP_STATICADDRESS_MASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 5}},
	{VRRP_SNMP_STATICADDRESS_SCOPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 6}},
	{VRRP_SNMP_STATICADDRESS_IFINDEX, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 7}},
	{VRRP_SNMP_STATICADDRESS_IFNAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 8}},
	{VRRP_SNMP_STATICADDRESS_IFALIAS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 9}},
	{VRRP_SNMP_STATICADDRESS_ISSET, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticaddress, 3, {3, 1, 10}},
};

void
vrrp_snmp_agent_init()
{
	snmp_agent_init(vrrp_oid, OID_LENGTH(vrrp_oid), "VRRP",
			(struct variable *)vrrp_vars,
			sizeof(struct variable8),
			sizeof(vrrp_vars)/sizeof(struct variable8));
}

void
vrrp_snmp_agent_close()
{
	snmp_agent_close(vrrp_oid, OID_LENGTH(vrrp_oid), "VRRP");
}
