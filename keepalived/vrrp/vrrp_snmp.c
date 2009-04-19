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
#include "vrrp_iproute.h"
#include "config.h"

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
#define VRRP_SNMP_STATICROUTE_INDEX 18
#define VRRP_SNMP_STATICROUTE_ADDRESSTYPE 19
#define VRRP_SNMP_STATICROUTE_DESTINATION 20
#define VRRP_SNMP_STATICROUTE_DESTINATIONMASK 21
#define VRRP_SNMP_STATICROUTE_GATEWAY 22
#define VRRP_SNMP_STATICROUTE_SECONDARYGATEWAY 23
#define VRRP_SNMP_STATICROUTE_SOURCE 24
#define VRRP_SNMP_STATICROUTE_METRIC 25
#define VRRP_SNMP_STATICROUTE_SCOPE 26
#define VRRP_SNMP_STATICROUTE_BLACKHOLE 27
#define VRRP_SNMP_STATICROUTE_IFINDEX 28
#define VRRP_SNMP_STATICROUTE_IFNAME 29
#define VRRP_SNMP_STATICROUTE_ROUTINGTABLE 30
#define VRRP_SNMP_STATICROUTE_ISSET 31

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

static u_char*
vrrp_snmp_script(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
        static unsigned long long_ret;
	vrrp_script *scr;

	if ((scr = (vrrp_script *)snmp_header_list_table(vp, name, length, exact,
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

	if ((addr = (ip_address *)snmp_header_list_table(vp, name, length, exact,
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
		long_ret = snmp_scope(addr->scope);
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

static u_char*
vrrp_snmp_staticroute(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
        static unsigned long long_ret;
	ip_route *route;

	if ((route = (ip_route *)snmp_header_list_table(vp, name, length, exact,
							var_len, write_method,
							vrrp_data->static_routes)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_STATICROUTE_INDEX:
                long_ret = name[*length - 1];
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_ADDRESSTYPE:
		long_ret = 1;	/* IPv4 only */
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_DESTINATION:
		*var_len = 4;
		return (u_char *)&route->dst;
	case VRRP_SNMP_STATICROUTE_DESTINATIONMASK:
		long_ret = route->dmask;
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_GATEWAY:
		*var_len = 4;
		return (u_char *)&route->gw;
	case VRRP_SNMP_STATICROUTE_SECONDARYGATEWAY:
		*var_len = 4;
		return (u_char *)&route->gw2;
	case VRRP_SNMP_STATICROUTE_SOURCE:
		*var_len = 4;
		return (u_char *)&route->src;
	case VRRP_SNMP_STATICROUTE_METRIC:
		long_ret = route->metric;
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_SCOPE:
		long_ret = snmp_scope(route->scope);
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_BLACKHOLE:
		long_ret = (route->blackhole)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_IFINDEX:
		long_ret = route->index;
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_IFNAME:
		if (route->index) {
			*var_len = strlen(IF_NAME(if_get_by_ifindex(route->index)));
			return (u_char *)&IF_NAME(if_get_by_ifindex(route->index));
		}
		*var_len = 0;
		return (u_char *)"";
	case VRRP_SNMP_STATICROUTE_ROUTINGTABLE:
		long_ret = route->table;
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_ISSET:
		long_ret = (route->set == TRUE)?1:2;
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
	/* vrrpStaticRouteTable */
	{VRRP_SNMP_STATICROUTE_ADDRESSTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 2}},
	{VRRP_SNMP_STATICROUTE_DESTINATION, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 3}},
	{VRRP_SNMP_STATICROUTE_DESTINATIONMASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 4}},
	{VRRP_SNMP_STATICROUTE_GATEWAY, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 5}},
	{VRRP_SNMP_STATICROUTE_SECONDARYGATEWAY, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 6}},
	{VRRP_SNMP_STATICROUTE_SOURCE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 7}},
	{VRRP_SNMP_STATICROUTE_METRIC, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 8}},
	{VRRP_SNMP_STATICROUTE_SCOPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 9}},
	{VRRP_SNMP_STATICROUTE_BLACKHOLE, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 10}},
	{VRRP_SNMP_STATICROUTE_IFINDEX, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 11}},
	{VRRP_SNMP_STATICROUTE_IFNAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 12}},
	{VRRP_SNMP_STATICROUTE_ROUTINGTABLE, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 13}},
	{VRRP_SNMP_STATICROUTE_ISSET, ASN_INTEGER, RONLY,
	 vrrp_snmp_staticroute, 3, {4, 1, 14}},
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
