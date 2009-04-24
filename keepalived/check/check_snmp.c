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

#include "check_snmp.h"
#include "check_data.h"
#include "list.h"

/* Magic */
#define CHECK_SNMP_VSGROUPNAME 1
#define CHECK_SNMP_VSGROUPMEMBERTYPE 3
#define CHECK_SNMP_VSGROUPMEMBERFWMARK 4
#define CHECK_SNMP_VSGROUPMEMBERADDRTYPE 5
#define CHECK_SNMP_VSGROUPMEMBERADDRESS 6
#define CHECK_SNMP_VSGROUPMEMBERADDR1 7
#define CHECK_SNMP_VSGROUPMEMBERADDR2 8
#define CHECK_SNMP_VSGROUPMEMBERPORT 9

static u_char*
check_snmp_vsgroup(struct variable *vp, oid *name, size_t *length,
		   int exact, size_t *var_len, WriteMethod **write_method)
{
	virtual_server_group *g;

	if ((g = (virtual_server_group *)
	     snmp_header_list_table(vp, name, length, exact,
				    var_len, write_method,
				    check_data->vs_group)) == NULL)
		return NULL;

	switch (vp->magic) {
	case CHECK_SNMP_VSGROUPNAME:
		*var_len = strlen(g->gname);
		return (u_char *)g->gname;
	default:
		break;
        }
        return NULL;
}

static u_char*
check_snmp_vsgroupmember(struct variable *vp, oid *name, size_t *length,
			 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	static uint32_t ip;
        oid *target, current[2], best[2];
        int result, target_len;
	int curgroup = 0, curentry;
	element e1, e2;
	virtual_server_group *group;
	virtual_server_group_entry *e, *be = NULL;
#define STATE_VSGM_FWMARK 1
#define STATE_VSGM_ADDRESS 2
#define STATE_VSGM_RANGE 3
#define STATE_VSGM_END 4
	int state;
	list l;


        if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
                memcpy(name, vp->name, sizeof(oid) * vp->namelen);
                *length = vp->namelen;
        }

	*write_method = 0;
	*var_len = sizeof(long);

	if (LIST_ISEMPTY(check_data->vs_group))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
        best[0] = best[1] = MAX_SUBID; /* Our best match */
        target = &name[vp->namelen];   /* Our target match */
        target_len = *length - vp->namelen;
	for (e1 = LIST_HEAD(check_data->vs_group); e1; ELEMENT_NEXT(e1)) {
		group = ELEMENT_DATA(e1);
		curgroup++;
		curentry = 0;
		if (target_len && (curgroup < target[0]))
			continue; /* Optimization: cannot be part of our set */
		if (be)
			break; /* Optimization: cannot be the lower anymore */
		state = STATE_VSGM_FWMARK;
		while (state != STATE_VSGM_END) {
			switch (state) {
			case STATE_VSGM_FWMARK:
				l = group->vfwmark;
				break;
			case STATE_VSGM_ADDRESS:
				l = group->addr_ip;
				break;
			case STATE_VSGM_RANGE:
				l = group->range;
				break;
			default:
				/* Dunno? */
				return NULL;
			}
			state++;
			if (LIST_ISEMPTY(l))
				continue;
			for (e2 = LIST_HEAD(l); e2; ELEMENT_NEXT(e2)) {
				e = ELEMENT_DATA(e2);
				curentry++;
				/* We build our current match */
				current[0] = curgroup;
				current[1] = curentry;
				/* And compare it to our target match */
				if ((result = snmp_oid_compare(current, 2, target,
							       target_len)) < 0)
					continue;
				if ((result == 0) && !exact)
					continue;
				if (result == 0) {
					/* Got an exact match and asked for it */
					be = e;
					goto vsgmember_found;
				}
				if (snmp_oid_compare(current, 2, best, 2) < 0) {
					/* This is our best match */
					memcpy(best, current, sizeof(oid) * 2);
					be = e;
					goto vsgmember_be_found;
				}
			}
		}
	}
	if (be == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
 vsgmember_be_found:
	/* Let's use our best match */
        memcpy(target, best, sizeof(oid) * 2);
        *length = vp->namelen + 2;
 vsgmember_found:
	switch (vp->magic) {
	case CHECK_SNMP_VSGROUPMEMBERTYPE:
		if (be->vfwmark)
			long_ret = 1;
		else if (be->range)
			long_ret = 3;
		else
			long_ret = 2;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERFWMARK:
		if (!be->vfwmark) break;
		long_ret = be->vfwmark;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERADDRTYPE:
		if (be->vfwmark) break;
		long_ret = 1;	/* IPv4 */
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERADDRESS:
		if (be->vfwmark || be->range) break;
		*var_len = 4;
		return (u_char *)&be->addr_ip;
	case CHECK_SNMP_VSGROUPMEMBERADDR1:
		if (!be->range) break;
		*var_len = 4;
		return (u_char *)&be->addr_ip;
	case CHECK_SNMP_VSGROUPMEMBERADDR2:
		if (!be->range) break;
		*var_len = 4;
		ip = be->addr_ip + htonl(be->range);
		return (u_char *)&ip;
	case CHECK_SNMP_VSGROUPMEMBERPORT:
		if (be->vfwmark) break;
		long_ret = htons(be->addr_port);
		return (u_char *)&long_ret;
	default:
		return NULL;
	}
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return check_snmp_vsgroupmember(vp, name, length,
						exact, var_len, write_method);
        return NULL;
}

static oid check_oid[] = CHECK_OID;
static struct variable8 check_vars[] = {
	/* virtualServerGroupTable */
	{CHECK_SNMP_VSGROUPNAME, ASN_OCTET_STR, RONLY,
	 check_snmp_vsgroup, 3, {1, 1, 2}},
	/* virtualServerGroupMemberTable */
	{CHECK_SNMP_VSGROUPMEMBERTYPE, ASN_INTEGER, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 2}},
	{CHECK_SNMP_VSGROUPMEMBERFWMARK, ASN_UNSIGNED, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 3}},
	{CHECK_SNMP_VSGROUPMEMBERADDRTYPE, ASN_INTEGER, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 4}},
	{CHECK_SNMP_VSGROUPMEMBERADDRESS, ASN_OCTET_STR, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 5}},
	{CHECK_SNMP_VSGROUPMEMBERADDR1, ASN_OCTET_STR, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 6}},
	{CHECK_SNMP_VSGROUPMEMBERADDR2, ASN_OCTET_STR, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 7}},
	{CHECK_SNMP_VSGROUPMEMBERPORT, ASN_UNSIGNED, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 8}},
};

void
check_snmp_agent_init()
{
	snmp_agent_init(check_oid, OID_LENGTH(check_oid), "Healthchecker",
			(struct variable *)check_vars,
			sizeof(struct variable8),
			sizeof(check_vars)/sizeof(struct variable8));
}

void
check_snmp_agent_close()
{
	snmp_agent_close(check_oid, OID_LENGTH(check_oid), "Healthchecker");
}
