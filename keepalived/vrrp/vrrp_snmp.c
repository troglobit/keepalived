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

#include "vrrp.h"
#include "vrrp_snmp.h"
#include "vrrp_data.h"
#include "vrrp_track.h"
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "config.h"
#include "vector.h"

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
#define VRRP_SNMP_SYNCGROUP_INDEX 32
#define VRRP_SNMP_SYNCGROUP_NAME 33
#define VRRP_SNMP_SYNCGROUP_STATE 34
#define VRRP_SNMP_SYNCGROUP_SMTPALERT 35
#define VRRP_SNMP_SYNCGROUP_NOTIFYEXEC 36
#define VRRP_SNMP_SYNCGROUP_SCRIPTMASTER 37
#define VRRP_SNMP_SYNCGROUP_SCRIPTBACKUP 38
#define VRRP_SNMP_SYNCGROUP_SCRIPTFAULT 39
#define VRRP_SNMP_SYNCGROUP_SCRIPT 40
#define VRRP_SNMP_SYNCGROUPMEMBER_INSTANCE 42
#define VRRP_SNMP_SYNCGROUPMEMBER_NAME 43
#define VRRP_SNMP_INSTANCE_INDEX 44
#define VRRP_SNMP_INSTANCE_NAME 45
#define VRRP_SNMP_INSTANCE_VIRTUALROUTERID 46
#define VRRP_SNMP_INSTANCE_STATE 47
#define VRRP_SNMP_INSTANCE_INITIALSTATE 48
#define VRRP_SNMP_INSTANCE_WANTEDSTATE 49
#define VRRP_SNMP_INSTANCE_BASEPRIORITY 50
#define VRRP_SNMP_INSTANCE_EFFECTIVEPRIORITY 51
#define VRRP_SNMP_INSTANCE_VIPSENABLED 52
#define VRRP_SNMP_INSTANCE_PRIMARYINTERFACE 53
#define VRRP_SNMP_INSTANCE_TRACKPRIMARYIF 54
#define VRRP_SNMP_INSTANCE_ADVERTISEMENTSINT 55
#define VRRP_SNMP_INSTANCE_PREEMPT 56
#define VRRP_SNMP_INSTANCE_PREEMPTDELAY 57
#define VRRP_SNMP_INSTANCE_AUTHTYPE 58
#define VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON 59
#define VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE 60
#define VRRP_SNMP_INSTANCE_SYNCGROUP 61
#define VRRP_SNMP_INSTANCE_GARPDELAY 62
#define VRRP_SNMP_INSTANCE_SMTPALERT 63
#define VRRP_SNMP_INSTANCE_NOTIFYEXEC 64
#define VRRP_SNMP_INSTANCE_SCRIPTMASTER 65
#define VRRP_SNMP_INSTANCE_SCRIPTBACKUP 66
#define VRRP_SNMP_INSTANCE_SCRIPTFAULT 67
#define VRRP_SNMP_INSTANCE_SCRIPTSTOP 68
#define VRRP_SNMP_INSTANCE_SCRIPT 69

/* Convert VRRP state to SNMP state */
static unsigned long
vrrp_snmp_state(int state)
{
	return (state<VRRP_STATE_GOTO_MASTER)?state:4;
}

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
		break;
	case VRRP_SNMP_STATICADDRESS_ISSET:
		long_ret = (addr->set)?1:2;
		return (u_char *)&long_ret;
	default:
		return NULL;
        }
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_staticaddress(vp, name, length,
					       exact, var_len, write_method);
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
		break;
	case VRRP_SNMP_STATICROUTE_ROUTINGTABLE:
		long_ret = route->table;
		return (u_char *)&long_ret;
	case VRRP_SNMP_STATICROUTE_ISSET:
		long_ret = (route->set)?1:2;
		return (u_char *)&long_ret;
	default:
		return NULL;
        }
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_staticroute(vp, name, length,
					     exact, var_len, write_method);
        return NULL;
}

static u_char*
vrrp_snmp_syncgroup(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
        static unsigned long long_ret;
	vrrp_sgroup *group;

	if ((group = (vrrp_sgroup *)
	     snmp_header_list_table(vp, name, length, exact,
				    var_len, write_method,
				    vrrp_data->vrrp_sync_group)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_SYNCGROUP_INDEX:
                long_ret = name[*length - 1];
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_NAME:
		*var_len = strlen(group->gname);
		return (u_char *)group->gname;
	case VRRP_SNMP_SYNCGROUP_STATE:
		long_ret = vrrp_snmp_state(group->state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_SMTPALERT:
		long_ret = group->smtp_alert?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_NOTIFYEXEC:
		long_ret = group->notify_exec?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_SCRIPTMASTER:
		if (group->script_master) {
			*var_len = strlen(group->script_master);
			return (u_char *)group->script_master;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPTBACKUP:
		if (group->script_backup) {
			*var_len = strlen(group->script_backup);
			return (u_char *)group->script_backup;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPTFAULT:
		if (group->script_fault) {
			*var_len = strlen(group->script_fault);
			return (u_char *)group->script_fault;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPT:
		if (group->script) {
			*var_len = strlen(group->script);
			return (u_char *)group->script;
		}
		break;
	default:
		return NULL;
        }
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_syncgroup(vp, name, length,
					   exact, var_len, write_method);
        return NULL;
}

static u_char*
vrrp_snmp_syncgroupmember(struct variable *vp, oid *name, size_t *length,
			  int exact, size_t *var_len, WriteMethod **write_method)
{
        oid *target, current[2], best[2];
        int result, target_len;
	int curgroup, curinstance;
	char *instance, *binstance = NULL;
	element e;
	vrrp_sgroup *group;

        if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
                memcpy(name, vp->name, sizeof(oid) * vp->namelen);
                *length = vp->namelen;
        }

	*write_method = 0;
	*var_len = sizeof(long);

	if (LIST_ISEMPTY(vrrp_data->vrrp_sync_group))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
        best[0] = best[1] = MAX_SUBID; /* Our best match */
        target = &name[vp->namelen];   /* Our target match */
        target_len = *length - vp->namelen;
	curgroup = 0;
	for (e = LIST_HEAD(vrrp_data->vrrp_sync_group); e; ELEMENT_NEXT(e)) {
		group = ELEMENT_DATA(e);
		curgroup++;
		vector_foreach_slot(group->iname, instance, curinstance) {
			/* We build our current match */
			current[0] = curgroup;
			current[1] = curinstance + 1;
			/* And compare it to our target match */
			if ((result = snmp_oid_compare(current, 2, target,
						       target_len)) < 0)
				continue;
			if ((result == 0) && !exact)
				continue;
			if (result == 0) {
				/* Got an exact match and asked for it */
				*var_len = strlen(instance);
				return (u_char *)instance;
			}
			if (snmp_oid_compare(current, 2, best, 2) < 0) {
				/* This is our best match */
				memcpy(best, current, sizeof(oid) * 2);
				binstance = instance;
			}
		}
	}
	if (binstance == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
	/* Let's use our best match */
        memcpy(target, best, sizeof(oid) * 2);
        *length = vp->namelen + 2;
	*var_len = strlen(binstance);
	return (u_char*)binstance;
}

static u_char*
vrrp_snmp_instance(struct variable *vp, oid *name, size_t *length,
		   int exact, size_t *var_len, WriteMethod **write_method)
{
        static unsigned long long_ret;
	vrrp_rt *rt;

	if ((rt = (vrrp_rt *)snmp_header_list_table(vp, name, length, exact,
						    var_len, write_method,
						    vrrp_data->vrrp)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_INSTANCE_INDEX:
                long_ret = name[*length - 1];
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_NAME:
		*var_len = strlen(rt->iname);
		return (u_char *)rt->iname;
	case VRRP_SNMP_INSTANCE_VIRTUALROUTERID:
		long_ret = rt->vrid;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_STATE:
		long_ret = vrrp_snmp_state(rt->state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_INITIALSTATE:
		long_ret = vrrp_snmp_state(rt->init_state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_WANTEDSTATE:
		long_ret = vrrp_snmp_state(rt->wantstate);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_BASEPRIORITY:
		long_ret = rt->base_priority;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_EFFECTIVEPRIORITY:
		long_ret = rt->effective_priority;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_VIPSENABLED:
		long_ret = rt->vipset?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PRIMARYINTERFACE:
		*var_len = strlen(rt->ifp->ifname);
		return (u_char *)&rt->ifp->ifname;
	case VRRP_SNMP_INSTANCE_TRACKPRIMARYIF:
		long_ret = rt->track_ifp?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_ADVERTISEMENTSINT:
		long_ret = rt->adver_int;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PREEMPT:
		long_ret = rt->nopreempt?2:1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PREEMPTDELAY:
		long_ret = rt->preempt_delay;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_AUTHTYPE:
		long_ret = rt->auth_type;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON:
		long_ret = (rt->lvs_syncd_if)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE:
		if (rt->lvs_syncd_if) {
			*var_len = strlen(rt->lvs_syncd_if);
			return (u_char *)rt->lvs_syncd_if;
		}
		break;
	case VRRP_SNMP_INSTANCE_SYNCGROUP:
		if (rt->sync) {
			*var_len = strlen(rt->sync->gname);
			return (u_char *)rt->sync->gname;
		}
		break;
	case VRRP_SNMP_INSTANCE_GARPDELAY:
		long_ret = rt->garp_delay;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_SMTPALERT:
		long_ret = rt->smtp_alert?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_NOTIFYEXEC:
		long_ret = rt->notify_exec?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_SCRIPTMASTER:
		if (rt->script_master) {
			*var_len = strlen(rt->script_master);
			return (u_char *)rt->script_master;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPTBACKUP:
		if (rt->script_backup) {
			*var_len = strlen(rt->script_backup);
			return (u_char *)rt->script_backup;
		}
		break;
		long_ret = 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_SCRIPTFAULT:
		if (rt->script_fault) {
			*var_len = strlen(rt->script_fault);
			return (u_char *)rt->script_fault;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPTSTOP:
		if (rt->script_stop) {
			*var_len = strlen(rt->script_stop);
			return (u_char *)rt->script_stop;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPT:
		if (rt->script_master) {
			*var_len = strlen(rt->script);
			return (u_char *)rt->script;
		}
		break;
	default:
		return NULL;
        }
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_instance(vp, name, length,
					  exact, var_len, write_method);
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
	/* vrrpSyncGroupTable */
	{VRRP_SNMP_SYNCGROUP_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {5, 1, 2}},
	{VRRP_SNMP_SYNCGROUP_STATE, ASN_INTEGER, RONLY,
	 vrrp_snmp_syncgroup, 3, {5, 1, 3}},
	{VRRP_SNMP_SYNCGROUP_SMTPALERT, ASN_INTEGER, RONLY,
	 vrrp_snmp_syncgroup, 3, {5, 1, 4}},
	{VRRP_SNMP_SYNCGROUP_NOTIFYEXEC, ASN_INTEGER, RONLY,
	 vrrp_snmp_syncgroup, 3, {5, 1, 5}},
	{VRRP_SNMP_SYNCGROUP_SCRIPTMASTER, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {5, 1, 6}},
	{VRRP_SNMP_SYNCGROUP_SCRIPTBACKUP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {5, 1, 7}},
	{VRRP_SNMP_SYNCGROUP_SCRIPTFAULT, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {5, 1, 8}},
	{VRRP_SNMP_SYNCGROUP_SCRIPT, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {5, 1, 9}},
	/* vrrpSyncGroupMemberTable */
	{VRRP_SNMP_SYNCGROUPMEMBER_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroupmember, 3, {6, 1, 2}},
	/* vrrpInstanceTable */
	{VRRP_SNMP_INSTANCE_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 2}},
	{VRRP_SNMP_INSTANCE_VIRTUALROUTERID, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 3}},
	{VRRP_SNMP_INSTANCE_STATE, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 4}},
	{VRRP_SNMP_INSTANCE_INITIALSTATE, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 5}},
	{VRRP_SNMP_INSTANCE_WANTEDSTATE, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 6}},
	{VRRP_SNMP_INSTANCE_BASEPRIORITY, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 7}},
	{VRRP_SNMP_INSTANCE_EFFECTIVEPRIORITY, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 8}},
	{VRRP_SNMP_INSTANCE_VIPSENABLED, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 9}},
	{VRRP_SNMP_INSTANCE_PRIMARYINTERFACE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 10}},
	{VRRP_SNMP_INSTANCE_TRACKPRIMARYIF, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 11}},
	{VRRP_SNMP_INSTANCE_ADVERTISEMENTSINT, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 12}},
	{VRRP_SNMP_INSTANCE_PREEMPT, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 13}},
	{VRRP_SNMP_INSTANCE_PREEMPTDELAY, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 14}},
	{VRRP_SNMP_INSTANCE_AUTHTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 15}},
	{VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 16}},
	{VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 17}},
	{VRRP_SNMP_INSTANCE_SYNCGROUP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 18}},
	{VRRP_SNMP_INSTANCE_GARPDELAY, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 19}},
	{VRRP_SNMP_INSTANCE_SMTPALERT, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 20}},
	{VRRP_SNMP_INSTANCE_NOTIFYEXEC, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 21}},
	{VRRP_SNMP_INSTANCE_SCRIPTMASTER, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 22}},
	{VRRP_SNMP_INSTANCE_SCRIPTBACKUP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 23}},
	{VRRP_SNMP_INSTANCE_SCRIPTFAULT, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 24}},
	{VRRP_SNMP_INSTANCE_SCRIPTSTOP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 25}},
	{VRRP_SNMP_INSTANCE_SCRIPT, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {7, 1, 26}},
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
