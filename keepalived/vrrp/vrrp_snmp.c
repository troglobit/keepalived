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
#include "config.h"

/* Magic */
#define VRRP_SNMP_KEEPALIVEDVERSION 1
#define VRRP_SNMP_SCRIPT_INDEX 2
#define VRRP_SNMP_SCRIPT_NAME 3
#define VRRP_SNMP_SCRIPT_COMMAND 4
#define VRRP_SNMP_SCRIPT_INTERVAL 5
#define VRRP_SNMP_SCRIPT_WEIGHT 6
#define VRRP_SNMP_SCRIPT_RESULT 7

static u_char*
vrrp_snmp_scalar(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_KEEPALIVEDVERSION:
		*var_len = strlen(VERSION_STRING);
		return (u_char *)VERSION_STRING;
	default:
		break;
        }
        return NULL;
}

static vrrp_script*
header_vrrpscript_table(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	element e;
	vrrp_script *scr;
	unsigned int target, current;

	if (header_simple_table(vp, name, length, exact, var_len, write_method, -1))
		return NULL;

	if (LIST_ISEMPTY(vrrp_data->vrrp_script))
		return NULL;

	target = name[*length - 1];
	current = 0;

	for (e = LIST_HEAD(vrrp_data->vrrp_script); e; ELEMENT_NEXT(e)) {
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

	if ((scr = header_vrrpscript_table(vp, name, length, exact,
					   var_len, write_method)) == NULL)
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

static oid vrrp_oid[] = VRRP_OID;
static struct variable8 vrrp_vars[] = {
	/* vrrpKeepalivedVersion */
	{VRRP_SNMP_KEEPALIVEDVERSION, ASN_OCTET_STR, RONLY, vrrp_snmp_scalar, 1, {1}},
	/* vrrpScriptTable */
	{VRRP_SNMP_SCRIPT_INDEX, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {2, 1, 1}},
	{VRRP_SNMP_SCRIPT_NAME, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {2, 1, 2}},
	{VRRP_SNMP_SCRIPT_COMMAND, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {2, 1, 3}},
	{VRRP_SNMP_SCRIPT_INTERVAL, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {2, 1, 4}},
	{VRRP_SNMP_SCRIPT_WEIGHT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {2, 1, 5}},
	{VRRP_SNMP_SCRIPT_RESULT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {2, 1, 6}},
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
