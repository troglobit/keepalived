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
#include "config.h"

#define VRRP_SNMP_KEEPALIVEDVERSION 1

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

static oid vrrp_oid[] = VRRP_OID;
static struct variable8 vrrp_vars[] = {
	/* vrrpKeepalivedVersion */
	{VRRP_SNMP_KEEPALIVEDVERSION, ASN_OCTET_STR, RONLY, vrrp_snmp_scalar, 1, {1}},
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
