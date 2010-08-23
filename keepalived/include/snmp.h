/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        snmp.c include file.
 *
 * Version:     $Id$
 *
 * Authors:     Vincent Bernat <bernat@luffy.cx>
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

#ifndef _SNMP_H
#define _SNMP_H

#define USING_AGENTX_SUBAGENT_MODULE

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/agent/util_funcs.h>
#undef FREE

#include "list.h"
#include "utils.h"

#define GLOBAL_OID {1, 3, 6, 1, 4, 1, 9586, 100, 5, 1}

/* For net-snmp */
extern int register_sysORTable(oid *, size_t, const char *);
extern int unregister_sysORTable(oid *, size_t);

extern unsigned long snmp_scope(int scope);
extern void* snmp_header_list_table(struct variable *vp, oid *name, size_t *length,
				    int exact, size_t *var_len, WriteMethod **write_method,
				    list dlist);
extern void snmp_agent_init(oid *myoid, int len,
			    char *name, struct variable *variables,
			    int varsize, int varlen);
extern void snmp_agent_close(oid *myoid, int len, char *name);

#endif
