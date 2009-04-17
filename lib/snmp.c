/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        SNMP framework
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

#include "snmp.h"
#include "logger.h"

int
snmp_keepalived_log(int major, int minor, void *serverarg, void *clientarg)
{
	struct snmp_log_message *slm = (struct snmp_log_message*)serverarg;
	log_message(slm->priority, "%s", slm->msg);
	return 0;
}

void
snmp_agent_init(oid *myoid, int len, char *name, struct variable *variables,
		int varsize, int varlen)
{
	netsnmp_enable_subagent();
	snmp_disable_log();
	snmp_enable_calllog();
	snmp_register_callback(SNMP_CALLBACK_LIBRARY,
			       SNMP_CALLBACK_LOGGING,
			       snmp_keepalived_log,
			       NULL);

	/* Do not handle persistent states */
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
	    NETSNMP_DS_LIB_DONT_PERSIST_STATE, TRUE);
	/* Do not load any MIB */
	setenv("MIBS", "", 1);

	init_agent(name);
	if (register_mib(name, (struct variable *) variables, varsize,
			 varlen, myoid, len) != MIB_REGISTERED_OK)
		log_message(LOG_WARNING, "Unable to register MIB");
	init_snmp(name);

	if (register_sysORTable(myoid, len,
				"keepalived") != 0)
		log_message(LOG_WARNING, "Unable to register to sysORTable");
}

void
snmp_agent_close(oid *myoid, int len, char *name)
{
	unregister_sysORTable(myoid, len);
	snmp_shutdown(name);
}
