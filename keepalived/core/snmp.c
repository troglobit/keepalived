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
#include "../keepalived/include/config.h"
#include "../keepalived/include/global_data.h"

static int
snmp_keepalived_log(int major, int minor, void *serverarg, void *clientarg)
{
	struct snmp_log_message *slm = (struct snmp_log_message*)serverarg;
	log_message(slm->priority, "%s", slm->msg);
	return 0;
}

/* Convert linux scope to InetScopeType */
unsigned long
snmp_scope(int scope)
{
	switch (scope) {
	case 0: return 14;  /* global */
	case 255: return 0; /* nowhere */
	case 254: return 1; /* host */
	case 253: return 2; /* link */
	case 200: return 5; /* site */
	default: return 0;
	}
	return 0;
}

void*
snmp_header_list_table(struct variable *vp, oid *name, size_t *length,
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

#define SNMP_KEEPALIVEDVERSION 1
#define SNMP_ROUTERID 2
#define SNMP_MAIL_SMTPSERVERADDRESSTYPE 3
#define SNMP_MAIL_SMTPSERVERADDRESS 4
#define SNMP_MAIL_SMTPSERVERTIMEOUT 5
#define SNMP_MAIL_EMAILFROM 6
#define SNMP_MAIL_EMAILADDRESS 7
#define SNMP_LINKBEAT 9

static u_char*
snmp_scalar(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;
	
	switch (vp->magic) {
	case SNMP_KEEPALIVEDVERSION:
		*var_len = strlen(VERSION_STRING) - 1;
		return (u_char *)VERSION_STRING;
	case SNMP_ROUTERID:
		*var_len = strlen(data->router_id);
		return (u_char *)data->router_id;
	case SNMP_MAIL_SMTPSERVERADDRESSTYPE:
		long_ret = 1;	/* IPv4 */
		return (u_char *)&long_ret;
	case SNMP_MAIL_SMTPSERVERADDRESS:
		*var_len = 4;
		return (u_char *)&data->smtp_server;
	case SNMP_MAIL_SMTPSERVERTIMEOUT:
		long_ret = data->smtp_connection_to / TIMER_HZ;
		return (u_char *)&long_ret;
	case SNMP_MAIL_EMAILFROM:
		*var_len = strlen(data->email_from);
		return (u_char *)data->email_from;
	case SNMP_LINKBEAT:
		long_ret = data->linkbeat_use_polling?2:1;
		return (u_char *)&long_ret;
	default:
		break;
	}
	return NULL;
}

static u_char*
snmp_mail(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	char *m;
	if ((m = (char *)snmp_header_list_table(vp, name, length, exact,
						 var_len, write_method,
						 data->email)) == NULL)
		return NULL;

	switch (vp->magic) {
	case SNMP_MAIL_EMAILADDRESS:
		*var_len = strlen(m);
		return (u_char *)m;
	default:
		break;
        }
        return NULL;
}

static oid global_oid[] = GLOBAL_OID;
static struct variable8 global_vars[] = {
	/* version */
	{SNMP_KEEPALIVEDVERSION, ASN_OCTET_STR, RONLY, snmp_scalar, 1, {1}},
	/* routerId */
	{SNMP_ROUTERID, ASN_OCTET_STR, RONLY, snmp_scalar, 1, {2}},
	/* mail */
	{SNMP_MAIL_SMTPSERVERADDRESSTYPE, ASN_INTEGER, RONLY, snmp_scalar, 2, {3, 1}},
	{SNMP_MAIL_SMTPSERVERADDRESS, ASN_OCTET_STR, RONLY, snmp_scalar, 2, {3, 2}},
	{SNMP_MAIL_SMTPSERVERTIMEOUT, ASN_UNSIGNED, RONLY, snmp_scalar, 2, {3, 3}},
	{SNMP_MAIL_EMAILFROM, ASN_OCTET_STR, RONLY, snmp_scalar, 2, {3, 4}},
	/* emailTable */
	{SNMP_MAIL_EMAILADDRESS, ASN_OCTET_STR, RONLY, snmp_mail, 4, {3, 5, 1, 2}},
	/* linkBeat */
	{SNMP_LINKBEAT, ASN_INTEGER, RONLY, snmp_scalar, 1, {5}},
};

void
snmp_agent_init(oid *myoid, int len, char *name, struct variable *variables,
		int varsize, int varlen)
{
	log_message(LOG_INFO, "Starting SNMP subagent");
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
	/* Ping AgentX less often than every 15 seconds: pinging can
	   block keepalived. We check every 2 minutes. */
	netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
			   NETSNMP_DS_AGENT_AGENTX_PING_INTERVAL, 120);

	init_agent(name);
	if (register_mib(name, (struct variable *) variables, varsize,
			 varlen, myoid, len) != MIB_REGISTERED_OK)
		log_message(LOG_WARNING, "Unable to register MIB");
	register_mib("Keepalived", (struct variable *) global_vars,
		     sizeof(struct variable8),
		     sizeof(global_vars)/sizeof(struct variable8),
		     global_oid, OID_LENGTH(global_oid));
	init_snmp(name);

	register_sysORTable(global_oid, OID_LENGTH(global_oid) - 1,
			    "The MIB module for Keepalived");
}

void
snmp_agent_close(oid *myoid, int len, char *name)
{
	unregister_sysORTable(myoid, len);
	snmp_shutdown(name);
}
