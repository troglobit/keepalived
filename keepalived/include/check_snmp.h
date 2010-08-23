/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        check_snmp.c program include file.
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

#ifndef _CHECK_SNMP_H
#define _CHECK_SNMP_H

#include "snmp.h"

#define CHECK_OID KEEPALIVED_OID, 3

extern void check_snmp_agent_init(void);
extern void check_snmp_agent_close(void);
extern void check_snmp_rs_trap(real_server *, virtual_server *);
extern void check_snmp_quorum_trap(virtual_server *);

#endif
