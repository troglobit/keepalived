/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        TCP checker.
 *
 * Version:     $Id: check_tcp.c,v 1.1.7 2004/04/04 23:28:05 acassen Exp $
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
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
 * Copyright (C) 2001-2004 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "check_tcp.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "layer4.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"

int tcp_connect_thread(thread *);

/* Configuration stream handling */
void
free_tcp_check(void *data)
{
	tcp_checker *tcp_chk = CHECKER_DATA(data);

	FREE(tcp_chk);
	FREE(data);
}

void
dump_tcp_check(void *data)
{
	tcp_checker *tcp_chk = CHECKER_DATA(data);

	syslog(LOG_INFO, "   Keepalive method = TCP_CHECK");
	if (tcp_chk->connection_port)
		syslog(LOG_INFO, "   Connection port = %d",
		       ntohs(tcp_chk->connection_port));
        if (tcp_chk->bindto)
                syslog(LOG_INFO, "   Bind to = %s", inet_ntop2(tcp_chk->bindto));
	syslog(LOG_INFO, "   Connection timeout = %d", tcp_chk->connection_to/TIMER_HZ);
}

void
tcp_check_handler(vector strvec)
{
	tcp_checker *tcp_chk = (tcp_checker *) MALLOC(sizeof (tcp_checker));

	/* queue new checker */
	queue_checker(free_tcp_check, dump_tcp_check, tcp_connect_thread,
		      tcp_chk);
}

void
connect_port_handler(vector strvec)
{
	tcp_checker *tcp_chk = CHECKER_GET();
	tcp_chk->connection_port = htons(CHECKER_VALUE_INT(strvec));
}

void
bind_handler(vector strvec)
{
	tcp_checker *tcp_chk = CHECKER_GET();
	inet_ston(VECTOR_SLOT(strvec, 1), &tcp_chk->bindto);
}

void
connect_timeout_handler(vector strvec)
{
	tcp_checker *tcp_chk = CHECKER_GET();
	tcp_chk->connection_to = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

void
install_tcp_check_keyword(void)
{
	install_keyword("TCP_CHECK", &tcp_check_handler);
	install_sublevel();
	install_keyword("connect_port", &connect_port_handler);
	install_keyword("bindto", &bind_handler);
	install_keyword("connect_timeout", &connect_timeout_handler);
	install_sublevel_end();
}

int
tcp_check_thread(thread * thread)
{
	checker *checker;
	tcp_checker *tcp_check;
	uint16_t addr_port;
	int status;

	checker = THREAD_ARG(thread);
	tcp_check = CHECKER_ARG(checker);

	addr_port = CHECKER_RPORT(checker);
	if (tcp_check->connection_port)
		addr_port = tcp_check->connection_port;
	status = tcp_socket_state(thread->u.fd, thread, CHECKER_RIP(checker)
				  , addr_port, tcp_check_thread);

	/* If status = connect_success, TCP connection to remote host is established.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	if (status == connect_success) {
		close(thread->u.fd);

		if (!svr_checker_up(checker->id, checker->rs)) {
			syslog(LOG_INFO, "TCP connection to [%s:%d] success.",
			       inet_ntop2(CHECKER_RIP(checker))
			       , ntohs(addr_port));
			smtp_alert(thread->master, checker->rs, NULL, NULL,
				   "UP",
				   "=> TCP CHECK succeed on service <=");
			update_svr_checker_state(UP, checker->id
						   , checker->vs
						   , checker->rs);
		}

	} else {

		if (svr_checker_up(checker->id, checker->rs)) {
			syslog(LOG_INFO, "TCP connection to [%s:%d] failed !!!",
			       inet_ntop2(CHECKER_RIP(checker))
			       , ntohs(addr_port));
			smtp_alert(thread->master, checker->rs, NULL, NULL,
				   "DOWN",
				   "=> TCP CHECK failed on service <=");
			update_svr_checker_state(DOWN, checker->id
						     , checker->vs
						     , checker->rs);
		}

	}

	/* Register next timer checker */
	if (status != connect_in_progress)
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				 checker->vs->delay_loop);
	return 0;
}

int
tcp_connect_thread(thread * thread)
{
	checker *checker = THREAD_ARG(thread);
	tcp_checker *tcp_check = CHECKER_ARG(checker);
	int fd;
	uint16_t addr_port;
	int status;

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!CHECKER_ENABLED(checker)) {
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DBG("TCP connect fail to create socket.");
		return 0;
	}

	addr_port = CHECKER_RPORT(checker);
	if (tcp_check->connection_port)
		addr_port = tcp_check->connection_port;
	status = tcp_bind_connect(fd, CHECKER_RIP(checker), addr_port
				  , tcp_check->bindto);

	/* handle tcp connection status & register check worker thread */
	tcp_connection_state(fd, status, thread, tcp_check_thread,
			     tcp_check->connection_to);
	return 0;
}