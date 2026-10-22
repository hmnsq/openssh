/* $OpenBSD: serverloop.c,v 1.248 2026/07/14 01:05:05 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Server main loop for handling the interactive session.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 support by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <netinet/in.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <termios.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "session.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "serverloop.h"
#अन्तर्भाव "ssherr.h"

बाह्य ServerOptions options;

/* XXX */
बाह्य Authctxt *the_authctxt;
बाह्य संरचना sshauthopt *auth_opts;

स्थिर पूर्णाङ्क no_अधिकम्_sessions = 0; /* Disallow further sessions. */

स्थिर चञ्चल sig_atomic_t child_terminated = 0; /* set on SIGCHLD */
स्थिर चञ्चल sig_atomic_t siginfo_received = 0;

/* prototypes */
स्थिर शून्य server_init_dispatch(संरचना ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
वर्ण *tun_fwd_ifnames = रिक्त;

स्थिर शून्य
sigchld_handler(पूर्णाङ्क sig)
{
	child_terminated = 1;
}

#यदि_परिभाषितम् SIGINFO
स्थिर शून्य
siginfo_handler(पूर्णाङ्क sig)
{
	siginfo_received = 1;
}
#यदि_अन्तः

स्थिर शून्य
client_alive_check(संरचना ssh *ssh)
{
	वर्ण remote_id[512];
	पूर्णाङ्क r, channel_id;

	/* timeout, check to see how many we have had */
	यदि (options.client_alive_गणनम्_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_गणनम्_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, परिमाण(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	यदि ((channel_id = channel_find_open(ssh)) == -1) {
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} अन्यथा {
		channel_request_start(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	यदि ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
स्थिर शून्य
wait_until_can_do_something(संरचना ssh *ssh,
    पूर्णाङ्क connection_अन्तर्, पूर्णाङ्क connection_बहिर्गमनम्, संरचना pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    पूर्णाङ्क *conn_अन्तर्_readyp, पूर्णाङ्क *conn_बहिर्गमनम्_readyp)
{
	संरचना timespec timeout;
	वर्ण remote_id[512];
	पूर्णाङ्क ret;
	पूर्णाङ्क client_alive_scheduled = 0;
	u_int p;
	time_t now;
	स्थिर time_t चरमः_client_time, अप्रयुक्तम्_connection_expiry;

	*conn_अन्तर्_readyp = *conn_बहिर्गमनम्_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	यदि (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	यदि (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	यदि (options.अप्रयुक्तम्_connection_timeout != 0) {
		यदि (channel_still_open(ssh))
			अप्रयुक्तम्_connection_expiry = 0;
		अन्यथा यदि (अप्रयुक्तम्_connection_expiry == 0) {
			अप्रयुक्तम्_connection_expiry = now +
			    options.अप्रयुक्तम्_connection_timeout;
		}
	}
	यदि (अप्रयुक्तम्_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, अप्रयुक्तम्_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	यदि (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		यदि (चरमः_client_time == 0)
			चरमः_client_time = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#यदि 0
	/* wrong: bad condition XXX */
	यदि (channel_not_very_much_buffered_दत्त())
#यदि_अन्तः
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_अन्तर्;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_बहिर्गमनम्;
	(*pfdp)[1].events = ssh_packet_have_दत्त_गन्तव्यम्_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	यदि (child_terminated && ssh_packet_not_very_much_दत्त_गन्तव्यम्_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	यदि (ret == -1) {
		प्रति (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		यदि (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		प्रत्यागम;
	}

	*conn_अन्तर्_readyp = (*pfdp)[0].revents != 0;
	*conn_बहिर्गमनम्_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	यदि (client_alive_scheduled) {
		यदि (ret == 0 &&
		    now >= चरमः_client_time + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			चरमः_client_time = now;
		} अन्यथा यदि (ret != 0 && *conn_अन्तर्_readyp) {
			/* Data from peer; reset probe timer. */
			चरमः_client_time = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	यदि (अप्रयुक्तम्_connection_expiry != 0 &&
	    now > अप्रयुक्तम्_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, परिमाण(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
स्थिर पूर्णाङ्क
process_निवेशः(संरचना ssh *ssh, पूर्णाङ्क connection_अन्तर्)
{
	पूर्णाङ्क r;

	यदि ((r = ssh_packet_process_read(ssh, connection_अन्तर्)) == 0)
		प्रत्यागम 0; /* success */
	यदि (r == SSH_ERR_SYSTEM_ERROR) {
		यदि (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			प्रत्यागम 0;
		यदि (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh));
			प्रत्यागम -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	प्रत्यागम -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
स्थिर शून्य
process_output(संरचना ssh *ssh, पूर्णाङ्क connection_बहिर्गमनम्)
{
	पूर्णाङ्क r;
	स्थिर पूर्णाङ्क interactive = -1;

	/* Send any buffered packet data to the client. */
	यदि (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_समुच्चयः_interactive(ssh, interactive);
	}
	यदि ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

स्थिर शून्य
process_buffered_निवेशः_packets(संरचना ssh *ssh)
{
	ssh_dispatch_सततम्_fatal(ssh, DISPATCH_NONBLOCK, रिक्त);
}

स्थिर शून्य
collect_children(संरचना ssh *ssh)
{
	pid_t pid;
	पूर्णाङ्क स्थितिः;

	यदि (child_terminated) {
		debug("Received SIGCHLD.");
		यावत् ((pid = waitpid(-1, &स्थितिः, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			यदि (pid > 0)
				session_close_by_pid(ssh, pid, स्थितिः);
		child_terminated = 0;
	}
}

शून्य
server_loop2(संरचना ssh *ssh, Authctxt *authctxt)
{
	संरचना pollfd *pfd = रिक्त;
	u_int npfd_alloc = 0, npfd_सक्रिय = 0;
	पूर्णाङ्क r, conn_अन्तर्_ready, conn_बहिर्गमनम्_ready;
	u_int connection_अन्तर्, connection_बहिर्गमनम्;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	यदि (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#यदि_परिभाषितम् SIGINFO
	यदि (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#यदि_अन्तः
	child_terminated = 0;
	connection_अन्तर् = ssh_packet_get_connection_अन्तर्(ssh);
	connection_बहिर्गमनम् = ssh_packet_get_connection_बहिर्गमनम्(ssh);

	server_init_dispatch(ssh);

	प्रति (;;) {
		process_buffered_निवेशः_packets(ssh);

		यदि (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_दत्त_गन्तव्यम्_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		यदि (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		यदि (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_अन्तर्, connection_बहिर्गमनम्,
		    &pfd, &npfd_alloc, &npfd_सक्रिय, &osigset,
		    &conn_अन्तर्_ready, &conn_बहिर्गमनम्_ready);
		यदि (sigprocmask(SIG_SETMASK, &osigset, रिक्त) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_सक्रिय);
		यदि (conn_अन्तर्_ready &&
		    process_निवेशः(ssh, connection_अन्तर्) < 0)
			भङ्ग;
		/* A timeout may have triggered rekeying */
		यदि ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		यदि (conn_बहिर्गमनम्_ready)
			process_output(ssh, connection_बहिर्गमनम्);
	}
	collect_children(ssh);
	मुक्त(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, रिक्त);
}

स्थिर पूर्णाङ्क
server_निवेशः_keep_alive(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_समुच्चयः_alive_timeouts(ssh, 0);
	प्रत्यागम 0;
}

स्थिर Channel *
server_request_प्रत्यक्षम्_tcpip(संरचना ssh *ssh, पूर्णाङ्क *reason, ध्रुव वर्ण **errmsg)
{
	Channel *c = रिक्त;
	वर्ण *target = रिक्त, *originator = रिक्त;
	u_int target_पत्तनम् = 0, originator_पत्तनम् = 0;
	पूर्णाङ्क r;

	यदि ((r = sshpkt_get_cstring(ssh, &target, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &target_पत्तनम्)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_पत्तनम्)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	यदि (target_पत्तनम् > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		गच्छ बहिर्गमनम्;
	}
	यदि (originator_पत्तनम् > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		गच्छ बहिर्गमनम्;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_पत्तनम्, target, target_पत्तनम्);

	/* XXX fine grained permissions */
	यदि ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_पत्तनम्_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_गन्तव्यम्_पत्तनम्(ssh, target, target_पत्तनम्,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} अन्यथा {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_पत्तनम्, target, target_पत्तनम्);
		यदि (reason != रिक्त)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 बहिर्गमनम्:
	मुक्त(originator);
	मुक्त(target);
	प्रत्यागम c;
}

स्थिर Channel *
server_request_प्रत्यक्षम्_streamlocal(संरचना ssh *ssh)
{
	Channel *c = रिक्त;
	वर्ण *target = रिक्त, *originator = रिक्त;
	u_int originator_पत्तनम् = 0;
	संरचना passwd *pw = the_authctxt->pw;
	पूर्णाङ्क r;

	यदि (pw == रिक्त || !the_authctxt->valid)
		fatal_f("no/invalid user");

	यदि ((r = sshpkt_get_cstring(ssh, &target, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_पत्तनम्)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	यदि (originator_पत्तनम् > 0xFFFF) {
		error_f("invalid originator port");
		गच्छ बहिर्गमनम्;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_पत्तनम्, target);

	/* XXX fine grained permissions */
	यदि ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_पत्तनम्_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_गन्तव्यम्_मार्गः(ssh, target,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} अन्यथा {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_पत्तनम्, target);
	}

बहिर्गमनम्:
	मुक्त(originator);
	मुक्त(target);
	प्रत्यागम c;
}

स्थिर Channel *
server_request_tun(संरचना ssh *ssh)
{
	Channel *c = रिक्त;
	u_int बहुलकम्, tun;
	पूर्णाङ्क r, sock;
	वर्ण *tmp, *ifname = रिक्त;

	यदि ((r = sshpkt_get_u32(ssh, &बहुलकम्)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	विकल्प (बहुलकम्) {
	पक्ष SSH_TUNMODE_POINTOPOINT:
	पक्ष SSH_TUNMODE_ETHERNET:
		भङ्ग;
	स्वभाव:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		प्रत्यागम रिक्त;
	}
	यदि ((options.permit_tun & बहुलकम्) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		प्रत्यागम रिक्त;
	}

	यदि ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	यदि (tun > अधिकतम_पूर्णाङ्कः) {
		debug_f("invalid tun");
		गच्छ समाप्तम्;
	}
	यदि (auth_opts->force_tun_device != -1) {
		यदि (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (पूर्णाङ्क)tun)
			गच्छ समाप्तम्;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, बहुलकम्, &ifname);
	यदि (sock < 0)
		गच्छ समाप्तम्;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_गवाक्षः_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#यदि defined(SSH_TUN_FILTER)
	यदि (बहुलकम् == SSH_TUNMODE_POINTOPOINT)
		channel_पञ्जिकाकोशः_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, रिक्त, रिक्त);
#यदि_अन्तः

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == रिक्त ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == रिक्त ? "" : ",",
	    ifname);
	मुक्त(tmp);
	मुक्त(ifname);

 समाप्तम्:
	यदि (c == रिक्त)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	प्रत्यागम c;
}

स्थिर Channel *
server_request_session(संरचना ssh *ssh)
{
	Channel *c;
	पूर्णाङ्क r;

	debug("input_session_request");
	यदि ((r = sshpkt_get_अन्तः(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	यदि (no_अधिकम्_sessions) {
		ssh_packet_disconnect(ssh, "Possible attack: attempt to open a "
		    "session after additional sessions disabled");
	}

	/*
	 * A server session has no fd to read or write until a
	 * CHANNEL_REQUEST for a shell is made, so we set the type to
	 * SSH_CHANNEL_LARVAL.  Additionally, a callback for handling all
	 * CHANNEL_REQUEST messages is registered.
	 */
	c = channel_new(ssh, "session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, /*window size*/0, CHAN_SES_PACKET_DEFAULT,
	    0, "server-session", 1);
	यदि (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		प्रत्यागम रिक्त;
	}
	channel_पञ्जिकाकोशः_cleanup(ssh, c->self, session_close_by_channel, 0);
	प्रत्यागम c;
}

स्थिर पूर्णाङ्क
server_निवेशः_channel_open(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = रिक्त;
	वर्ण *ctype = रिक्त;
	ध्रुव वर्ण *errmsg = रिक्त;
	पूर्णाङ्क r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	यदि ((r = sshpkt_get_cstring(ssh, &ctype, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	यदि (वाक्यं_तुलय(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} अन्यथा यदि (वाक्यं_तुलय(ctype, "direct-tcpip") == 0) {
		c = server_request_प्रत्यक्षम्_tcpip(ssh, &reason, &errmsg);
	} अन्यथा यदि (वाक्यं_तुलय(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_प्रत्यक्षम्_streamlocal(ssh);
	} अन्यथा यदि (वाक्यं_तुलय(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	यदि (c != रिक्त) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_गवाक्षः = rwindow;
		c->remote_maxpacket = rmaxpack;
		यदि (c->type != SSH_CHANNEL_CONNECTING) {
			यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_गवाक्षः)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} अन्यथा {
		debug_f("failure %s", ctype);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	मुक्त(ctype);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
server_निवेशः_hostkeys_prove(संरचना ssh *ssh, संरचना sshbuf **respp)
{
	संरचना sshbuf *resp = रिक्त;
	संरचना sshbuf *sigbuf = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त, *कुञ्चिका_pub = रिक्त, *कुञ्चिका_prv = रिक्त;
	पूर्णाङ्क r, ndx, success = 0;
	ध्रुव u_char *blob;
	ध्रुव वर्ण *sigalg, *kex_rsa_sigalg = रिक्त;
	u_char *sig = रिक्त;
	आकार_t blen, slen;

	यदि ((resp = sshbuf_new()) == रिक्त || (sigbuf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == कुञ्चिका_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	यावत् (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(कुञ्चिका);
		कुञ्चिका = रिक्त;
		यदि ((r = sshpkt_get_string_प्रत्यक्षम्(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &कुञ्चिका)) != 0) {
			error_fr(r, "parse key");
			गच्छ बहिर्गमनम्;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		यदि ((ndx = ssh->kex->host_कुञ्चिका_सूचकांक(कुञ्चिका, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(कुञ्चिका));
			गच्छ बहिर्गमनम्;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		यदि ((कुञ्चिका_prv = get_hostkey_by_सूचकांक(ndx)) == रिक्त &&
		    (कुञ्चिका_pub = get_hostkey_लौकिकम्_by_सूचकांक(ndx, ssh)) == रिक्त) {
			error_f("can't retrieve hostkey %d", ndx);
			गच्छ बहिर्गमनम्;
		}
		sshbuf_reset(sigbuf);
		मुक्त(sig);
		sig = रिक्त;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(कुञ्चिका);
		यदि (sshkey_type_plain(कुञ्चिका->type) == कुञ्चिका_RSA) {
			यदि (kex_rsa_sigalg != रिक्त)
				sigalg = kex_rsa_sigalg;
			अन्यथा यदि (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			अन्यथा यदि (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(कुञ्चिका), ndx, sigalg == रिक्त ? "default" : sigalg);
		यदि ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(कुञ्चिका, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, कुञ्चिका_prv, कुञ्चिका_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			गच्छ बहिर्गमनम्;
		}
	}
	/* Success */
	*respp = resp;
	resp = रिक्त; /* don't free it */
	success = 1;
 बहिर्गमनम्:
	मुक्त(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(कुञ्चिका);
	प्रत्यागम success;
}

स्थिर पूर्णाङ्क
server_निवेशः_global_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	वर्ण *rtype = रिक्त;
	u_char want_प्रत्युत्तरम् = 0;
	पूर्णाङ्क r, success = 0, allocated_listen_पत्तनम् = 0;
	u_int पत्तनम् = 0;
	संरचना sshbuf *resp = रिक्त;
	संरचना passwd *pw = the_authctxt->pw;
	संरचना Forward fwd;

	स्मृतिं_पूरय(&fwd, 0, परिमाण(fwd));
	यदि (pw == रिक्त || !the_authctxt->valid)
		fatal_f("no/invalid user");

	यदि ((r = sshpkt_get_cstring(ssh, &rtype, रिक्त)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_प्रत्युत्तरम्)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_प्रत्युत्तरम्);

	/* -R style forwarding */
	यदि (वाक्यं_तुलय(rtype, "tcpip-forward") == 0) {
		यदि ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, रिक्त)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &पत्तनम्)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, पत्तनम्);
		यदि (पत्तनम् <= अधिकतम_पूर्णाङ्कः)
			fwd.listen_पत्तनम् = (पूर्णाङ्क)पत्तनम्;
		/* check permissions */
		यदि (पत्तनम् > अधिकतम_पूर्णाङ्कः ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_पत्तनम्_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_प्रत्युत्तरम् && fwd.listen_पत्तनम् == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} अन्यथा {
			/* Start listening on the port */
			success = channel_सज्जता_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_पत्तनम्, &options.fwd_opts);
		}
		यदि ((resp = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new");
		यदि (allocated_listen_पत्तनम् != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_पत्तनम्)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} अन्यथा यदि (वाक्यं_तुलय(rtype, "cancel-tcpip-forward") == 0) {
		यदि ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, रिक्त)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &पत्तनम्)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, पत्तनम्);
		यदि (पत्तनम् <= अधिकतम_पूर्णाङ्कः) {
			fwd.listen_पत्तनम् = (पूर्णाङ्क)पत्तनम्;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} अन्यथा यदि (वाक्यं_तुलय(rtype, "streamlocal-forward@openssh.com") == 0) {
		यदि ((r = sshpkt_get_cstring(ssh, &fwd.listen_मार्गः, रिक्त)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_मार्गः);

		/* check permissions */
		यदि ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_पत्तनम्_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} अन्यथा {
			/* Start listening on the socket */
			success = channel_सज्जता_remote_fwd_listener(ssh,
			    &fwd, रिक्त, &options.fwd_opts);
		}
	} अन्यथा यदि (वाक्यं_तुलय(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		यदि ((r = sshpkt_get_cstring(ssh, &fwd.listen_मार्गः, रिक्त)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_मार्गः);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} अन्यथा यदि (वाक्यं_तुलय(rtype, "no-more-sessions@openssh.com") == 0) {
		no_अधिकम्_sessions = 1;
		success = 1;
	} अन्यथा यदि (वाक्यं_तुलय(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_निवेशः_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	यदि (want_प्रत्युत्तरम्) {
		यदि ((r = sshpkt_start(ssh, success ?
		    SSH2_सन्देशः_REQUEST_SUCCESS : SSH2_सन्देशः_REQUEST_FAILURE)) != 0 ||
		    (success && resp != रिक्त && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	मुक्त(fwd.listen_host);
	मुक्त(fwd.listen_मार्गः);
	मुक्त(rtype);
	sshbuf_free(resp);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
server_निवेशः_channel_req(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c;
	पूर्णाङ्क r, success = 0;
	वर्ण *rtype = रिक्त;
	u_char want_प्रत्युत्तरम् = 0;
	u_int id = 0;

	यदि ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, रिक्त)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_प्रत्युत्तरम्)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_प्रत्युत्तरम्);

	यदि (id >= अधिकतम_पूर्णाङ्कः || (c = channel_lookup(ssh, (पूर्णाङ्क)id)) == रिक्त) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	यदि (!वाक्यं_तुलय(rtype, "eow@openssh.com")) {
		यदि ((r = sshpkt_get_अन्तः(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} अन्यथा यदि ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && वाक्यं_तुलय(c->ctype, "session") == 0)
		success = session_निवेशः_channel_req(ssh, c, rtype);
	यदि (want_प्रत्युत्तरम् && !(c->flags & CHAN_CLOSE_प्रेषितम्)) {
		यदि (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		यदि ((r = sshpkt_start(ssh, success ?
		    SSH2_सन्देशः_CHANNEL_SUCCESS : SSH2_सन्देशः_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	मुक्त(rtype);
	प्रत्यागम 0;
}

स्थिर शून्य
server_init_dispatch(संरचना ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_CLOSE, &channel_निवेशः_oclose);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_दत्त, &channel_निवेशः_दत्त);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_EOF, &channel_निवेशः_ieof);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_EXTENDED_दत्त, &channel_निवेशः_extended_दत्त);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_OPEN, &server_निवेशः_channel_open);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_OPEN_CONFIRMATION, &channel_निवेशः_open_confirmation);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_OPEN_FAILURE, &channel_निवेशः_open_failure);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_REQUEST, &server_निवेशः_channel_req);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_गवाक्षः_ADJUST, &channel_निवेशः_गवाक्षः_adjust);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_GLOBAL_REQUEST, &server_निवेशः_global_request);
	/* client_alive */
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_SUCCESS, &server_निवेशः_keep_alive);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_FAILURE, &server_निवेशः_keep_alive);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_REQUEST_SUCCESS, &server_निवेशः_keep_alive);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_REQUEST_FAILURE, &server_निवेशः_keep_alive);
	/* rekeying */
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEXINIT, &kex_निवेशः_kexinit);
}
