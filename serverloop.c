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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <netinet/in.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <termios.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "sshpty.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "session.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "serverloop.h"
#അന്തര്ഭാവ "ssherr.h"

ബാഹ്യ ServerOptions options;

/* XXX */
ബാഹ്യ Authctxt *the_authctxt;
ബാഹ്യ ഘടന sshauthopt *auth_opts;

സ്ഥിതം പൂർണ്ണസംഖ്യ no_more_sessions = 0; /* Disallow further sessions. */

സ്ഥിതം അസ്ഥിര sig_atomic_t child_terminated = 0; /* set on SIGCHLD */
സ്ഥിതം അസ്ഥിര sig_atomic_t siginfo_received = 0;

/* prototypes */
സ്ഥിതം ശൂന്യം server_init_dispatch(ഘടന ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
അക്ഷരം *tun_fwd_ifnames = ശൂന്യ;

സ്ഥിതം ശൂന്യം
sigchld_handler(പൂർണ്ണസംഖ്യ sig)
{
	child_terminated = 1;
}

#ifdef SIGINFO
സ്ഥിതം ശൂന്യം
siginfo_handler(പൂർണ്ണസംഖ്യ sig)
{
	siginfo_received = 1;
}
#endif

സ്ഥിതം ശൂന്യം
client_alive_check(ഘടന ssh *ssh)
{
	അക്ഷരം remote_id[512];
	പൂർണ്ണസംഖ്യ r, channel_id;

	/* timeout, check to see how many we have had */
	എങ്കിൽ (options.client_alive_എണ്ണം_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_എണ്ണം_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, വലുപ്പം(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	എങ്കിൽ ((channel_id = channel_find_open(ssh)) == -1) {
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} അല്ലെങ്കിൽ {
		channel_request_start(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
സ്ഥിതം ശൂന്യം
wait_until_can_do_something(ഘടന ssh *ssh,
    പൂർണ്ണസംഖ്യ connection_in, പൂർണ്ണസംഖ്യ connection_out, ഘടന pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    പൂർണ്ണസംഖ്യ *conn_in_readyp, പൂർണ്ണസംഖ്യ *conn_out_readyp)
{
	ഘടന timespec timeout;
	അക്ഷരം remote_id[512];
	പൂർണ്ണസംഖ്യ ret;
	പൂർണ്ണസംഖ്യ client_alive_scheduled = 0;
	u_int p;
	time_t now;
	സ്ഥിതം time_t last_client_time, unused_connection_expiry;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	എങ്കിൽ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	എങ്കിൽ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	എങ്കിൽ (options.unused_connection_timeout != 0) {
		എങ്കിൽ (channel_still_open(ssh))
			unused_connection_expiry = 0;
		അല്ലെങ്കിൽ എങ്കിൽ (unused_connection_expiry == 0) {
			unused_connection_expiry = now +
			    options.unused_connection_timeout;
		}
	}
	എങ്കിൽ (unused_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, unused_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	എങ്കിൽ (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		എങ്കിൽ (last_client_time == 0)
			last_client_time = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#എങ്കിൽ 0
	/* wrong: bad condition XXX */
	എങ്കിൽ (channel_not_very_much_buffered_data())
#endif
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_in;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_out;
	(*pfdp)[1].events = ssh_packet_have_data_to_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	എങ്കിൽ (child_terminated && ssh_packet_not_very_much_data_to_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	എങ്കിൽ (ret == -1) {
		വേണ്ടി (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		എങ്കിൽ (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		തിരികെ;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	എങ്കിൽ (client_alive_scheduled) {
		എങ്കിൽ (ret == 0 &&
		    now >= last_client_time + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			last_client_time = now;
		} അല്ലെങ്കിൽ എങ്കിൽ (ret != 0 && *conn_in_readyp) {
			/* Data from peer; reset probe timer. */
			last_client_time = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	എങ്കിൽ (unused_connection_expiry != 0 &&
	    now > unused_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, വലുപ്പം(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
process_നിവേശം(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ connection_in)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		തിരികെ 0; /* success */
	എങ്കിൽ (r == SSH_ERR_SYSTEM_ERROR) {
		എങ്കിൽ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			തിരികെ 0;
		എങ്കിൽ (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
			തിരികെ -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	തിരികെ -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
സ്ഥിതം ശൂന്യം
process_output(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ connection_out)
{
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിതം പൂർണ്ണസംഖ്യ interactive = -1;

	/* Send any buffered packet data to the client. */
	എങ്കിൽ (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_set_interactive(ssh, interactive);
	}
	എങ്കിൽ ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

സ്ഥിതം ശൂന്യം
process_buffered_നിവേശം_packets(ഘടന ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, ശൂന്യ);
}

സ്ഥിതം ശൂന്യം
collect_children(ഘടന ssh *ssh)
{
	pid_t pid;
	പൂർണ്ണസംഖ്യ status;

	എങ്കിൽ (child_terminated) {
		debug("Received SIGCHLD.");
		ആകുമ്പോൾ ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			എങ്കിൽ (pid > 0)
				session_close_by_pid(ssh, pid, status);
		child_terminated = 0;
	}
}

ശൂന്യം
server_loop2(ഘടന ssh *ssh, Authctxt *authctxt)
{
	ഘടന pollfd *pfd = ശൂന്യ;
	u_int npfd_alloc = 0, npfd_active = 0;
	പൂർണ്ണസംഖ്യ r, conn_in_ready, conn_out_ready;
	u_int connection_in, connection_out;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	എങ്കിൽ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#ifdef SIGINFO
	എങ്കിൽ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#endif
	child_terminated = 0;
	connection_in = ssh_packet_get_connection_in(ssh);
	connection_out = ssh_packet_get_connection_out(ssh);

	server_init_dispatch(ssh);

	വേണ്ടി (;;) {
		process_buffered_നിവേശം_packets(ssh);

		എങ്കിൽ (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_data_to_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		എങ്കിൽ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		എങ്കിൽ (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_in, connection_out,
		    &pfd, &npfd_alloc, &npfd_active, &osigset,
		    &conn_in_ready, &conn_out_ready);
		എങ്കിൽ (sigprocmask(SIG_SETMASK, &osigset, ശൂന്യ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_active);
		എങ്കിൽ (conn_in_ready &&
		    process_നിവേശം(ssh, connection_in) < 0)
			നിർത്തുക;
		/* A timeout may have triggered rekeying */
		എങ്കിൽ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		എങ്കിൽ (conn_out_ready)
			process_output(ssh, connection_out);
	}
	collect_children(ssh);
	സ്വതന്ത്രം(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, ശൂന്യ);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
server_നിവേശം_keep_alive(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_set_alive_timeouts(ssh, 0);
	തിരികെ 0;
}

സ്ഥിതം Channel *
server_request_direct_tcpip(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ *reason, സ്ഥിരം അക്ഷരം **errmsg)
{
	Channel *c = ശൂന്യ;
	അക്ഷരം *target = ശൂന്യ, *originator = ശൂന്യ;
	u_int target_port = 0, originator_port = 0;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &target, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &target_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	എങ്കിൽ (target_port > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		പോകുക out;
	}
	എങ്കിൽ (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		പോകുക out;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_port, target, target_port);

	/* XXX fine grained permissions */
	എങ്കിൽ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_port(ssh, target, target_port,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} അല്ലെങ്കിൽ {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_port, target, target_port);
		എങ്കിൽ (reason != ശൂന്യ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 out:
	സ്വതന്ത്രം(originator);
	സ്വതന്ത്രം(target);
	തിരികെ c;
}

സ്ഥിതം Channel *
server_request_direct_streamlocal(ഘടന ssh *ssh)
{
	Channel *c = ശൂന്യ;
	അക്ഷരം *target = ശൂന്യ, *originator = ശൂന്യ;
	u_int originator_port = 0;
	ഘടന passwd *pw = the_authctxt->pw;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (pw == ശൂന്യ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &target, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	എങ്കിൽ (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		പോകുക out;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_port, target);

	/* XXX fine grained permissions */
	എങ്കിൽ ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_path(ssh, target,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} അല്ലെങ്കിൽ {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_port, target);
	}

out:
	സ്വതന്ത്രം(originator);
	സ്വതന്ത്രം(target);
	തിരികെ c;
}

സ്ഥിതം Channel *
server_request_tun(ഘടന ssh *ssh)
{
	Channel *c = ശൂന്യ;
	u_int mode, tun;
	പൂർണ്ണസംഖ്യ r, sock;
	അക്ഷരം *tmp, *ifname = ശൂന്യ;

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &mode)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	തിരഞ്ഞെടുപ്പ് (mode) {
	അവസ്ഥ SSH_TUNMODE_POINTOPOINT:
	അവസ്ഥ SSH_TUNMODE_ETHERNET:
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((options.permit_tun & mode) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		തിരികെ ശൂന്യ;
	}

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	എങ്കിൽ (tun > INT_MAX) {
		debug_f("invalid tun");
		പോകുക done;
	}
	എങ്കിൽ (auth_opts->force_tun_device != -1) {
		എങ്കിൽ (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (പൂർണ്ണസംഖ്യ)tun)
			പോകുക done;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, mode, &ifname);
	എങ്കിൽ (sock < 0)
		പോകുക done;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#എങ്കിൽ defined(SSH_TUN_FILTER)
	എങ്കിൽ (mode == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ശൂന്യ, ശൂന്യ);
#endif

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == ശൂന്യ ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == ശൂന്യ ? "" : ",",
	    ifname);
	സ്വതന്ത്രം(tmp);
	സ്വതന്ത്രം(ifname);

 done:
	എങ്കിൽ (c == ശൂന്യ)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	തിരികെ c;
}

സ്ഥിതം Channel *
server_request_session(ഘടന ssh *ssh)
{
	Channel *c;
	പൂർണ്ണസംഖ്യ r;

	debug("input_session_request");
	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	എങ്കിൽ (no_more_sessions) {
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
	എങ്കിൽ (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		തിരികെ ശൂന്യ;
	}
	channel_register_cleanup(ssh, c->self, session_close_by_channel, 0);
	തിരികെ c;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
server_നിവേശം_channel_open(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Channel *c = ശൂന്യ;
	അക്ഷരം *ctype = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *errmsg = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &ctype, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	എങ്കിൽ (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip(ssh, &reason, &errmsg);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_direct_streamlocal(ssh);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	എങ്കിൽ (c != ശൂന്യ) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		എങ്കിൽ (c->type != SSH_CHANNEL_CONNECTING) {
			എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} അല്ലെങ്കിൽ {
		debug_f("failure %s", ctype);
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	സ്വതന്ത്രം(ctype);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
server_നിവേശം_hostkeys_prove(ഘടന ssh *ssh, ഘടന sshbuf **respp)
{
	ഘടന sshbuf *resp = ശൂന്യ;
	ഘടന sshbuf *sigbuf = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ, *താക്കോൽ_pub = ശൂന്യ, *താക്കോൽ_prv = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, ndx, success = 0;
	സ്ഥിരം u_char *blob;
	സ്ഥിരം അക്ഷരം *sigalg, *kex_rsa_sigalg = ശൂന്യ;
	u_char *sig = ശൂന്യ;
	size_t blen, slen;

	എങ്കിൽ ((resp = sshbuf_new()) == ശൂന്യ || (sigbuf = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == താക്കോൽ_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	ആകുമ്പോൾ (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(താക്കോൽ);
		താക്കോൽ = ശൂന്യ;
		എങ്കിൽ ((r = sshpkt_get_string_direct(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &താക്കോൽ)) != 0) {
			error_fr(r, "parse key");
			പോകുക out;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		എങ്കിൽ ((ndx = ssh->kex->host_താക്കോൽ_index(താക്കോൽ, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(താക്കോൽ));
			പോകുക out;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		എങ്കിൽ ((താക്കോൽ_prv = get_hostkey_by_index(ndx)) == ശൂന്യ &&
		    (താക്കോൽ_pub = get_hostkey_public_by_index(ndx, ssh)) == ശൂന്യ) {
			error_f("can't retrieve hostkey %d", ndx);
			പോകുക out;
		}
		sshbuf_reset(sigbuf);
		സ്വതന്ത്രം(sig);
		sig = ശൂന്യ;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(താക്കോൽ);
		എങ്കിൽ (sshkey_type_plain(താക്കോൽ->type) == താക്കോൽ_RSA) {
			എങ്കിൽ (kex_rsa_sigalg != ശൂന്യ)
				sigalg = kex_rsa_sigalg;
			അല്ലെങ്കിൽ എങ്കിൽ (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			അല്ലെങ്കിൽ എങ്കിൽ (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(താക്കോൽ), ndx, sigalg == ശൂന്യ ? "default" : sigalg);
		എങ്കിൽ ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(താക്കോൽ, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, താക്കോൽ_prv, താക്കോൽ_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			പോകുക out;
		}
	}
	/* Success */
	*respp = resp;
	resp = ശൂന്യ; /* don't free it */
	success = 1;
 out:
	സ്വതന്ത്രം(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(താക്കോൽ);
	തിരികെ success;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
server_നിവേശം_global_request(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	അക്ഷരം *rtype = ശൂന്യ;
	u_char want_reply = 0;
	പൂർണ്ണസംഖ്യ r, success = 0, allocated_listen_port = 0;
	u_int port = 0;
	ഘടന sshbuf *resp = ശൂന്യ;
	ഘടന passwd *pw = the_authctxt->pw;
	ഘടന Forward fwd;

	memset(&fwd, 0, വലുപ്പം(fwd));
	എങ്കിൽ (pw == ശൂന്യ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &rtype, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_reply);

	/* -R style forwarding */
	എങ്കിൽ (strcmp(rtype, "tcpip-forward") == 0) {
		എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ശൂന്യ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, port);
		എങ്കിൽ (port <= INT_MAX)
			fwd.listen_port = (പൂർണ്ണസംഖ്യ)port;
		/* check permissions */
		എങ്കിൽ (port > INT_MAX ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_reply && fwd.listen_port == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} അല്ലെങ്കിൽ {
			/* Start listening on the port */
			success = channel_setup_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_port, &options.fwd_opts);
		}
		എങ്കിൽ ((resp = sshbuf_new()) == ശൂന്യ)
			fatal_f("sshbuf_new");
		എങ്കിൽ (allocated_listen_port != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_port)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ശൂന്യ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, port);
		എങ്കിൽ (port <= INT_MAX) {
			fwd.listen_port = (പൂർണ്ണസംഖ്യ)port;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, ശൂന്യ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_path);

		/* check permissions */
		എങ്കിൽ ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} അല്ലെങ്കിൽ {
			/* Start listening on the socket */
			success = channel_setup_remote_fwd_listener(ssh,
			    &fwd, ശൂന്യ, &options.fwd_opts);
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, ശൂന്യ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_path);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_more_sessions = 1;
		success = 1;
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_നിവേശം_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	എങ്കിൽ (want_reply) {
		എങ്കിൽ ((r = sshpkt_start(ssh, success ?
		    SSH2_സന്ദേശം_REQUEST_SUCCESS : SSH2_സന്ദേശം_REQUEST_FAILURE)) != 0 ||
		    (success && resp != ശൂന്യ && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	സ്വതന്ത്രം(fwd.listen_host);
	സ്വതന്ത്രം(fwd.listen_path);
	സ്വതന്ത്രം(rtype);
	sshbuf_free(resp);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
server_നിവേശം_channel_req(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Channel *c;
	പൂർണ്ണസംഖ്യ r, success = 0;
	അക്ഷരം *rtype = ശൂന്യ;
	u_char want_reply = 0;
	u_int id = 0;

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_reply);

	എങ്കിൽ (id >= INT_MAX || (c = channel_lookup(ssh, (പൂർണ്ണസംഖ്യ)id)) == ശൂന്യ) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	എങ്കിൽ (!strcmp(rtype, "eow@openssh.com")) {
		എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} അല്ലെങ്കിൽ എങ്കിൽ ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_നിവേശം_channel_req(ssh, c, rtype);
	എങ്കിൽ (want_reply && !(c->flags & CHAN_CLOSE_SENT)) {
		എങ്കിൽ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		എങ്കിൽ ((r = sshpkt_start(ssh, success ?
		    SSH2_സന്ദേശം_CHANNEL_SUCCESS : SSH2_സന്ദേശം_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	സ്വതന്ത്രം(rtype);
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
server_init_dispatch(ഘടന ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_CLOSE, &channel_നിവേശം_oclose);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_DATA, &channel_നിവേശം_data);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_EOF, &channel_നിവേശം_ieof);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_EXTENDED_DATA, &channel_നിവേശം_extended_data);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN, &server_നിവേശം_channel_open);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION, &channel_നിവേശം_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_FAILURE, &channel_നിവേശം_open_failure);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_REQUEST, &server_നിവേശം_channel_req);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_WINDOW_ADJUST, &channel_നിവേശം_window_adjust);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST, &server_നിവേശം_global_request);
	/* client_alive */
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_SUCCESS, &server_നിവേശം_keep_alive);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_FAILURE, &server_നിവേശം_keep_alive);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_REQUEST_SUCCESS, &server_നിവേശം_keep_alive);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_REQUEST_FAILURE, &server_നിവേശം_keep_alive);
	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEXINIT, &kex_നിവേശം_kexinit);
}
