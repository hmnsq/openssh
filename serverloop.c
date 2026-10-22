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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <netinet/in.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <termios.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "sshpty.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "session.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "serverloop.h"
#அந்தர்பாவ "ssherr.h"

வெளி ServerOptions options;

/* XXX */
வெளி Authctxt *the_authctxt;
வெளி கட்டமைப்பு sshauthopt *auth_opts;

நிலையான முழு no_more_sessions = 0; /* Disallow further sessions. */

நிலையான நிலையற்ற sig_atomic_t child_terminated = 0; /* set on SIGCHLD */
நிலையான நிலையற்ற sig_atomic_t siginfo_received = 0;

/* prototypes */
நிலையான வெறுமை server_init_dispatch(கட்டமைப்பு ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
எழுத்து *tun_fwd_ifnames = வெற்று;

நிலையான வெறுமை
sigchld_handler(முழு sig)
{
	child_terminated = 1;
}

#ifdef SIGINFO
நிலையான வெறுமை
siginfo_handler(முழு sig)
{
	siginfo_received = 1;
}
#endif

நிலையான வெறுமை
client_alive_check(கட்டமைப்பு ssh *ssh)
{
	எழுத்து remote_id[512];
	முழு r, channel_id;

	/* timeout, check to see how many we have had */
	எனில் (options.client_alive_மொத்தம்_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_மொத்தம்_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, அளவு(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	எனில் ((channel_id = channel_find_open(ssh)) == -1) {
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} இல்லையெனில் {
		channel_request_start(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	எனில் ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
நிலையான வெறுமை
wait_until_can_do_something(கட்டமைப்பு ssh *ssh,
    முழு connection_in, முழு connection_out, கட்டமைப்பு pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    முழு *conn_in_readyp, முழு *conn_out_readyp)
{
	கட்டமைப்பு timespec timeout;
	எழுத்து remote_id[512];
	முழு ret;
	முழு client_alive_scheduled = 0;
	u_int p;
	time_t now;
	நிலையான time_t last_client_time, unused_connection_expiry;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	எனில் (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	எனில் (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	எனில் (options.unused_connection_timeout != 0) {
		எனில் (channel_still_open(ssh))
			unused_connection_expiry = 0;
		இல்லையெனில் எனில் (unused_connection_expiry == 0) {
			unused_connection_expiry = now +
			    options.unused_connection_timeout;
		}
	}
	எனில் (unused_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, unused_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	எனில் (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		எனில் (last_client_time == 0)
			last_client_time = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#எனில் 0
	/* wrong: bad condition XXX */
	எனில் (channel_not_very_much_buffered_data())
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
	எனில் (child_terminated && ssh_packet_not_very_much_data_to_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	எனில் (ret == -1) {
		க்கு (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		எனில் (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		திரும்பு;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	எனில் (client_alive_scheduled) {
		எனில் (ret == 0 &&
		    now >= last_client_time + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			last_client_time = now;
		} இல்லையெனில் எனில் (ret != 0 && *conn_in_readyp) {
			/* Data from peer; reset probe timer. */
			last_client_time = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	எனில் (unused_connection_expiry != 0 &&
	    now > unused_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, அளவு(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
நிலையான முழு
process_உள்ளீடு(கட்டமைப்பு ssh *ssh, முழு connection_in)
{
	முழு r;

	எனில் ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		திரும்பு 0; /* success */
	எனில் (r == SSH_ERR_SYSTEM_ERROR) {
		எனில் (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			திரும்பு 0;
		எனில் (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
			திரும்பு -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	திரும்பு -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
நிலையான வெறுமை
process_output(கட்டமைப்பு ssh *ssh, முழு connection_out)
{
	முழு r;
	நிலையான முழு interactive = -1;

	/* Send any buffered packet data to the client. */
	எனில் (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_set_interactive(ssh, interactive);
	}
	எனில் ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

நிலையான வெறுமை
process_buffered_உள்ளீடு_packets(கட்டமைப்பு ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, வெற்று);
}

நிலையான வெறுமை
collect_children(கட்டமைப்பு ssh *ssh)
{
	pid_t pid;
	முழு status;

	எனில் (child_terminated) {
		debug("Received SIGCHLD.");
		போது ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			எனில் (pid > 0)
				session_close_by_pid(ssh, pid, status);
		child_terminated = 0;
	}
}

வெறுமை
server_loop2(கட்டமைப்பு ssh *ssh, Authctxt *authctxt)
{
	கட்டமைப்பு pollfd *pfd = வெற்று;
	u_int npfd_alloc = 0, npfd_active = 0;
	முழு r, conn_in_ready, conn_out_ready;
	u_int connection_in, connection_out;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	எனில் (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#ifdef SIGINFO
	எனில் (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#endif
	child_terminated = 0;
	connection_in = ssh_packet_get_connection_in(ssh);
	connection_out = ssh_packet_get_connection_out(ssh);

	server_init_dispatch(ssh);

	க்கு (;;) {
		process_buffered_உள்ளீடு_packets(ssh);

		எனில் (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_data_to_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		எனில் (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		எனில் (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_in, connection_out,
		    &pfd, &npfd_alloc, &npfd_active, &osigset,
		    &conn_in_ready, &conn_out_ready);
		எனில் (sigprocmask(SIG_SETMASK, &osigset, வெற்று) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_active);
		எனில் (conn_in_ready &&
		    process_உள்ளீடு(ssh, connection_in) < 0)
			நிறுத்து;
		/* A timeout may have triggered rekeying */
		எனில் ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		எனில் (conn_out_ready)
			process_output(ssh, connection_out);
	}
	collect_children(ssh);
	விடுவி(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, வெற்று);
}

நிலையான முழு
server_உள்ளீடு_keep_alive(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_set_alive_timeouts(ssh, 0);
	திரும்பு 0;
}

நிலையான Channel *
server_request_direct_tcpip(கட்டமைப்பு ssh *ssh, முழு *reason, மாறிலி எழுத்து **errmsg)
{
	Channel *c = வெற்று;
	எழுத்து *target = வெற்று, *originator = வெற்று;
	u_int target_port = 0, originator_port = 0;
	முழு r;

	எனில் ((r = sshpkt_get_cstring(ssh, &target, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &target_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	எனில் (target_port > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		செல் out;
	}
	எனில் (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		செல் out;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_port, target, target_port);

	/* XXX fine grained permissions */
	எனில் ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_port(ssh, target, target_port,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} இல்லையெனில் {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_port, target, target_port);
		எனில் (reason != வெற்று)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 out:
	விடுவி(originator);
	விடுவி(target);
	திரும்பு c;
}

நிலையான Channel *
server_request_direct_streamlocal(கட்டமைப்பு ssh *ssh)
{
	Channel *c = வெற்று;
	எழுத்து *target = வெற்று, *originator = வெற்று;
	u_int originator_port = 0;
	கட்டமைப்பு passwd *pw = the_authctxt->pw;
	முழு r;

	எனில் (pw == வெற்று || !the_authctxt->valid)
		fatal_f("no/invalid user");

	எனில் ((r = sshpkt_get_cstring(ssh, &target, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	எனில் (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		செல் out;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_port, target);

	/* XXX fine grained permissions */
	எனில் ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_path(ssh, target,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} இல்லையெனில் {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_port, target);
	}

out:
	விடுவி(originator);
	விடுவி(target);
	திரும்பு c;
}

நிலையான Channel *
server_request_tun(கட்டமைப்பு ssh *ssh)
{
	Channel *c = வெற்று;
	u_int mode, tun;
	முழு r, sock;
	எழுத்து *tmp, *ifname = வெற்று;

	எனில் ((r = sshpkt_get_u32(ssh, &mode)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	தேர்வு (mode) {
	நிலை SSH_TUNMODE_POINTOPOINT:
	நிலை SSH_TUNMODE_ETHERNET:
		நிறுத்து;
	இயல்பு:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		திரும்பு வெற்று;
	}
	எனில் ((options.permit_tun & mode) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		திரும்பு வெற்று;
	}

	எனில் ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	எனில் (tun > INT_MAX) {
		debug_f("invalid tun");
		செல் done;
	}
	எனில் (auth_opts->force_tun_device != -1) {
		எனில் (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (முழு)tun)
			செல் done;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, mode, &ifname);
	எனில் (sock < 0)
		செல் done;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#எனில் defined(SSH_TUN_FILTER)
	எனில் (mode == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, வெற்று, வெற்று);
#endif

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == வெற்று ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == வெற்று ? "" : ",",
	    ifname);
	விடுவி(tmp);
	விடுவி(ifname);

 done:
	எனில் (c == வெற்று)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	திரும்பு c;
}

நிலையான Channel *
server_request_session(கட்டமைப்பு ssh *ssh)
{
	Channel *c;
	முழு r;

	debug("input_session_request");
	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	எனில் (no_more_sessions) {
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
	எனில் (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		திரும்பு வெற்று;
	}
	channel_register_cleanup(ssh, c->self, session_close_by_channel, 0);
	திரும்பு c;
}

நிலையான முழு
server_உள்ளீடு_channel_open(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Channel *c = வெற்று;
	எழுத்து *ctype = வெற்று;
	மாறிலி எழுத்து *errmsg = வெற்று;
	முழு r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	எனில் ((r = sshpkt_get_cstring(ssh, &ctype, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	எனில் (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} இல்லையெனில் எனில் (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip(ssh, &reason, &errmsg);
	} இல்லையெனில் எனில் (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_direct_streamlocal(ssh);
	} இல்லையெனில் எனில் (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	எனில் (c != வெற்று) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		எனில் (c->type != SSH_CHANNEL_CONNECTING) {
			எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} இல்லையெனில் {
		debug_f("failure %s", ctype);
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	விடுவி(ctype);
	திரும்பு 0;
}

நிலையான முழு
server_உள்ளீடு_hostkeys_prove(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf **respp)
{
	கட்டமைப்பு sshbuf *resp = வெற்று;
	கட்டமைப்பு sshbuf *sigbuf = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று, *சாவி_pub = வெற்று, *சாவி_prv = வெற்று;
	முழு r, ndx, success = 0;
	மாறிலி u_char *blob;
	மாறிலி எழுத்து *sigalg, *kex_rsa_sigalg = வெற்று;
	u_char *sig = வெற்று;
	size_t blen, slen;

	எனில் ((resp = sshbuf_new()) == வெற்று || (sigbuf = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == சாவி_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	போது (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(சாவி);
		சாவி = வெற்று;
		எனில் ((r = sshpkt_get_string_direct(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &சாவி)) != 0) {
			error_fr(r, "parse key");
			செல் out;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		எனில் ((ndx = ssh->kex->host_சாவி_index(சாவி, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(சாவி));
			செல் out;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		எனில் ((சாவி_prv = get_hostkey_by_index(ndx)) == வெற்று &&
		    (சாவி_pub = get_hostkey_public_by_index(ndx, ssh)) == வெற்று) {
			error_f("can't retrieve hostkey %d", ndx);
			செல் out;
		}
		sshbuf_reset(sigbuf);
		விடுவி(sig);
		sig = வெற்று;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(சாவி);
		எனில் (sshkey_type_plain(சாவி->type) == சாவி_RSA) {
			எனில் (kex_rsa_sigalg != வெற்று)
				sigalg = kex_rsa_sigalg;
			இல்லையெனில் எனில் (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			இல்லையெனில் எனில் (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(சாவி), ndx, sigalg == வெற்று ? "default" : sigalg);
		எனில் ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(சாவி, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, சாவி_prv, சாவி_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			செல் out;
		}
	}
	/* Success */
	*respp = resp;
	resp = வெற்று; /* don't free it */
	success = 1;
 out:
	விடுவி(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(சாவி);
	திரும்பு success;
}

நிலையான முழு
server_உள்ளீடு_global_request(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	எழுத்து *rtype = வெற்று;
	u_char want_reply = 0;
	முழு r, success = 0, allocated_listen_port = 0;
	u_int port = 0;
	கட்டமைப்பு sshbuf *resp = வெற்று;
	கட்டமைப்பு passwd *pw = the_authctxt->pw;
	கட்டமைப்பு Forward fwd;

	memset(&fwd, 0, அளவு(fwd));
	எனில் (pw == வெற்று || !the_authctxt->valid)
		fatal_f("no/invalid user");

	எனில் ((r = sshpkt_get_cstring(ssh, &rtype, வெற்று)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_reply);

	/* -R style forwarding */
	எனில் (strcmp(rtype, "tcpip-forward") == 0) {
		எனில் ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, வெற்று)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, port);
		எனில் (port <= INT_MAX)
			fwd.listen_port = (முழு)port;
		/* check permissions */
		எனில் (port > INT_MAX ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_reply && fwd.listen_port == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} இல்லையெனில் {
			/* Start listening on the port */
			success = channel_setup_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_port, &options.fwd_opts);
		}
		எனில் ((resp = sshbuf_new()) == வெற்று)
			fatal_f("sshbuf_new");
		எனில் (allocated_listen_port != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_port)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} இல்லையெனில் எனில் (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		எனில் ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, வெற்று)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, port);
		எனில் (port <= INT_MAX) {
			fwd.listen_port = (முழு)port;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} இல்லையெனில் எனில் (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		எனில் ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, வெற்று)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_path);

		/* check permissions */
		எனில் ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} இல்லையெனில் {
			/* Start listening on the socket */
			success = channel_setup_remote_fwd_listener(ssh,
			    &fwd, வெற்று, &options.fwd_opts);
		}
	} இல்லையெனில் எனில் (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		எனில் ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, வெற்று)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_path);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} இல்லையெனில் எனில் (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_more_sessions = 1;
		success = 1;
	} இல்லையெனில் எனில் (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_உள்ளீடு_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	எனில் (want_reply) {
		எனில் ((r = sshpkt_start(ssh, success ?
		    SSH2_செய்தி_REQUEST_SUCCESS : SSH2_செய்தி_REQUEST_FAILURE)) != 0 ||
		    (success && resp != வெற்று && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	விடுவி(fwd.listen_host);
	விடுவி(fwd.listen_path);
	விடுவி(rtype);
	sshbuf_free(resp);
	திரும்பு 0;
}

நிலையான முழு
server_உள்ளீடு_channel_req(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Channel *c;
	முழு r, success = 0;
	எழுத்து *rtype = வெற்று;
	u_char want_reply = 0;
	u_int id = 0;

	எனில் ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, வெற்று)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_reply);

	எனில் (id >= INT_MAX || (c = channel_lookup(ssh, (முழு)id)) == வெற்று) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	எனில் (!strcmp(rtype, "eow@openssh.com")) {
		எனில் ((r = sshpkt_get_end(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} இல்லையெனில் எனில் ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_உள்ளீடு_channel_req(ssh, c, rtype);
	எனில் (want_reply && !(c->flags & CHAN_CLOSE_SENT)) {
		எனில் (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		எனில் ((r = sshpkt_start(ssh, success ?
		    SSH2_செய்தி_CHANNEL_SUCCESS : SSH2_செய்தி_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	விடுவி(rtype);
	திரும்பு 0;
}

நிலையான வெறுமை
server_init_dispatch(கட்டமைப்பு ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_CLOSE, &channel_உள்ளீடு_oclose);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_DATA, &channel_உள்ளீடு_data);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_EOF, &channel_உள்ளீடு_ieof);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_EXTENDED_DATA, &channel_உள்ளீடு_extended_data);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_OPEN, &server_உள்ளீடு_channel_open);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION, &channel_உள்ளீடு_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_OPEN_FAILURE, &channel_உள்ளீடு_open_failure);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_REQUEST, &server_உள்ளீடு_channel_req);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_WINDOW_ADJUST, &channel_உள்ளீடு_window_adjust);
	ssh_dispatch_set(ssh, SSH2_செய்தி_GLOBAL_REQUEST, &server_உள்ளீடு_global_request);
	/* client_alive */
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_SUCCESS, &server_உள்ளீடு_keep_alive);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_FAILURE, &server_உள்ளீடு_keep_alive);
	ssh_dispatch_set(ssh, SSH2_செய்தி_REQUEST_SUCCESS, &server_உள்ளீடு_keep_alive);
	ssh_dispatch_set(ssh, SSH2_செய்தி_REQUEST_FAILURE, &server_உள்ளீடு_keep_alive);
	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEXINIT, &kex_உள்ளீடு_kexinit);
}
