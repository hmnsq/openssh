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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <netinet/in.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <termios.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "sshpty.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "session.h"
#অন্তর্ভাব "dispatch.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "serverloop.h"
#অন্তর্ভাব "ssherr.h"

বাহ্য ServerOptions options;

/* XXX */
বাহ্য Authctxt *the_authctxt;
বাহ্য সংরচনা sshauthopt *auth_opts;

স্থির পূর্ণাঙ্ক no_more_sessions = 0; /* Disallow further sessions. */

স্থির চঞ্চল sig_atomic_t child_terminated = 0; /* set on SIGCHLD */
স্থির চঞ্চল sig_atomic_t siginfo_received = 0;

/* prototypes */
স্থির শূন্য server_init_dispatch(সংরচনা ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
বর্ণ *tun_fwd_ifnames = রিক্ত;

স্থির শূন্য
sigchld_handler(পূর্ণাঙ্ক sig)
{
	child_terminated = 1;
}

#ifdef SIGINFO
স্থির শূন্য
siginfo_handler(পূর্ণাঙ্ক sig)
{
	siginfo_received = 1;
}
#endif

স্থির শূন্য
client_alive_check(সংরচনা ssh *ssh)
{
	বর্ণ remote_id[512];
	পূর্ণাঙ্ক r, channel_id;

	/* timeout, check to see how many we have had */
	যদি (options.client_alive_গুনতি_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_গুনতি_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, পরিমাণ(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	যদি ((channel_id = channel_find_open(ssh)) == -1) {
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} অন্যথা {
		channel_request_start(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	যদি ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
স্থির শূন্য
wait_until_can_do_something(সংরচনা ssh *ssh,
    পূর্ণাঙ্ক connection_in, পূর্ণাঙ্ক connection_out, সংরচনা pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    পূর্ণাঙ্ক *conn_in_readyp, পূর্ণাঙ্ক *conn_out_readyp)
{
	সংরচনা timespec timeout;
	বর্ণ remote_id[512];
	পূর্ণাঙ্ক ret;
	পূর্ণাঙ্ক client_alive_scheduled = 0;
	u_int p;
	time_t now;
	স্থির time_t last_client_time, unused_connection_expiry;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	যদি (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	যদি (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	যদি (options.unused_connection_timeout != 0) {
		যদি (channel_still_open(ssh))
			unused_connection_expiry = 0;
		অন্যথা যদি (unused_connection_expiry == 0) {
			unused_connection_expiry = now +
			    options.unused_connection_timeout;
		}
	}
	যদি (unused_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, unused_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	যদি (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		যদি (last_client_time == 0)
			last_client_time = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#যদি 0
	/* wrong: bad condition XXX */
	যদি (channel_not_very_much_buffered_data())
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
	যদি (child_terminated && ssh_packet_not_very_much_data_to_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	যদি (ret == -1) {
		প্রতি (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		যদি (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		প্রত্যাগম;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	যদি (client_alive_scheduled) {
		যদি (ret == 0 &&
		    now >= last_client_time + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			last_client_time = now;
		} অন্যথা যদি (ret != 0 && *conn_in_readyp) {
			/* Data from peer; reset probe timer. */
			last_client_time = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	যদি (unused_connection_expiry != 0 &&
	    now > unused_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, পরিমাণ(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
স্থির পূর্ণাঙ্ক
process_প্রবেশ(সংরচনা ssh *ssh, পূর্ণাঙ্ক connection_in)
{
	পূর্ণাঙ্ক r;

	যদি ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		প্রত্যাগম 0; /* success */
	যদি (r == SSH_ERR_SYSTEM_ERROR) {
		যদি (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			প্রত্যাগম 0;
		যদি (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
			প্রত্যাগম -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	প্রত্যাগম -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
স্থির শূন্য
process_output(সংরচনা ssh *ssh, পূর্ণাঙ্ক connection_out)
{
	পূর্ণাঙ্ক r;
	স্থির পূর্ণাঙ্ক interactive = -1;

	/* Send any buffered packet data to the client. */
	যদি (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_set_interactive(ssh, interactive);
	}
	যদি ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

স্থির শূন্য
process_buffered_প্রবেশ_packets(সংরচনা ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, রিক্ত);
}

স্থির শূন্য
collect_children(সংরচনা ssh *ssh)
{
	pid_t pid;
	পূর্ণাঙ্ক status;

	যদি (child_terminated) {
		debug("Received SIGCHLD.");
		যাবত্ ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			যদি (pid > 0)
				session_close_by_pid(ssh, pid, status);
		child_terminated = 0;
	}
}

শূন্য
server_loop2(সংরচনা ssh *ssh, Authctxt *authctxt)
{
	সংরচনা pollfd *pfd = রিক্ত;
	u_int npfd_alloc = 0, npfd_active = 0;
	পূর্ণাঙ্ক r, conn_in_ready, conn_out_ready;
	u_int connection_in, connection_out;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	যদি (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#ifdef SIGINFO
	যদি (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#endif
	child_terminated = 0;
	connection_in = ssh_packet_get_connection_in(ssh);
	connection_out = ssh_packet_get_connection_out(ssh);

	server_init_dispatch(ssh);

	প্রতি (;;) {
		process_buffered_প্রবেশ_packets(ssh);

		যদি (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_data_to_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		যদি (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		যদি (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_in, connection_out,
		    &pfd, &npfd_alloc, &npfd_active, &osigset,
		    &conn_in_ready, &conn_out_ready);
		যদি (sigprocmask(SIG_SETMASK, &osigset, রিক্ত) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_active);
		যদি (conn_in_ready &&
		    process_প্রবেশ(ssh, connection_in) < 0)
			ভঙ্গ;
		/* A timeout may have triggered rekeying */
		যদি ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		যদি (conn_out_ready)
			process_output(ssh, connection_out);
	}
	collect_children(ssh);
	মুক্ত(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, রিক্ত);
}

স্থির পূর্ণাঙ্ক
server_প্রবেশ_keep_alive(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_set_alive_timeouts(ssh, 0);
	প্রত্যাগম 0;
}

স্থির Channel *
server_request_direct_tcpip(সংরচনা ssh *ssh, পূর্ণাঙ্ক *reason, ধ্রুব বর্ণ **errmsg)
{
	Channel *c = রিক্ত;
	বর্ণ *target = রিক্ত, *originator = রিক্ত;
	u_int target_port = 0, originator_port = 0;
	পূর্ণাঙ্ক r;

	যদি ((r = sshpkt_get_cstring(ssh, &target, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &target_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	যদি (target_port > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		গচ্ছ out;
	}
	যদি (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		গচ্ছ out;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_port, target, target_port);

	/* XXX fine grained permissions */
	যদি ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_port(ssh, target, target_port,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} অন্যথা {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_port, target, target_port);
		যদি (reason != রিক্ত)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 out:
	মুক্ত(originator);
	মুক্ত(target);
	প্রত্যাগম c;
}

স্থির Channel *
server_request_direct_streamlocal(সংরচনা ssh *ssh)
{
	Channel *c = রিক্ত;
	বর্ণ *target = রিক্ত, *originator = রিক্ত;
	u_int originator_port = 0;
	সংরচনা passwd *pw = the_authctxt->pw;
	পূর্ণাঙ্ক r;

	যদি (pw == রিক্ত || !the_authctxt->valid)
		fatal_f("no/invalid user");

	যদি ((r = sshpkt_get_cstring(ssh, &target, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	যদি (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		গচ্ছ out;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_port, target);

	/* XXX fine grained permissions */
	যদি ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_path(ssh, target,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} অন্যথা {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_port, target);
	}

out:
	মুক্ত(originator);
	মুক্ত(target);
	প্রত্যাগম c;
}

স্থির Channel *
server_request_tun(সংরচনা ssh *ssh)
{
	Channel *c = রিক্ত;
	u_int mode, tun;
	পূর্ণাঙ্ক r, sock;
	বর্ণ *tmp, *ifname = রিক্ত;

	যদি ((r = sshpkt_get_u32(ssh, &mode)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	বিকল্প (mode) {
	পক্ষ SSH_TUNMODE_POINTOPOINT:
	পক্ষ SSH_TUNMODE_ETHERNET:
		ভঙ্গ;
	স্বভাব:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		প্রত্যাগম রিক্ত;
	}
	যদি ((options.permit_tun & mode) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		প্রত্যাগম রিক্ত;
	}

	যদি ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	যদি (tun > INT_MAX) {
		debug_f("invalid tun");
		গচ্ছ done;
	}
	যদি (auth_opts->force_tun_device != -1) {
		যদি (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (পূর্ণাঙ্ক)tun)
			গচ্ছ done;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, mode, &ifname);
	যদি (sock < 0)
		গচ্ছ done;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#যদি defined(SSH_TUN_FILTER)
	যদি (mode == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, রিক্ত, রিক্ত);
#endif

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == রিক্ত ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == রিক্ত ? "" : ",",
	    ifname);
	মুক্ত(tmp);
	মুক্ত(ifname);

 done:
	যদি (c == রিক্ত)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	প্রত্যাগম c;
}

স্থির Channel *
server_request_session(সংরচনা ssh *ssh)
{
	Channel *c;
	পূর্ণাঙ্ক r;

	debug("input_session_request");
	যদি ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	যদি (no_more_sessions) {
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
	যদি (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		প্রত্যাগম রিক্ত;
	}
	channel_register_cleanup(ssh, c->self, session_close_by_channel, 0);
	প্রত্যাগম c;
}

স্থির পূর্ণাঙ্ক
server_প্রবেশ_channel_open(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Channel *c = রিক্ত;
	বর্ণ *ctype = রিক্ত;
	ধ্রুব বর্ণ *errmsg = রিক্ত;
	পূর্ণাঙ্ক r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	যদি ((r = sshpkt_get_cstring(ssh, &ctype, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	যদি (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} অন্যথা যদি (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip(ssh, &reason, &errmsg);
	} অন্যথা যদি (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_direct_streamlocal(ssh);
	} অন্যথা যদি (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	যদি (c != রিক্ত) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		যদি (c->type != SSH_CHANNEL_CONNECTING) {
			যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} অন্যথা {
		debug_f("failure %s", ctype);
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	মুক্ত(ctype);
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
server_প্রবেশ_hostkeys_prove(সংরচনা ssh *ssh, সংরচনা sshbuf **respp)
{
	সংরচনা sshbuf *resp = রিক্ত;
	সংরচনা sshbuf *sigbuf = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত, *চাবি_pub = রিক্ত, *চাবি_prv = রিক্ত;
	পূর্ণাঙ্ক r, ndx, success = 0;
	ধ্রুব u_char *blob;
	ধ্রুব বর্ণ *sigalg, *kex_rsa_sigalg = রিক্ত;
	u_char *sig = রিক্ত;
	size_t blen, slen;

	যদি ((resp = sshbuf_new()) == রিক্ত || (sigbuf = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == চাবি_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	যাবত্ (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(চাবি);
		চাবি = রিক্ত;
		যদি ((r = sshpkt_get_string_direct(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &চাবি)) != 0) {
			error_fr(r, "parse key");
			গচ্ছ out;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		যদি ((ndx = ssh->kex->host_চাবি_index(চাবি, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(চাবি));
			গচ্ছ out;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		যদি ((চাবি_prv = get_hostkey_by_index(ndx)) == রিক্ত &&
		    (চাবি_pub = get_hostkey_public_by_index(ndx, ssh)) == রিক্ত) {
			error_f("can't retrieve hostkey %d", ndx);
			গচ্ছ out;
		}
		sshbuf_reset(sigbuf);
		মুক্ত(sig);
		sig = রিক্ত;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(চাবি);
		যদি (sshkey_type_plain(চাবি->type) == চাবি_RSA) {
			যদি (kex_rsa_sigalg != রিক্ত)
				sigalg = kex_rsa_sigalg;
			অন্যথা যদি (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			অন্যথা যদি (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(চাবি), ndx, sigalg == রিক্ত ? "default" : sigalg);
		যদি ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(চাবি, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, চাবি_prv, চাবি_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			গচ্ছ out;
		}
	}
	/* Success */
	*respp = resp;
	resp = রিক্ত; /* don't free it */
	success = 1;
 out:
	মুক্ত(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(চাবি);
	প্রত্যাগম success;
}

স্থির পূর্ণাঙ্ক
server_প্রবেশ_global_request(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	বর্ণ *rtype = রিক্ত;
	u_char want_reply = 0;
	পূর্ণাঙ্ক r, success = 0, allocated_listen_port = 0;
	u_int port = 0;
	সংরচনা sshbuf *resp = রিক্ত;
	সংরচনা passwd *pw = the_authctxt->pw;
	সংরচনা Forward fwd;

	memset(&fwd, 0, পরিমাণ(fwd));
	যদি (pw == রিক্ত || !the_authctxt->valid)
		fatal_f("no/invalid user");

	যদি ((r = sshpkt_get_cstring(ssh, &rtype, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_reply);

	/* -R style forwarding */
	যদি (strcmp(rtype, "tcpip-forward") == 0) {
		যদি ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, রিক্ত)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, port);
		যদি (port <= INT_MAX)
			fwd.listen_port = (পূর্ণাঙ্ক)port;
		/* check permissions */
		যদি (port > INT_MAX ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_reply && fwd.listen_port == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} অন্যথা {
			/* Start listening on the port */
			success = channel_setup_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_port, &options.fwd_opts);
		}
		যদি ((resp = sshbuf_new()) == রিক্ত)
			fatal_f("sshbuf_new");
		যদি (allocated_listen_port != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_port)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} অন্যথা যদি (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		যদি ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, রিক্ত)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, port);
		যদি (port <= INT_MAX) {
			fwd.listen_port = (পূর্ণাঙ্ক)port;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} অন্যথা যদি (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		যদি ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, রিক্ত)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_path);

		/* check permissions */
		যদি ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} অন্যথা {
			/* Start listening on the socket */
			success = channel_setup_remote_fwd_listener(ssh,
			    &fwd, রিক্ত, &options.fwd_opts);
		}
	} অন্যথা যদি (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		যদি ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, রিক্ত)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_path);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} অন্যথা যদি (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_more_sessions = 1;
		success = 1;
	} অন্যথা যদি (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_প্রবেশ_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	যদি (want_reply) {
		যদি ((r = sshpkt_start(ssh, success ?
		    SSH2_বার্তা_REQUEST_SUCCESS : SSH2_বার্তা_REQUEST_FAILURE)) != 0 ||
		    (success && resp != রিক্ত && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	মুক্ত(fwd.listen_host);
	মুক্ত(fwd.listen_path);
	মুক্ত(rtype);
	sshbuf_free(resp);
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
server_প্রবেশ_channel_req(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Channel *c;
	পূর্ণাঙ্ক r, success = 0;
	বর্ণ *rtype = রিক্ত;
	u_char want_reply = 0;
	u_int id = 0;

	যদি ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_reply);

	যদি (id >= INT_MAX || (c = channel_lookup(ssh, (পূর্ণাঙ্ক)id)) == রিক্ত) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	যদি (!strcmp(rtype, "eow@openssh.com")) {
		যদি ((r = sshpkt_get_end(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} অন্যথা যদি ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_প্রবেশ_channel_req(ssh, c, rtype);
	যদি (want_reply && !(c->flags & CHAN_CLOSE_SENT)) {
		যদি (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		যদি ((r = sshpkt_start(ssh, success ?
		    SSH2_বার্তা_CHANNEL_SUCCESS : SSH2_বার্তা_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	মুক্ত(rtype);
	প্রত্যাগম 0;
}

স্থির শূন্য
server_init_dispatch(সংরচনা ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_CLOSE, &channel_প্রবেশ_oclose);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_DATA, &channel_প্রবেশ_data);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_EOF, &channel_প্রবেশ_ieof);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_EXTENDED_DATA, &channel_প্রবেশ_extended_data);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_OPEN, &server_প্রবেশ_channel_open);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION, &channel_প্রবেশ_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_OPEN_FAILURE, &channel_প্রবেশ_open_failure);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_REQUEST, &server_প্রবেশ_channel_req);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_WINDOW_ADJUST, &channel_প্রবেশ_window_adjust);
	ssh_dispatch_set(ssh, SSH2_বার্তা_GLOBAL_REQUEST, &server_প্রবেশ_global_request);
	/* client_alive */
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_SUCCESS, &server_প্রবেশ_keep_alive);
	ssh_dispatch_set(ssh, SSH2_বার্তা_CHANNEL_FAILURE, &server_প্রবেশ_keep_alive);
	ssh_dispatch_set(ssh, SSH2_বার্তা_REQUEST_SUCCESS, &server_প্রবেশ_keep_alive);
	ssh_dispatch_set(ssh, SSH2_বার্তা_REQUEST_FAILURE, &server_প্রবেশ_keep_alive);
	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEXINIT, &kex_প্রবেশ_kexinit);
}
