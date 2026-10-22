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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <netinet/in.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <termios.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "sshpty.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "session.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "serverloop.h"
#અન્તર્ભાવ "ssherr.h"

બાહ્ય ServerOptions options;

/* XXX */
બાહ્ય Authctxt *the_authctxt;
બાહ્ય સંરચના sshauthopt *auth_opts;

સ્થિર પૂર્ણાંક no_more_sessions = 0; /* Disallow further sessions. */

સ્થિર અસ્થિર sig_atomic_t child_terminated = 0; /* set on SIGCHLD */
સ્થિર અસ્થિર sig_atomic_t siginfo_received = 0;

/* prototypes */
સ્થિર શૂન્ય server_init_dispatch(સંરચના ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
અક્ષર *tun_fwd_ifnames = ખાલી;

સ્થિર શૂન્ય
sigchld_handler(પૂર્ણાંક sig)
{
	child_terminated = 1;
}

#ifdef SIGINFO
સ્થિર શૂન્ય
siginfo_handler(પૂર્ણાંક sig)
{
	siginfo_received = 1;
}
#endif

સ્થિર શૂન્ય
client_alive_check(સંરચના ssh *ssh)
{
	અક્ષર remote_id[512];
	પૂર્ણાંક r, channel_id;

	/* timeout, check to see how many we have had */
	જો (options.client_alive_ગણતરી_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_ગણતરી_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, કદ(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	જો ((channel_id = channel_find_open(ssh)) == -1) {
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} નહીંતર {
		channel_request_start(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	જો ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
સ્થિર શૂન્ય
wait_until_can_do_something(સંરચના ssh *ssh,
    પૂર્ણાંક connection_in, પૂર્ણાંક connection_out, સંરચના pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    પૂર્ણાંક *conn_in_readyp, પૂર્ણાંક *conn_out_readyp)
{
	સંરચના timespec timeout;
	અક્ષર remote_id[512];
	પૂર્ણાંક ret;
	પૂર્ણાંક client_alive_scheduled = 0;
	u_int p;
	time_t now;
	સ્થિર time_t last_client_time, unused_connection_expiry;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	જો (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	જો (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	જો (options.unused_connection_timeout != 0) {
		જો (channel_still_open(ssh))
			unused_connection_expiry = 0;
		નહીંતર જો (unused_connection_expiry == 0) {
			unused_connection_expiry = now +
			    options.unused_connection_timeout;
		}
	}
	જો (unused_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, unused_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	જો (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		જો (last_client_time == 0)
			last_client_time = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#જો 0
	/* wrong: bad condition XXX */
	જો (channel_not_very_much_buffered_data())
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
	જો (child_terminated && ssh_packet_not_very_much_data_to_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	જો (ret == -1) {
		માટે (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		જો (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		પાછા;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	જો (client_alive_scheduled) {
		જો (ret == 0 &&
		    now >= last_client_time + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			last_client_time = now;
		} નહીંતર જો (ret != 0 && *conn_in_readyp) {
			/* Data from peer; reset probe timer. */
			last_client_time = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	જો (unused_connection_expiry != 0 &&
	    now > unused_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, કદ(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
સ્થિર પૂર્ણાંક
process_આગત(સંરચના ssh *ssh, પૂર્ણાંક connection_in)
{
	પૂર્ણાંક r;

	જો ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		પાછા 0; /* success */
	જો (r == SSH_ERR_SYSTEM_ERROR) {
		જો (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			પાછા 0;
		જો (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
			પાછા -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	પાછા -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
સ્થિર શૂન્ય
process_output(સંરચના ssh *ssh, પૂર્ણાંક connection_out)
{
	પૂર્ણાંક r;
	સ્થિર પૂર્ણાંક interactive = -1;

	/* Send any buffered packet data to the client. */
	જો (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_set_interactive(ssh, interactive);
	}
	જો ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

સ્થિર શૂન્ય
process_buffered_આગત_packets(સંરચના ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, ખાલી);
}

સ્થિર શૂન્ય
collect_children(સંરચના ssh *ssh)
{
	pid_t pid;
	પૂર્ણાંક status;

	જો (child_terminated) {
		debug("Received SIGCHLD.");
		જ્યારે ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			જો (pid > 0)
				session_close_by_pid(ssh, pid, status);
		child_terminated = 0;
	}
}

શૂન્ય
server_loop2(સંરચના ssh *ssh, Authctxt *authctxt)
{
	સંરચના pollfd *pfd = ખાલી;
	u_int npfd_alloc = 0, npfd_active = 0;
	પૂર્ણાંક r, conn_in_ready, conn_out_ready;
	u_int connection_in, connection_out;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	જો (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#ifdef SIGINFO
	જો (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#endif
	child_terminated = 0;
	connection_in = ssh_packet_get_connection_in(ssh);
	connection_out = ssh_packet_get_connection_out(ssh);

	server_init_dispatch(ssh);

	માટે (;;) {
		process_buffered_આગત_packets(ssh);

		જો (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_data_to_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		જો (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		જો (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_in, connection_out,
		    &pfd, &npfd_alloc, &npfd_active, &osigset,
		    &conn_in_ready, &conn_out_ready);
		જો (sigprocmask(SIG_SETMASK, &osigset, ખાલી) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_active);
		જો (conn_in_ready &&
		    process_આગત(ssh, connection_in) < 0)
			તોડો;
		/* A timeout may have triggered rekeying */
		જો ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		જો (conn_out_ready)
			process_output(ssh, connection_out);
	}
	collect_children(ssh);
	મુક્ત(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, ખાલી);
}

સ્થિર પૂર્ણાંક
server_આગત_keep_alive(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_set_alive_timeouts(ssh, 0);
	પાછા 0;
}

સ્થિર Channel *
server_request_direct_tcpip(સંરચના ssh *ssh, પૂર્ણાંક *reason, અચલ અક્ષર **errmsg)
{
	Channel *c = ખાલી;
	અક્ષર *target = ખાલી, *originator = ખાલી;
	u_int target_port = 0, originator_port = 0;
	પૂર્ણાંક r;

	જો ((r = sshpkt_get_cstring(ssh, &target, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &target_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	જો (target_port > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		જાઓ out;
	}
	જો (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		જાઓ out;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_port, target, target_port);

	/* XXX fine grained permissions */
	જો ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_port(ssh, target, target_port,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} નહીંતર {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_port, target, target_port);
		જો (reason != ખાલી)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 out:
	મુક્ત(originator);
	મુક્ત(target);
	પાછા c;
}

સ્થિર Channel *
server_request_direct_streamlocal(સંરચના ssh *ssh)
{
	Channel *c = ખાલી;
	અક્ષર *target = ખાલી, *originator = ખાલી;
	u_int originator_port = 0;
	સંરચના passwd *pw = the_authctxt->pw;
	પૂર્ણાંક r;

	જો (pw == ખાલી || !the_authctxt->valid)
		fatal_f("no/invalid user");

	જો ((r = sshpkt_get_cstring(ssh, &target, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	જો (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		જાઓ out;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_port, target);

	/* XXX fine grained permissions */
	જો ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_path(ssh, target,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} નહીંતર {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_port, target);
	}

out:
	મુક્ત(originator);
	મુક્ત(target);
	પાછા c;
}

સ્થિર Channel *
server_request_tun(સંરચના ssh *ssh)
{
	Channel *c = ખાલી;
	u_int mode, tun;
	પૂર્ણાંક r, sock;
	અક્ષર *tmp, *ifname = ખાલી;

	જો ((r = sshpkt_get_u32(ssh, &mode)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	પસંદગી (mode) {
	સ્થિતિ SSH_TUNMODE_POINTOPOINT:
	સ્થિતિ SSH_TUNMODE_ETHERNET:
		તોડો;
	મૂળભૂત:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		પાછા ખાલી;
	}
	જો ((options.permit_tun & mode) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		પાછા ખાલી;
	}

	જો ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	જો (tun > INT_MAX) {
		debug_f("invalid tun");
		જાઓ done;
	}
	જો (auth_opts->force_tun_device != -1) {
		જો (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (પૂર્ણાંક)tun)
			જાઓ done;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, mode, &ifname);
	જો (sock < 0)
		જાઓ done;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#જો defined(SSH_TUN_FILTER)
	જો (mode == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ખાલી, ખાલી);
#endif

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == ખાલી ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == ખાલી ? "" : ",",
	    ifname);
	મુક્ત(tmp);
	મુક્ત(ifname);

 done:
	જો (c == ખાલી)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	પાછા c;
}

સ્થિર Channel *
server_request_session(સંરચના ssh *ssh)
{
	Channel *c;
	પૂર્ણાંક r;

	debug("input_session_request");
	જો ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	જો (no_more_sessions) {
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
	જો (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		પાછા ખાલી;
	}
	channel_register_cleanup(ssh, c->self, session_close_by_channel, 0);
	પાછા c;
}

સ્થિર પૂર્ણાંક
server_આગત_channel_open(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Channel *c = ખાલી;
	અક્ષર *ctype = ખાલી;
	અચલ અક્ષર *errmsg = ખાલી;
	પૂર્ણાંક r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	જો ((r = sshpkt_get_cstring(ssh, &ctype, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	જો (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} નહીંતર જો (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip(ssh, &reason, &errmsg);
	} નહીંતર જો (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_direct_streamlocal(ssh);
	} નહીંતર જો (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	જો (c != ખાલી) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		જો (c->type != SSH_CHANNEL_CONNECTING) {
			જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} નહીંતર {
		debug_f("failure %s", ctype);
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	મુક્ત(ctype);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
server_આગત_hostkeys_prove(સંરચના ssh *ssh, સંરચના sshbuf **respp)
{
	સંરચના sshbuf *resp = ખાલી;
	સંરચના sshbuf *sigbuf = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી, *ચાવી_pub = ખાલી, *ચાવી_prv = ખાલી;
	પૂર્ણાંક r, ndx, success = 0;
	અચલ u_char *blob;
	અચલ અક્ષર *sigalg, *kex_rsa_sigalg = ખાલી;
	u_char *sig = ખાલી;
	size_t blen, slen;

	જો ((resp = sshbuf_new()) == ખાલી || (sigbuf = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == ચાવી_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	જ્યારે (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(ચાવી);
		ચાવી = ખાલી;
		જો ((r = sshpkt_get_string_direct(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &ચાવી)) != 0) {
			error_fr(r, "parse key");
			જાઓ out;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		જો ((ndx = ssh->kex->host_ચાવી_index(ચાવી, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(ચાવી));
			જાઓ out;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		જો ((ચાવી_prv = get_hostkey_by_index(ndx)) == ખાલી &&
		    (ચાવી_pub = get_hostkey_public_by_index(ndx, ssh)) == ખાલી) {
			error_f("can't retrieve hostkey %d", ndx);
			જાઓ out;
		}
		sshbuf_reset(sigbuf);
		મુક્ત(sig);
		sig = ખાલી;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(ચાવી);
		જો (sshkey_type_plain(ચાવી->type) == ચાવી_RSA) {
			જો (kex_rsa_sigalg != ખાલી)
				sigalg = kex_rsa_sigalg;
			નહીંતર જો (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			નહીંતર જો (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(ચાવી), ndx, sigalg == ખાલી ? "default" : sigalg);
		જો ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ચાવી, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, ચાવી_prv, ચાવી_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			જાઓ out;
		}
	}
	/* Success */
	*respp = resp;
	resp = ખાલી; /* don't free it */
	success = 1;
 out:
	મુક્ત(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(ચાવી);
	પાછા success;
}

સ્થિર પૂર્ણાંક
server_આગત_global_request(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	અક્ષર *rtype = ખાલી;
	u_char want_reply = 0;
	પૂર્ણાંક r, success = 0, allocated_listen_port = 0;
	u_int port = 0;
	સંરચના sshbuf *resp = ખાલી;
	સંરચના passwd *pw = the_authctxt->pw;
	સંરચના Forward fwd;

	memset(&fwd, 0, કદ(fwd));
	જો (pw == ખાલી || !the_authctxt->valid)
		fatal_f("no/invalid user");

	જો ((r = sshpkt_get_cstring(ssh, &rtype, ખાલી)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_reply);

	/* -R style forwarding */
	જો (strcmp(rtype, "tcpip-forward") == 0) {
		જો ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ખાલી)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, port);
		જો (port <= INT_MAX)
			fwd.listen_port = (પૂર્ણાંક)port;
		/* check permissions */
		જો (port > INT_MAX ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_reply && fwd.listen_port == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} નહીંતર {
			/* Start listening on the port */
			success = channel_setup_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_port, &options.fwd_opts);
		}
		જો ((resp = sshbuf_new()) == ખાલી)
			fatal_f("sshbuf_new");
		જો (allocated_listen_port != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_port)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} નહીંતર જો (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		જો ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ખાલી)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, port);
		જો (port <= INT_MAX) {
			fwd.listen_port = (પૂર્ણાંક)port;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} નહીંતર જો (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		જો ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, ખાલી)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_path);

		/* check permissions */
		જો ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} નહીંતર {
			/* Start listening on the socket */
			success = channel_setup_remote_fwd_listener(ssh,
			    &fwd, ખાલી, &options.fwd_opts);
		}
	} નહીંતર જો (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		જો ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, ખાલી)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_path);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} નહીંતર જો (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_more_sessions = 1;
		success = 1;
	} નહીંતર જો (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_આગત_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	જો (want_reply) {
		જો ((r = sshpkt_start(ssh, success ?
		    SSH2_સંદેશ_REQUEST_SUCCESS : SSH2_સંદેશ_REQUEST_FAILURE)) != 0 ||
		    (success && resp != ખાલી && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	મુક્ત(fwd.listen_host);
	મુક્ત(fwd.listen_path);
	મુક્ત(rtype);
	sshbuf_free(resp);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
server_આગત_channel_req(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Channel *c;
	પૂર્ણાંક r, success = 0;
	અક્ષર *rtype = ખાલી;
	u_char want_reply = 0;
	u_int id = 0;

	જો ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, ખાલી)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_reply);

	જો (id >= INT_MAX || (c = channel_lookup(ssh, (પૂર્ણાંક)id)) == ખાલી) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	જો (!strcmp(rtype, "eow@openssh.com")) {
		જો ((r = sshpkt_get_end(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} નહીંતર જો ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_આગત_channel_req(ssh, c, rtype);
	જો (want_reply && !(c->flags & CHAN_CLOSE_SENT)) {
		જો (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		જો ((r = sshpkt_start(ssh, success ?
		    SSH2_સંદેશ_CHANNEL_SUCCESS : SSH2_સંદેશ_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	મુક્ત(rtype);
	પાછા 0;
}

સ્થિર શૂન્ય
server_init_dispatch(સંરચના ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_CLOSE, &channel_આગત_oclose);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_DATA, &channel_આગત_data);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_EOF, &channel_આગત_ieof);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_EXTENDED_DATA, &channel_આગત_extended_data);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_OPEN, &server_આગત_channel_open);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION, &channel_આગત_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_OPEN_FAILURE, &channel_આગત_open_failure);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_REQUEST, &server_આગત_channel_req);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_WINDOW_ADJUST, &channel_આગત_window_adjust);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_GLOBAL_REQUEST, &server_આગત_global_request);
	/* client_alive */
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_SUCCESS, &server_આગત_keep_alive);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_FAILURE, &server_આગત_keep_alive);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_REQUEST_SUCCESS, &server_આગત_keep_alive);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_REQUEST_FAILURE, &server_આગત_keep_alive);
	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEXINIT, &kex_આગત_kexinit);
}
