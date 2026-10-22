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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <termios.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "session.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "serverloop.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಬಾಹ್ಯ ServerOptions options;

/* XXX */
ಬಾಹ್ಯ Authctxt *the_authctxt;
ಬಾಹ್ಯ ಸಂರಚನಾ sshauthopt *auth_opts;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ no_more_sessions = 0; /* Disallow further sessions. */

ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t child_terminated = 0; /* set on SIGCHLD */
ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t siginfo_received = 0;

/* prototypes */
ಸ್ಥಿರ ಶೂನ್ಯ server_init_dispatch(ಸಂರಚನಾ ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
ವರ್ಣ *tun_fwd_ifnames = ರಿಕ್ತ;

ಸ್ಥಿರ ಶೂನ್ಯ
sigchld_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	child_terminated = 1;
}

#ifdef SIGINFO
ಸ್ಥಿರ ಶೂನ್ಯ
siginfo_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	siginfo_received = 1;
}
#endif

ಸ್ಥಿರ ಶೂನ್ಯ
client_alive_check(ಸಂರಚನಾ ssh *ssh)
{
	ವರ್ಣ remote_id[512];
	ಪೂರ್ಣಾಙ್ಕ r, channel_id;

	/* timeout, check to see how many we have had */
	ಯದಿ (options.client_alive_ಎಣಿಕೆ_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_ಎಣಿಕೆ_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, ಪರಿಮಾಣ(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	ಯದಿ ((channel_id = channel_find_open(ssh)) == -1) {
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} ಅನ್ಯಥಾ {
		channel_request_start(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	ಯದಿ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
wait_until_can_do_something(ಸಂರಚನಾ ssh *ssh,
    ಪೂರ್ಣಾಙ್ಕ connection_in, ಪೂರ್ಣಾಙ್ಕ connection_out, ಸಂರಚನಾ pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    ಪೂರ್ಣಾಙ್ಕ *conn_in_readyp, ಪೂರ್ಣಾಙ್ಕ *conn_out_readyp)
{
	ಸಂರಚನಾ timespec timeout;
	ವರ್ಣ remote_id[512];
	ಪೂರ್ಣಾಙ್ಕ ret;
	ಪೂರ್ಣಾಙ್ಕ client_alive_scheduled = 0;
	u_int p;
	time_t now;
	ಸ್ಥಿರ time_t last_client_time, unused_connection_expiry;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	ಯದಿ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	ಯದಿ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	ಯದಿ (options.unused_connection_timeout != 0) {
		ಯದಿ (channel_still_open(ssh))
			unused_connection_expiry = 0;
		ಅನ್ಯಥಾ ಯದಿ (unused_connection_expiry == 0) {
			unused_connection_expiry = now +
			    options.unused_connection_timeout;
		}
	}
	ಯದಿ (unused_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, unused_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	ಯದಿ (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		ಯದಿ (last_client_time == 0)
			last_client_time = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#ಯದಿ 0
	/* wrong: bad condition XXX */
	ಯದಿ (channel_not_very_much_buffered_data())
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
	ಯದಿ (child_terminated && ssh_packet_not_very_much_data_to_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	ಯದಿ (ret == -1) {
		ಪ್ರತಿ (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ಯದಿ (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	ಯದಿ (client_alive_scheduled) {
		ಯದಿ (ret == 0 &&
		    now >= last_client_time + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			last_client_time = now;
		} ಅನ್ಯಥಾ ಯದಿ (ret != 0 && *conn_in_readyp) {
			/* Data from peer; reset probe timer. */
			last_client_time = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	ಯದಿ (unused_connection_expiry != 0 &&
	    now > unused_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, ಪರಿಮಾಣ(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
process_ಒಳಹರಿವು(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ connection_in)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		ಪ್ರತ್ಯಾಗಮ 0; /* success */
	ಯದಿ (r == SSH_ERR_SYSTEM_ERROR) {
		ಯದಿ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
process_output(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ connection_out)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ interactive = -1;

	/* Send any buffered packet data to the client. */
	ಯದಿ (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_set_interactive(ssh, interactive);
	}
	ಯದಿ ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_buffered_ಒಳಹರಿವು_packets(ಸಂರಚನಾ ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, ರಿಕ್ತ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
collect_children(ಸಂರಚನಾ ssh *ssh)
{
	pid_t pid;
	ಪೂರ್ಣಾಙ್ಕ status;

	ಯದಿ (child_terminated) {
		debug("Received SIGCHLD.");
		ಯಾವತ್ ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			ಯದಿ (pid > 0)
				session_close_by_pid(ssh, pid, status);
		child_terminated = 0;
	}
}

ಶೂನ್ಯ
server_loop2(ಸಂರಚನಾ ssh *ssh, Authctxt *authctxt)
{
	ಸಂರಚನಾ pollfd *pfd = ರಿಕ್ತ;
	u_int npfd_alloc = 0, npfd_active = 0;
	ಪೂರ್ಣಾಙ್ಕ r, conn_in_ready, conn_out_ready;
	u_int connection_in, connection_out;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	ಯದಿ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#ifdef SIGINFO
	ಯದಿ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#endif
	child_terminated = 0;
	connection_in = ssh_packet_get_connection_in(ssh);
	connection_out = ssh_packet_get_connection_out(ssh);

	server_init_dispatch(ssh);

	ಪ್ರತಿ (;;) {
		process_buffered_ಒಳಹರಿವು_packets(ssh);

		ಯದಿ (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_data_to_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		ಯದಿ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		ಯದಿ (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_in, connection_out,
		    &pfd, &npfd_alloc, &npfd_active, &osigset,
		    &conn_in_ready, &conn_out_ready);
		ಯದಿ (sigprocmask(SIG_SETMASK, &osigset, ರಿಕ್ತ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_active);
		ಯದಿ (conn_in_ready &&
		    process_ಒಳಹರಿವು(ssh, connection_in) < 0)
			ಭಙ್ಗ;
		/* A timeout may have triggered rekeying */
		ಯದಿ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		ಯದಿ (conn_out_ready)
			process_output(ssh, connection_out);
	}
	collect_children(ssh);
	ಮುಕ್ತ(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, ರಿಕ್ತ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
server_ಒಳಹರಿವು_keep_alive(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_set_alive_timeouts(ssh, 0);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ Channel *
server_request_direct_tcpip(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ *reason, ಧ್ರುವ ವರ್ಣ **errmsg)
{
	Channel *c = ರಿಕ್ತ;
	ವರ್ಣ *target = ರಿಕ್ತ, *originator = ರಿಕ್ತ;
	u_int target_port = 0, originator_port = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &target, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &target_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ಯದಿ (target_port > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ಗಚ್ಛ out;
	}
	ಯದಿ (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ಗಚ್ಛ out;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_port, target, target_port);

	/* XXX fine grained permissions */
	ಯದಿ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_port(ssh, target, target_port,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} ಅನ್ಯಥಾ {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_port, target, target_port);
		ಯದಿ (reason != ರಿಕ್ತ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 out:
	ಮುಕ್ತ(originator);
	ಮುಕ್ತ(target);
	ಪ್ರತ್ಯಾಗಮ c;
}

ಸ್ಥಿರ Channel *
server_request_direct_streamlocal(ಸಂರಚನಾ ssh *ssh)
{
	Channel *c = ರಿಕ್ತ;
	ವರ್ಣ *target = ರಿಕ್ತ, *originator = ರಿಕ್ತ;
	u_int originator_port = 0;
	ಸಂರಚನಾ passwd *pw = the_authctxt->pw;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (pw == ರಿಕ್ತ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &target, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ಯದಿ (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		ಗಚ್ಛ out;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_port, target);

	/* XXX fine grained permissions */
	ಯದಿ ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_path(ssh, target,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} ಅನ್ಯಥಾ {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_port, target);
	}

out:
	ಮುಕ್ತ(originator);
	ಮುಕ್ತ(target);
	ಪ್ರತ್ಯಾಗಮ c;
}

ಸ್ಥಿರ Channel *
server_request_tun(ಸಂರಚನಾ ssh *ssh)
{
	Channel *c = ರಿಕ್ತ;
	u_int mode, tun;
	ಪೂರ್ಣಾಙ್ಕ r, sock;
	ವರ್ಣ *tmp, *ifname = ರಿಕ್ತ;

	ಯದಿ ((r = sshpkt_get_u32(ssh, &mode)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	ವಿಕಲ್ಪ (mode) {
	ಪಕ್ಷ SSH_TUNMODE_POINTOPOINT:
	ಪಕ್ಷ SSH_TUNMODE_ETHERNET:
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((options.permit_tun & mode) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	ಯದಿ ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	ಯದಿ (tun > INT_MAX) {
		debug_f("invalid tun");
		ಗಚ್ಛ done;
	}
	ಯದಿ (auth_opts->force_tun_device != -1) {
		ಯದಿ (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (ಪೂರ್ಣಾಙ್ಕ)tun)
			ಗಚ್ಛ done;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, mode, &ifname);
	ಯದಿ (sock < 0)
		ಗಚ್ಛ done;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#ಯದಿ defined(SSH_TUN_FILTER)
	ಯದಿ (mode == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ರಿಕ್ತ, ರಿಕ್ತ);
#endif

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == ರಿಕ್ತ ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == ರಿಕ್ತ ? "" : ",",
	    ifname);
	ಮುಕ್ತ(tmp);
	ಮುಕ್ತ(ifname);

 done:
	ಯದಿ (c == ರಿಕ್ತ)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	ಪ್ರತ್ಯಾಗಮ c;
}

ಸ್ಥಿರ Channel *
server_request_session(ಸಂರಚನಾ ssh *ssh)
{
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug("input_session_request");
	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ಯದಿ (no_more_sessions) {
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
	ಯದಿ (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	channel_register_cleanup(ssh, c->self, session_close_by_channel, 0);
	ಪ್ರತ್ಯಾಗಮ c;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
server_ಒಳಹರಿವು_channel_open(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Channel *c = ರಿಕ್ತ;
	ವರ್ಣ *ctype = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *errmsg = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &ctype, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	ಯದಿ (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip(ssh, &reason, &errmsg);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_direct_streamlocal(ssh);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	ಯದಿ (c != ರಿಕ್ತ) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		ಯದಿ (c->type != SSH_CHANNEL_CONNECTING) {
			ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} ಅನ್ಯಥಾ {
		debug_f("failure %s", ctype);
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	ಮುಕ್ತ(ctype);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
server_ಒಳಹರಿವು_hostkeys_prove(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf **respp)
{
	ಸಂರಚನಾ sshbuf *resp = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *sigbuf = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ, *ಕೀಲಿ_pub = ರಿಕ್ತ, *ಕೀಲಿ_prv = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ndx, success = 0;
	ಧ್ರುವ u_char *blob;
	ಧ್ರುವ ವರ್ಣ *sigalg, *kex_rsa_sigalg = ರಿಕ್ತ;
	u_char *sig = ರಿಕ್ತ;
	size_t blen, slen;

	ಯದಿ ((resp = sshbuf_new()) == ರಿಕ್ತ || (sigbuf = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == ಕೀಲಿ_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	ಯಾವತ್ (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ರಿಕ್ತ;
		ಯದಿ ((r = sshpkt_get_string_direct(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &ಕೀಲಿ)) != 0) {
			error_fr(r, "parse key");
			ಗಚ್ಛ out;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		ಯದಿ ((ndx = ssh->kex->host_ಕೀಲಿ_index(ಕೀಲಿ, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(ಕೀಲಿ));
			ಗಚ್ಛ out;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		ಯದಿ ((ಕೀಲಿ_prv = get_hostkey_by_index(ndx)) == ರಿಕ್ತ &&
		    (ಕೀಲಿ_pub = get_hostkey_public_by_index(ndx, ssh)) == ರಿಕ್ತ) {
			error_f("can't retrieve hostkey %d", ndx);
			ಗಚ್ಛ out;
		}
		sshbuf_reset(sigbuf);
		ಮುಕ್ತ(sig);
		sig = ರಿಕ್ತ;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(ಕೀಲಿ);
		ಯದಿ (sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA) {
			ಯದಿ (kex_rsa_sigalg != ರಿಕ್ತ)
				sigalg = kex_rsa_sigalg;
			ಅನ್ಯಥಾ ಯದಿ (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			ಅನ್ಯಥಾ ಯದಿ (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(ಕೀಲಿ), ndx, sigalg == ರಿಕ್ತ ? "default" : sigalg);
		ಯದಿ ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ಕೀಲಿ, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, ಕೀಲಿ_prv, ಕೀಲಿ_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			ಗಚ್ಛ out;
		}
	}
	/* Success */
	*respp = resp;
	resp = ರಿಕ್ತ; /* don't free it */
	success = 1;
 out:
	ಮುಕ್ತ(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
server_ಒಳಹರಿವು_global_request(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ವರ್ಣ *rtype = ರಿಕ್ತ;
	u_char want_reply = 0;
	ಪೂರ್ಣಾಙ್ಕ r, success = 0, allocated_listen_port = 0;
	u_int port = 0;
	ಸಂರಚನಾ sshbuf *resp = ರಿಕ್ತ;
	ಸಂರಚನಾ passwd *pw = the_authctxt->pw;
	ಸಂರಚನಾ Forward fwd;

	memset(&fwd, 0, ಪರಿಮಾಣ(fwd));
	ಯದಿ (pw == ರಿಕ್ತ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &rtype, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_reply);

	/* -R style forwarding */
	ಯದಿ (strcmp(rtype, "tcpip-forward") == 0) {
		ಯದಿ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ರಿಕ್ತ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, port);
		ಯದಿ (port <= INT_MAX)
			fwd.listen_port = (ಪೂರ್ಣಾಙ್ಕ)port;
		/* check permissions */
		ಯದಿ (port > INT_MAX ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_reply && fwd.listen_port == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} ಅನ್ಯಥಾ {
			/* Start listening on the port */
			success = channel_setup_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_port, &options.fwd_opts);
		}
		ಯದಿ ((resp = sshbuf_new()) == ರಿಕ್ತ)
			fatal_f("sshbuf_new");
		ಯದಿ (allocated_listen_port != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_port)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		ಯದಿ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ರಿಕ್ತ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, port);
		ಯದಿ (port <= INT_MAX) {
			fwd.listen_port = (ಪೂರ್ಣಾಙ್ಕ)port;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		ಯದಿ ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, ರಿಕ್ತ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_path);

		/* check permissions */
		ಯದಿ ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} ಅನ್ಯಥಾ {
			/* Start listening on the socket */
			success = channel_setup_remote_fwd_listener(ssh,
			    &fwd, ರಿಕ್ತ, &options.fwd_opts);
		}
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		ಯದಿ ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, ರಿಕ್ತ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_path);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_more_sessions = 1;
		success = 1;
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_ಒಳಹರಿವು_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	ಯದಿ (want_reply) {
		ಯದಿ ((r = sshpkt_start(ssh, success ?
		    SSH2_ಸಂದೇಶ_REQUEST_SUCCESS : SSH2_ಸಂದೇಶ_REQUEST_FAILURE)) != 0 ||
		    (success && resp != ರಿಕ್ತ && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	ಮುಕ್ತ(fwd.listen_host);
	ಮುಕ್ತ(fwd.listen_path);
	ಮುಕ್ತ(rtype);
	sshbuf_free(resp);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
server_ಒಳಹರಿವು_channel_req(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ r, success = 0;
	ವರ್ಣ *rtype = ರಿಕ್ತ;
	u_char want_reply = 0;
	u_int id = 0;

	ಯದಿ ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_reply);

	ಯದಿ (id >= INT_MAX || (c = channel_lookup(ssh, (ಪೂರ್ಣಾಙ್ಕ)id)) == ರಿಕ್ತ) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	ಯದಿ (!strcmp(rtype, "eow@openssh.com")) {
		ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} ಅನ್ಯಥಾ ಯದಿ ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_ಒಳಹರಿವು_channel_req(ssh, c, rtype);
	ಯದಿ (want_reply && !(c->flags & CHAN_CLOSE_SENT)) {
		ಯದಿ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ಯದಿ ((r = sshpkt_start(ssh, success ?
		    SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS : SSH2_ಸಂದೇಶ_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	ಮುಕ್ತ(rtype);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
server_init_dispatch(ಸಂರಚನಾ ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_CLOSE, &channel_ಒಳಹರಿವು_oclose);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_DATA, &channel_ಒಳಹರಿವು_data);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EOF, &channel_ಒಳಹರಿವು_ieof);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_DATA, &channel_ಒಳಹರಿವು_extended_data);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN, &server_ಒಳಹರಿವು_channel_open);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION, &channel_ಒಳಹರಿವು_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE, &channel_ಒಳಹರಿವು_open_failure);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST, &server_ಒಳಹರಿವು_channel_req);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_WINDOW_ADJUST, &channel_ಒಳಹರಿವು_window_adjust);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST, &server_ಒಳಹರಿವು_global_request);
	/* client_alive */
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS, &server_ಒಳಹರಿವು_keep_alive);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_CHANNEL_FAILURE, &server_ಒಳಹರಿವು_keep_alive);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_REQUEST_SUCCESS, &server_ಒಳಹರಿವು_keep_alive);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_REQUEST_FAILURE, &server_ಒಳಹರಿವು_keep_alive);
	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_ಒಳಹರಿವು_kexinit);
}
