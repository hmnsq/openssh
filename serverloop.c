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
ಬಾಹ್ಯ ರಚನೆ sshauthopt *auth_opts;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ no_ಇನ್ನಷ್ಟು_sessions = 0; /* Disallow further sessions. */

ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t ಮಗು_terminated = 0; /* set on SIGCHLD */
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t siginfo_received = 0;

/* prototypes */
ಸ್ಥಿರ ಶೂನ್ಯ server_init_dispatch(ರಚನೆ ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
ಅಕ್ಷರ *tun_fwd_ifnames = ಖಾಲಿ;

ಸ್ಥಿರ ಶೂನ್ಯ
sigchld_handler(ಪೂರ್ಣಾಂಕ sig)
{
	ಮಗು_terminated = 1;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
ಸ್ಥಿರ ಶೂನ್ಯ
siginfo_handler(ಪೂರ್ಣಾಂಕ sig)
{
	siginfo_received = 1;
}
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಶೂನ್ಯ
client_alive_check(ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ remote_id[512];
	ಪೂರ್ಣಾಂಕ r, channel_id;

	/* timeout, check to see how many we have had */
	ಆದರೆ (options.client_alive_ಎಣಿಕೆ_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_ಎಣಿಕೆ_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, ಗಾತ್ರ(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	ಆದರೆ ((channel_id = channel_ಕಂಡುಹಿಡಿ_open(ssh)) == -1) {
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} ಇಲ್ಲದಿದ್ದರೆ {
		channel_request_ಆರಂಭ(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
wait_until_can_do_something(ರಚನೆ ssh *ssh,
    ಪೂರ್ಣಾಂಕ connection_ಒಳ, ಪೂರ್ಣಾಂಕ connection_ಹೊರಹೋಗು, ರಚನೆ pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    ಪೂರ್ಣಾಂಕ *conn_ಒಳ_readyp, ಪೂರ್ಣಾಂಕ *conn_ಹೊರಹೋಗು_readyp)
{
	ರಚನೆ timespec timeout;
	ಅಕ್ಷರ remote_id[512];
	ಪೂರ್ಣಾಂಕ ret;
	ಪೂರ್ಣಾಂಕ client_alive_scheduled = 0;
	u_int p;
	time_t now;
	ಸ್ಥಿರ time_t ಕೊನೆಯ_client_ಸಮಯ, ಬಳಸದ_connection_expiry;

	*conn_ಒಳ_readyp = *conn_ಹೊರಹೋಗು_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	ಆದರೆ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	ಆದರೆ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	ಆದರೆ (options.ಬಳಸದ_connection_timeout != 0) {
		ಆದರೆ (channel_still_open(ssh))
			ಬಳಸದ_connection_expiry = 0;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಬಳಸದ_connection_expiry == 0) {
			ಬಳಸದ_connection_expiry = now +
			    options.ಬಳಸದ_connection_timeout;
		}
	}
	ಆದರೆ (ಬಳಸದ_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, ಬಳಸದ_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	ಆದರೆ (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		ಆದರೆ (ಕೊನೆಯ_client_ಸಮಯ == 0)
			ಕೊನೆಯ_client_ಸಮಯ = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#ಆದರೆ 0
	/* wrong: bad condition XXX */
	ಆದರೆ (channel_not_very_much_buffered_ದತ್ತಾಂಶ())
#ಆದರೆ_ಅಂತ್ಯ
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_ಒಳ;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_ಹೊರಹೋಗು;
	(*pfdp)[1].events = ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	ಆದರೆ (ಮಗು_terminated && ssh_packet_not_very_much_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	ಆದರೆ (ret == -1) {
		ಗಾಗಿ (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ಆದರೆ (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}

	*conn_ಒಳ_readyp = (*pfdp)[0].revents != 0;
	*conn_ಹೊರಹೋಗು_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	ಆದರೆ (client_alive_scheduled) {
		ಆದರೆ (ret == 0 &&
		    now >= ಕೊನೆಯ_client_ಸಮಯ + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			ಕೊನೆಯ_client_ಸಮಯ = now;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ret != 0 && *conn_ಒಳ_readyp) {
			/* Data from peer; reset probe timer. */
			ಕೊನೆಯ_client_ಸಮಯ = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	ಆದರೆ (ಬಳಸದ_connection_expiry != 0 &&
	    now > ಬಳಸದ_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, ಗಾತ್ರ(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_ಒಳಹರಿವು(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ connection_ಒಳ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = ssh_packet_process_read(ssh, connection_ಒಳ)) == 0)
		ಹಿಂತಿರುಗಿ 0; /* success */
	ಆದರೆ (r == SSH_ERR_SYSTEM_ERROR) {
		ಆದರೆ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
			ಹಿಂತಿರುಗಿ -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	ಹಿಂತಿರುಗಿ -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
process_output(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ connection_ಹೊರಹೋಗು)
{
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ interactive = -1;

	/* Send any buffered packet data to the client. */
	ಆದರೆ (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_ಗಣ_interactive(ssh, interactive);
	}
	ಆದರೆ ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_buffered_ಒಳಹರಿವು_packets(ರಚನೆ ssh *ssh)
{
	ssh_dispatch_ಸತತ_fatal(ssh, DISPATCH_NONBLOCK, ಖಾಲಿ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
collect_children(ರಚನೆ ssh *ssh)
{
	pid_t pid;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;

	ಆದರೆ (ಮಗು_terminated) {
		debug("Received SIGCHLD.");
		ಆಗ ((pid = waitpid(-1, &ಸ್ಥಿತಿ_2, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			ಆದರೆ (pid > 0)
				session_close_by_pid(ssh, pid, ಸ್ಥಿತಿ_2);
		ಮಗು_terminated = 0;
	}
}

ಶೂನ್ಯ
server_loop2(ರಚನೆ ssh *ssh, Authctxt *authctxt)
{
	ರಚನೆ pollfd *pfd = ಖಾಲಿ;
	u_int npfd_alloc = 0, npfd_ಸಕ್ರಿಯ = 0;
	ಪೂರ್ಣಾಂಕ r, conn_ಒಳ_ready, conn_ಹೊರಹೋಗು_ready;
	u_int connection_ಒಳ, connection_ಹೊರಹೋಗು;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	ಆದರೆ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
	ಆದರೆ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#ಆದರೆ_ಅಂತ್ಯ
	ಮಗು_terminated = 0;
	connection_ಒಳ = ssh_packet_get_connection_ಒಳ(ssh);
	connection_ಹೊರಹೋಗು = ssh_packet_get_connection_ಹೊರಹೋಗು(ssh);

	server_init_dispatch(ssh);

	ಗಾಗಿ (;;) {
		process_buffered_ಒಳಹರಿವು_packets(ssh);

		ಆದರೆ (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		ಆದರೆ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		ಆದರೆ (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_ಒಳ, connection_ಹೊರಹೋಗು,
		    &pfd, &npfd_alloc, &npfd_ಸಕ್ರಿಯ, &osigset,
		    &conn_ಒಳ_ready, &conn_ಹೊರಹೋಗು_ready);
		ಆದರೆ (sigprocmask(SIG_SETMASK, &osigset, ಖಾಲಿ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_ಸಕ್ರಿಯ);
		ಆದರೆ (conn_ಒಳ_ready &&
		    process_ಒಳಹರಿವು(ssh, connection_ಒಳ) < 0)
			ನಿಲ್ಲಿಸು;
		/* A timeout may have triggered rekeying */
		ಆದರೆ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		ಆದರೆ (conn_ಹೊರಹೋಗು_ready)
			process_output(ssh, connection_ಹೊರಹೋಗು);
	}
	collect_children(ssh);
	ಬಿಡುಗಡೆ(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, ಖಾಲಿ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
server_ಒಳಹರಿವು_keep_alive(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_ಗಣ_alive_timeouts(ssh, 0);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ Channel *
server_request_ನೇರ_tcpip(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ *reason, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errmsg)
{
	Channel *c = ಖಾಲಿ;
	ಅಕ್ಷರ *ಗುರಿ = ಖಾಲಿ, *originator = ಖಾಲಿ;
	u_int ಗುರಿ_ಪೋರ್ಟ್ = 0, originator_ಪೋರ್ಟ್ = 0;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &ಗುರಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &ಗುರಿ_ಪೋರ್ಟ್)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_ಪೋರ್ಟ್)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ಆದರೆ (ಗುರಿ_ಪೋರ್ಟ್ > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (originator_ಪೋರ್ಟ್ > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_ಪೋರ್ಟ್, ಗುರಿ, ಗುರಿ_ಪೋರ್ಟ್);

	/* XXX fine grained permissions */
	ಆದರೆ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_ಪೋರ್ಟ್_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_ಗಮ್ಯ_ಪೋರ್ಟ್(ssh, ಗುರಿ, ಗುರಿ_ಪೋರ್ಟ್,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} ಇಲ್ಲದಿದ್ದರೆ {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_ಪೋರ್ಟ್, ಗುರಿ, ಗುರಿ_ಪೋರ್ಟ್);
		ಆದರೆ (reason != ಖಾಲಿ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(originator);
	ಬಿಡುಗಡೆ(ಗುರಿ);
	ಹಿಂತಿರುಗಿ c;
}

ಸ್ಥಿರ Channel *
server_request_ನೇರ_streamlocal(ರಚನೆ ssh *ssh)
{
	Channel *c = ಖಾಲಿ;
	ಅಕ್ಷರ *ಗುರಿ = ಖಾಲಿ, *originator = ಖಾಲಿ;
	u_int originator_ಪೋರ್ಟ್ = 0;
	ರಚನೆ passwd *pw = the_authctxt->pw;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (pw == ಖಾಲಿ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &ಗುರಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_ಪೋರ್ಟ್)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ಆದರೆ (originator_ಪೋರ್ಟ್ > 0xFFFF) {
		error_f("invalid originator port");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_ಪೋರ್ಟ್, ಗುರಿ);

	/* XXX fine grained permissions */
	ಆದರೆ ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_ಪೋರ್ಟ್_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_ಗಮ್ಯ_ಮಾರ್ಗ(ssh, ಗುರಿ,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} ಇಲ್ಲದಿದ್ದರೆ {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_ಪೋರ್ಟ್, ಗುರಿ);
	}

ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(originator);
	ಬಿಡುಗಡೆ(ಗುರಿ);
	ಹಿಂತಿರುಗಿ c;
}

ಸ್ಥಿರ Channel *
server_request_tun(ರಚನೆ ssh *ssh)
{
	Channel *c = ಖಾಲಿ;
	u_int ಬಹುಲಕ, tun;
	ಪೂರ್ಣಾಂಕ r, sock;
	ಅಕ್ಷರ *tmp, *ifname = ಖಾಲಿ;

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &ಬಹುಲಕ)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	ಆಯ್ಕೆ (ಬಹುಲಕ) {
	ಸ್ಥಿತಿ SSH_TUNMODE_POINTOPOINT:
	ಸ್ಥಿತಿ SSH_TUNMODE_ETHERNET:
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((options.permit_tun & ಬಹುಲಕ) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	ಆದರೆ (tun > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
		debug_f("invalid tun");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (auth_opts->force_tun_device != -1) {
		ಆದರೆ (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (ಪೂರ್ಣಾಂಕ)tun)
			ಹೋಗು ಮುಗಿದ;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, ಬಹುಲಕ, &ifname);
	ಆದರೆ (sock < 0)
		ಹೋಗು ಮುಗಿದ;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#ಆದರೆ defined(SSH_TUN_FILTER)
	ಆದರೆ (ಬಹುಲಕ == SSH_TUNMODE_POINTOPOINT)
		channel_ರಿಜಿಸ್ಟರ್_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ಖಾಲಿ, ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == ಖಾಲಿ ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == ಖಾಲಿ ? "" : ",",
	    ifname);
	ಬಿಡುಗಡೆ(tmp);
	ಬಿಡುಗಡೆ(ifname);

 ಮುಗಿದ:
	ಆದರೆ (c == ಖಾಲಿ)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	ಹಿಂತಿರುಗಿ c;
}

ಸ್ಥಿರ Channel *
server_request_session(ರಚನೆ ssh *ssh)
{
	Channel *c;
	ಪೂರ್ಣಾಂಕ r;

	debug("input_session_request");
	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ಆದರೆ (no_ಇನ್ನಷ್ಟು_sessions) {
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
	ಆದರೆ (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	channel_ರಿಜಿಸ್ಟರ್_cleanup(ssh, c->self, session_close_by_channel, 0);
	ಹಿಂತಿರುಗಿ c;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
server_ಒಳಹರಿವು_channel_open(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Channel *c = ಖಾಲಿ;
	ಅಕ್ಷರ *ctype = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errmsg = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &ctype, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	ಆದರೆ (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_ನೇರ_tcpip(ssh, &reason, &errmsg);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_ನೇರ_streamlocal(ssh);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	ಆದರೆ (c != ಖಾಲಿ) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_ಕಿಟಕಿ = rwindow;
		c->remote_maxpacket = rmaxpack;
		ಆದರೆ (c->type != SSH_CHANNEL_CONNECTING) {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_ಕಿಟಕಿ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug_f("failure %s", ctype);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	ಬಿಡುಗಡೆ(ctype);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
server_ಒಳಹರಿವು_hostkeys_prove(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf **respp)
{
	ರಚನೆ sshbuf *resp = ಖಾಲಿ;
	ರಚನೆ sshbuf *sigbuf = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ, *ಕೀಲಿ_pub = ಖಾಲಿ, *ಕೀಲಿ_prv = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ndx, success = 0;
	ಸ್ಥಿರಾಂಕ u_char *blob;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sigalg, *kex_rsa_sigalg = ಖಾಲಿ;
	u_char *sig = ಖಾಲಿ;
	ಗಾತ್ರ_t blen, slen;

	ಆದರೆ ((resp = sshbuf_new()) == ಖಾಲಿ || (sigbuf = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == ಕೀಲಿ_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	ಆಗ (ssh_packet_ಉಳಿದ(ssh) > 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ಖಾಲಿ;
		ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &ಕೀಲಿ)) != 0) {
			error_fr(r, "parse key");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		ಆದರೆ ((ndx = ssh->kex->host_ಕೀಲಿ_ಸೂಚ್ಯಂಕ(ಕೀಲಿ, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(ಕೀಲಿ));
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		ಆದರೆ ((ಕೀಲಿ_prv = get_hostkey_by_ಸೂಚ್ಯಂಕ(ndx)) == ಖಾಲಿ &&
		    (ಕೀಲಿ_pub = get_hostkey_ಬಹಿರಂಗ_by_ಸೂಚ್ಯಂಕ(ndx, ssh)) == ಖಾಲಿ) {
			error_f("can't retrieve hostkey %d", ndx);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		sshbuf_reset(sigbuf);
		ಬಿಡುಗಡೆ(sig);
		sig = ಖಾಲಿ;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(ಕೀಲಿ);
		ಆದರೆ (sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA) {
			ಆದರೆ (kex_rsa_sigalg != ಖಾಲಿ)
				sigalg = kex_rsa_sigalg;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(ಕೀಲಿ), ndx, sigalg == ಖಾಲಿ ? "default" : sigalg);
		ಆದರೆ ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ಕೀಲಿ, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, ಕೀಲಿ_prv, ಕೀಲಿ_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	/* Success */
	*respp = resp;
	resp = ಖಾಲಿ; /* don't free it */
	success = 1;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
server_ಒಳಹರಿವು_global_request(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ *rtype = ಖಾಲಿ;
	u_char want_ಉತ್ತರ = 0;
	ಪೂರ್ಣಾಂಕ r, success = 0, allocated_listen_ಪೋರ್ಟ್ = 0;
	u_int ಪೋರ್ಟ್ = 0;
	ರಚನೆ sshbuf *resp = ಖಾಲಿ;
	ರಚನೆ passwd *pw = the_authctxt->pw;
	ರಚನೆ Forward fwd;

	memset(&fwd, 0, ಗಾತ್ರ(fwd));
	ಆದರೆ (pw == ಖಾಲಿ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &rtype, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_ಉತ್ತರ)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_ಉತ್ತರ);

	/* -R style forwarding */
	ಆದರೆ (strcmp(rtype, "tcpip-forward") == 0) {
		ಆದರೆ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ಖಾಲಿ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &ಪೋರ್ಟ್)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, ಪೋರ್ಟ್);
		ಆದರೆ (ಪೋರ್ಟ್ <= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
			fwd.listen_ಪೋರ್ಟ್ = (ಪೂರ್ಣಾಂಕ)ಪೋರ್ಟ್;
		/* check permissions */
		ಆದರೆ (ಪೋರ್ಟ್ > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_ಪೋರ್ಟ್_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_ಉತ್ತರ && fwd.listen_ಪೋರ್ಟ್ == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* Start listening on the port */
			success = channel_ಸಿದ್ಧತೆ_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_ಪೋರ್ಟ್, &options.fwd_opts);
		}
		ಆದರೆ ((resp = sshbuf_new()) == ಖಾಲಿ)
			fatal_f("sshbuf_new");
		ಆದರೆ (allocated_listen_ಪೋರ್ಟ್ != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_ಪೋರ್ಟ್)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		ಆದರೆ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ಖಾಲಿ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &ಪೋರ್ಟ್)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, ಪೋರ್ಟ್);
		ಆದರೆ (ಪೋರ್ಟ್ <= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
			fwd.listen_ಪೋರ್ಟ್ = (ಪೂರ್ಣಾಂಕ)ಪೋರ್ಟ್;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		ಆದರೆ ((r = sshpkt_get_cstring(ssh, &fwd.listen_ಮಾರ್ಗ, ಖಾಲಿ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_ಮಾರ್ಗ);

		/* check permissions */
		ಆದರೆ ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_ಪೋರ್ಟ್_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* Start listening on the socket */
			success = channel_ಸಿದ್ಧತೆ_remote_fwd_listener(ssh,
			    &fwd, ಖಾಲಿ, &options.fwd_opts);
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		ಆದರೆ ((r = sshpkt_get_cstring(ssh, &fwd.listen_ಮಾರ್ಗ, ಖಾಲಿ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_ಮಾರ್ಗ);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_ಇನ್ನಷ್ಟು_sessions = 1;
		success = 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_ಒಳಹರಿವು_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	ಆದರೆ (want_ಉತ್ತರ) {
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, success ?
		    SSH2_ಸಂದೇಶ_REQUEST_SUCCESS : SSH2_ಸಂದೇಶ_REQUEST_FAILURE)) != 0 ||
		    (success && resp != ಖಾಲಿ && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	ಬಿಡುಗಡೆ(fwd.listen_host);
	ಬಿಡುಗಡೆ(fwd.listen_ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(rtype);
	sshbuf_free(resp);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
server_ಒಳಹರಿವು_channel_req(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Channel *c;
	ಪೂರ್ಣಾಂಕ r, success = 0;
	ಅಕ್ಷರ *rtype = ಖಾಲಿ;
	u_char want_ಉತ್ತರ = 0;
	u_int id = 0;

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_ಉತ್ತರ)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_ಉತ್ತರ);

	ಆದರೆ (id >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ || (c = channel_lookup(ssh, (ಪೂರ್ಣಾಂಕ)id)) == ಖಾಲಿ) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	ಆದರೆ (!strcmp(rtype, "eow@openssh.com")) {
		ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_ಒಳಹರಿವು_channel_req(ssh, c, rtype);
	ಆದರೆ (want_ಉತ್ತರ && !(c->flags & CHAN_CLOSE_ಕಳುಹಿಸಿದ)) {
		ಆದರೆ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, success ?
		    SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS : SSH2_ಸಂದೇಶ_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	ಬಿಡುಗಡೆ(rtype);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
server_init_dispatch(ರಚನೆ ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_CLOSE, &channel_ಒಳಹರಿವು_oclose);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ, &channel_ಒಳಹರಿವು_ದತ್ತಾಂಶ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EOF, &channel_ಒಳಹರಿವು_ieof);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_ದತ್ತಾಂಶ, &channel_ಒಳಹರಿವು_extended_ದತ್ತಾಂಶ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN, &server_ಒಳಹರಿವು_channel_open);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION, &channel_ಒಳಹರಿವು_open_confirmation);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE, &channel_ಒಳಹರಿವು_open_failure);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST, &server_ಒಳಹರಿವು_channel_req);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST, &channel_ಒಳಹರಿವು_ಕಿಟಕಿ_adjust);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST, &server_ಒಳಹರಿವು_global_request);
	/* client_alive */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS, &server_ಒಳಹರಿವು_keep_alive);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_FAILURE, &server_ಒಳಹರಿವು_keep_alive);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_REQUEST_SUCCESS, &server_ಒಳಹರಿವು_keep_alive);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_REQUEST_FAILURE, &server_ಒಳಹರಿವು_keep_alive);
	/* rekeying */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_ಒಳಹರಿವು_kexinit);
}
