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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "serverloop.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਬਾਹਰੀ ServerOptions options;

/* XXX */
ਬਾਹਰੀ Authctxt *the_authctxt;
ਬਾਹਰੀ ਬਣਤਰ sshauthopt *auth_opts;

ਸਥਿਰ ਪੂਰਨ no_ਹੋਰ_sessions = 0; /* Disallow further sessions. */

ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t ਬੱਚਾ_terminated = 0; /* set on SIGCHLD */
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t siginfo_received = 0;

/* prototypes */
ਸਥਿਰ ਖਾਲੀ server_init_dispatch(ਬਣਤਰ ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
ਅੱਖਰ *tun_fwd_ifnames = ਨਿਰਾ;

ਸਥਿਰ ਖਾਲੀ
sigchld_handler(ਪੂਰਨ sig)
{
	ਬੱਚਾ_terminated = 1;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
ਸਥਿਰ ਖਾਲੀ
siginfo_handler(ਪੂਰਨ sig)
{
	siginfo_received = 1;
}
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਖਾਲੀ
client_alive_check(ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ remote_id[512];
	ਪੂਰਨ r, channel_id;

	/* timeout, check to see how many we have had */
	ਜੇ (options.client_alive_ਗਿਣਤੀ_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_ਗਿਣਤੀ_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, ਆਕਾਰ(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	ਜੇ ((channel_id = channel_ਲੱਭੋ_open(ssh)) == -1) {
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} ਨਹੀਂਤਾਂ {
		channel_request_ਸ਼ੁਰੂ(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	ਜੇ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
ਸਥਿਰ ਖਾਲੀ
wait_until_can_do_something(ਬਣਤਰ ssh *ssh,
    ਪੂਰਨ connection_ਵਿੱਚ, ਪੂਰਨ connection_ਬਾਹਰਲਾ, ਬਣਤਰ pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    ਪੂਰਨ *conn_ਵਿੱਚ_readyp, ਪੂਰਨ *conn_ਬਾਹਰਲਾ_readyp)
{
	ਬਣਤਰ timespec timeout;
	ਅੱਖਰ remote_id[512];
	ਪੂਰਨ ret;
	ਪੂਰਨ client_alive_scheduled = 0;
	u_int p;
	time_t now;
	ਸਥਿਰ time_t ਆਖਰੀ_client_ਸਮਾਂ, ਅਣਵਰਤਿਆ_connection_expiry;

	*conn_ਵਿੱਚ_readyp = *conn_ਬਾਹਰਲਾ_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	ਜੇ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	ਜੇ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	ਜੇ (options.ਅਣਵਰਤਿਆ_connection_timeout != 0) {
		ਜੇ (channel_still_open(ssh))
			ਅਣਵਰਤਿਆ_connection_expiry = 0;
		ਨਹੀਂਤਾਂ ਜੇ (ਅਣਵਰਤਿਆ_connection_expiry == 0) {
			ਅਣਵਰਤਿਆ_connection_expiry = now +
			    options.ਅਣਵਰਤਿਆ_connection_timeout;
		}
	}
	ਜੇ (ਅਣਵਰਤਿਆ_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, ਅਣਵਰਤਿਆ_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	ਜੇ (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		ਜੇ (ਆਖਰੀ_client_ਸਮਾਂ == 0)
			ਆਖਰੀ_client_ਸਮਾਂ = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#ਜੇ 0
	/* wrong: bad condition XXX */
	ਜੇ (channel_not_very_much_buffered_ਅੰਕੜੇ())
#ਜੇ_ਅੰਤ
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_ਵਿੱਚ;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_ਬਾਹਰਲਾ;
	(*pfdp)[1].events = ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	ਜੇ (ਬੱਚਾ_terminated && ssh_packet_not_very_much_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	ਜੇ (ret == -1) {
		ਲਈ (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ਜੇ (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		ਵਾਪਸ;
	}

	*conn_ਵਿੱਚ_readyp = (*pfdp)[0].revents != 0;
	*conn_ਬਾਹਰਲਾ_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	ਜੇ (client_alive_scheduled) {
		ਜੇ (ret == 0 &&
		    now >= ਆਖਰੀ_client_ਸਮਾਂ + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			ਆਖਰੀ_client_ਸਮਾਂ = now;
		} ਨਹੀਂਤਾਂ ਜੇ (ret != 0 && *conn_ਵਿੱਚ_readyp) {
			/* Data from peer; reset probe timer. */
			ਆਖਰੀ_client_ਸਮਾਂ = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	ਜੇ (ਅਣਵਰਤਿਆ_connection_expiry != 0 &&
	    now > ਅਣਵਰਤਿਆ_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, ਆਕਾਰ(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
ਸਥਿਰ ਪੂਰਨ
process_ਨਿਵੇਸ਼(ਬਣਤਰ ssh *ssh, ਪੂਰਨ connection_ਵਿੱਚ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = ssh_packet_process_read(ssh, connection_ਵਿੱਚ)) == 0)
		ਵਾਪਸ 0; /* success */
	ਜੇ (r == SSH_ERR_SYSTEM_ERROR) {
		ਜੇ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ਵਾਪਸ 0;
		ਜੇ (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
			ਵਾਪਸ -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	ਵਾਪਸ -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
ਸਥਿਰ ਖਾਲੀ
process_output(ਬਣਤਰ ssh *ssh, ਪੂਰਨ connection_ਬਾਹਰਲਾ)
{
	ਪੂਰਨ r;
	ਸਥਿਰ ਪੂਰਨ interactive = -1;

	/* Send any buffered packet data to the client. */
	ਜੇ (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_ਸੈੱਟ_interactive(ssh, interactive);
	}
	ਜੇ ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

ਸਥਿਰ ਖਾਲੀ
process_buffered_ਨਿਵੇਸ਼_packets(ਬਣਤਰ ssh *ssh)
{
	ssh_dispatch_ਲੜੀਵਾਰ_fatal(ssh, DISPATCH_NONBLOCK, ਨਿਰਾ);
}

ਸਥਿਰ ਖਾਲੀ
collect_children(ਬਣਤਰ ssh *ssh)
{
	pid_t pid;
	ਪੂਰਨ ਸਥਿਤੀ;

	ਜੇ (ਬੱਚਾ_terminated) {
		debug("Received SIGCHLD.");
		ਜਦੋਂ ((pid = waitpid(-1, &ਸਥਿਤੀ, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			ਜੇ (pid > 0)
				session_close_by_pid(ssh, pid, ਸਥਿਤੀ);
		ਬੱਚਾ_terminated = 0;
	}
}

ਖਾਲੀ
server_loop2(ਬਣਤਰ ssh *ssh, Authctxt *authctxt)
{
	ਬਣਤਰ pollfd *pfd = ਨਿਰਾ;
	u_int npfd_alloc = 0, npfd_ਸਰਗਰਮ = 0;
	ਪੂਰਨ r, conn_ਵਿੱਚ_ready, conn_ਬਾਹਰਲਾ_ready;
	u_int connection_ਵਿੱਚ, connection_ਬਾਹਰਲਾ;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	ਜੇ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
	ਜੇ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#ਜੇ_ਅੰਤ
	ਬੱਚਾ_terminated = 0;
	connection_ਵਿੱਚ = ssh_packet_get_connection_ਵਿੱਚ(ssh);
	connection_ਬਾਹਰਲਾ = ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh);

	server_init_dispatch(ssh);

	ਲਈ (;;) {
		process_buffered_ਨਿਵੇਸ਼_packets(ssh);

		ਜੇ (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		ਜੇ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		ਜੇ (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_ਵਿੱਚ, connection_ਬਾਹਰਲਾ,
		    &pfd, &npfd_alloc, &npfd_ਸਰਗਰਮ, &osigset,
		    &conn_ਵਿੱਚ_ready, &conn_ਬਾਹਰਲਾ_ready);
		ਜੇ (sigprocmask(SIG_SETMASK, &osigset, ਨਿਰਾ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_ਸਰਗਰਮ);
		ਜੇ (conn_ਵਿੱਚ_ready &&
		    process_ਨਿਵੇਸ਼(ssh, connection_ਵਿੱਚ) < 0)
			ਰੋਕੋ;
		/* A timeout may have triggered rekeying */
		ਜੇ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		ਜੇ (conn_ਬਾਹਰਲਾ_ready)
			process_output(ssh, connection_ਬਾਹਰਲਾ);
	}
	collect_children(ssh);
	ਮੁਕਤ(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, ਨਿਰਾ);
}

ਸਥਿਰ ਪੂਰਨ
server_ਨਿਵੇਸ਼_keep_alive(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_ਸੈੱਟ_alive_timeouts(ssh, 0);
	ਵਾਪਸ 0;
}

ਸਥਿਰ Channel *
server_request_ਸਿੱਧਾ_tcpip(ਬਣਤਰ ssh *ssh, ਪੂਰਨ *reason, ਅਚਲ ਅੱਖਰ **errmsg)
{
	Channel *c = ਨਿਰਾ;
	ਅੱਖਰ *ਨਿਸ਼ਾਨਾ = ਨਿਰਾ, *originator = ਨਿਰਾ;
	u_int ਨਿਸ਼ਾਨਾ_ਪੋਰਟ = 0, originator_ਪੋਰਟ = 0;
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &ਨਿਸ਼ਾਨਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &ਨਿਸ਼ਾਨਾ_ਪੋਰਟ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_ਪੋਰਟ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ਜੇ (ਨਿਸ਼ਾਨਾ_ਪੋਰਟ > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (originator_ਪੋਰਟ > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_ਪੋਰਟ, ਨਿਸ਼ਾਨਾ, ਨਿਸ਼ਾਨਾ_ਪੋਰਟ);

	/* XXX fine grained permissions */
	ਜੇ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_ਪੋਰਟ_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_ਮੰਜ਼ਿਲ_ਪੋਰਟ(ssh, ਨਿਸ਼ਾਨਾ, ਨਿਸ਼ਾਨਾ_ਪੋਰਟ,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} ਨਹੀਂਤਾਂ {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_ਪੋਰਟ, ਨਿਸ਼ਾਨਾ, ਨਿਸ਼ਾਨਾ_ਪੋਰਟ);
		ਜੇ (reason != ਨਿਰਾ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(originator);
	ਮੁਕਤ(ਨਿਸ਼ਾਨਾ);
	ਵਾਪਸ c;
}

ਸਥਿਰ Channel *
server_request_ਸਿੱਧਾ_streamlocal(ਬਣਤਰ ssh *ssh)
{
	Channel *c = ਨਿਰਾ;
	ਅੱਖਰ *ਨਿਸ਼ਾਨਾ = ਨਿਰਾ, *originator = ਨਿਰਾ;
	u_int originator_ਪੋਰਟ = 0;
	ਬਣਤਰ passwd *pw = the_authctxt->pw;
	ਪੂਰਨ r;

	ਜੇ (pw == ਨਿਰਾ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	ਜੇ ((r = sshpkt_get_cstring(ssh, &ਨਿਸ਼ਾਨਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_ਪੋਰਟ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ਜੇ (originator_ਪੋਰਟ > 0xFFFF) {
		error_f("invalid originator port");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_ਪੋਰਟ, ਨਿਸ਼ਾਨਾ);

	/* XXX fine grained permissions */
	ਜੇ ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_ਪੋਰਟ_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_ਮੰਜ਼ਿਲ_ਰਸਤਾ(ssh, ਨਿਸ਼ਾਨਾ,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} ਨਹੀਂਤਾਂ {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_ਪੋਰਟ, ਨਿਸ਼ਾਨਾ);
	}

ਬਾਹਰਲਾ:
	ਮੁਕਤ(originator);
	ਮੁਕਤ(ਨਿਸ਼ਾਨਾ);
	ਵਾਪਸ c;
}

ਸਥਿਰ Channel *
server_request_tun(ਬਣਤਰ ssh *ssh)
{
	Channel *c = ਨਿਰਾ;
	u_int ਬਹੁਲਕ, tun;
	ਪੂਰਨ r, sock;
	ਅੱਖਰ *tmp, *ifname = ਨਿਰਾ;

	ਜੇ ((r = sshpkt_get_u32(ssh, &ਬਹੁਲਕ)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	ਚੋਣ (ਬਹੁਲਕ) {
	ਹਾਲਤ SSH_TUNMODE_POINTOPOINT:
	ਹਾਲਤ SSH_TUNMODE_ETHERNET:
		ਰੋਕੋ;
	ਮੂਲ:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((options.permit_tun & ਬਹੁਲਕ) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		ਵਾਪਸ ਨਿਰਾ;
	}

	ਜੇ ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	ਜੇ (tun > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
		debug_f("invalid tun");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (auth_opts->force_tun_device != -1) {
		ਜੇ (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (ਪੂਰਨ)tun)
			ਜਾਓ ਪੂਰਾ;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, ਬਹੁਲਕ, &ifname);
	ਜੇ (sock < 0)
		ਜਾਓ ਪੂਰਾ;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#ਜੇ defined(SSH_TUN_FILTER)
	ਜੇ (ਬਹੁਲਕ == SSH_TUNMODE_POINTOPOINT)
		channel_ਰਜਿਸਟਰ_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ਨਿਰਾ, ਨਿਰਾ);
#ਜੇ_ਅੰਤ

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == ਨਿਰਾ ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == ਨਿਰਾ ? "" : ",",
	    ifname);
	ਮੁਕਤ(tmp);
	ਮੁਕਤ(ifname);

 ਪੂਰਾ:
	ਜੇ (c == ਨਿਰਾ)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	ਵਾਪਸ c;
}

ਸਥਿਰ Channel *
server_request_session(ਬਣਤਰ ssh *ssh)
{
	Channel *c;
	ਪੂਰਨ r;

	debug("input_session_request");
	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ਜੇ (no_ਹੋਰ_sessions) {
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
	ਜੇ (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		ਵਾਪਸ ਨਿਰਾ;
	}
	channel_ਰਜਿਸਟਰ_cleanup(ssh, c->self, session_close_by_channel, 0);
	ਵਾਪਸ c;
}

ਸਥਿਰ ਪੂਰਨ
server_ਨਿਵੇਸ਼_channel_open(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Channel *c = ਨਿਰਾ;
	ਅੱਖਰ *ctype = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *errmsg = ਨਿਰਾ;
	ਪੂਰਨ r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &ctype, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	ਜੇ (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_ਸਿੱਧਾ_tcpip(ssh, &reason, &errmsg);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_ਸਿੱਧਾ_streamlocal(ssh);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	ਜੇ (c != ਨਿਰਾ) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_ਖਿੜਕੀ = rwindow;
		c->remote_maxpacket = rmaxpack;
		ਜੇ (c->type != SSH_CHANNEL_CONNECTING) {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_ਖਿੜਕੀ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} ਨਹੀਂਤਾਂ {
		debug_f("failure %s", ctype);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	ਮੁਕਤ(ctype);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
server_ਨਿਵੇਸ਼_hostkeys_prove(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf **respp)
{
	ਬਣਤਰ sshbuf *resp = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *sigbuf = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ, *ਕੁੰਜੀ_pub = ਨਿਰਾ, *ਕੁੰਜੀ_prv = ਨਿਰਾ;
	ਪੂਰਨ r, ndx, success = 0;
	ਅਚਲ u_char *blob;
	ਅਚਲ ਅੱਖਰ *sigalg, *kex_rsa_sigalg = ਨਿਰਾ;
	u_char *sig = ਨਿਰਾ;
	ਮਾਪ_t blen, slen;

	ਜੇ ((resp = sshbuf_new()) == ਨਿਰਾ || (sigbuf = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == ਕੁੰਜੀ_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	ਜਦੋਂ (ssh_packet_ਬਚਿਆ(ssh) > 0) {
		sshkey_free(ਕੁੰਜੀ);
		ਕੁੰਜੀ = ਨਿਰਾ;
		ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &ਕੁੰਜੀ)) != 0) {
			error_fr(r, "parse key");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		ਜੇ ((ndx = ssh->kex->host_ਕੁੰਜੀ_ਸੂਚਕਾਂਕ(ਕੁੰਜੀ, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(ਕੁੰਜੀ));
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		ਜੇ ((ਕੁੰਜੀ_prv = get_hostkey_by_ਸੂਚਕਾਂਕ(ndx)) == ਨਿਰਾ &&
		    (ਕੁੰਜੀ_pub = get_hostkey_ਜਨਤਕ_by_ਸੂਚਕਾਂਕ(ndx, ssh)) == ਨਿਰਾ) {
			error_f("can't retrieve hostkey %d", ndx);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		sshbuf_reset(sigbuf);
		ਮੁਕਤ(sig);
		sig = ਨਿਰਾ;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(ਕੁੰਜੀ);
		ਜੇ (sshkey_type_plain(ਕੁੰਜੀ->type) == ਕੁੰਜੀ_RSA) {
			ਜੇ (kex_rsa_sigalg != ਨਿਰਾ)
				sigalg = kex_rsa_sigalg;
			ਨਹੀਂਤਾਂ ਜੇ (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			ਨਹੀਂਤਾਂ ਜੇ (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(ਕੁੰਜੀ), ndx, sigalg == ਨਿਰਾ ? "default" : sigalg);
		ਜੇ ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ਕੁੰਜੀ, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, ਕੁੰਜੀ_prv, ਕੁੰਜੀ_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	/* Success */
	*respp = resp;
	resp = ਨਿਰਾ; /* don't free it */
	success = 1;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(ਕੁੰਜੀ);
	ਵਾਪਸ success;
}

ਸਥਿਰ ਪੂਰਨ
server_ਨਿਵੇਸ਼_global_request(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ *rtype = ਨਿਰਾ;
	u_char want_ਜਵਾਬ = 0;
	ਪੂਰਨ r, success = 0, allocated_listen_ਪੋਰਟ = 0;
	u_int ਪੋਰਟ = 0;
	ਬਣਤਰ sshbuf *resp = ਨਿਰਾ;
	ਬਣਤਰ passwd *pw = the_authctxt->pw;
	ਬਣਤਰ Forward fwd;

	memset(&fwd, 0, ਆਕਾਰ(fwd));
	ਜੇ (pw == ਨਿਰਾ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	ਜੇ ((r = sshpkt_get_cstring(ssh, &rtype, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_ਜਵਾਬ)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_ਜਵਾਬ);

	/* -R style forwarding */
	ਜੇ (strcmp(rtype, "tcpip-forward") == 0) {
		ਜੇ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ਨਿਰਾ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &ਪੋਰਟ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, ਪੋਰਟ);
		ਜੇ (ਪੋਰਟ <= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
			fwd.listen_ਪੋਰਟ = (ਪੂਰਨ)ਪੋਰਟ;
		/* check permissions */
		ਜੇ (ਪੋਰਟ > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_ਪੋਰਟ_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_ਜਵਾਬ && fwd.listen_ਪੋਰਟ == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} ਨਹੀਂਤਾਂ {
			/* Start listening on the port */
			success = channel_ਤਿਆਰੀ_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_ਪੋਰਟ, &options.fwd_opts);
		}
		ਜੇ ((resp = sshbuf_new()) == ਨਿਰਾ)
			fatal_f("sshbuf_new");
		ਜੇ (allocated_listen_ਪੋਰਟ != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_ਪੋਰਟ)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		ਜੇ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ਨਿਰਾ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &ਪੋਰਟ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, ਪੋਰਟ);
		ਜੇ (ਪੋਰਟ <= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
			fwd.listen_ਪੋਰਟ = (ਪੂਰਨ)ਪੋਰਟ;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		ਜੇ ((r = sshpkt_get_cstring(ssh, &fwd.listen_ਰਸਤਾ, ਨਿਰਾ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_ਰਸਤਾ);

		/* check permissions */
		ਜੇ ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_ਪੋਰਟ_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} ਨਹੀਂਤਾਂ {
			/* Start listening on the socket */
			success = channel_ਤਿਆਰੀ_remote_fwd_listener(ssh,
			    &fwd, ਨਿਰਾ, &options.fwd_opts);
		}
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		ਜੇ ((r = sshpkt_get_cstring(ssh, &fwd.listen_ਰਸਤਾ, ਨਿਰਾ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_ਰਸਤਾ);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_ਹੋਰ_sessions = 1;
		success = 1;
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_ਨਿਵੇਸ਼_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	ਜੇ (want_ਜਵਾਬ) {
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, success ?
		    SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS : SSH2_ਸੁਨੇਹਾ_REQUEST_FAILURE)) != 0 ||
		    (success && resp != ਨਿਰਾ && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	ਮੁਕਤ(fwd.listen_host);
	ਮੁਕਤ(fwd.listen_ਰਸਤਾ);
	ਮੁਕਤ(rtype);
	sshbuf_free(resp);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
server_ਨਿਵੇਸ਼_channel_req(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Channel *c;
	ਪੂਰਨ r, success = 0;
	ਅੱਖਰ *rtype = ਨਿਰਾ;
	u_char want_ਜਵਾਬ = 0;
	u_int id = 0;

	ਜੇ ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_ਜਵਾਬ)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_ਜਵਾਬ);

	ਜੇ (id >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ || (c = channel_lookup(ssh, (ਪੂਰਨ)id)) == ਨਿਰਾ) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	ਜੇ (!strcmp(rtype, "eow@openssh.com")) {
		ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} ਨਹੀਂਤਾਂ ਜੇ ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_ਨਿਵੇਸ਼_channel_req(ssh, c, rtype);
	ਜੇ (want_ਜਵਾਬ && !(c->flags & CHAN_CLOSE_ਭੇਜਿਆ)) {
		ਜੇ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, success ?
		    SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS : SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	ਮੁਕਤ(rtype);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
server_init_dispatch(ਬਣਤਰ ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE, &channel_ਨਿਵੇਸ਼_oclose);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ, &channel_ਨਿਵੇਸ਼_ਅੰਕੜੇ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_EOF, &channel_ਨਿਵੇਸ਼_ieof);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_EXTENDED_ਅੰਕੜੇ, &channel_ਨਿਵੇਸ਼_extended_ਅੰਕੜੇ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN, &server_ਨਿਵੇਸ਼_channel_open);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION, &channel_ਨਿਵੇਸ਼_open_confirmation);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE, &channel_ਨਿਵੇਸ਼_open_failure);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_REQUEST, &server_ਨਿਵੇਸ਼_channel_req);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST, &channel_ਨਿਵੇਸ਼_ਖਿੜਕੀ_adjust);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST, &server_ਨਿਵੇਸ਼_global_request);
	/* client_alive */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS, &server_ਨਿਵੇਸ਼_keep_alive);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE, &server_ਨਿਵੇਸ਼_keep_alive);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS, &server_ਨਿਵੇਸ਼_keep_alive);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_REQUEST_FAILURE, &server_ਨਿਵੇਸ਼_keep_alive);
	/* rekeying */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEXINIT, &kex_ਨਿਵੇਸ਼_kexinit);
}
