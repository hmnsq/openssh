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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/wait.h>
#ضمن <sys/socket.h>
#ضمن <sys/time.h>
#ضمن <sys/queue.h>

#ضمن <netinet/in.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <pwd.h>
#ضمن <limits.h>
#ضمن <poll.h>
#ضمن <signal.h>
#ضمن <string.h>
#ضمن <termios.h>
#ضمن <unistd.h>
#ضمن <stdarg.h>

#ضمن "xmalloc.h"
#ضمن "packet.h"
#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "canohost.h"
#ضمن "sshpty.h"
#ضمن "channels.h"
#ضمن "ssh2.h"
#ضمن "sshkey.h"
#ضمن "cipher.h"
#ضمن "kex.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "session.h"
#ضمن "dispatch.h"
#ضمن "auth-options.h"
#ضمن "serverloop.h"
#ضمن "ssherr.h"

خارجي ServerOptions options;

/* XXX */
خارجي Authctxt *the_authctxt;
خارجي بنية sshauthopt *auth_opts;

ساكن صحيح no_ہور_sessions = 0; /* Disallow further sessions. */

ساكن متطاير sig_atomic_t بچہ_terminated = 0; /* set on SIGCHLD */
ساكن متطاير sig_atomic_t siginfo_received = 0;

/* prototypes */
ساكن فراغ server_init_dispatch(بنية ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
حرف *tun_fwd_ifnames = عدم;

ساكن فراغ
sigchld_handler(صحيح sig)
{
	بچہ_terminated = 1;
}

#جے_تعریف_شدہ SIGINFO
ساكن فراغ
siginfo_handler(صحيح sig)
{
	siginfo_received = 1;
}
#جے_انت

ساكن فراغ
client_alive_check(بنية ssh *ssh)
{
	حرف remote_id[512];
	صحيح r, channel_id;

	/* timeout, check to see how many we have had */
	إذا (options.client_alive_گنتی_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_گنتی_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	إذا ((channel_id = channel_لبھو_open(ssh)) == -1) {
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} وإلا {
		channel_request_شروع(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	إذا ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
ساكن فراغ
wait_until_can_do_something(بنية ssh *ssh,
    صحيح connection_وچ, صحيح connection_باہرلا, بنية pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    صحيح *conn_وچ_readyp, صحيح *conn_باہرلا_readyp)
{
	بنية timespec timeout;
	حرف remote_id[512];
	صحيح ret;
	صحيح client_alive_scheduled = 0;
	u_int p;
	time_t now;
	ساكن time_t آخری_client_ویلا, بن_ورتیا_connection_expiry;

	*conn_وچ_readyp = *conn_باہرلا_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	إذا (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	إذا (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	إذا (options.بن_ورتیا_connection_timeout != 0) {
		إذا (channel_still_open(ssh))
			بن_ورتیا_connection_expiry = 0;
		وإلا إذا (بن_ورتیا_connection_expiry == 0) {
			بن_ورتیا_connection_expiry = now +
			    options.بن_ورتیا_connection_timeout;
		}
	}
	إذا (بن_ورتیا_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, بن_ورتیا_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	إذا (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		إذا (آخری_client_ویلا == 0)
			آخری_client_ویلا = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#إذا 0
	/* wrong: bad condition XXX */
	إذا (channel_not_very_much_buffered_انکڑے())
#جے_انت
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_وچ;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_باہرلا;
	(*pfdp)[1].events = ssh_packet_have_انکڑے_منزل_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	إذا (بچہ_terminated && ssh_packet_not_very_much_انکڑے_منزل_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	إذا (ret == -1) {
		لكل (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		إذا (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		أرجع;
	}

	*conn_وچ_readyp = (*pfdp)[0].revents != 0;
	*conn_باہرلا_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	إذا (client_alive_scheduled) {
		إذا (ret == 0 &&
		    now >= آخری_client_ویلا + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			آخری_client_ویلا = now;
		} وإلا إذا (ret != 0 && *conn_وچ_readyp) {
			/* Data from peer; reset probe timer. */
			آخری_client_ویلا = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	إذا (بن_ورتیا_connection_expiry != 0 &&
	    now > بن_ورتیا_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
ساكن صحيح
process_داخلہ(بنية ssh *ssh, صحيح connection_وچ)
{
	صحيح r;

	إذا ((r = ssh_packet_process_read(ssh, connection_وچ)) == 0)
		أرجع 0; /* success */
	إذا (r == SSH_ERR_SYSTEM_ERROR) {
		إذا (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			أرجع 0;
		إذا (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
			أرجع -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	أرجع -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
ساكن فراغ
process_output(بنية ssh *ssh, صحيح connection_باہرلا)
{
	صحيح r;
	ساكن صحيح interactive = -1;

	/* Send any buffered packet data to the client. */
	إذا (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_سیٹ_interactive(ssh, interactive);
	}
	إذا ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

ساكن فراغ
process_buffered_داخلہ_packets(بنية ssh *ssh)
{
	ssh_dispatch_لگاتار_fatal(ssh, DISPATCH_NONBLOCK, عدم);
}

ساكن فراغ
collect_children(بنية ssh *ssh)
{
	pid_t pid;
	صحيح حالت;

	إذا (بچہ_terminated) {
		debug("Received SIGCHLD.");
		طالما ((pid = waitpid(-1, &حالت, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			إذا (pid > 0)
				session_close_by_pid(ssh, pid, حالت);
		بچہ_terminated = 0;
	}
}

فراغ
server_loop2(بنية ssh *ssh, Authctxt *authctxt)
{
	بنية pollfd *pfd = عدم;
	u_int npfd_alloc = 0, npfd_سرگرم = 0;
	صحيح r, conn_وچ_ready, conn_باہرلا_ready;
	u_int connection_وچ, connection_باہرلا;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	إذا (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#جے_تعریف_شدہ SIGINFO
	إذا (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#جے_انت
	بچہ_terminated = 0;
	connection_وچ = ssh_packet_get_connection_وچ(ssh);
	connection_باہرلا = ssh_packet_get_connection_باہرلا(ssh);

	server_init_dispatch(ssh);

	لكل (;;) {
		process_buffered_داخلہ_packets(ssh);

		إذا (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_انکڑے_منزل_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		إذا (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		إذا (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_وچ, connection_باہرلا,
		    &pfd, &npfd_alloc, &npfd_سرگرم, &osigset,
		    &conn_وچ_ready, &conn_باہرلا_ready);
		إذا (sigprocmask(SIG_SETMASK, &osigset, عدم) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_سرگرم);
		إذا (conn_وچ_ready &&
		    process_داخلہ(ssh, connection_وچ) < 0)
			اكسر;
		/* A timeout may have triggered rekeying */
		إذا ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		إذا (conn_باہرلا_ready)
			process_output(ssh, connection_باہرلا);
	}
	collect_children(ssh);
	حرر(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, عدم);
}

ساكن صحيح
server_داخلہ_keep_alive(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_سیٹ_alive_timeouts(ssh, 0);
	أرجع 0;
}

ساكن Channel *
server_request_سدھا_tcpip(بنية ssh *ssh, صحيح *reason, ثابت حرف **errmsg)
{
	Channel *c = عدم;
	حرف *نشانہ = عدم, *originator = عدم;
	u_int نشانہ_پورٹ = 0, originator_پورٹ = 0;
	صحيح r;

	إذا ((r = sshpkt_get_cstring(ssh, &نشانہ, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &نشانہ_پورٹ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_پورٹ)) != 0 ||
	    (r = sshpkt_get_سرا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	إذا (نشانہ_پورٹ > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		اذهب باہرلا;
	}
	إذا (originator_پورٹ > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		اذهب باہرلا;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_پورٹ, نشانہ, نشانہ_پورٹ);

	/* XXX fine grained permissions */
	إذا ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_پورٹ_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_منزل_پورٹ(ssh, نشانہ, نشانہ_پورٹ,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} وإلا {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_پورٹ, نشانہ, نشانہ_پورٹ);
		إذا (reason != عدم)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 باہرلا:
	حرر(originator);
	حرر(نشانہ);
	أرجع c;
}

ساكن Channel *
server_request_سدھا_streamlocal(بنية ssh *ssh)
{
	Channel *c = عدم;
	حرف *نشانہ = عدم, *originator = عدم;
	u_int originator_پورٹ = 0;
	بنية passwd *pw = the_authctxt->pw;
	صحيح r;

	إذا (pw == عدم || !the_authctxt->valid)
		fatal_f("no/invalid user");

	إذا ((r = sshpkt_get_cstring(ssh, &نشانہ, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_پورٹ)) != 0 ||
	    (r = sshpkt_get_سرا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	إذا (originator_پورٹ > 0xFFFF) {
		error_f("invalid originator port");
		اذهب باہرلا;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_پورٹ, نشانہ);

	/* XXX fine grained permissions */
	إذا ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_پورٹ_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_منزل_رستہ(ssh, نشانہ,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} وإلا {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_پورٹ, نشانہ);
	}

باہرلا:
	حرر(originator);
	حرر(نشانہ);
	أرجع c;
}

ساكن Channel *
server_request_tun(بنية ssh *ssh)
{
	Channel *c = عدم;
	u_int منوال, tun;
	صحيح r, sock;
	حرف *tmp, *ifname = عدم;

	إذا ((r = sshpkt_get_u32(ssh, &منوال)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	بدل (منوال) {
	حالة SSH_TUNMODE_POINTOPOINT:
	حالة SSH_TUNMODE_ETHERNET:
		اكسر;
	افتراضي:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		أرجع عدم;
	}
	إذا ((options.permit_tun & منوال) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		أرجع عدم;
	}

	إذا ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	إذا (tun > ودھ_توں_ودھ_عدد) {
		debug_f("invalid tun");
		اذهب پورا;
	}
	إذا (auth_opts->force_tun_device != -1) {
		إذا (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (صحيح)tun)
			اذهب پورا;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, منوال, &ifname);
	إذا (sock < 0)
		اذهب پورا;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#إذا defined(SSH_TUN_FILTER)
	إذا (منوال == SSH_TUNMODE_POINTOPOINT)
		channel_رجسٹر_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, عدم, عدم);
#جے_انت

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == عدم ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == عدم ? "" : ",",
	    ifname);
	حرر(tmp);
	حرر(ifname);

 پورا:
	إذا (c == عدم)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	أرجع c;
}

ساكن Channel *
server_request_session(بنية ssh *ssh)
{
	Channel *c;
	صحيح r;

	debug("input_session_request");
	إذا ((r = sshpkt_get_سرا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	إذا (no_ہور_sessions) {
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
	إذا (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		أرجع عدم;
	}
	channel_رجسٹر_cleanup(ssh, c->self, session_close_by_channel, 0);
	أرجع c;
}

ساكن صحيح
server_داخلہ_channel_open(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Channel *c = عدم;
	حرف *ctype = عدم;
	ثابت حرف *errmsg = عدم;
	صحيح r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	إذا ((r = sshpkt_get_cstring(ssh, &ctype, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	إذا (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} وإلا إذا (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_سدھا_tcpip(ssh, &reason, &errmsg);
	} وإلا إذا (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_سدھا_streamlocal(ssh);
	} وإلا إذا (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	إذا (c != عدم) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_کھڑکی = rwindow;
		c->remote_maxpacket = rmaxpack;
		إذا (c->type != SSH_CHANNEL_CONNECTING) {
			إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_کھڑکی)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} وإلا {
		debug_f("failure %s", ctype);
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	حرر(ctype);
	أرجع 0;
}

ساكن صحيح
server_داخلہ_hostkeys_prove(بنية ssh *ssh, بنية sshbuf **respp)
{
	بنية sshbuf *resp = عدم;
	بنية sshbuf *sigbuf = عدم;
	بنية sshkey *کلید = عدم, *کلید_pub = عدم, *کلید_prv = عدم;
	صحيح r, ndx, success = 0;
	ثابت u_char *blob;
	ثابت حرف *sigalg, *kex_rsa_sigalg = عدم;
	u_char *sig = عدم;
	ناپ_t blen, slen;

	إذا ((resp = sshbuf_new()) == عدم || (sigbuf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == کلید_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	طالما (ssh_packet_بچیا(ssh) > 0) {
		sshkey_free(کلید);
		کلید = عدم;
		إذا ((r = sshpkt_get_string_سدھا(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &کلید)) != 0) {
			error_fr(r, "parse key");
			اذهب باہرلا;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		إذا ((ndx = ssh->kex->host_کلید_اشاریہ(کلید, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(کلید));
			اذهب باہرلا;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		إذا ((کلید_prv = get_hostkey_by_اشاریہ(ndx)) == عدم &&
		    (کلید_pub = get_hostkey_عوامی_by_اشاریہ(ndx, ssh)) == عدم) {
			error_f("can't retrieve hostkey %d", ndx);
			اذهب باہرلا;
		}
		sshbuf_reset(sigbuf);
		حرر(sig);
		sig = عدم;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(کلید);
		إذا (sshkey_type_plain(کلید->type) == کلید_RSA) {
			إذا (kex_rsa_sigalg != عدم)
				sigalg = kex_rsa_sigalg;
			وإلا إذا (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			وإلا إذا (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(کلید), ndx, sigalg == عدم ? "default" : sigalg);
		إذا ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(کلید, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, کلید_prv, کلید_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			اذهب باہرلا;
		}
	}
	/* Success */
	*respp = resp;
	resp = عدم; /* don't free it */
	success = 1;
 باہرلا:
	حرر(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(کلید);
	أرجع success;
}

ساكن صحيح
server_داخلہ_global_request(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	حرف *rtype = عدم;
	u_char want_جواب = 0;
	صحيح r, success = 0, allocated_listen_پورٹ = 0;
	u_int پورٹ = 0;
	بنية sshbuf *resp = عدم;
	بنية passwd *pw = the_authctxt->pw;
	بنية Forward fwd;

	memset(&fwd, 0, حجم(fwd));
	إذا (pw == عدم || !the_authctxt->valid)
		fatal_f("no/invalid user");

	إذا ((r = sshpkt_get_cstring(ssh, &rtype, عدم)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_جواب)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_جواب);

	/* -R style forwarding */
	إذا (strcmp(rtype, "tcpip-forward") == 0) {
		إذا ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, عدم)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &پورٹ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, پورٹ);
		إذا (پورٹ <= ودھ_توں_ودھ_عدد)
			fwd.listen_پورٹ = (صحيح)پورٹ;
		/* check permissions */
		إذا (پورٹ > ودھ_توں_ودھ_عدد ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_پورٹ_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_جواب && fwd.listen_پورٹ == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} وإلا {
			/* Start listening on the port */
			success = channel_تیاری_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_پورٹ, &options.fwd_opts);
		}
		إذا ((resp = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new");
		إذا (allocated_listen_پورٹ != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_پورٹ)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} وإلا إذا (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		إذا ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, عدم)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &پورٹ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, پورٹ);
		إذا (پورٹ <= ودھ_توں_ودھ_عدد) {
			fwd.listen_پورٹ = (صحيح)پورٹ;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} وإلا إذا (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		إذا ((r = sshpkt_get_cstring(ssh, &fwd.listen_رستہ, عدم)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_رستہ);

		/* check permissions */
		إذا ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_پورٹ_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} وإلا {
			/* Start listening on the socket */
			success = channel_تیاری_remote_fwd_listener(ssh,
			    &fwd, عدم, &options.fwd_opts);
		}
	} وإلا إذا (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		إذا ((r = sshpkt_get_cstring(ssh, &fwd.listen_رستہ, عدم)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_رستہ);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} وإلا إذا (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_ہور_sessions = 1;
		success = 1;
	} وإلا إذا (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_داخلہ_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	إذا (want_جواب) {
		إذا ((r = sshpkt_شروع(ssh, success ?
		    SSH2_پیغام_REQUEST_SUCCESS : SSH2_پیغام_REQUEST_FAILURE)) != 0 ||
		    (success && resp != عدم && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	حرر(fwd.listen_host);
	حرر(fwd.listen_رستہ);
	حرر(rtype);
	sshbuf_free(resp);
	أرجع 0;
}

ساكن صحيح
server_داخلہ_channel_req(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Channel *c;
	صحيح r, success = 0;
	حرف *rtype = عدم;
	u_char want_جواب = 0;
	u_int id = 0;

	إذا ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, عدم)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_جواب)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_جواب);

	إذا (id >= ودھ_توں_ودھ_عدد || (c = channel_lookup(ssh, (صحيح)id)) == عدم) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	إذا (!strcmp(rtype, "eow@openssh.com")) {
		إذا ((r = sshpkt_get_سرا(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} وإلا إذا ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_داخلہ_channel_req(ssh, c, rtype);
	إذا (want_جواب && !(c->flags & CHAN_CLOSE_گھلیا)) {
		إذا (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		إذا ((r = sshpkt_شروع(ssh, success ?
		    SSH2_پیغام_CHANNEL_SUCCESS : SSH2_پیغام_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	حرر(rtype);
	أرجع 0;
}

ساكن فراغ
server_init_dispatch(بنية ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_CLOSE, &channel_داخلہ_oclose);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_انکڑے, &channel_داخلہ_انکڑے);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_EOF, &channel_داخلہ_ieof);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_EXTENDED_انکڑے, &channel_داخلہ_extended_انکڑے);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_OPEN, &server_داخلہ_channel_open);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION, &channel_داخلہ_open_confirmation);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_OPEN_FAILURE, &channel_داخلہ_open_failure);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_REQUEST, &server_داخلہ_channel_req);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_کھڑکی_ADJUST, &channel_داخلہ_کھڑکی_adjust);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_GLOBAL_REQUEST, &server_داخلہ_global_request);
	/* client_alive */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_SUCCESS, &server_داخلہ_keep_alive);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_FAILURE, &server_داخلہ_keep_alive);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_REQUEST_SUCCESS, &server_داخلہ_keep_alive);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_REQUEST_FAILURE, &server_داخلہ_keep_alive);
	/* rekeying */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEXINIT, &kex_داخلہ_kexinit);
}
