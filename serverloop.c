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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/wait.h>
#شامل <sys/socket.h>
#شامل <sys/time.h>
#شامل <sys/queue.h>

#شامل <netinet/in.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <pwd.h>
#شامل <limits.h>
#شامل <poll.h>
#شامل <signal.h>
#شامل <string.h>
#شامل <termios.h>
#شامل <unistd.h>
#شامل <stdarg.h>

#شامل "xmalloc.h"
#شامل "packet.h"
#شامل "sshbuf.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "canohost.h"
#شامل "sshpty.h"
#شامل "channels.h"
#شامل "ssh2.h"
#شامل "sshkey.h"
#شامل "cipher.h"
#شامل "kex.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "session.h"
#شامل "dispatch.h"
#شامل "auth-options.h"
#شامل "serverloop.h"
#شامل "ssherr.h"

خارجی ServerOptions options;

/* XXX */
خارجی Authctxt *the_authctxt;
خارجی ساخت sshauthopt *auth_opts;

ساکن صحیح no_مزید_sessions = 0; /* Disallow further sessions. */

ساکن متلون sig_atomic_t بچہ_terminated = 0; /* set on SIGCHLD */
ساکن متلون sig_atomic_t siginfo_received = 0;

/* prototypes */
ساکن خالی server_init_dispatch(ساخت ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
حرف *tun_fwd_ifnames = تہی;

ساکن خالی
sigchld_handler(صحیح sig)
{
	بچہ_terminated = 1;
}

#اگر_تعریف_شدہ SIGINFO
ساکن خالی
siginfo_handler(صحیح sig)
{
	siginfo_received = 1;
}
#اگر_ختم

ساکن خالی
client_alive_check(ساخت ssh *ssh)
{
	حرف remote_id[512];
	صحیح r, channel_id;

	/* timeout, check to see how many we have had */
	اگر (options.client_alive_گنتی_max > 0 &&
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
	اگر ((channel_id = channel_ڈھونڈو_open(ssh)) == -1) {
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} ورنہ {
		channel_request_آغاز(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
ساکن خالی
wait_until_can_do_something(ساخت ssh *ssh,
    صحیح connection_اندر, صحیح connection_برآمد, ساخت pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    صحیح *conn_اندر_readyp, صحیح *conn_برآمد_readyp)
{
	ساخت timespec timeout;
	حرف remote_id[512];
	صحیح ret;
	صحیح client_alive_scheduled = 0;
	u_int p;
	time_t now;
	ساکن time_t آخری_client_وقت, غیر_مستعمل_connection_expiry;

	*conn_اندر_readyp = *conn_برآمد_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	اگر (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	اگر (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	اگر (options.غیر_مستعمل_connection_timeout != 0) {
		اگر (channel_still_open(ssh))
			غیر_مستعمل_connection_expiry = 0;
		ورنہ اگر (غیر_مستعمل_connection_expiry == 0) {
			غیر_مستعمل_connection_expiry = now +
			    options.غیر_مستعمل_connection_timeout;
		}
	}
	اگر (غیر_مستعمل_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, غیر_مستعمل_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	اگر (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		اگر (آخری_client_وقت == 0)
			آخری_client_وقت = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#اگر 0
	/* wrong: bad condition XXX */
	اگر (channel_not_very_much_buffered_ڈیٹا())
#اگر_ختم
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_اندر;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_برآمد;
	(*pfdp)[1].events = ssh_packet_have_ڈیٹا_مقصد_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	اگر (بچہ_terminated && ssh_packet_not_very_much_ڈیٹا_مقصد_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	اگر (ret == -1) {
		برائے (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		اگر (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		واپس;
	}

	*conn_اندر_readyp = (*pfdp)[0].revents != 0;
	*conn_برآمد_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	اگر (client_alive_scheduled) {
		اگر (ret == 0 &&
		    now >= آخری_client_وقت + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			آخری_client_وقت = now;
		} ورنہ اگر (ret != 0 && *conn_اندر_readyp) {
			/* Data from peer; reset probe timer. */
			آخری_client_وقت = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	اگر (غیر_مستعمل_connection_expiry != 0 &&
	    now > غیر_مستعمل_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
ساکن صحیح
process_داخلہ(ساخت ssh *ssh, صحیح connection_اندر)
{
	صحیح r;

	اگر ((r = ssh_packet_process_read(ssh, connection_اندر)) == 0)
		واپس 0; /* success */
	اگر (r == SSH_ERR_SYSTEM_ERROR) {
		اگر (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			واپس 0;
		اگر (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
			واپس -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	واپس -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
ساکن خالی
process_output(ساخت ssh *ssh, صحیح connection_برآمد)
{
	صحیح r;
	ساکن صحیح interactive = -1;

	/* Send any buffered packet data to the client. */
	اگر (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_سیٹ_interactive(ssh, interactive);
	}
	اگر ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

ساکن خالی
process_buffered_داخلہ_packets(ساخت ssh *ssh)
{
	ssh_dispatch_تسلسل_fatal(ssh, DISPATCH_NONBLOCK, تہی);
}

ساکن خالی
collect_children(ساخت ssh *ssh)
{
	pid_t pid;
	صحیح حالت_2;

	اگر (بچہ_terminated) {
		debug("Received SIGCHLD.");
		جب ((pid = waitpid(-1, &حالت_2, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			اگر (pid > 0)
				session_close_by_pid(ssh, pid, حالت_2);
		بچہ_terminated = 0;
	}
}

خالی
server_loop2(ساخت ssh *ssh, Authctxt *authctxt)
{
	ساخت pollfd *pfd = تہی;
	u_int npfd_alloc = 0, npfd_فعال = 0;
	صحیح r, conn_اندر_ready, conn_برآمد_ready;
	u_int connection_اندر, connection_برآمد;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	اگر (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#اگر_تعریف_شدہ SIGINFO
	اگر (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#اگر_ختم
	بچہ_terminated = 0;
	connection_اندر = ssh_packet_get_connection_اندر(ssh);
	connection_برآمد = ssh_packet_get_connection_برآمد(ssh);

	server_init_dispatch(ssh);

	برائے (;;) {
		process_buffered_داخلہ_packets(ssh);

		اگر (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_ڈیٹا_مقصد_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		اگر (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		اگر (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_اندر, connection_برآمد,
		    &pfd, &npfd_alloc, &npfd_فعال, &osigset,
		    &conn_اندر_ready, &conn_برآمد_ready);
		اگر (sigprocmask(SIG_SETMASK, &osigset, تہی) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_فعال);
		اگر (conn_اندر_ready &&
		    process_داخلہ(ssh, connection_اندر) < 0)
			توڑو;
		/* A timeout may have triggered rekeying */
		اگر ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		اگر (conn_برآمد_ready)
			process_output(ssh, connection_برآمد);
	}
	collect_children(ssh);
	آزاد(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, تہی);
}

ساکن صحیح
server_داخلہ_keep_alive(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_سیٹ_alive_timeouts(ssh, 0);
	واپس 0;
}

ساکن Channel *
server_request_براہ_راست_tcpip(ساخت ssh *ssh, صحیح *reason, ثابت حرف **errmsg)
{
	Channel *c = تہی;
	حرف *ہدف = تہی, *originator = تہی;
	u_int ہدف_پورٹ = 0, originator_پورٹ = 0;
	صحیح r;

	اگر ((r = sshpkt_get_cstring(ssh, &ہدف, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &ہدف_پورٹ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_پورٹ)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	اگر (ہدف_پورٹ > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		جاؤ برآمد;
	}
	اگر (originator_پورٹ > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		جاؤ برآمد;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_پورٹ, ہدف, ہدف_پورٹ);

	/* XXX fine grained permissions */
	اگر ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_پورٹ_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_مقصد_پورٹ(ssh, ہدف, ہدف_پورٹ,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} ورنہ {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_پورٹ, ہدف, ہدف_پورٹ);
		اگر (reason != تہی)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 برآمد:
	آزاد(originator);
	آزاد(ہدف);
	واپس c;
}

ساکن Channel *
server_request_براہ_راست_streamlocal(ساخت ssh *ssh)
{
	Channel *c = تہی;
	حرف *ہدف = تہی, *originator = تہی;
	u_int originator_پورٹ = 0;
	ساخت passwd *pw = the_authctxt->pw;
	صحیح r;

	اگر (pw == تہی || !the_authctxt->valid)
		fatal_f("no/invalid user");

	اگر ((r = sshpkt_get_cstring(ssh, &ہدف, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_پورٹ)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	اگر (originator_پورٹ > 0xFFFF) {
		error_f("invalid originator port");
		جاؤ برآمد;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_پورٹ, ہدف);

	/* XXX fine grained permissions */
	اگر ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_پورٹ_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_مقصد_راستہ(ssh, ہدف,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} ورنہ {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_پورٹ, ہدف);
	}

برآمد:
	آزاد(originator);
	آزاد(ہدف);
	واپس c;
}

ساکن Channel *
server_request_tun(ساخت ssh *ssh)
{
	Channel *c = تہی;
	u_int منوال, tun;
	صحیح r, sock;
	حرف *tmp, *ifname = تہی;

	اگر ((r = sshpkt_get_u32(ssh, &منوال)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	انتخاب (منوال) {
	حالت SSH_TUNMODE_POINTOPOINT:
	حالت SSH_TUNMODE_ETHERNET:
		توڑو;
	طےشدہ:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		واپس تہی;
	}
	اگر ((options.permit_tun & منوال) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		واپس تہی;
	}

	اگر ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	اگر (tun > زیادہ_سے_زیادہ_عدد) {
		debug_f("invalid tun");
		جاؤ مکمل;
	}
	اگر (auth_opts->force_tun_device != -1) {
		اگر (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (صحیح)tun)
			جاؤ مکمل;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, منوال, &ifname);
	اگر (sock < 0)
		جاؤ مکمل;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#اگر defined(SSH_TUN_FILTER)
	اگر (منوال == SSH_TUNMODE_POINTOPOINT)
		channel_رجسٹر_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, تہی, تہی);
#اگر_ختم

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == تہی ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == تہی ? "" : ",",
	    ifname);
	آزاد(tmp);
	آزاد(ifname);

 مکمل:
	اگر (c == تہی)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	واپس c;
}

ساکن Channel *
server_request_session(ساخت ssh *ssh)
{
	Channel *c;
	صحیح r;

	debug("input_session_request");
	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	اگر (no_مزید_sessions) {
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
	اگر (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		واپس تہی;
	}
	channel_رجسٹر_cleanup(ssh, c->self, session_close_by_channel, 0);
	واپس c;
}

ساکن صحیح
server_داخلہ_channel_open(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Channel *c = تہی;
	حرف *ctype = تہی;
	ثابت حرف *errmsg = تہی;
	صحیح r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	اگر ((r = sshpkt_get_cstring(ssh, &ctype, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	اگر (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} ورنہ اگر (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_براہ_راست_tcpip(ssh, &reason, &errmsg);
	} ورنہ اگر (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_براہ_راست_streamlocal(ssh);
	} ورنہ اگر (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	اگر (c != تہی) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_کھڑکی = rwindow;
		c->remote_maxpacket = rmaxpack;
		اگر (c->type != SSH_CHANNEL_CONNECTING) {
			اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_کھڑکی)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} ورنہ {
		debug_f("failure %s", ctype);
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	آزاد(ctype);
	واپس 0;
}

ساکن صحیح
server_داخلہ_hostkeys_prove(ساخت ssh *ssh, ساخت sshbuf **respp)
{
	ساخت sshbuf *resp = تہی;
	ساخت sshbuf *sigbuf = تہی;
	ساخت sshkey *کلید = تہی, *کلید_pub = تہی, *کلید_prv = تہی;
	صحیح r, ndx, success = 0;
	ثابت u_char *blob;
	ثابت حرف *sigalg, *kex_rsa_sigalg = تہی;
	u_char *sig = تہی;
	سائز_t blen, slen;

	اگر ((resp = sshbuf_new()) == تہی || (sigbuf = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == کلید_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	جب (ssh_packet_بقایا(ssh) > 0) {
		sshkey_free(کلید);
		کلید = تہی;
		اگر ((r = sshpkt_get_string_براہ_راست(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &کلید)) != 0) {
			error_fr(r, "parse key");
			جاؤ برآمد;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		اگر ((ndx = ssh->kex->host_کلید_اشاریہ(کلید, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(کلید));
			جاؤ برآمد;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		اگر ((کلید_prv = get_hostkey_by_اشاریہ(ndx)) == تہی &&
		    (کلید_pub = get_hostkey_عوامی_by_اشاریہ(ndx, ssh)) == تہی) {
			error_f("can't retrieve hostkey %d", ndx);
			جاؤ برآمد;
		}
		sshbuf_reset(sigbuf);
		آزاد(sig);
		sig = تہی;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(کلید);
		اگر (sshkey_type_plain(کلید->type) == کلید_RSA) {
			اگر (kex_rsa_sigalg != تہی)
				sigalg = kex_rsa_sigalg;
			ورنہ اگر (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			ورنہ اگر (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(کلید), ndx, sigalg == تہی ? "default" : sigalg);
		اگر ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(کلید, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, کلید_prv, کلید_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			جاؤ برآمد;
		}
	}
	/* Success */
	*respp = resp;
	resp = تہی; /* don't free it */
	success = 1;
 برآمد:
	آزاد(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(کلید);
	واپس success;
}

ساکن صحیح
server_داخلہ_global_request(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	حرف *rtype = تہی;
	u_char want_جواب = 0;
	صحیح r, success = 0, allocated_listen_پورٹ = 0;
	u_int پورٹ = 0;
	ساخت sshbuf *resp = تہی;
	ساخت passwd *pw = the_authctxt->pw;
	ساخت Forward fwd;

	memset(&fwd, 0, حجم(fwd));
	اگر (pw == تہی || !the_authctxt->valid)
		fatal_f("no/invalid user");

	اگر ((r = sshpkt_get_cstring(ssh, &rtype, تہی)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_جواب)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_جواب);

	/* -R style forwarding */
	اگر (strcmp(rtype, "tcpip-forward") == 0) {
		اگر ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, تہی)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &پورٹ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, پورٹ);
		اگر (پورٹ <= زیادہ_سے_زیادہ_عدد)
			fwd.listen_پورٹ = (صحیح)پورٹ;
		/* check permissions */
		اگر (پورٹ > زیادہ_سے_زیادہ_عدد ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_پورٹ_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_جواب && fwd.listen_پورٹ == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} ورنہ {
			/* Start listening on the port */
			success = channel_تیاری_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_پورٹ, &options.fwd_opts);
		}
		اگر ((resp = sshbuf_new()) == تہی)
			fatal_f("sshbuf_new");
		اگر (allocated_listen_پورٹ != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_پورٹ)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} ورنہ اگر (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		اگر ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, تہی)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &پورٹ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, پورٹ);
		اگر (پورٹ <= زیادہ_سے_زیادہ_عدد) {
			fwd.listen_پورٹ = (صحیح)پورٹ;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} ورنہ اگر (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		اگر ((r = sshpkt_get_cstring(ssh, &fwd.listen_راستہ, تہی)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_راستہ);

		/* check permissions */
		اگر ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_پورٹ_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} ورنہ {
			/* Start listening on the socket */
			success = channel_تیاری_remote_fwd_listener(ssh,
			    &fwd, تہی, &options.fwd_opts);
		}
	} ورنہ اگر (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		اگر ((r = sshpkt_get_cstring(ssh, &fwd.listen_راستہ, تہی)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_راستہ);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} ورنہ اگر (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_مزید_sessions = 1;
		success = 1;
	} ورنہ اگر (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_داخلہ_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	اگر (want_جواب) {
		اگر ((r = sshpkt_آغاز(ssh, success ?
		    SSH2_پیغام_REQUEST_SUCCESS : SSH2_پیغام_REQUEST_FAILURE)) != 0 ||
		    (success && resp != تہی && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	آزاد(fwd.listen_host);
	آزاد(fwd.listen_راستہ);
	آزاد(rtype);
	sshbuf_free(resp);
	واپس 0;
}

ساکن صحیح
server_داخلہ_channel_req(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Channel *c;
	صحیح r, success = 0;
	حرف *rtype = تہی;
	u_char want_جواب = 0;
	u_int id = 0;

	اگر ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, تہی)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_جواب)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_جواب);

	اگر (id >= زیادہ_سے_زیادہ_عدد || (c = channel_lookup(ssh, (صحیح)id)) == تہی) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	اگر (!strcmp(rtype, "eow@openssh.com")) {
		اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} ورنہ اگر ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_داخلہ_channel_req(ssh, c, rtype);
	اگر (want_جواب && !(c->flags & CHAN_CLOSE_بھیجا)) {
		اگر (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		اگر ((r = sshpkt_آغاز(ssh, success ?
		    SSH2_پیغام_CHANNEL_SUCCESS : SSH2_پیغام_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	آزاد(rtype);
	واپس 0;
}

ساکن خالی
server_init_dispatch(ساخت ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_CLOSE, &channel_داخلہ_oclose);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_ڈیٹا, &channel_داخلہ_ڈیٹا);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_EOF, &channel_داخلہ_ieof);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_EXTENDED_ڈیٹا, &channel_داخلہ_extended_ڈیٹا);
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
