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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <netinet/in.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <termios.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "sshpty.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "session.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "serverloop.h"
#అన్తర్భావ "ssherr.h"

బాహ్య ServerOptions options;

/* XXX */
బాహ్య Authctxt *the_authctxt;
బాహ్య నిర్మాణం sshauthopt *auth_opts;

స్థిర పూర్ణాంకం no_మరిన్ని_sessions = 0; /* Disallow further sessions. */

స్థిర అస్థిర sig_atomic_t బిడ్డ_terminated = 0; /* set on SIGCHLD */
స్థిర అస్థిర sig_atomic_t siginfo_received = 0;

/* prototypes */
స్థిర శూన్య server_init_dispatch(నిర్మాణం ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
అక్షరం *tun_fwd_ifnames = ఖాళీ;

స్థిర శూన్య
sigchld_handler(పూర్ణాంకం sig)
{
	బిడ్డ_terminated = 1;
}

#నిర్వచితమైతే SIGINFO
స్థిర శూన్య
siginfo_handler(పూర్ణాంకం sig)
{
	siginfo_received = 1;
}
#అయితే_ముగింపు

స్థిర శూన్య
client_alive_check(నిర్మాణం ssh *ssh)
{
	అక్షరం remote_id[512];
	పూర్ణాంకం r, channel_id;

	/* timeout, check to see how many we have had */
	ఒకవేళ (options.client_alive_లెక్క_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_లెక్క_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, పరిమాణం(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	ఒకవేళ ((channel_id = channel_కనుగొను_open(ssh)) == -1) {
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} లేకపోతే {
		channel_request_ప్రారంభం(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
స్థిర శూన్య
wait_until_can_do_something(నిర్మాణం ssh *ssh,
    పూర్ణాంకం connection_లోపల, పూర్ణాంకం connection_బహిర్గతం, నిర్మాణం pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    పూర్ణాంకం *conn_లోపల_readyp, పూర్ణాంకం *conn_బహిర్గతం_readyp)
{
	నిర్మాణం timespec timeout;
	అక్షరం remote_id[512];
	పూర్ణాంకం ret;
	పూర్ణాంకం client_alive_scheduled = 0;
	u_int p;
	time_t now;
	స్థిర time_t చివరి_client_సమయం, వాడని_connection_expiry;

	*conn_లోపల_readyp = *conn_బహిర్గతం_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	ఒకవేళ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	ఒకవేళ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	ఒకవేళ (options.వాడని_connection_timeout != 0) {
		ఒకవేళ (channel_still_open(ssh))
			వాడని_connection_expiry = 0;
		లేకపోతే ఒకవేళ (వాడని_connection_expiry == 0) {
			వాడని_connection_expiry = now +
			    options.వాడని_connection_timeout;
		}
	}
	ఒకవేళ (వాడని_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, వాడని_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	ఒకవేళ (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		ఒకవేళ (చివరి_client_సమయం == 0)
			చివరి_client_సమయం = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#ఒకవేళ 0
	/* wrong: bad condition XXX */
	ఒకవేళ (channel_not_very_much_buffered_దత్తాంశం())
#అయితే_ముగింపు
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_లోపల;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_బహిర్గతం;
	(*pfdp)[1].events = ssh_packet_have_దత్తాంశం_గమ్యం_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	ఒకవేళ (బిడ్డ_terminated && ssh_packet_not_very_much_దత్తాంశం_గమ్యం_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	ఒకవేళ (ret == -1) {
		కొరకు (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ఒకవేళ (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		తిరిగి;
	}

	*conn_లోపల_readyp = (*pfdp)[0].revents != 0;
	*conn_బహిర్గతం_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	ఒకవేళ (client_alive_scheduled) {
		ఒకవేళ (ret == 0 &&
		    now >= చివరి_client_సమయం + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			చివరి_client_సమయం = now;
		} లేకపోతే ఒకవేళ (ret != 0 && *conn_లోపల_readyp) {
			/* Data from peer; reset probe timer. */
			చివరి_client_సమయం = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	ఒకవేళ (వాడని_connection_expiry != 0 &&
	    now > వాడని_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, పరిమాణం(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
స్థిర పూర్ణాంకం
process_ఆదానం(నిర్మాణం ssh *ssh, పూర్ణాంకం connection_లోపల)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = ssh_packet_process_read(ssh, connection_లోపల)) == 0)
		తిరిగి 0; /* success */
	ఒకవేళ (r == SSH_ERR_SYSTEM_ERROR) {
		ఒకవేళ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			తిరిగి 0;
		ఒకవేళ (errno == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
			తిరిగి -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	తిరిగి -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
స్థిర శూన్య
process_output(నిర్మాణం ssh *ssh, పూర్ణాంకం connection_బహిర్గతం)
{
	పూర్ణాంకం r;
	స్థిర పూర్ణాంకం interactive = -1;

	/* Send any buffered packet data to the client. */
	ఒకవేళ (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_సమితి_interactive(ssh, interactive);
	}
	ఒకవేళ ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

స్థిర శూన్య
process_buffered_ఆదానం_packets(నిర్మాణం ssh *ssh)
{
	ssh_dispatch_నిరంతరం_fatal(ssh, DISPATCH_NONBLOCK, ఖాళీ);
}

స్థిర శూన్య
collect_children(నిర్మాణం ssh *ssh)
{
	pid_t pid;
	పూర్ణాంకం స్థితి_2;

	ఒకవేళ (బిడ్డ_terminated) {
		debug("Received SIGCHLD.");
		అయితే ((pid = waitpid(-1, &స్థితి_2, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			ఒకవేళ (pid > 0)
				session_close_by_pid(ssh, pid, స్థితి_2);
		బిడ్డ_terminated = 0;
	}
}

శూన్య
server_loop2(నిర్మాణం ssh *ssh, Authctxt *authctxt)
{
	నిర్మాణం pollfd *pfd = ఖాళీ;
	u_int npfd_alloc = 0, npfd_చురుకైన = 0;
	పూర్ణాంకం r, conn_లోపల_ready, conn_బహిర్గతం_ready;
	u_int connection_లోపల, connection_బహిర్గతం;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	ఒకవేళ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
#నిర్వచితమైతే SIGINFO
	ఒకవేళ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGINFO, siginfo_handler);
#అయితే_ముగింపు
	బిడ్డ_terminated = 0;
	connection_లోపల = ssh_packet_get_connection_లోపల(ssh);
	connection_బహిర్గతం = ssh_packet_get_connection_బహిర్గతం(ssh);

	server_init_dispatch(ssh);

	కొరకు (;;) {
		process_buffered_ఆదానం_packets(ssh);

		ఒకవేళ (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_దత్తాంశం_గమ్యం_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		ఒకవేళ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		ఒకవేళ (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_లోపల, connection_బహిర్గతం,
		    &pfd, &npfd_alloc, &npfd_చురుకైన, &osigset,
		    &conn_లోపల_ready, &conn_బహిర్గతం_ready);
		ఒకవేళ (sigprocmask(SIG_SETMASK, &osigset, ఖాళీ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		channel_after_poll(ssh, pfd, npfd_చురుకైన);
		ఒకవేళ (conn_లోపల_ready &&
		    process_ఆదానం(ssh, connection_లోపల) < 0)
			ఆపు;
		/* A timeout may have triggered rekeying */
		ఒకవేళ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		ఒకవేళ (conn_బహిర్గతం_ready)
			process_output(ssh, connection_బహిర్గతం);
	}
	collect_children(ssh);
	విడుదల(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, ఖాళీ);
}

స్థిర పూర్ణాంకం
server_ఆదానం_keep_alive(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_సమితి_alive_timeouts(ssh, 0);
	తిరిగి 0;
}

స్థిర Channel *
server_request_ప్రత్యక్ష_tcpip(నిర్మాణం ssh *ssh, పూర్ణాంకం *reason, స్థిరరాశి అక్షరం **errmsg)
{
	Channel *c = ఖాళీ;
	అక్షరం *లక్ష్యం = ఖాళీ, *originator = ఖాళీ;
	u_int లక్ష్యం_పోర్టు = 0, originator_పోర్టు = 0;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &లక్ష్యం, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &లక్ష్యం_పోర్టు)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_పోర్టు)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ఒకవేళ (లక్ష్యం_పోర్టు > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (originator_పోర్టు > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		వెళ్ళు బహిర్గతం;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_పోర్టు, లక్ష్యం, లక్ష్యం_పోర్టు);

	/* XXX fine grained permissions */
	ఒకవేళ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_పోర్టు_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_గమ్యం_పోర్టు(ssh, లక్ష్యం, లక్ష్యం_పోర్టు,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} లేకపోతే {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_పోర్టు, లక్ష్యం, లక్ష్యం_పోర్టు);
		ఒకవేళ (reason != ఖాళీ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 బహిర్గతం:
	విడుదల(originator);
	విడుదల(లక్ష్యం);
	తిరిగి c;
}

స్థిర Channel *
server_request_ప్రత్యక్ష_streamlocal(నిర్మాణం ssh *ssh)
{
	Channel *c = ఖాళీ;
	అక్షరం *లక్ష్యం = ఖాళీ, *originator = ఖాళీ;
	u_int originator_పోర్టు = 0;
	నిర్మాణం passwd *pw = the_authctxt->pw;
	పూర్ణాంకం r;

	ఒకవేళ (pw == ఖాళీ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &లక్ష్యం, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_పోర్టు)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ఒకవేళ (originator_పోర్టు > 0xFFFF) {
		error_f("invalid originator port");
		వెళ్ళు బహిర్గతం;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_పోర్టు, లక్ష్యం);

	/* XXX fine grained permissions */
	ఒకవేళ ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_పోర్టు_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_గమ్యం_మార్గం(ssh, లక్ష్యం,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} లేకపోతే {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_పోర్టు, లక్ష్యం);
	}

బహిర్గతం:
	విడుదల(originator);
	విడుదల(లక్ష్యం);
	తిరిగి c;
}

స్థిర Channel *
server_request_tun(నిర్మాణం ssh *ssh)
{
	Channel *c = ఖాళీ;
	u_int బహుళకం, tun;
	పూర్ణాంకం r, sock;
	అక్షరం *tmp, *ifname = ఖాళీ;

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &బహుళకం)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	ఎంపిక (బహుళకం) {
	స్థితి SSH_TUNMODE_POINTOPOINT:
	స్థితి SSH_TUNMODE_ETHERNET:
		ఆపు;
	అప్రమేయ:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((options.permit_tun & బహుళకం) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		తిరిగి ఖాళీ;
	}

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	ఒకవేళ (tun > గరిష్ఠ_పూర్ణాంకం) {
		debug_f("invalid tun");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (auth_opts->force_tun_device != -1) {
		ఒకవేళ (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (పూర్ణాంకం)tun)
			వెళ్ళు పూర్తి;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, బహుళకం, &ifname);
	ఒకవేళ (sock < 0)
		వెళ్ళు పూర్తి;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#ఒకవేళ defined(SSH_TUN_FILTER)
	ఒకవేళ (బహుళకం == SSH_TUNMODE_POINTOPOINT)
		channel_రిజిస్టరు_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ఖాళీ, ఖాళీ);
#అయితే_ముగింపు

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == ఖాళీ ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == ఖాళీ ? "" : ",",
	    ifname);
	విడుదల(tmp);
	విడుదల(ifname);

 పూర్తి:
	ఒకవేళ (c == ఖాళీ)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	తిరిగి c;
}

స్థిర Channel *
server_request_session(నిర్మాణం ssh *ssh)
{
	Channel *c;
	పూర్ణాంకం r;

	debug("input_session_request");
	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ఒకవేళ (no_మరిన్ని_sessions) {
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
	ఒకవేళ (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		తిరిగి ఖాళీ;
	}
	channel_రిజిస్టరు_cleanup(ssh, c->self, session_close_by_channel, 0);
	తిరిగి c;
}

స్థిర పూర్ణాంకం
server_ఆదానం_channel_open(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Channel *c = ఖాళీ;
	అక్షరం *ctype = ఖాళీ;
	స్థిరరాశి అక్షరం *errmsg = ఖాళీ;
	పూర్ణాంకం r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &ctype, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	ఒకవేళ (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} లేకపోతే ఒకవేళ (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_ప్రత్యక్ష_tcpip(ssh, &reason, &errmsg);
	} లేకపోతే ఒకవేళ (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_ప్రత్యక్ష_streamlocal(ssh);
	} లేకపోతే ఒకవేళ (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	ఒకవేళ (c != ఖాళీ) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_కిటికీ = rwindow;
		c->remote_maxpacket = rmaxpack;
		ఒకవేళ (c->type != SSH_CHANNEL_CONNECTING) {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_కిటికీ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} లేకపోతే {
		debug_f("failure %s", ctype);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	విడుదల(ctype);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
server_ఆదానం_hostkeys_prove(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf **respp)
{
	నిర్మాణం sshbuf *resp = ఖాళీ;
	నిర్మాణం sshbuf *sigbuf = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ, *కీలకం_pub = ఖాళీ, *కీలకం_prv = ఖాళీ;
	పూర్ణాంకం r, ndx, success = 0;
	స్థిరరాశి u_char *blob;
	స్థిరరాశి అక్షరం *sigalg, *kex_rsa_sigalg = ఖాళీ;
	u_char *sig = ఖాళీ;
	కొలత_t blen, slen;

	ఒకవేళ ((resp = sshbuf_new()) == ఖాళీ || (sigbuf = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == కీలకం_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	అయితే (ssh_packet_మిగిలిన(ssh) > 0) {
		sshkey_free(కీలకం);
		కీలకం = ఖాళీ;
		ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &కీలకం)) != 0) {
			error_fr(r, "parse key");
			వెళ్ళు బహిర్గతం;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		ఒకవేళ ((ndx = ssh->kex->host_కీలకం_సూచీ(కీలకం, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(కీలకం));
			వెళ్ళు బహిర్గతం;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		ఒకవేళ ((కీలకం_prv = get_hostkey_by_సూచీ(ndx)) == ఖాళీ &&
		    (కీలకం_pub = get_hostkey_ప్రజా_by_సూచీ(ndx, ssh)) == ఖాళీ) {
			error_f("can't retrieve hostkey %d", ndx);
			వెళ్ళు బహిర్గతం;
		}
		sshbuf_reset(sigbuf);
		విడుదల(sig);
		sig = ఖాళీ;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(కీలకం);
		ఒకవేళ (sshkey_type_plain(కీలకం->type) == కీలకం_RSA) {
			ఒకవేళ (kex_rsa_sigalg != ఖాళీ)
				sigalg = kex_rsa_sigalg;
			లేకపోతే ఒకవేళ (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			లేకపోతే ఒకవేళ (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(కీలకం), ndx, sigalg == ఖాళీ ? "default" : sigalg);
		ఒకవేళ ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(కీలకం, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, కీలకం_prv, కీలకం_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			వెళ్ళు బహిర్గతం;
		}
	}
	/* Success */
	*respp = resp;
	resp = ఖాళీ; /* don't free it */
	success = 1;
 బహిర్గతం:
	విడుదల(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(కీలకం);
	తిరిగి success;
}

స్థిర పూర్ణాంకం
server_ఆదానం_global_request(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	అక్షరం *rtype = ఖాళీ;
	u_char want_జవాబు = 0;
	పూర్ణాంకం r, success = 0, allocated_listen_పోర్టు = 0;
	u_int పోర్టు = 0;
	నిర్మాణం sshbuf *resp = ఖాళీ;
	నిర్మాణం passwd *pw = the_authctxt->pw;
	నిర్మాణం Forward fwd;

	memset(&fwd, 0, పరిమాణం(fwd));
	ఒకవేళ (pw == ఖాళీ || !the_authctxt->valid)
		fatal_f("no/invalid user");

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &rtype, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_జవాబు)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_జవాబు);

	/* -R style forwarding */
	ఒకవేళ (strcmp(rtype, "tcpip-forward") == 0) {
		ఒకవేళ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ఖాళీ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &పోర్టు)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, పోర్టు);
		ఒకవేళ (పోర్టు <= గరిష్ఠ_పూర్ణాంకం)
			fwd.listen_పోర్టు = (పూర్ణాంకం)పోర్టు;
		/* check permissions */
		ఒకవేళ (పోర్టు > గరిష్ఠ_పూర్ణాంకం ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_పోర్టు_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_జవాబు && fwd.listen_పోర్టు == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} లేకపోతే {
			/* Start listening on the port */
			success = channel_అమరిక_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_పోర్టు, &options.fwd_opts);
		}
		ఒకవేళ ((resp = sshbuf_new()) == ఖాళీ)
			fatal_f("sshbuf_new");
		ఒకవేళ (allocated_listen_పోర్టు != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_పోర్టు)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} లేకపోతే ఒకవేళ (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		ఒకవేళ ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, ఖాళీ)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &పోర్టు)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, పోర్టు);
		ఒకవేళ (పోర్టు <= గరిష్ఠ_పూర్ణాంకం) {
			fwd.listen_పోర్టు = (పూర్ణాంకం)పోర్టు;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} లేకపోతే ఒకవేళ (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		ఒకవేళ ((r = sshpkt_get_cstring(ssh, &fwd.listen_మార్గం, ఖాళీ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_మార్గం);

		/* check permissions */
		ఒకవేళ ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_పోర్టు_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} లేకపోతే {
			/* Start listening on the socket */
			success = channel_అమరిక_remote_fwd_listener(ssh,
			    &fwd, ఖాళీ, &options.fwd_opts);
		}
	} లేకపోతే ఒకవేళ (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		ఒకవేళ ((r = sshpkt_get_cstring(ssh, &fwd.listen_మార్గం, ఖాళీ)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_మార్గం);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} లేకపోతే ఒకవేళ (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_మరిన్ని_sessions = 1;
		success = 1;
	} లేకపోతే ఒకవేళ (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_ఆదానం_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	ఒకవేళ (want_జవాబు) {
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, success ?
		    SSH2_సందేశం_REQUEST_SUCCESS : SSH2_సందేశం_REQUEST_FAILURE)) != 0 ||
		    (success && resp != ఖాళీ && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	విడుదల(fwd.listen_host);
	విడుదల(fwd.listen_మార్గం);
	విడుదల(rtype);
	sshbuf_free(resp);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
server_ఆదానం_channel_req(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Channel *c;
	పూర్ణాంకం r, success = 0;
	అక్షరం *rtype = ఖాళీ;
	u_char want_జవాబు = 0;
	u_int id = 0;

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_జవాబు)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_జవాబు);

	ఒకవేళ (id >= గరిష్ఠ_పూర్ణాంకం || (c = channel_lookup(ssh, (పూర్ణాంకం)id)) == ఖాళీ) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	ఒకవేళ (!strcmp(rtype, "eow@openssh.com")) {
		ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} లేకపోతే ఒకవేళ ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_ఆదానం_channel_req(ssh, c, rtype);
	ఒకవేళ (want_జవాబు && !(c->flags & CHAN_CLOSE_పంపిన)) {
		ఒకవేళ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, success ?
		    SSH2_సందేశం_CHANNEL_SUCCESS : SSH2_సందేశం_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	విడుదల(rtype);
	తిరిగి 0;
}

స్థిర శూన్య
server_init_dispatch(నిర్మాణం ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_CLOSE, &channel_ఆదానం_oclose);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_దత్తాంశం, &channel_ఆదానం_దత్తాంశం);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_EOF, &channel_ఆదానం_ieof);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_EXTENDED_దత్తాంశం, &channel_ఆదానం_extended_దత్తాంశం);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_OPEN, &server_ఆదానం_channel_open);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION, &channel_ఆదానం_open_confirmation);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_OPEN_FAILURE, &channel_ఆదానం_open_failure);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_REQUEST, &server_ఆదానం_channel_req);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST, &channel_ఆదానం_కిటికీ_adjust);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_GLOBAL_REQUEST, &server_ఆదానం_global_request);
	/* client_alive */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_SUCCESS, &server_ఆదానం_keep_alive);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_FAILURE, &server_ఆదానం_keep_alive);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_REQUEST_SUCCESS, &server_ఆదానం_keep_alive);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_REQUEST_FAILURE, &server_ఆదానం_keep_alive);
	/* rekeying */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEXINIT, &kex_ఆదానం_kexinit);
}
