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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/wait.h>
#समावेश <sys/socket.h>
#समावेश <sys/time.h>
#समावेश <sys/queue.h>

#समावेश <netinet/in.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <pwd.h>
#समावेश <limits.h>
#समावेश <poll.h>
#समावेश <signal.h>
#समावेश <string.h>
#समावेश <termios.h>
#समावेश <unistd.h>
#समावेश <stdarg.h>

#समावेश "xmalloc.h"
#समावेश "packet.h"
#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "canohost.h"
#समावेश "sshpty.h"
#समावेश "channels.h"
#समावेश "ssh2.h"
#समावेश "sshkey.h"
#समावेश "cipher.h"
#समावेश "kex.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "session.h"
#समावेश "dispatch.h"
#समावेश "auth-options.h"
#समावेश "serverloop.h"
#समावेश "ssherr.h"

बाह्य ServerOptions options;

/* XXX */
बाह्य Authctxt *the_authctxt;
बाह्य काष्ठा sshauthopt *auth_opts;

अटल पूर्णांक no_more_sessions = 0; /* Disallow further sessions. */

अटल अस्थिर संक_पूर्ण_प्रकार child_terminated = 0; /* set on SIGCHLD */
अटल अस्थिर संक_पूर्ण_प्रकार siginfo_received = 0;

/* prototypes */
अटल व्योम server_init_dispatch(काष्ठा ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
अक्षर *tun_fwd_ifnames = शून्य;

अटल व्योम
sigchld_handler(पूर्णांक sig)
{
	child_terminated = 1;
}

#अगर_घोषित SIGINFO
अटल व्योम
siginfo_handler(पूर्णांक sig)
{
	siginfo_received = 1;
}
#पूर्ण_अगर

अटल व्योम
client_alive_check(काष्ठा ssh *ssh)
{
	अक्षर remote_id[512];
	पूर्णांक r, channel_id;

	/* timeout, check to see how many we have had */
	अगर (options.client_alive_गिनती_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_गिनती_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, माप(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	अगर ((channel_id = channel_find_open(ssh)) == -1) {
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} अन्यथा {
		channel_request_start(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	अगर ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
अटल व्योम
wait_until_can_do_something(काष्ठा ssh *ssh,
    पूर्णांक connection_in, पूर्णांक connection_out, काष्ठा pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    पूर्णांक *conn_in_readyp, पूर्णांक *conn_out_readyp)
{
	काष्ठा timespec timeout;
	अक्षर remote_id[512];
	पूर्णांक ret;
	पूर्णांक client_alive_scheduled = 0;
	u_int p;
	समय_प्रकार now;
	अटल समय_प्रकार last_client_time, unused_connection_expiry;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();
	अगर (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	अगर (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	अगर (options.unused_connection_timeout != 0) {
		अगर (channel_still_open(ssh))
			unused_connection_expiry = 0;
		अन्यथा अगर (unused_connection_expiry == 0) {
			unused_connection_expiry = now +
			    options.unused_connection_timeout;
		}
	}
	अगर (unused_connection_expiry != 0)
		ptimeout_deadline_monotime(&timeout, unused_connection_expiry);

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	अगर (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		अगर (last_client_time == 0)
			last_client_time = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#अगर 0
	/* wrong: bad condition XXX */
	अगर (channel_not_very_much_buffered_तथ्य())
#पूर्ण_अगर
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_in;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_out;
	(*pfdp)[1].events = ssh_packet_have_तथ्य_to_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	अगर (child_terminated && ssh_packet_not_very_much_तथ्य_to_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	अगर (ret == -1) {
		क्रम (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		अगर (त्रुटि_सं != EINTR)
			fatal_f("ppoll: %.100s", म_त्रुटि(त्रुटि_सं));
		वापस;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	अगर (client_alive_scheduled) {
		अगर (ret == 0 &&
		    now >= last_client_time + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			last_client_time = now;
		} अन्यथा अगर (ret != 0 && *conn_in_readyp) {
			/* Data from peer; reset probe timer. */
			last_client_time = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	अगर (unused_connection_expiry != 0 &&
	    now > unused_connection_expiry && !channel_still_open(ssh)) {
		sshpkt_fmt_connection_id(ssh, remote_id, माप(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
अटल पूर्णांक
process_निवेश(काष्ठा ssh *ssh, पूर्णांक connection_in)
{
	पूर्णांक r;

	अगर ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		वापस 0; /* success */
	अगर (r == SSH_ERR_SYSTEM_ERROR) {
		अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR || त्रुटि_सं == EWOULDBLOCK)
			वापस 0;
		अगर (त्रुटि_सं == EPIPE) {
			logit("Connection closed by %.100s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
			वापस -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    म_त्रुटि(त्रुटि_सं));
		cleanup_exit(255);
	}
	वापस -1;
}

/*
 * Sends data from internal buffers to client program stdin.
 */
अटल व्योम
process_output(काष्ठा ssh *ssh, पूर्णांक connection_out)
{
	पूर्णांक r;
	अटल पूर्णांक interactive = -1;

	/* Send any buffered packet data to the client. */
	अगर (interactive != !channel_has_bulk(ssh)) {
		interactive = !channel_has_bulk(ssh);
		debug2_f("session QoS is now %s", interactive ?
		    "interactive" : "non-interactive");
		ssh_packet_set_interactive(ssh, interactive);
	}
	अगर ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

अटल व्योम
process_buffered_निवेश_packets(काष्ठा ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, शून्य);
}

अटल व्योम
collect_children(काष्ठा ssh *ssh)
{
	pid_t pid;
	पूर्णांक status;

	अगर (child_terminated) {
		debug("Received SIGCHLD.");
		जबतक ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
		    (pid == -1 && त्रुटि_सं == EINTR))
			अगर (pid > 0)
				session_close_by_pid(ssh, pid, status);
		child_terminated = 0;
	}
}

व्योम
server_loop2(काष्ठा ssh *ssh, Authctxt *authctxt)
{
	काष्ठा pollfd *pfd = शून्य;
	u_int npfd_alloc = 0, npfd_active = 0;
	पूर्णांक r, conn_in_ready, conn_out_ready;
	u_int connection_in, connection_out;
	sigset_t bsigset, osigset;

	debug("Entering interactive session for SSH2.");

	अगर (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", म_त्रुटि(त्रुटि_सं));
	ssh_signal(SIGCHLD, sigchld_handler);
#अगर_घोषित SIGINFO
	अगर (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", म_त्रुटि(त्रुटि_सं));
	ssh_signal(SIGINFO, siginfo_handler);
#पूर्ण_अगर
	child_terminated = 0;
	connection_in = ssh_packet_get_connection_in(ssh);
	connection_out = ssh_packet_get_connection_out(ssh);

	server_init_dispatch(ssh);

	क्रम (;;) {
		process_buffered_निवेश_packets(ssh);

		अगर (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_तथ्य_to_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		अगर (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", म_त्रुटि(त्रुटि_सं));
		collect_children(ssh);
		अगर (siginfo_received) {
			siginfo_received = 0;
			channel_report_open(ssh, SYSLOG_LEVEL_INFO);
		}
		wait_until_can_do_something(ssh, connection_in, connection_out,
		    &pfd, &npfd_alloc, &npfd_active, &osigset,
		    &conn_in_ready, &conn_out_ready);
		अगर (sigprocmask(SIG_SETMASK, &osigset, शून्य) == -1)
			error_f("osigset sigprocmask: %s", म_त्रुटि(त्रुटि_सं));

		channel_after_poll(ssh, pfd, npfd_active);
		अगर (conn_in_ready &&
		    process_निवेश(ssh, connection_in) < 0)
			अवरोध;
		/* A timeout may have triggered rekeying */
		अगर ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");
		अगर (conn_out_ready)
			process_output(ssh, connection_out);
	}
	collect_children(ssh);
	मुक्त(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, शून्य);
}

अटल पूर्णांक
server_निवेश_keep_alive(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_set_alive_timeouts(ssh, 0);
	वापस 0;
}

अटल Channel *
server_request_direct_tcpip(काष्ठा ssh *ssh, पूर्णांक *reason, स्थिर अक्षर **errmsg)
{
	Channel *c = शून्य;
	अक्षर *target = शून्य, *originator = शून्य;
	u_int target_port = 0, originator_port = 0;
	पूर्णांक r;

	अगर ((r = sshpkt_get_cstring(ssh, &target, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &target_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	अगर (target_port > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		जाओ out;
	}
	अगर (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		जाओ out;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, originator_port, target, target_port);

	/* XXX fine grained permissions */
	अगर ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_port(ssh, target, target_port,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} अन्यथा {
		logit("refused local port forward: "
		    "originator %s port %d, target %s port %d",
		    originator, originator_port, target, target_port);
		अगर (reason != शून्य)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 out:
	मुक्त(originator);
	मुक्त(target);
	वापस c;
}

अटल Channel *
server_request_direct_streamlocal(काष्ठा ssh *ssh)
{
	Channel *c = शून्य;
	अक्षर *target = शून्य, *originator = शून्य;
	u_int originator_port = 0;
	काष्ठा passwd *pw = the_authctxt->pw;
	पूर्णांक r;

	अगर (pw == शून्य || !the_authctxt->valid)
		fatal_f("no/invalid user");

	अगर ((r = sshpkt_get_cstring(ssh, &target, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	अगर (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		जाओ out;
	}

	debug_f("originator %s port %d, target %s",
	    originator, originator_port, target);

	/* XXX fine grained permissions */
	अगर ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_path(ssh, target,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} अन्यथा {
		logit("refused streamlocal port forward: "
		    "originator %s port %d, target %s",
		    originator, originator_port, target);
	}

out:
	मुक्त(originator);
	मुक्त(target);
	वापस c;
}

अटल Channel *
server_request_tun(काष्ठा ssh *ssh)
{
	Channel *c = शून्य;
	u_int mode, tun;
	पूर्णांक r, sock;
	अक्षर *tmp, *ifname = शून्य;

	अगर ((r = sshpkt_get_u32(ssh, &mode)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	चयन (mode) {
	हाल SSH_TUNMODE_POINTOPOINT:
	हाल SSH_TUNMODE_ETHERNET:
		अवरोध;
	शेष:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		वापस शून्य;
	}
	अगर ((options.permit_tun & mode) == 0 || options.disable_forwarding ||
	    auth_opts->restricted) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		वापस शून्य;
	}

	अगर ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	अगर (tun > पूर्णांक_उच्च) {
		debug_f("invalid tun");
		जाओ done;
	}
	अगर (auth_opts->force_tun_device != -1) {
		अगर (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (पूर्णांक)tun)
			जाओ done;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, mode, &ifname);
	अगर (sock < 0)
		जाओ done;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#अगर defined(SSH_TUN_FILTER)
	अगर (mode == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, शून्य, शून्य);
#पूर्ण_अगर

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == शून्य ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == शून्य ? "" : ",",
	    ifname);
	मुक्त(tmp);
	मुक्त(ifname);

 done:
	अगर (c == शून्य)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	वापस c;
}

अटल Channel *
server_request_session(काष्ठा ssh *ssh)
{
	Channel *c;
	पूर्णांक r;

	debug("input_session_request");
	अगर ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	अगर (no_more_sessions) {
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
	अगर (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		वापस शून्य;
	}
	channel_register_cleanup(ssh, c->self, session_close_by_channel, 0);
	वापस c;
}

अटल पूर्णांक
server_निवेश_channel_open(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Channel *c = शून्य;
	अक्षर *ctype = शून्य;
	स्थिर अक्षर *errmsg = शून्य;
	पूर्णांक r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int rchan = 0, rmaxpack = 0, rwindow = 0;

	अगर ((r = sshpkt_get_cstring(ssh, &ctype, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	अगर (म_भेद(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} अन्यथा अगर (म_भेद(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip(ssh, &reason, &errmsg);
	} अन्यथा अगर (म_भेद(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_direct_streamlocal(ssh);
	} अन्यथा अगर (म_भेद(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	अगर (c != शून्य) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		अगर (c->type != SSH_CHANNEL_CONNECTING) {
			अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} अन्यथा {
		debug_f("failure %s", ctype);
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	मुक्त(ctype);
	वापस 0;
}

अटल पूर्णांक
server_निवेश_hostkeys_prove(काष्ठा ssh *ssh, काष्ठा sshbuf **respp)
{
	काष्ठा sshbuf *resp = शून्य;
	काष्ठा sshbuf *sigbuf = शून्य;
	काष्ठा sshkey *कुंजी = शून्य, *कुंजी_pub = शून्य, *कुंजी_prv = शून्य;
	पूर्णांक r, ndx, success = 0;
	स्थिर u_char *blob;
	स्थिर अक्षर *sigalg, *kex_rsa_sigalg = शून्य;
	u_char *sig = शून्य;
	माप_प्रकार blen, slen;

	अगर ((resp = sshbuf_new()) == शून्य || (sigbuf = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == कुंजी_RSA)
		kex_rsa_sigalg = ssh->kex->hostkey_alg;
	जबतक (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(कुंजी);
		कुंजी = शून्य;
		अगर ((r = sshpkt_get_string_direct(ssh, &blob, &blen)) != 0 ||
		    (r = sshkey_from_blob(blob, blen, &कुंजी)) != 0) {
			error_fr(r, "parse key");
			जाओ out;
		}
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		अगर ((ndx = ssh->kex->host_कुंजी_सूचकांक(कुंजी, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(कुंजी));
			जाओ out;
		}
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		अगर ((कुंजी_prv = get_hostkey_by_सूचकांक(ndx)) == शून्य &&
		    (कुंजी_pub = get_hostkey_public_by_सूचकांक(ndx, ssh)) == शून्य) {
			error_f("can't retrieve hostkey %d", ndx);
			जाओ out;
		}
		sshbuf_reset(sigbuf);
		मुक्त(sig);
		sig = शून्य;
		/*
		 * For RSA keys, prefer to use the signature type negotiated
		 * during KEX to the default (SHA1).
		 */
		sigalg = sshkey_ssh_name(कुंजी);
		अगर (sshkey_type_plain(कुंजी->type) == कुंजी_RSA) {
			अगर (kex_rsa_sigalg != शून्य)
				sigalg = kex_rsa_sigalg;
			अन्यथा अगर (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				sigalg = "rsa-sha2-512";
			अन्यथा अगर (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				sigalg = "rsa-sha2-256";
		}

		debug3_f("sign %s key (index %d) using sigalg %s",
		    sshkey_type(कुंजी), ndx, sigalg == शून्य ? "default" : sigalg);
		अगर ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(कुंजी, sigbuf)) != 0 ||
		    (r = ssh->kex->sign(ssh, कुंजी_prv, कुंजी_pub, &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), sigalg)) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			जाओ out;
		}
	}
	/* Success */
	*respp = resp;
	resp = शून्य; /* don't free it */
	success = 1;
 out:
	मुक्त(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(कुंजी);
	वापस success;
}

अटल पूर्णांक
server_निवेश_global_request(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	अक्षर *rtype = शून्य;
	u_char want_reply = 0;
	पूर्णांक r, success = 0, allocated_listen_port = 0;
	u_int port = 0;
	काष्ठा sshbuf *resp = शून्य;
	काष्ठा passwd *pw = the_authctxt->pw;
	काष्ठा Forward fwd;

	स_रखो(&fwd, 0, माप(fwd));
	अगर (pw == शून्य || !the_authctxt->valid)
		fatal_f("no/invalid user");

	अगर ((r = sshpkt_get_cstring(ssh, &rtype, शून्य)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, want_reply);

	/* -R style forwarding */
	अगर (म_भेद(rtype, "tcpip-forward") == 0) {
		अगर ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, शून्य)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, port);
		अगर (port <= पूर्णांक_उच्च)
			fwd.listen_port = (पूर्णांक)port;
		/* check permissions */
		अगर (port > पूर्णांक_उच्च ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_reply && fwd.listen_port == 0)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} अन्यथा {
			/* Start listening on the port */
			success = channel_setup_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_port, &options.fwd_opts);
		}
		अगर ((resp = sshbuf_new()) == शून्य)
			fatal_f("sshbuf_new");
		अगर (allocated_listen_port != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_port)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} अन्यथा अगर (म_भेद(rtype, "cancel-tcpip-forward") == 0) {
		अगर ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, शून्य)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %d",
		    fwd.listen_host, port);
		अगर (port <= पूर्णांक_उच्च) {
			fwd.listen_port = (पूर्णांक)port;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} अन्यथा अगर (म_भेद(rtype, "streamlocal-forward@openssh.com") == 0) {
		अगर ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, शून्य)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_path);

		/* check permissions */
		अगर ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} अन्यथा {
			/* Start listening on the socket */
			success = channel_setup_remote_fwd_listener(ssh,
			    &fwd, शून्य, &options.fwd_opts);
		}
	} अन्यथा अगर (म_भेद(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		अगर ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, शून्य)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_path);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} अन्यथा अगर (म_भेद(rtype, "no-more-sessions@openssh.com") == 0) {
		no_more_sessions = 1;
		success = 1;
	} अन्यथा अगर (म_भेद(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_निवेश_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	अगर (want_reply) {
		अगर ((r = sshpkt_start(ssh, success ?
		    SSH2_संदेश_REQUEST_SUCCESS : SSH2_संदेश_REQUEST_FAILURE)) != 0 ||
		    (success && resp != शून्य && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	मुक्त(fwd.listen_host);
	मुक्त(fwd.listen_path);
	मुक्त(rtype);
	sshbuf_free(resp);
	वापस 0;
}

अटल पूर्णांक
server_निवेश_channel_req(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Channel *c;
	पूर्णांक r, success = 0;
	अक्षर *rtype = शून्य;
	u_char want_reply = 0;
	u_int id = 0;

	अगर ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, शून्य)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    id, rtype, want_reply);

	अगर (id >= पूर्णांक_उच्च || (c = channel_lookup(ssh, (पूर्णांक)id)) == शून्य) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %d",
		    __func__, id);
	}
	अगर (!म_भेद(rtype, "eow@openssh.com")) {
		अगर ((r = sshpkt_get_end(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} अन्यथा अगर ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && म_भेद(c->ctype, "session") == 0)
		success = session_निवेश_channel_req(ssh, c, rtype);
	अगर (want_reply && !(c->flags & CHAN_CLOSE_SENT)) {
		अगर (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		अगर ((r = sshpkt_start(ssh, success ?
		    SSH2_संदेश_CHANNEL_SUCCESS : SSH2_संदेश_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	मुक्त(rtype);
	वापस 0;
}

अटल व्योम
server_init_dispatch(काष्ठा ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_CLOSE, &channel_निवेश_oclose);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_तथ्य, &channel_निवेश_तथ्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_EOF, &channel_निवेश_ieof);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_EXTENDED_तथ्य, &channel_निवेश_extended_तथ्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_OPEN, &server_निवेश_channel_open);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION, &channel_निवेश_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_OPEN_FAILURE, &channel_निवेश_open_failure);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_REQUEST, &server_निवेश_channel_req);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_WINDOW_ADJUST, &channel_निवेश_window_adjust);
	ssh_dispatch_set(ssh, SSH2_संदेश_GLOBAL_REQUEST, &server_निवेश_global_request);
	/* client_alive */
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_SUCCESS, &server_निवेश_keep_alive);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_FAILURE, &server_निवेश_keep_alive);
	ssh_dispatch_set(ssh, SSH2_संदेश_REQUEST_SUCCESS, &server_निवेश_keep_alive);
	ssh_dispatch_set(ssh, SSH2_संदेश_REQUEST_FAILURE, &server_निवेश_keep_alive);
	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_निवेश_kexinit);
}
