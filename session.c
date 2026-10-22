/* $OpenBSD: session.c,v 1.351 2026/09/16 00:25:50 djm Exp $ */
/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
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
#అన్తర్భావ <sys/un.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <grp.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "sshpty.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "sshlogin.h"
#అన్తర్భావ "serverloop.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "session.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "sftp.h"
#అన్తర్భావ "atomicio.h"

#ఒకవేళ defined(KRB5) && defined(USE_AFS)
#అన్తర్భావ <kafs.h>
#అయితే_ముగింపు

#నిర్వచితమైతే WITH_SELINUX
#అన్తర్భావ <selinux/selinux.h>
#అయితే_ముగింపు

/*
 * Hack for systems that do not support FD passing: allocate PTYs directly
 * without calling into the monitor. This requires either the post-auth
 * privsep process retain root privileges (see the comment in
 * sshd-session.c:privsep_postauth) or that PTY allocation doesn't require
 * privileges to begin with (e.g. Cygwin).
 */
#నిర్వచితమైతే DISABLE_FD_PASSING
#నిర్వచించు mm_pty_allocate pty_allocate
#అయితే_ముగింపు

#నిర్వచించు IS_అంతర్గత_SFTP(c) \
	(!అక్షరశ్రేణి_పోలిక(c, అంతర్గత_SFTP_NAME, పరిమాణం(అంతర్గత_SFTP_NAME) - 1) && \
	 (c[పరిమాణం(అంతర్గత_SFTP_NAME) - 1] == '\0' || \
	  c[పరిమాణం(అంతర్గత_SFTP_NAME) - 1] == ' ' || \
	  c[పరిమాణం(అంతర్గత_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(శూన్య);
శూన్య	session_సమితి_fds(నిర్మాణం ssh *, Session *, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);
శూన్య	session_pty_cleanup(Session *);
శూన్య	session_proctitle(Session *);
పూర్ణాంకం	session_అమరిక_x11fwd(నిర్మాణం ssh *, Session *);
పూర్ణాంకం	do_exec_pty(నిర్మాణం ssh *, Session *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	do_exec_no_pty(నిర్మాణం ssh *, Session *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	do_exec(నిర్మాణం ssh *, Session *, స్థిరరాశి అక్షరం *);
శూన్య	do_login(నిర్మాణం ssh *, Session *, స్థిరరాశి అక్షరం *);
శూన్య	do_బిడ్డ(నిర్మాణం ssh *, Session *, స్థిరరాశి అక్షరం *);
శూన్య	do_motd(శూన్య);
పూర్ణాంకం	check_quietlogin(Session *, స్థిరరాశి అక్షరం *);

స్థిర శూన్య do_authenticated2(నిర్మాణం ssh *, Authctxt *);

స్థిర పూర్ణాంకం session_pty_req(నిర్మాణం ssh *, Session *);

/* import */
బాహ్య ServerOptions options;
బాహ్య అక్షరం *__progname;
బాహ్య పూర్ణాంకం debug_flag;
బాహ్య నిర్మాణం sshbuf *loginmsg;
బాహ్య నిర్మాణం sshauthopt *auth_opts;
బాహ్య అక్షరం *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
స్థిరరాశి అక్షరం *original_command = ఖాళీ;

/*దత్తాంశం*/
స్థిర పూర్ణాంకం sessions_మొదటి_వాడని = -1;
స్థిర పూర్ణాంకం sessions_nalloc = 0;
స్థిర Session *sessions = ఖాళీ;

#నిర్వచించు SUBSYSTEM_NONE			0
#నిర్వచించు SUBSYSTEM_EXT			1
#నిర్వచించు SUBSYSTEM_INT_SFTP		2
#నిర్వచించు SUBSYSTEM_INT_SFTP_ERROR	3

#నిర్వచితమైతే HAVE_LOGIN_CAP
login_cap_t *lc;
#అయితే_ముగింపు

స్థిర పూర్ణాంకం is_బిడ్డ = 0;
స్థిర పూర్ణాంకం లోపల_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
స్థిర అక్షరం *auth_info_file = ఖాళీ;

/* Name and directory of socket for authentication agent forwarding. */
స్థిర అక్షరం *auth_sock_name = ఖాళీ;
స్థిర అక్షరం *auth_sock_dir = ఖాళీ; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

స్థిర శూన్య
auth_sock_cleanup_proc(నిర్మాణం passwd *pw)
{
	ఒకవేళ (auth_sock_name != ఖాళీ) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_మార్గం,
		    auth_sock_name, auth_sock_dir);
		విడుదల(auth_sock_name);
		auth_sock_name = ఖాళీ;
		restore_uid();
	}
}

స్థిర పూర్ణాంకం
auth_ఆదానం_request_forwarding(నిర్మాణం ssh *ssh, నిర్మాణం passwd *pw, పూర్ణాంకం agent_new)
{
	Channel *nc;
	పూర్ణాంకం sock = -1;

	ఒకవేళ (auth_sock_name != ఖాళీ) {
		error("authentication forwarding requested twice.");
		తిరిగి 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	ఒకవేళ (agent_listener(options.agent_socket_మార్గం, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		వెళ్ళు authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_కిటికీ_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->మార్గం = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	తిరిగి 1;

 authsock_err:
	విడుదల(auth_sock_name);
	ఒకవేళ (sock != -1)
		close(sock);
	auth_sock_name = ఖాళీ;
	తిరిగి 0;
}

స్థిర శూన్య
display_loginmsg(శూన్య)
{
	పూర్ణాంకం r;

	ఒకవేళ (sshbuf_len(loginmsg) == 0)
		తిరిగి;
	ఒకవేళ ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	రాయి("%s", (అక్షరం *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

స్థిర శూన్య
prepare_auth_info_file(నిర్మాణం passwd *pw, నిర్మాణం sshbuf *info)
{
	పూర్ణాంకం fd = -1, success = 0;

	ఒకవేళ (!options.expose_userauth_info || info == ఖాళీ)
		తిరిగి;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	ఒకవేళ ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	success = 1;
 బహిర్గతం:
	ఒకవేళ (!success) {
		ఒకవేళ (fd != -1)
			close(fd);
		విడుదల(auth_info_file);
		auth_info_file = ఖాళీ;
	}
	restore_uid();
}

స్థిర శూన్య
సమితి_fwdpermit_from_authopts(నిర్మాణం ssh *ssh, స్థిరరాశి నిర్మాణం sshauthopt *opts)
{
	అక్షరం *tmp, *cp, *host;
	పూర్ణాంకం పోర్టు;
	కొలత_t i;

	ఒకవేళ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		కొరకు (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			ఒకవేళ ((host = hpdelim2(&cp, ఖాళీ)) == ఖాళీ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ఒకవేళ (cp == ఖాళీ || (పోర్టు = permitopen_పోర్టు(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_కూడు_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, పోర్టు);
			విడుదల(tmp);
		}
	}
	ఒకవేళ ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		కొరకు (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			ఒకవేళ ((host = hpdelim(&cp)) == ఖాళీ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ఒకవేళ (cp == ఖాళీ || (పోర్టు = permitopen_పోర్టు(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_కూడు_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, పోర్టు);
			విడుదల(tmp);
		}
	}
}

శూన్య
do_authenticated(నిర్మాణం ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	సమితి_fwdpermit_from_authopts(ssh, auth_opts);

	ఒకవేళ (!auth_opts->permit_పోర్టు_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} లేకపోతే {
		ఒకవేళ ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		లేకపోతే
			channel_permit_all(ssh, FORWARD_LOCAL);
		ఒకవేళ ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		లేకపోతే
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
స్థిర పూర్ణాంకం
xauth_valid_string(స్థిరరాశి అక్షరం *s)
{
	కొలత_t i;

	కొరకు (i = 0; s[i] != '\0'; i++) {
		ఒకవేళ (!అక్షరమా_అంకెనా((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			తిరిగి 0;
	}
	తిరిగి 1;
}

#నిర్వచించు USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
పూర్ణాంకం
do_exec_no_pty(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *command)
{
	pid_t pid;
#నిర్వచితమైతే USE_PIPES
	పూర్ణాంకం pin[2], pout[2], perr[2];

	ఒకవేళ (s == ఖాళీ)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	ఒకవేళ (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		తిరిగి -1;
	}
	ఒకవేళ (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		తిరిగి -1;
	}
#లేకపోతే
	పూర్ణాంకం inout[2], err[2];

	ఒకవేళ (s == ఖాళీ)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		తిరిగి -1;
	}
#అయితే_ముగింపు

	session_proctitle(s);

	/* Fork the child. */
	ఎంపిక ((pid = fork())) {
	స్థితి -1:
		error_f("fork: %.100s", strerror(errno));
#నిర్వచితమైతే USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#లేకపోతే
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#అయితే_ముగింపు
		తిరిగి -1;
	స్థితి 0:
		is_బిడ్డ = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		ఒకవేళ (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#నిర్వచితమైతే USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		ఒకవేళ (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		ఒకవేళ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		ఒకవేళ (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#లేకపోతే
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		ఒకవేళ (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		ఒకవేళ (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		ఒకవేళ (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#అయితే_ముగింపు

		/* Do processing for the child (exec command etc). */
		do_బిడ్డ(ssh, s, command);
		/* NOTREACHED */
	అప్రమేయ:
		ఆపు;
	}

#నిర్వచితమైతే HAVE_CYGWIN
	cygwin_సమితి_impersonation_token(INVALID_HANDLE_విలువ);
#అయితే_ముగింపు

	s->pid = pid;

	/*
	 * Clear loginmsg, since it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

#నిర్వచితమైతే USE_PIPES
	/* We are the parent.  Close the child sides of the pipes. */
	close(pin[0]);
	close(pout[1]);
	close(perr[1]);

	session_సమితి_fds(ssh, s, pin[1], pout[0], perr[0],
	    s->is_subsystem, 0);
#లేకపోతే
	/* We are the parent.  Close the child sides of the socket pairs. */
	close(inout[0]);
	close(err[0]);

	/*
	 * Enter the interactive session.  Note: server_loop must be able to
	 * handle the case that fdin and fdout are the same.
	 */
	session_సమితి_fds(ssh, s, inout[1], inout[1], err[1],
	    s->is_subsystem, 0);
#అయితే_ముగింపు
	తిరిగి 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
పూర్ణాంకం
do_exec_pty(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *command)
{
	పూర్ణాంకం fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	ఒకవేళ (s == ఖాళీ)
		fatal("do_exec_pty: no session");
	ptyfd = s->ptyfd;
	ttyfd = s->ttyfd;

	/*
	 * Create another descriptor of the pty master side for use as the
	 * standard input.  We could use the original descriptor, but this
	 * simplifies code in server_loop.  The descriptor is bidirectional.
	 * Do this before forking (and cleanup in the child) so as to
	 * detect and gracefully fail out-of-fd conditions.
	 */
	ఒకవేళ ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		తిరిగి -1;
	}
	/* we keep a reference to the pty master */
	ఒకవేళ ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		తిరిగి -1;
	}

	/* Fork the child. */
	ఎంపిక ((pid = fork())) {
	స్థితి -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		తిరిగి -1;
	స్థితి 0:
		is_బిడ్డ = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		ఒకవేళ (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		ఒకవేళ (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		ఒకవేళ (dup2(ttyfd, 2) == -1)
			error("dup2 stderr: %s", strerror(errno));

		/* Close the extra descriptor for the pseudo tty. */
		close(ttyfd);

		/* record login, etc. similar to login(1) */
#నిర్వచితం_కాకపోతే HAVE_OSF_SIA
		do_login(ssh, s, command);
#అయితే_ముగింపు
		/*
		 * Do common processing for the child, such as execing
		 * the command.
		 */
		do_బిడ్డ(ssh, s, command);
		/* NOTREACHED */
	అప్రమేయ:
		ఆపు;
	}

#నిర్వచితమైతే HAVE_CYGWIN
	cygwin_సమితి_impersonation_token(INVALID_HANDLE_విలువ);
#అయితే_ముగింపు

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_సమితి_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	తిరిగి 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
పూర్ణాంకం
do_exec(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *command)
{
	పూర్ణాంకం ret;
	స్థిరరాశి అక్షరం *forced = ఖాళీ, *tty = ఖాళీ;
	అక్షరం session_type[1024];

	ఒకవేళ (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} లేకపోతే ఒకవేళ (auth_opts->force_command != ఖాళీ) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	ఒకవేళ (forced != ఖాళీ) {
		s->forced = 1;
		ఒకవేళ (IS_అంతర్గత_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} లేకపోతే ఒకవేళ (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, పరిమాణం(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} లేకపోతే ఒకవేళ (s->is_subsystem) {
		snprintf(session_type, పరిమాణం(session_type),
		    "subsystem '%.900s'", s->subsys);
	} లేకపోతే ఒకవేళ (command == ఖాళీ) {
		snprintf(session_type, పరిమాణం(session_type), "shell");
	} లేకపోతే {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, పరిమాణం(session_type), "command");
	}

	ఒకవేళ (s->ttyfd != -1) {
		tty = s->tty;
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == ఖాళీ ? "" : " on ",
	    tty == ఖాళీ ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_పోర్టు(ssh),
	    s->self);

#నిర్వచితమైతే SSH_AUDIT_EVENTS
	ఒకవేళ (command != ఖాళీ)
		mm_audit_నిరంతరం_command(command);
	లేకపోతే ఒకవేళ (s->ttyfd == -1) {
		అక్షరం *shell = s->pw->pw_shell;

		ఒకవేళ (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_నిరంతరం_command(shell);
	}
#అయితే_ముగింపు
	ఒకవేళ (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	లేకపోతే
		ret = do_exec_no_pty(ssh, s, command);

	original_command = ఖాళీ;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	తిరిగి ret;
}

/* administrative, login(1)-like work */
శూన్య
do_login(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *command)
{
	socklen_t fromlen;
	నిర్మాణం sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, పరిమాణం(from));
	fromlen = పరిమాణం(from);
	ఒకవేళ (ssh_packet_connection_is_on_socket(ssh)) {
		ఒకవేళ (getpeername(ssh_packet_get_connection_లోపల(ssh),
		    (నిర్మాణం sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	ఒకవేళ (check_quietlogin(s, command))
		తిరిగి;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
శూన్య
do_motd(శూన్య)
{
	FILE *f;
	అక్షరం buf[256];

	ఒకవేళ (options.print_motd) {
#నిర్వచితమైతే HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#లేకపోతే
		f = fopen("/etc/motd", "r");
#అయితే_ముగింపు
		ఒకవేళ (f) {
			అయితే (fgets(buf, పరిమాణం(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
పూర్ణాంకం
check_quietlogin(Session *s, స్థిరరాశి అక్షరం *command)
{
	అక్షరం buf[256];
	నిర్మాణం passwd *pw = s->pw;
	నిర్మాణం stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	ఒకవేళ (command != ఖాళీ)
		తిరిగి 1;
	snprintf(buf, పరిమాణం(buf), "%.200s/.hushlogin", pw->pw_dir);
#నిర్వచితమైతే HAVE_LOGIN_CAP
	ఒకవేళ (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		తిరిగి 1;
#లేకపోతే
	ఒకవేళ (stat(buf, &st) >= 0)
		తిరిగి 1;
#అయితే_ముగింపు
	తిరిగి 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
స్థిర శూన్య
read_environment_file(అక్షరం ***env, u_int *envsize,
	స్థిరరాశి అక్షరం *filename, స్థిరరాశి అక్షరం *allowlist)
{
	FILE *f;
	అక్షరం *పంక్తి = ఖాళీ, *cp, *విలువ;
	కొలత_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	ఒకవేళ (!f)
		తిరిగి;

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		ఒకవేళ (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		కొరకు (cp = పంక్తి; *cp == ' ' || *cp == '\t'; cp++)
			;
		ఒకవేళ (!*cp || *cp == '#' || *cp == '\n')
			కొనసాగు;

		cp[strcspn(cp, "\n")] = '\0';

		విలువ = strchr(cp, '=');
		ఒకవేళ (విలువ == ఖాళీ) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			కొనసాగు;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*విలువ = '\0';
		విలువ++;
		ఒకవేళ (allowlist != ఖాళీ &&
		    సరిపోలిక_నమూనా_list(cp, allowlist, 0) != 1)
			కొనసాగు;
		బిడ్డ_సమితి_env(env, envsize, cp, విలువ);
	}
	విడుదల(పంక్తి);
	fclose(f);
}

#నిర్వచితమైతే HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
స్థిర అక్షరం *
బిడ్డ_get_env(అక్షరం **env, స్థిరరాశి అక్షరం *name)
{
	పూర్ణాంకం i;
	కొలత_t len;

	len = అక్షరశ్రేణి_పొడవు(name);
	కొరకు (i=0; env[i] != ఖాళీ; i++)
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(name, env[i], len) == 0 && env[i][len] == '=')
			తిరిగి(env[i] + len + 1);
	తిరిగి ఖాళీ;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
స్థిర శూన్య
read_etc_default_login(అక్షరం ***env, u_int *envsize, uid_t uid)
{
	అక్షరం **tmpenv = ఖాళీ, *var;
	u_int i, tmpenvsize = 0;
	u_long ముసుగు;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	ఒకవేళ (tmpenv == ఖాళీ)
		తిరిగి;

	ఒకవేళ (uid == 0)
		var = బిడ్డ_get_env(tmpenv, "SUPATH");
	లేకపోతే
		var = బిడ్డ_get_env(tmpenv, "PATH");
	ఒకవేళ (var != ఖాళీ)
		బిడ్డ_సమితి_env(env, envsize, "PATH", var);

	ఒకవేళ ((var = బిడ్డ_get_env(tmpenv, "UMASK")) != ఖాళీ)
		ఒకవేళ (అక్షరశ్రేణి_చదువు(var, "%5lo", &ముసుగు) == 1)
			umask((బహుళకం_t)ముసుగు);

	కొరకు (i = 0; tmpenv[i] != ఖాళీ; i++)
		విడుదల(tmpenv[i]);
	విడుదల(tmpenv);
}
#అయితే_ముగింపు /* HAVE_ETC_DEFAULT_LOGIN */

#ఒకవేళ defined(USE_PAM) || defined(HAVE_CYGWIN)
స్థిర శూన్య
copy_environment_denylist(అక్షరం **ఆధారం, అక్షరం ***env, u_int *envsize,
    స్థిరరాశి అక్షరం *denylist)
{
	అక్షరం *var_name, *var_val;
	పూర్ణాంకం i;

	ఒకవేళ (ఆధారం == ఖాళీ)
		తిరిగి;

	కొరకు(i = 0; ఆధారం[i] != ఖాళీ; i++) {
		var_name = xstrdup(ఆధారం[i]);
		ఒకవేళ ((var_val = అక్షరశ్రేణి_శోధన(var_name, "=")) == ఖాళీ) {
			విడుదల(var_name);
			కొనసాగు;
		}
		*var_val++ = '\0';

		ఒకవేళ (denylist == ఖాళీ ||
		    సరిపోలిక_నమూనా_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			బిడ్డ_సమితి_env(env, envsize, var_name, var_val);
		}

		విడుదల(var_name);
	}
}
#అయితే_ముగింపు /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#నిర్వచితమైతే HAVE_CYGWIN
స్థిర శూన్య
copy_environment(అక్షరం **ఆధారం, అక్షరం ***env, u_int *envsize)
{
	copy_environment_denylist(ఆధారం, env, envsize, ఖాళీ);
}
#అయితే_ముగింపు

స్థిర అక్షరం **
do_అమరిక_env(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *shell)
{
	అక్షరం buf[256];
	కొలత_t n;
	u_int i, envsize;
	అక్షరం *ocp, *cp, *విలువ, **env, *laddr;
	నిర్మాణం passwd *pw = s->pw;
#ఒకవేళ !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	అక్షరం *మార్గం = ఖాళీ;
#అయితే_ముగింపు

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, పరిమాణం(అక్షరం *));
	env[0] = ఖాళీ;

#నిర్వచితమైతే HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		అక్షరం **p;

		p = fetch_windows_environment();
		copy_environment(p, &env, &envsize);
		free_windows_environment(p);
	}
#అయితే_ముగింపు

#నిర్వచితమైతే GSSAPI
	/* Allow any GSSAPI methods that we've used to alter
	 * the child's environment as they see fit
	 */
	ssh_gssapi_do_బిడ్డ(&env, &envsize);
#అయితే_ముగింపు

	/* Set basic environment. */
	కొరకు (i = 0; i < s->అంకె_env; i++)
		బిడ్డ_సమితి_env(&env, &envsize, s->env[i].name, s->env[i].val);

	బిడ్డ_సమితి_env(&env, &envsize, "USER", pw->pw_name);
	బిడ్డ_సమితి_env(&env, &envsize, "LOGNAME", pw->pw_name);
#నిర్వచితమైతే _AIX
	బిడ్డ_సమితి_env(&env, &envsize, "LOGIN", pw->pw_name);
#అయితే_ముగింపు
	బిడ్డ_సమితి_env(&env, &envsize, "HOME", pw->pw_dir);
#నిర్వచితమైతే HAVE_LOGIN_CAP
	ఒకవేళ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		బిడ్డ_సమితి_env(&env, &envsize, "PATH", _PATH_STDPATH);
	లేకపోతే
		బిడ్డ_సమితి_env(&env, &envsize, "PATH", getenv("PATH"));
#లేకపోతే /* HAVE_LOGIN_CAP */
# ifndef HAVE_CYGWIN
	/*
	 * There's no standard path on Windows. The path contains
	 * important components pointing to the system directories,
	 * needed for loading shared libraries. So the path better
	 * remains intact here.
	 */
#  ifdef HAVE_ETC_DEFAULT_LOGIN
	read_etc_default_login(&env, &envsize, pw->pw_uid);
	మార్గం = బిడ్డ_get_env(env, "PATH");
#  endif /* HAVE_ETC_DEFAULT_LOGIN */
	ఒకవేళ (మార్గం == ఖాళీ || *మార్గం == '\0') {
		బిడ్డ_సమితి_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_మార్గం : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#అయితే_ముగింపు /* HAVE_LOGIN_CAP */

	ఒకవేళ (!options.use_pam) {
		snprintf(buf, పరిమాణం buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		బిడ్డ_సమితి_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	బిడ్డ_సమితి_env(&env, &envsize, "SHELL", shell);

	ఒకవేళ (getenv("TZ"))
		బిడ్డ_సమితి_env(&env, &envsize, "TZ", getenv("TZ"));
#నిర్వచితమైతే HAVE_LOGIN_CAP
	ఒకవేళ (getenv("XDG_RUNTIME_DIR")) {
		బిడ్డ_సమితి_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#అయితే_ముగింపు /* HAVE_LOGIN_CAP */
	ఒకవేళ (s->పదం)
		బిడ్డ_సమితి_env(&env, &envsize, "TERM", s->పదం);
	ఒకవేళ (s->display)
		బిడ్డ_సమితి_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		అక్షరం *cp;

		ఒకవేళ ((cp = getenv("KRB5CCNAME")) != ఖాళీ)
			బిడ్డ_సమితి_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#నిర్వచితమైతే _AIX
	{
		అక్షరం *cp;

		ఒకవేళ ((cp = getenv("AUTHSTATE")) != ఖాళీ)
			బిడ్డ_సమితి_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#అయితే_ముగింపు
#నిర్వచితమైతే KRB5
	ఒకవేళ (s->authctxt->krb5_ccname)
		బిడ్డ_సమితి_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#అయితే_ముగింపు
	ఒకవేళ (auth_sock_name != ఖాళీ)
		బిడ్డ_సమితి_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	ఒకవేళ (options.permit_user_env) {
		కొరకు (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			ఒకవేళ (cp != ఖాళీ) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				ఒకవేళ (options.permit_user_env_allowlist == ఖాళీ ||
				    సరిపోలిక_నమూనా_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					బిడ్డ_సమితి_env(&env, &envsize,
					    ocp, cp + 1);
			}
			విడుదల(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	ఒకవేళ (options.permit_user_env) {
		snprintf(buf, పరిమాణం buf, "%.200s/%s/environment",
		    pw->pw_dir, మార్గం_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#నిర్వచితమైతే USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	ఒకవేళ (options.use_pam) {
		అక్షరం **p;

		/*
		 * Don't allow PAM-internal env vars to leak
		 * back into the session environment.
		 */
#నిర్వచించు PAM_ENV_DENYLIST  "SSH_AUTH_INFO*,SSH_CONNECTION*"
		p = fetch_pam_బిడ్డ_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);

		p = fetch_pam_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);
	}
#అయితే_ముగింపు /* USE_PAM */

	/* Environment specified by admin */
	కొరకు (i = 0; i < options.అంకె_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		ఒకవేళ ((విలువ = strchr(cp, '=')) == ఖాళీ) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*విలువ++ = '\0';
		బిడ్డ_సమితి_env(&env, &envsize, cp, విలువ);
		విడుదల(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, పరిమాణం buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
	    ssh_local_పోర్టు(ssh));
	బిడ్డ_సమితి_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_లోపల(ssh));
	snprintf(buf, పరిమాణం buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
	    laddr, ssh_local_పోర్టు(ssh));
	విడుదల(laddr);
	బిడ్డ_సమితి_env(&env, &envsize, "SSH_CONNECTION", buf);

	ఒకవేళ (tun_fwd_ifnames != ఖాళీ)
		బిడ్డ_సమితి_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	ఒకవేళ (auth_info_file != ఖాళీ)
		బిడ్డ_సమితి_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	ఒకవేళ (s->ttyfd != -1)
		బిడ్డ_సమితి_env(&env, &envsize, "SSH_TTY", s->tty);
	ఒకవేళ (original_command)
		బిడ్డ_సమితి_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	ఒకవేళ (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		కొరకు (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	తిరిగి env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
స్థిర శూన్య
do_rc_files(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *shell)
{
	FILE *f = ఖాళీ;
	అక్షరం *cmd = ఖాళీ, *user_rc = ఖాళీ;
	పూర్ణాంకం do_xauth;
	నిర్మాణం stat st;

	do_xauth =
	    s->display != ఖాళీ && s->auth_proto != ఖాళీ && s->auth_దత్తాంశం != ఖాళీ;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, మార్గం_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	ఒకవేళ (!s->is_subsystem && options.adm_forced_command == ఖాళీ &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		ఒకవేళ (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		ఒకవేళ (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		ఒకవేళ (f) {
			ఒకవేళ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_దత్తాంశం);
			pclose(f);
		} లేకపోతే
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} లేకపోతే ఒకవేళ (stat(మార్గం_SSH_SYSTEM_RC, &st) >= 0) {
		ఒకవేళ (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    మార్గం_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " మార్గం_SSH_SYSTEM_RC, "w");
		ఒకవేళ (f) {
			ఒకవేళ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_దత్తాంశం);
			pclose(f);
		} లేకపోతే
			fprintf(stderr, "Could not run %s\n",
			    మార్గం_SSH_SYSTEM_RC);
	} లేకపోతే ఒకవేళ (do_xauth && options.xauth_location != ఖాళీ) {
		/* Add authority data to .Xauthority if appropriate. */
		ఒకవేళ (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_దత్తాంశం);
		}
		ఒకవేళ (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		ఒకవేళ (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_దత్తాంశం);
			pclose(f);
		} లేకపోతే {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	విడుదల(cmd);
	విడుదల(user_rc);
}

స్థిర శూన్య
do_nologin(నిర్మాణం passwd *pw)
{
	FILE *f = ఖాళీ;
	అక్షరం buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	నిర్మాణం stat sb;

#నిర్వచితమైతే HAVE_LOGIN_CAP
	ఒకవేళ (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		తిరిగి;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#లేకపోతే
	ఒకవేళ (pw->pw_uid == 0)
		తిరిగి;
	nl = def_nl;
#అయితే_ముగింపు
	ఒకవేళ (stat(nl, &sb) == -1)
		తిరిగి;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	ఒకవేళ ((f = fopen(nl, "r")) != ఖాళీ) {
		అయితే (fgets(buf, పరిమాణం(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	నిష్క్రమించు(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
స్థిర శూన్య
safely_chroot(స్థిరరాశి అక్షరం *మార్గం, uid_t uid)
{
	స్థిరరాశి అక్షరం *cp;
	అక్షరం component[PATH_MAX];
	నిర్మాణం stat st;

	ఒకవేళ (!మార్గం_absolute(మార్గం))
		fatal("chroot path does not begin at root");
	ఒకవేళ (అక్షరశ్రేణి_పొడవు(మార్గం) >= పరిమాణం(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	కొరకు (cp = మార్గం; cp != ఖాళీ;) {
		ఒకవేళ ((cp = strchr(cp, '/')) == ఖాళీ)
			strlcpy(component, మార్గం, పరిమాణం(component));
		లేకపోతే {
			cp++;
			జ్ఞాపకం_నకలు(component, మార్గం, cp - మార్గం);
			component[cp - మార్గం] = '\0';
		}

		debug3_f("checking '%s'", component);

		ఒకవేళ (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		ఒకవేళ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ఖాళీ ? "" : "component ", component);
		ఒకవేళ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ఖాళీ ? "" : "component ", component);

	}

	ఒకవేళ (chdir(మార్గం) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", మార్గం, strerror(errno));
	ఒకవేళ (chroot(మార్గం) == -1)
		fatal("chroot(\"%s\"): %s", మార్గం, strerror(errno));
	ఒకవేళ (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", మార్గం);
}

/* Set login name, uid, gid, and groups. */
శూన్య
do_setusercontext(నిర్మాణం passwd *pw)
{
	అక్షరం uidstr[32], *chroot_మార్గం, *tmp;

	platform_setusercontext(pw);

	ఒకవేళ (platform_privileged_uidswap()) {
#నిర్వచితమైతే HAVE_LOGIN_CAP
		ఒకవేళ (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			నిష్క్రమించు(1);
		}
#లేకపోతే
		ఒకవేళ (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		ఒకవేళ (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			నిష్క్రమించు(1);
		}
		/* Initialize the group list. */
		ఒకవేళ (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			నిష్క్రమించు(1);
		}
		endgrent();
#అయితే_ముగింపు

		platform_setusercontext_post_groups(pw);

		ఒకవేళ (!లోపల_chroot && options.chroot_directory != ఖాళీ &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, పరిమాణం(uidstr), "%llu",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)pw->pw_uid);
			chroot_మార్గం = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (అక్షరం *)ఖాళీ);
			safely_chroot(chroot_మార్గం, pw->pw_uid);
			విడుదల(tmp);
			విడుదల(chroot_మార్గం);
			/* Make sure we don't attempt to chroot again */
			విడుదల(options.chroot_directory);
			options.chroot_directory = ఖాళీ;
			లోపల_chroot = 1;
		}

#నిర్వచితమైతే HAVE_LOGIN_CAP
		ఒకవేళ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			నిష్క్రమించు(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(శూన్య) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#లేకపోతే
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		ఒకవేళ (!లోపల_chroot && సమితి_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_సమితి_uid(pw);
#అయితే_ముగింపు
	} లేకపోతే ఒకవేళ (options.chroot_directory != ఖాళీ &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	ఒకవేళ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

స్థిర శూన్య
do_pwchange(Session *s)
{
	fflush(ఖాళీ);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	ఒకవేళ (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#నిర్వచితమైతే WITH_SELINUX
		setexeccon(ఖాళీ);
#అయితే_ముగింపు
#నిర్వచితమైతే PASSWD_NEEDS_USERNAME
		execl(మార్గం_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (అక్షరం *)ఖాళీ);
#లేకపోతే
		execl(మార్గం_PASSWD_PROG, "passwd", (అక్షరం *)ఖాళీ);
#అయితే_ముగింపు
		perror("passwd");
	} లేకపోతే {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	నిష్క్రమించు(1);
}

స్థిర శూన్య
బిడ్డ_close_fds(నిర్మాణం ssh *ssh)
{
	బాహ్య పూర్ణాంకం auth_sock;

	ఒకవేళ (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	ఒకవేళ (ssh_packet_get_connection_లోపల(ssh) ==
	    ssh_packet_get_connection_బహిర్గతం(ssh))
		close(ssh_packet_get_connection_లోపల(ssh));
	లేకపోతే {
		close(ssh_packet_get_connection_లోపల(ssh));
		close(ssh_packet_get_connection_బహిర్గతం(ssh));
	}
	/*
	 * Close all descriptors related to channels.  They will still remain
	 * open in the parent.
	 */
	/* XXX better use close-on-exec? -markus */
	channel_close_all(ssh);

	/*
	 * Close any extra file descriptors.  Note that there may still be
	 * descriptors left by system functions.  They will be closed later.
	 */
	endpwent();

	/* Stop directing logs to a high-numbered fd before we close it */
	log_redirect_stderr_గమ్యం(ఖాళీ);

	/*
	 * Close any extra open file descriptors so that we don't have them
	 * hanging around in clients.  Note that we want to do this after
	 * initgroups, because at least on Solaris 2.3 it leaves file
	 * descriptors open.
	 */
	closefrom(STDERR_FILENO + 1);
}

/*
 * Performs common processing for the child, such as setting up the
 * environment, closing extra file descriptors, setting the user and group
 * ids, and executing the command or shell.
 */
#నిర్వచించు ARGV_MAX 10
శూన్య
do_బిడ్డ(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *command)
{
	బాహ్య అక్షరం **environ;
	అక్షరం **env, *argv[ARGV_MAX], remote_id[512];
	స్థిరరాశి అక్షరం *shell, *shell0;
	నిర్మాణం passwd *pw = s->pw;
	పూర్ణాంకం r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, పరిమాణం(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_కీలకాలు(ssh);

	/* Force a password change */
	ఒకవేళ (s->authctxt->force_pwchange) {
		do_setusercontext(pw);
		బిడ్డ_close_fds(ssh);
		do_pwchange(s);
		నిష్క్రమించు(1);
	}

	/*
	 * Login(1) does this as well, and it needs uid 0 for the "-h"
	 * switch, so we let login(1) to this for us.
	 */
#నిర్వచితమైతే HAVE_OSF_SIA
	session_అమరిక_sia(pw, s->ttyfd == -1 ? ఖాళీ : s->tty);
	ఒకవేళ (!check_quietlogin(s, command))
		do_motd();
#లేకపోతే /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	ఒకవేళ (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	ఒకవేళ (!check_quietlogin(s, command))
		display_loginmsg();
#అయితే_ముగింపు /* HAVE_OSF_SIA */

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam && !is_pam_session_open()) {
		debug3("PAM session not opened, exiting");
		display_loginmsg();
		నిష్క్రమించు(254);
	}
#అయితే_ముగింపు

	/*
	 * Get the shell from the password data.  An empty shell field is
	 * legal, and means /bin/sh.
	 */
	shell = (pw->pw_shell[0] == '\0') ? _PATH_BSHELL : pw->pw_shell;

	/*
	 * Make sure $SHELL points to the shell from the password file,
	 * even if shell is overridden from login.conf
	 */
	env = do_అమరిక_env(ssh, s, shell);

#నిర్వచితమైతే HAVE_LOGIN_CAP
	shell = login_getcapstr(lc, "shell", (అక్షరం *)shell, (అక్షరం *)shell);
#అయితే_ముగింపు

	/*
	 * Close the connection descriptors; note that this is the child, and
	 * the server will still have the socket open, and it is important
	 * that we do not shutdown it.  Note that the descriptors cannot be
	 * closed before building the environment, as we call
	 * ssh_remote_ipaddr there.
	 */
	బిడ్డ_close_fds(ssh);

	/*
	 * Must take new environment into use so that .ssh/rc,
	 * /etc/ssh/sshrc and xauth are run in the proper environment.
	 */
	environ = env;

#ఒకవేళ defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	ఒకవేళ (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != ఖాళీ)) {
		అక్షరం cell[64];

		debug("Getting AFS token");

		k_setpag();

		ఒకవేళ (k_afs_cell_యొక్క_file(pw->pw_dir, cell, పరిమాణం(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, ఖాళీ);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, ఖాళీ, ఖాళీ, pw->pw_dir);
	}
#అయితే_ముగింపు

	/* Change current directory to the user's home directory. */
	ఒకవేళ (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#నిర్వచితమైతే HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#అయితే_ముగింపు
		ఒకవేళ (r || !లోపల_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		ఒకవేళ (r)
			నిష్క్రమించు(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	ఒకవేళ (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		రాయి("This service allows sftp connections only.\n");
		fflush(ఖాళీ);
		నిష్క్రమించు(1);
	} లేకపోతే ఒకవేళ (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		బాహ్య పూర్ణాంకం optind, optreset;
		పూర్ణాంకం sftp_argc;
		అక్షరం **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, అంతర్గత_SFTP_NAME);
		ఒకవేళ (argv_విభజించు(command == ఖాళీ ? "sftp-server" : command,
		    &sftp_argc, &sftp_argv, 1) != 0) {
			error("internal error: can't split internal-sftp "
			    "arguments");
			నిష్క్రమించు(1);
		}
		optind = optreset = 1;
		__progname = sftp_argv[0];
#నిర్వచితమైతే WITH_SELINUX
		ssh_selinux_change_context("sftpd_t");
#అయితే_ముగింపు
		నిష్క్రమించు(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}

	fflush(ఖాళీ);

	/* Get the last component of the shell name. */
	ఒకవేళ ((shell0 = strrchr(shell, '/')) != ఖాళీ)
		shell0++;
	లేకపోతే
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	ఒకవేళ (!command) {
		అక్షరం argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		ఒకవేళ (strlcpy(argv0 + 1, shell0, పరిమాణం(argv0) - 1)
		    >= పరిమాణం(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			నిష్క్రమించు(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = ఖాళీ;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		నిష్క్రమించు(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (అక్షరం *) shell0;
	argv[1] = "-c";
	argv[2] = (అక్షరం *) command;
	argv[3] = ఖాళీ;
	execve(shell, argv, env);
	perror(shell);
	నిష్క్రమించు(1);
}

శూన్య
session_వాడని(పూర్ణాంకం id)
{
	debug3_f("session id %d unused", id);
	ఒకవేళ (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, పరిమాణం(*sessions));
	sessions[id].self = id;
	sessions[id].వాడిన = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = ఖాళీ;
	sessions[id].తదుపరి_వాడని = sessions_మొదటి_వాడని;
	sessions_మొదటి_వాడని = id;
}

Session *
session_new(శూన్య)
{
	Session *s, *tmp;

	ఒకవేళ (sessions_మొదటి_వాడని == -1) {
		ఒకవేళ (sessions_nalloc >= options.max_sessions)
			తిరిగి ఖాళీ;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, పరిమాణం(*sessions));
		ఒకవేళ (tmp == ఖాళీ) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			తిరిగి ఖాళీ;
		}
		sessions = tmp;
		session_వాడని(sessions_nalloc++);
	}

	ఒకవేళ (sessions_మొదటి_వాడని >= sessions_nalloc ||
	    sessions_మొదటి_వాడని < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_మొదటి_వాడని, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_మొదటి_వాడని];
	ఒకవేళ (s->వాడిన)
		fatal_f("session %d already used", sessions_మొదటి_వాడని);
	sessions_మొదటి_వాడని = s->తదుపరి_వాడని;
	s->వాడిన = 1;
	s->తదుపరి_వాడని = -1;
	debug("session_new: session %d", s->self);

	తిరిగి s;
}

స్థిర శూన్య
session_dump(శూన్య)
{
	పూర్ణాంకం i;
	కొరకు (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->వాడిన,
		    s->తదుపరి_వాడని,
		    s->self,
		    s->chanid,
		    (దీర్ఘ)s->pid);
	}
}

పూర్ణాంకం
session_open(Authctxt *authctxt, పూర్ణాంకం chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	ఒకవేళ (s == ఖాళీ) {
		error("no more sessions");
		తిరిగి 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	ఒకవేళ (s->pw == ఖాళీ || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	తిరిగి 1;
}

Session *
session_by_tty(అక్షరం *tty)
{
	పూర్ణాంకం i;
	కొరకు (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ఒకవేళ (s->వాడిన && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			తిరిగి s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	తిరిగి ఖాళీ;
}

స్థిర Session *
session_by_channel(పూర్ణాంకం id)
{
	పూర్ణాంకం i;
	కొరకు (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ఒకవేళ (s->వాడిన && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			తిరిగి s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	తిరిగి ఖాళీ;
}

స్థిర Session *
session_by_x11_channel(పూర్ణాంకం id)
{
	పూర్ణాంకం i, j;

	కొరకు (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		ఒకవేళ (s->x11_chanids == ఖాళీ || !s->వాడిన)
			కొనసాగు;
		కొరకు (j = 0; s->x11_chanids[j] != -1; j++) {
			ఒకవేళ (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				తిరిగి s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	తిరిగి ఖాళీ;
}

స్థిర Session *
session_by_pid(pid_t pid)
{
	పూర్ణాంకం i;
	debug("session_by_pid: pid %ld", (దీర్ఘ)pid);
	కొరకు (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ఒకవేళ (s->వాడిన && s->pid == pid)
			తిరిగి s;
	}
	error("session_by_pid: unknown pid %ld", (దీర్ఘ)pid);
	session_dump();
	తిరిగి ఖాళీ;
}

స్థిర పూర్ణాంకం
session_కిటికీ_change_req(నిర్మాణం ssh *ssh, Session *s)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &s->నిలువు)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->అడ్డువరుస)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_కిటికీ_కొలత(s->ptyfd, s->అడ్డువరుస, s->నిలువు, s->xpixel, s->ypixel);
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
session_pty_req(నిర్మాణం ssh *ssh, Session *s)
{
	పూర్ణాంకం r;

	ఒకవేళ (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		తిరిగి 0;
	}
	ఒకవేళ (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		తిరిగి 0;
	}

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &s->పదం, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->నిలువు)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->అడ్డువరుస)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ఒకవేళ (strcmp(s->పదం, "") == 0) {
		విడుదల(s->పదం);
		s->పదం = ఖాళీ;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	ఒకవేళ (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, పరిమాణం(s->tty))) {
		విడుదల(s->పదం);
		s->పదం = ఖాళీ;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		తిరిగి 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_కిటికీ_కొలత(s->ptyfd, s->అడ్డువరుస, s->నిలువు, s->xpixel, s->ypixel);

	session_proctitle(s);
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
session_subsystem_req(నిర్మాణం ssh *ssh, Session *s)
{
	నిర్మాణం stat st;
	పూర్ణాంకం r, success = 0, దొరికింది = 0;
	అక్షరం *prog, *cmd, *type;
	u_int i;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &s->subsys, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	కొరకు (i = 0; i < options.అంకె_subsystems; i++) {
		ఒకవేళ (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			కొనసాగు;
		దొరికింది = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_వాదనలు[i];
		ఒకవేళ (strcmp(అంతర్గత_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} లేకపోతే {
			ఒకవేళ (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_సమితి_xtype(ssh, s->chanid, type);
		విడుదల(type);
		success = do_exec(ssh, s, cmd) == 0;
		ఆపు;
	}

	ఒకవేళ (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    దొరికింది ? "execution failed" : "subsystem not found");
	}

	తిరిగి success;
}

స్థిర పూర్ణాంకం
session_x11_req(నిర్మాణం ssh *ssh, Session *s)
{
	పూర్ణాంకం r, success;
	u_char single_connection = 0;

	ఒకవేళ (s->auth_proto != ఖాళీ || s->auth_దత్తాంశం != ఖాళీ) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		తిరిగి 0;
	}
	ఒకవేళ ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_దత్తాంశం, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	ఒకవేళ (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_దత్తాంశం))
		success = session_అమరిక_x11fwd(ssh, s);
	లేకపోతే {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	ఒకవేళ (!success) {
		విడుదల(s->auth_proto);
		విడుదల(s->auth_దత్తాంశం);
		s->auth_proto = ఖాళీ;
		s->auth_దత్తాంశం = ఖాళీ;
	}
	తిరిగి success;
}

స్థిర పూర్ణాంకం
session_shell_req(నిర్మాణం ssh *ssh, Session *s)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_సమితి_xtype(ssh, s->chanid, "session:shell");

	తిరిగి do_exec(ssh, s, ఖాళీ) == 0;
}

స్థిర పూర్ణాంకం
session_exec_req(నిర్మాణం ssh *ssh, Session *s)
{
	u_int success;
	పూర్ణాంకం r;
	అక్షరం *command = ఖాళీ;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &command, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_సమితి_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	విడుదల(command);
	తిరిగి success;
}

స్థిర పూర్ణాంకం
session_break_req(నిర్మాణం ssh *ssh, Session *s)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_get_u32(ssh, ఖాళీ)) != 0 || /* ignore */
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ఒకవేళ (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
session_env_req(నిర్మాణం ssh *ssh, Session *s)
{
	అక్షరం *name, *val;
	u_int i;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &name, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	ఒకవేళ (s->అంకె_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		వెళ్ళు fail;
	}

	కొరకు (i = 0; i < options.అంకె_accept_env; i++) {
		ఒకవేళ (సరిపోలిక_నమూనా(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->అంకె_env, name, val);
			s->env = xrecallocarray(s->env, s->అంకె_env,
			    s->అంకె_env + 1, పరిమాణం(*s->env));
			s->env[s->అంకె_env].name = name;
			s->env[s->అంకె_env].val = val;
			s->అంకె_env++;
			తిరిగి (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	విడుదల(name);
	విడుదల(val);
	తిరిగి (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
స్థిర పూర్ణాంకం
name2sig(అక్షరం *name)
{
#నిర్వచించు SSH_SIG(x) ఒకవేళ (strcmp(name, #x) == 0) తిరిగి SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(పదం_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#నిర్వచనం_రద్దు	SSH_SIG
#నిర్వచితమైతే SIGINFO
	ఒకవేళ (strcmp(name, "INFO@openssh.com") == 0)
		తిరిగి SIGINFO;
#అయితే_ముగింపు
	తిరిగి -1;
}

స్థిర పూర్ణాంకం
session_signal_req(నిర్మాణం ssh *ssh, Session *s)
{
	అక్షరం *signame = ఖాళీ;
	పూర్ణాంకం r, sig, success = 0;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &signame, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0) {
		error_fr(r, "parse");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		వెళ్ళు బహిర్గతం;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (దీర్ఘ)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	ఒకవేళ (r != 0) {
		error_f("killpg(%ld, %d): %s", (దీర్ఘ)s->pid,
		    sig, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}

	/* success */
	success = 1;
 బహిర్గతం:
	విడుదల(signame);
	తిరిగి success;
}

స్థిర పూర్ణాంకం
session_auth_agent_req(నిర్మాణం ssh *ssh, Session *s, పూర్ణాంకం agent_new)
{
	స్థిర పూర్ణాంకం called = 0;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ఒకవేళ (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		తిరిగి 0;
	}
	ఒకవేళ (called)
		తిరిగి 0;

	called = 1;
	తిరిగి auth_ఆదానం_request_forwarding(ssh, s->pw, agent_new);
}

పూర్ణాంకం
session_ఆదానం_channel_req(నిర్మాణం ssh *ssh, Channel *c, స్థిరరాశి అక్షరం *rtype)
{
	పూర్ణాంకం success = 0;
	Session *s;

	ఒకవేళ ((s = session_by_channel(c->self)) == ఖాళీ) {
		logit_f("no session %d req %.100s", c->self, rtype);
		తిరిగి 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	ఒకవేళ (c->type == SSH_CHANNEL_LARVAL) {
		ఒకవేళ (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} లేకపోతే ఒకవేళ (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} లేకపోతే ఒకవేళ (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} లేకపోతే ఒకవేళ (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} లేకపోతే ఒకవేళ (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} లేకపోతే ఒకవేళ (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} లేకపోతే ఒకవేళ (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} లేకపోతే ఒకవేళ (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	ఒకవేళ (strcmp(rtype, "window-change") == 0) {
		success = session_కిటికీ_change_req(ssh, s);
	} లేకపోతే ఒకవేళ (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} లేకపోతే ఒకవేళ (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	తిరిగి success;
}

శూన్య
session_సమితి_fds(నిర్మాణం ssh *ssh, Session *s,
    పూర్ణాంకం fdin, పూర్ణాంకం fdout, పూర్ణాంకం fderr, పూర్ణాంకం ignore_fderr, పూర్ణాంకం is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	ఒకవేళ (s->chanid == -1)
		fatal("no channel for session %d", s->self);
	channel_సమితి_fds(ssh, s->chanid,
	    fdout, fdin, fderr,
	    ignore_fderr ? CHAN_EXTENDED_IGNORE : CHAN_EXTENDED_READ,
	    1, is_tty, CHAN_SES_కిటికీ_DEFAULT);
}

/*
 * Function to perform pty cleanup. Also called if we get aborted abnormally
 * (e.g., due to a dropped connection).
 */
శూన్య
session_pty_cleanup2(Session *s)
{
	ఒకవేళ (s == ఖాళీ) {
		error_f("no session");
		తిరిగి;
	}
	ఒకవేళ (s->ttyfd == -1)
		తిరిగి;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	ఒకవేళ (s->pid != 0)
		రికార్డు_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	ఒకవేళ (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	ఒకవేళ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

శూన్య
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

స్థిర అక్షరం *
sig2name(పూర్ణాంకం sig)
{
#నిర్వచించు SSH_SIG(x) ఒకవేళ (sig == SIG ## x) తిరిగి #x
	SSH_SIG(ABRT);
	SSH_SIG(ALRM);
	SSH_SIG(FPE);
	SSH_SIG(HUP);
	SSH_SIG(ILL);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(PIPE);
	SSH_SIG(QUIT);
	SSH_SIG(SEGV);
	SSH_SIG(పదం_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#నిర్వచనం_రద్దు	SSH_SIG
	తిరిగి "SIG@openssh.com";
}

స్థిర శూన్య
session_close_x11(నిర్మాణం ssh *ssh, పూర్ణాంకం id)
{
	Channel *c;

	ఒకవేళ ((c = channel_by_id(ssh, id)) == ఖాళీ) {
		debug_f("x11 channel %d missing", id);
	} లేకపోతే {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		ఒకవేళ (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

స్థిర శూన్య
session_close_single_x11(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం force, శూన్య *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	ఒకవేళ ((s = session_by_x11_channel(id)) == ఖాళీ)
		fatal_f("no x11 channel %d", id);
	కొరకు (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		ఒకవేళ (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	విడుదల(s->x11_chanids);
	s->x11_chanids = ఖాళీ;
	విడుదల(s->display);
	s->display = ఖాళీ;
	విడుదల(s->auth_proto);
	s->auth_proto = ఖాళీ;
	విడుదల(s->auth_దత్తాంశం);
	s->auth_దత్తాంశం = ఖాళీ;
	విడుదల(s->auth_display);
	s->auth_display = ఖాళీ;
}

స్థిర శూన్య
session_exit_సందేశం(నిర్మాణం ssh *ssh, Session *s, పూర్ణాంకం స్థితి_2)
{
	Channel *c;
	పూర్ణాంకం r;
	అక్షరం *note = ఖాళీ;

	ఒకవేళ ((c = channel_lookup(ssh, s->chanid)) == ఖాళీ)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	ఒకవేళ (WIFEXITED(స్థితి_2)) {
		channel_request_ప్రారంభం(ssh, s->chanid, "exit-status", 0);
		ఒకవేళ ((r = sshpkt_put_u32(ssh, WEXITSTATUS(స్థితి_2))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(స్థితి_2));
	} లేకపోతే ఒకవేళ (WIFSIGNALED(స్థితి_2)) {
		channel_request_ప్రారంభం(ssh, s->chanid, "exit-signal", 0);
#నిర్వచితం_కాకపోతే WCOREDUMP
# define WCOREDUMP(x) (0)
#అయితే_ముగింపు
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(స్థితి_2)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(స్థితి_2)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(స్థితి_2),
		    WCOREDUMP(స్థితి_2) ? " core dumped" : "");
	} లేకపోతే {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    స్థితి_2);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (దీర్ఘ)s->pid, note == ఖాళీ ? "UNKNOWN" : note);
	విడుదల(note);

	/* disconnect channel */
	debug_f("release channel %d", s->chanid);

	/*
	 * Adjust cleanup callback attachment to send close messages when
	 * the channel gets EOF. The session will be then be closed
	 * by session_close_by_channel when the child sessions close their fds.
	 */
	channel_రిజిస్టరు_cleanup(ssh, c->self, session_close_by_channel, 1);

	/*
	 * emulate a write failure with 'chan_write_failed', nobody will be
	 * interested in data we write.
	 * Note that we must not call 'chan_read_failed', since there could
	 * be some more data waiting in the pipe.
	 */
	ఒకవేళ (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

శూన్య
session_close(నిర్మాణం ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_పోర్టు(ssh),
	    s->self);

	ఒకవేళ (s->ttyfd != -1)
		session_pty_cleanup(s);
	విడుదల(s->పదం);
	విడుదల(s->display);
	విడుదల(s->x11_chanids);
	విడుదల(s->auth_display);
	విడుదల(s->auth_దత్తాంశం);
	విడుదల(s->auth_proto);
	విడుదల(s->subsys);
	ఒకవేళ (s->env != ఖాళీ) {
		కొరకు (i = 0; i < s->అంకె_env; i++) {
			విడుదల(s->env[i].name);
			విడుదల(s->env[i].val);
		}
		విడుదల(s->env);
	}
	session_proctitle(s);
	session_వాడని(s->self);
}

శూన్య
session_close_by_pid(నిర్మాణం ssh *ssh, pid_t pid, పూర్ణాంకం స్థితి_2)
{
	Session *s = session_by_pid(pid);
	ఒకవేళ (s == ఖాళీ) {
		debug_f("no session for pid %ld", (దీర్ఘ)pid);
		తిరిగి;
	}
	ఒకవేళ (s->chanid != -1)
		session_exit_సందేశం(ssh, s, స్థితి_2);
	ఒకవేళ (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
శూన్య
session_close_by_channel(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం force, శూన్య *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	ఒకవేళ (s == ఖాళీ) {
		debug_f("no session for id %d", id);
		తిరిగి;
	}
	debug_f("channel %d child %ld", id, (దీర్ఘ)s->pid);
	ఒకవేళ (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		ఒకవేళ (s->ttyfd != -1)
			session_pty_cleanup(s);
		ఒకవేళ (!force)
			తిరిగి;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	ఒకవేళ (s->x11_chanids != ఖాళీ) {
		కొరకు (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

శూన్య
session_destroy_all(నిర్మాణం ssh *ssh, శూన్య (*closefunc)(Session *))
{
	పూర్ణాంకం i;
	కొరకు (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ఒకవేళ (s->వాడిన) {
			ఒకవేళ (closefunc != ఖాళీ)
				closefunc(s);
			లేకపోతే
				session_close(ssh, s);
		}
	}
}

స్థిర అక్షరం *
session_tty_list(శూన్య)
{
	స్థిర అక్షరం buf[1024];
	పూర్ణాంకం i;
	అక్షరం *cp;

	buf[0] = '\0';
	కొరకు (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ఒకవేళ (s->వాడిన && s->ttyfd != -1) {

			ఒకవేళ (అక్షరశ్రేణి_పోలిక(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == ఖాళీ) ? s->tty : cp + 1;
			} లేకపోతే
				cp = s->tty + 5;

			ఒకవేళ (buf[0] != '\0')
				strlcat(buf, ",", పరిమాణం buf);
			strlcat(buf, cp, పరిమాణం buf);
		}
	}
	ఒకవేళ (buf[0] == '\0')
		strlcpy(buf, "notty", పరిమాణం buf);
	తిరిగి buf;
}

శూన్య
session_proctitle(Session *s)
{
	ఒకవేళ (s->pw == ఖాళీ)
		error("no user for session %d", s->self);
	లేకపోతే
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

పూర్ణాంకం
session_అమరిక_x11fwd(నిర్మాణం ssh *ssh, Session *s)
{
	నిర్మాణం stat st;
	అక్షరం display[512], auth_display[512];
	అక్షరం hostname[NI_MAXHOST];
	u_int i;

	ఒకవేళ (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		తిరిగి 0;
	}
	ఒకవేళ (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		తిరిగి 0;
	}
	ఒకవేళ (options.xauth_location == ఖాళీ ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		తిరిగి 0;
	}
	ఒకవేళ (s->display != ఖాళీ) {
		debug("X11 display already set.");
		తిరిగి 0;
	}
	ఒకవేళ (x11_create_display_inet(ssh, options.x11_display_స్థానభ్రంశం,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_సంఖ్య, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		తిరిగి 0;
	}
	కొరకు (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_రిజిస్టరు_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	ఒకవేళ (gethostname(hostname, పరిమాణం(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	ఒకవేళ (options.x11_use_localhost) {
		snprintf(display, పరిమాణం display, "localhost:%u.%u",
		    s->display_సంఖ్య, s->screen);
		snprintf(auth_display, పరిమాణం auth_display, "unix:%u.%u",
		    s->display_సంఖ్య, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} లేకపోతే {
#నిర్వచితమైతే IPADDR_లోపల_DISPLAY
		నిర్మాణం hostent *he;
		నిర్మాణం in_addr my_addr;

		he = gethostbyname(hostname);
		ఒకవేళ (he == ఖాళీ) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			తిరిగి 0;
		}
		జ్ఞాపకం_నకలు(&my_addr, he->h_addr_list[0], పరిమాణం(నిర్మాణం in_addr));
		snprintf(display, పరిమాణం display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_సంఖ్య, s->screen);
#లేకపోతే
		snprintf(display, పరిమాణం display, "%.400s:%u.%u", hostname,
		    s->display_సంఖ్య, s->screen);
#అయితే_ముగింపు
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	తిరిగి 1;
}

స్థిర శూన్య
do_authenticated2(నిర్మాణం ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

శూన్య
do_cleanup(నిర్మాణం ssh *ssh, Authctxt *authctxt)
{
	స్థిర పూర్ణాంకం called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	ఒకవేళ (is_బిడ్డ)
		తిరిగి;

	/* avoid double cleanup */
	ఒకవేళ (called)
		తిరిగి;
	called = 1;

	ఒకవేళ (authctxt == ఖాళీ)
		తిరిగి;

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#అయితే_ముగింపు

	ఒకవేళ (!authctxt->authenticated)
		తిరిగి;

#నిర్వచితమైతే KRB5
	ఒకవేళ (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#అయితే_ముగింపు

#నిర్వచితమైతే GSSAPI
	ఒకవేళ (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#అయితే_ముగింపు

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	ఒకవేళ (auth_info_file != ఖాళీ) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		విడుదల(auth_info_file);
		auth_info_file = ఖాళీ;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	ఒకవేళ (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

స్థిరరాశి అక్షరం *
session_get_remote_name_or_ip(నిర్మాణం ssh *ssh, u_int utmp_కొలత, పూర్ణాంకం use_dns)
{
	స్థిరరాశి అక్షరం *remote = "";

	ఒకవేళ (utmp_కొలత > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	ఒకవేళ (utmp_కొలత == 0 || అక్షరశ్రేణి_పొడవు(remote) > utmp_కొలత)
		remote = ssh_remote_ipaddr(ssh);
	తిరిగి remote;
}

