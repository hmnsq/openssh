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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/un.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <grp.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "sshpty.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "uidswap.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "sshlogin.h"
#অন্তর্ভাব "serverloop.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "session.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "sftp.h"
#অন্তর্ভাব "atomicio.h"

#যদি defined(KRB5) && defined(USE_AFS)
#অন্তর্ভাব <kafs.h>
#endif

#ifdef WITH_SELINUX
#অন্তর্ভাব <selinux/selinux.h>
#endif

/*
 * Hack for systems that do not support FD passing: allocate PTYs directly
 * without calling into the monitor. This requires either the post-auth
 * privsep process retain root privileges (see the comment in
 * sshd-session.c:privsep_postauth) or that PTY allocation doesn't require
 * privileges to begin with (e.g. Cygwin).
 */
#ifdef DISABLE_FD_PASSING
#define mm_pty_allocate pty_allocate
#endif

#define IS_INTERNAL_SFTP(c) \
	(!strncmp(c, INTERNAL_SFTP_NAME, আকার(INTERNAL_SFTP_NAME) - 1) && \
	 (c[আকার(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[আকার(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[আকার(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(শূন্য);
শূন্য	session_set_fds(কাঠামো ssh *, Session *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
শূন্য	session_pty_cleanup(Session *);
শূন্য	session_proctitle(Session *);
পূর্ণসংখ্যা	session_setup_x11fwd(কাঠামো ssh *, Session *);
পূর্ণসংখ্যা	do_exec_pty(কাঠামো ssh *, Session *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	do_exec_no_pty(কাঠামো ssh *, Session *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	do_exec(কাঠামো ssh *, Session *, ধ্রুবক অক্ষর *);
শূন্য	do_login(কাঠামো ssh *, Session *, ধ্রুবক অক্ষর *);
শূন্য	do_child(কাঠামো ssh *, Session *, ধ্রুবক অক্ষর *);
শূন্য	do_motd(শূন্য);
পূর্ণসংখ্যা	check_quietlogin(Session *, ধ্রুবক অক্ষর *);

স্থির শূন্য do_authenticated2(কাঠামো ssh *, Authctxt *);

স্থির পূর্ণসংখ্যা session_pty_req(কাঠামো ssh *, Session *);

/* import */
বাহ্যিক ServerOptions options;
বাহ্যিক অক্ষর *__progname;
বাহ্যিক পূর্ণসংখ্যা debug_flag;
বাহ্যিক কাঠামো sshbuf *loginmsg;
বাহ্যিক কাঠামো sshauthopt *auth_opts;
বাহ্যিক অক্ষর *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
ধ্রুবক অক্ষর *original_command = ফাঁকা;

/*তথ্য*/
স্থির পূর্ণসংখ্যা sessions_first_unused = -1;
স্থির পূর্ণসংখ্যা sessions_nalloc = 0;
স্থির Session *sessions = ফাঁকা;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

স্থির পূর্ণসংখ্যা is_child = 0;
স্থির পূর্ণসংখ্যা in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
স্থির অক্ষর *auth_info_file = ফাঁকা;

/* Name and directory of socket for authentication agent forwarding. */
স্থির অক্ষর *auth_sock_name = ফাঁকা;
স্থির অক্ষর *auth_sock_dir = ফাঁকা; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

স্থির শূন্য
auth_sock_cleanup_proc(কাঠামো passwd *pw)
{
	যদি (auth_sock_name != ফাঁকা) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		মুক্ত(auth_sock_name);
		auth_sock_name = ফাঁকা;
		restore_uid();
	}
}

স্থির পূর্ণসংখ্যা
auth_প্রবেশ_request_forwarding(কাঠামো ssh *ssh, কাঠামো passwd *pw, পূর্ণসংখ্যা agent_new)
{
	Channel *nc;
	পূর্ণসংখ্যা sock = -1;

	যদি (auth_sock_name != ফাঁকা) {
		error("authentication forwarding requested twice.");
		ফেরত 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	যদি (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		যাও authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	ফেরত 1;

 authsock_err:
	মুক্ত(auth_sock_name);
	যদি (sock != -1)
		close(sock);
	auth_sock_name = ফাঁকা;
	ফেরত 0;
}

স্থির শূন্য
display_loginmsg(শূন্য)
{
	পূর্ণসংখ্যা r;

	যদি (sshbuf_len(loginmsg) == 0)
		ফেরত;
	যদি ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	printf("%s", (অক্ষর *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

স্থির শূন্য
prepare_auth_info_file(কাঠামো passwd *pw, কাঠামো sshbuf *info)
{
	পূর্ণসংখ্যা fd = -1, success = 0;

	যদি (!options.expose_userauth_info || info == ফাঁকা)
		ফেরত;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	যদি ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		যাও out;
	}
	যদি (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		যাও out;
	}
	যদি (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		যাও out;
	}
	success = 1;
 out:
	যদি (!success) {
		যদি (fd != -1)
			close(fd);
		মুক্ত(auth_info_file);
		auth_info_file = ফাঁকা;
	}
	restore_uid();
}

স্থির শূন্য
set_fwdpermit_from_authopts(কাঠামো ssh *ssh, ধ্রুবক কাঠামো sshauthopt *opts)
{
	অক্ষর *tmp, *cp, *host;
	পূর্ণসংখ্যা port;
	আকার_t i;

	যদি ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		জন্য (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			যদি ((host = hpdelim2(&cp, ফাঁকা)) == ফাঁকা)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			যদি (cp == ফাঁকা || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			মুক্ত(tmp);
		}
	}
	যদি ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		জন্য (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			যদি ((host = hpdelim(&cp)) == ফাঁকা)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			যদি (cp == ফাঁকা || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			মুক্ত(tmp);
		}
	}
}

শূন্য
do_authenticated(কাঠামো ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	যদি (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} অন্যথা {
		যদি ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		অন্যথা
			channel_permit_all(ssh, FORWARD_LOCAL);
		যদি ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		অন্যথা
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
স্থির পূর্ণসংখ্যা
xauth_valid_string(ধ্রুবক অক্ষর *s)
{
	আকার_t i;

	জন্য (i = 0; s[i] != '\0'; i++) {
		যদি (!isalnum((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			ফেরত 0;
	}
	ফেরত 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
পূর্ণসংখ্যা
do_exec_no_pty(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *command)
{
	pid_t pid;
#ifdef USE_PIPES
	পূর্ণসংখ্যা pin[2], pout[2], perr[2];

	যদি (s == ফাঁকা)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	যদি (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		ফেরত -1;
	}
	যদি (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		ফেরত -1;
	}
	যদি (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		ফেরত -1;
	}
#অন্যথা
	পূর্ণসংখ্যা inout[2], err[2];

	যদি (s == ফাঁকা)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		ফেরত -1;
	}
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		ফেরত -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	নির্বাচন ((pid = fork())) {
	ক্ষেত্র -1:
		error_f("fork: %.100s", strerror(errno));
#ifdef USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#অন্যথা
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#endif
		ফেরত -1;
	ক্ষেত্র 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		যদি (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		যদি (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		যদি (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		যদি (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#অন্যথা
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		যদি (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		যদি (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		যদি (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	পূর্বনির্ধারিত:
		বিরতি;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_মান);
#endif

	s->pid = pid;

	/*
	 * Clear loginmsg, since it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

#ifdef USE_PIPES
	/* We are the parent.  Close the child sides of the pipes. */
	close(pin[0]);
	close(pout[1]);
	close(perr[1]);

	session_set_fds(ssh, s, pin[1], pout[0], perr[0],
	    s->is_subsystem, 0);
#অন্যথা
	/* We are the parent.  Close the child sides of the socket pairs. */
	close(inout[0]);
	close(err[0]);

	/*
	 * Enter the interactive session.  Note: server_loop must be able to
	 * handle the case that fdin and fdout are the same.
	 */
	session_set_fds(ssh, s, inout[1], inout[1], err[1],
	    s->is_subsystem, 0);
#endif
	ফেরত 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
পূর্ণসংখ্যা
do_exec_pty(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *command)
{
	পূর্ণসংখ্যা fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	যদি (s == ফাঁকা)
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
	যদি ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		ফেরত -1;
	}
	/* we keep a reference to the pty master */
	যদি ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		ফেরত -1;
	}

	/* Fork the child. */
	নির্বাচন ((pid = fork())) {
	ক্ষেত্র -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		ফেরত -1;
	ক্ষেত্র 0:
		is_child = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		যদি (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		যদি (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		যদি (dup2(ttyfd, 2) == -1)
			error("dup2 stderr: %s", strerror(errno));

		/* Close the extra descriptor for the pseudo tty. */
		close(ttyfd);

		/* record login, etc. similar to login(1) */
#ifndef HAVE_OSF_SIA
		do_login(ssh, s, command);
#endif
		/*
		 * Do common processing for the child, such as execing
		 * the command.
		 */
		do_child(ssh, s, command);
		/* NOTREACHED */
	পূর্বনির্ধারিত:
		বিরতি;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_মান);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	ফেরত 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
পূর্ণসংখ্যা
do_exec(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *command)
{
	পূর্ণসংখ্যা ret;
	ধ্রুবক অক্ষর *forced = ফাঁকা, *tty = ফাঁকা;
	অক্ষর session_type[1024];

	যদি (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} অন্যথা যদি (auth_opts->force_command != ফাঁকা) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	যদি (forced != ফাঁকা) {
		s->forced = 1;
		যদি (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} অন্যথা যদি (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, আকার(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} অন্যথা যদি (s->is_subsystem) {
		snprintf(session_type, আকার(session_type),
		    "subsystem '%.900s'", s->subsys);
	} অন্যথা যদি (command == ফাঁকা) {
		snprintf(session_type, আকার(session_type), "shell");
	} অন্যথা {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, আকার(session_type), "command");
	}

	যদি (s->ttyfd != -1) {
		tty = s->tty;
		যদি (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == ফাঁকা ? "" : " on ",
	    tty == ফাঁকা ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	যদি (command != ফাঁকা)
		mm_audit_run_command(command);
	অন্যথা যদি (s->ttyfd == -1) {
		অক্ষর *shell = s->pw->pw_shell;

		যদি (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	যদি (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	অন্যথা
		ret = do_exec_no_pty(ssh, s, command);

	original_command = ফাঁকা;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	ফেরত ret;
}

/* administrative, login(1)-like work */
শূন্য
do_login(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *command)
{
	socklen_t fromlen;
	কাঠামো sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, আকার(from));
	fromlen = আকার(from);
	যদি (ssh_packet_connection_is_on_socket(ssh)) {
		যদি (getpeername(ssh_packet_get_connection_in(ssh),
		    (কাঠামো sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	যদি (check_quietlogin(s, command))
		ফেরত;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
শূন্য
do_motd(শূন্য)
{
	FILE *f;
	অক্ষর buf[256];

	যদি (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#অন্যথা
		f = fopen("/etc/motd", "r");
#endif
		যদি (f) {
			যখন (fgets(buf, আকার(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
পূর্ণসংখ্যা
check_quietlogin(Session *s, ধ্রুবক অক্ষর *command)
{
	অক্ষর buf[256];
	কাঠামো passwd *pw = s->pw;
	কাঠামো stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	যদি (command != ফাঁকা)
		ফেরত 1;
	snprintf(buf, আকার(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	যদি (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		ফেরত 1;
#অন্যথা
	যদি (stat(buf, &st) >= 0)
		ফেরত 1;
#endif
	ফেরত 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
স্থির শূন্য
read_environment_file(অক্ষর ***env, u_int *envsize,
	ধ্রুবক অক্ষর *filename, ধ্রুবক অক্ষর *allowlist)
{
	FILE *f;
	অক্ষর *সারি = ফাঁকা, *cp, *মান;
	আকার_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	যদি (!f)
		ফেরত;

	যখন (getline(&সারি, &linesize, f) != -1) {
		যদি (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		জন্য (cp = সারি; *cp == ' ' || *cp == '\t'; cp++)
			;
		যদি (!*cp || *cp == '#' || *cp == '\n')
			চালু;

		cp[strcspn(cp, "\n")] = '\0';

		মান = strchr(cp, '=');
		যদি (মান == ফাঁকা) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			চালু;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*মান = '\0';
		মান++;
		যদি (allowlist != ফাঁকা &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			চালু;
		child_set_env(env, envsize, cp, মান);
	}
	মুক্ত(সারি);
	fclose(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
স্থির অক্ষর *
child_get_env(অক্ষর **env, ধ্রুবক অক্ষর *name)
{
	পূর্ণসংখ্যা i;
	আকার_t len;

	len = strlen(name);
	জন্য (i=0; env[i] != ফাঁকা; i++)
		যদি (strncmp(name, env[i], len) == 0 && env[i][len] == '=')
			ফেরত(env[i] + len + 1);
	ফেরত ফাঁকা;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
স্থির শূন্য
read_etc_default_login(অক্ষর ***env, u_int *envsize, uid_t uid)
{
	অক্ষর **tmpenv = ফাঁকা, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	যদি (tmpenv == ফাঁকা)
		ফেরত;

	যদি (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	অন্যথা
		var = child_get_env(tmpenv, "PATH");
	যদি (var != ফাঁকা)
		child_set_env(env, envsize, "PATH", var);

	যদি ((var = child_get_env(tmpenv, "UMASK")) != ফাঁকা)
		যদি (sscanf(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	জন্য (i = 0; tmpenv[i] != ফাঁকা; i++)
		মুক্ত(tmpenv[i]);
	মুক্ত(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#যদি defined(USE_PAM) || defined(HAVE_CYGWIN)
স্থির শূন্য
copy_environment_denylist(অক্ষর **source, অক্ষর ***env, u_int *envsize,
    ধ্রুবক অক্ষর *denylist)
{
	অক্ষর *var_name, *var_val;
	পূর্ণসংখ্যা i;

	যদি (source == ফাঁকা)
		ফেরত;

	জন্য(i = 0; source[i] != ফাঁকা; i++) {
		var_name = xstrdup(source[i]);
		যদি ((var_val = strstr(var_name, "=")) == ফাঁকা) {
			মুক্ত(var_name);
			চালু;
		}
		*var_val++ = '\0';

		যদি (denylist == ফাঁকা ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		মুক্ত(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
স্থির শূন্য
copy_environment(অক্ষর **source, অক্ষর ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, ফাঁকা);
}
#endif

স্থির অক্ষর **
do_setup_env(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *shell)
{
	অক্ষর buf[256];
	আকার_t n;
	u_int i, envsize;
	অক্ষর *ocp, *cp, *মান, **env, *laddr;
	কাঠামো passwd *pw = s->pw;
#যদি !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	অক্ষর *path = ফাঁকা;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, আকার(অক্ষর *));
	env[0] = ফাঁকা;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		অক্ষর **p;

		p = fetch_windows_environment();
		copy_environment(p, &env, &envsize);
		free_windows_environment(p);
	}
#endif

#ifdef GSSAPI
	/* Allow any GSSAPI methods that we've used to alter
	 * the child's environment as they see fit
	 */
	ssh_gssapi_do_child(&env, &envsize);
#endif

	/* Set basic environment. */
	জন্য (i = 0; i < s->অঙ্ক_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	যদি (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	অন্যথা
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#অন্যথা /* HAVE_LOGIN_CAP */
# ifndef HAVE_CYGWIN
	/*
	 * There's no standard path on Windows. The path contains
	 * important components pointing to the system directories,
	 * needed for loading shared libraries. So the path better
	 * remains intact here.
	 */
#  ifdef HAVE_ETC_DEFAULT_LOGIN
	read_etc_default_login(&env, &envsize, pw->pw_uid);
	path = child_get_env(env, "PATH");
#  endif /* HAVE_ETC_DEFAULT_LOGIN */
	যদি (path == ফাঁকা || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	যদি (!options.use_pam) {
		snprintf(buf, আকার buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	যদি (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
#ifdef HAVE_LOGIN_CAP
	যদি (getenv("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	যদি (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	যদি (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		অক্ষর *cp;

		যদি ((cp = getenv("KRB5CCNAME")) != ফাঁকা)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		অক্ষর *cp;

		যদি ((cp = getenv("AUTHSTATE")) != ফাঁকা)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	যদি (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	যদি (auth_sock_name != ফাঁকা)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	যদি (options.permit_user_env) {
		জন্য (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			যদি (cp != ফাঁকা) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				যদি (options.permit_user_env_allowlist == ফাঁকা ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			মুক্ত(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	যদি (options.permit_user_env) {
		snprintf(buf, আকার buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	যদি (options.use_pam) {
		অক্ষর **p;

		/*
		 * Don't allow PAM-internal env vars to leak
		 * back into the session environment.
		 */
#define PAM_ENV_DENYLIST  "SSH_AUTH_INFO*,SSH_CONNECTION*"
		p = fetch_pam_child_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);

		p = fetch_pam_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);
	}
#endif /* USE_PAM */

	/* Environment specified by admin */
	জন্য (i = 0; i < options.অঙ্ক_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		যদি ((মান = strchr(cp, '=')) == ফাঁকা) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*মান++ = '\0';
		child_set_env(&env, &envsize, cp, মান);
		মুক্ত(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, আকার buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, আকার buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	মুক্ত(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	যদি (tun_fwd_ifnames != ফাঁকা)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	যদি (auth_info_file != ফাঁকা)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	যদি (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	যদি (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	যদি (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		জন্য (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	ফেরত env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
স্থির শূন্য
do_rc_files(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *shell)
{
	FILE *f = ফাঁকা;
	অক্ষর *cmd = ফাঁকা, *user_rc = ফাঁকা;
	পূর্ণসংখ্যা do_xauth;
	কাঠামো stat st;

	do_xauth =
	    s->display != ফাঁকা && s->auth_proto != ফাঁকা && s->auth_তথ্য != ফাঁকা;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	যদি (!s->is_subsystem && options.adm_forced_command == ফাঁকা &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		যদি (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		যদি (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		যদি (f) {
			যদি (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_তথ্য);
			pclose(f);
		} অন্যথা
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} অন্যথা যদি (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		যদি (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		যদি (f) {
			যদি (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_তথ্য);
			pclose(f);
		} অন্যথা
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} অন্যথা যদি (do_xauth && options.xauth_location != ফাঁকা) {
		/* Add authority data to .Xauthority if appropriate. */
		যদি (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_তথ্য);
		}
		যদি (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		যদি (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_তথ্য);
			pclose(f);
		} অন্যথা {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	মুক্ত(cmd);
	মুক্ত(user_rc);
}

স্থির শূন্য
do_nologin(কাঠামো passwd *pw)
{
	FILE *f = ফাঁকা;
	অক্ষর buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	কাঠামো stat sb;

#ifdef HAVE_LOGIN_CAP
	যদি (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		ফেরত;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#অন্যথা
	যদি (pw->pw_uid == 0)
		ফেরত;
	nl = def_nl;
#endif
	যদি (stat(nl, &sb) == -1)
		ফেরত;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	যদি ((f = fopen(nl, "r")) != ফাঁকা) {
		যখন (fgets(buf, আকার(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
স্থির শূন্য
safely_chroot(ধ্রুবক অক্ষর *path, uid_t uid)
{
	ধ্রুবক অক্ষর *cp;
	অক্ষর component[PATH_MAX];
	কাঠামো stat st;

	যদি (!path_absolute(path))
		fatal("chroot path does not begin at root");
	যদি (strlen(path) >= আকার(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	জন্য (cp = path; cp != ফাঁকা;) {
		যদি ((cp = strchr(cp, '/')) == ফাঁকা)
			strlcpy(component, path, আকার(component));
		অন্যথা {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		যদি (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		যদি (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ফাঁকা ? "" : "component ", component);
		যদি (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ফাঁকা ? "" : "component ", component);

	}

	যদি (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	যদি (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	যদি (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
শূন্য
do_setusercontext(কাঠামো passwd *pw)
{
	অক্ষর uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	যদি (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		যদি (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			exit(1);
		}
#অন্যথা
		যদি (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		যদি (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			exit(1);
		}
		/* Initialize the group list. */
		যদি (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			exit(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		যদি (!in_chroot && options.chroot_directory != ফাঁকা &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, আকার(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (অক্ষর *)ফাঁকা);
			safely_chroot(chroot_path, pw->pw_uid);
			মুক্ত(tmp);
			মুক্ত(chroot_path);
			/* Make sure we don't attempt to chroot again */
			মুক্ত(options.chroot_directory);
			options.chroot_directory = ফাঁকা;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		যদি (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			exit(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(শূন্য) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#অন্যথা
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		যদি (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} অন্যথা যদি (options.chroot_directory != ফাঁকা &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	যদি (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

স্থির শূন্য
do_pwchange(Session *s)
{
	fflush(ফাঁকা);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	যদি (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(ফাঁকা);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (অক্ষর *)ফাঁকা);
#অন্যথা
		execl(_PATH_PASSWD_PROG, "passwd", (অক্ষর *)ফাঁকা);
#endif
		perror("passwd");
	} অন্যথা {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	exit(1);
}

স্থির শূন্য
child_close_fds(কাঠামো ssh *ssh)
{
	বাহ্যিক পূর্ণসংখ্যা auth_sock;

	যদি (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	যদি (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	অন্যথা {
		close(ssh_packet_get_connection_in(ssh));
		close(ssh_packet_get_connection_out(ssh));
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
	log_redirect_stderr_to(ফাঁকা);

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
#define ARGV_MAX 10
শূন্য
do_child(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *command)
{
	বাহ্যিক অক্ষর **environ;
	অক্ষর **env, *argv[ARGV_MAX], remote_id[512];
	ধ্রুবক অক্ষর *shell, *shell0;
	কাঠামো passwd *pw = s->pw;
	পূর্ণসংখ্যা r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, আকার(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_চাবিগুলি(ssh);

	/* Force a password change */
	যদি (s->authctxt->force_pwchange) {
		do_setusercontext(pw);
		child_close_fds(ssh);
		do_pwchange(s);
		exit(1);
	}

	/*
	 * Login(1) does this as well, and it needs uid 0 for the "-h"
	 * switch, so we let login(1) to this for us.
	 */
#ifdef HAVE_OSF_SIA
	session_setup_sia(pw, s->ttyfd == -1 ? ফাঁকা : s->tty);
	যদি (!check_quietlogin(s, command))
		do_motd();
#অন্যথা /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	যদি (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	যদি (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	যদি (options.use_pam && !is_pam_session_open()) {
		debug3("PAM session not opened, exiting");
		display_loginmsg();
		exit(254);
	}
#endif

	/*
	 * Get the shell from the password data.  An empty shell field is
	 * legal, and means /bin/sh.
	 */
	shell = (pw->pw_shell[0] == '\0') ? _PATH_BSHELL : pw->pw_shell;

	/*
	 * Make sure $SHELL points to the shell from the password file,
	 * even if shell is overridden from login.conf
	 */
	env = do_setup_env(ssh, s, shell);

#ifdef HAVE_LOGIN_CAP
	shell = login_getcapstr(lc, "shell", (অক্ষর *)shell, (অক্ষর *)shell);
#endif

	/*
	 * Close the connection descriptors; note that this is the child, and
	 * the server will still have the socket open, and it is important
	 * that we do not shutdown it.  Note that the descriptors cannot be
	 * closed before building the environment, as we call
	 * ssh_remote_ipaddr there.
	 */
	child_close_fds(ssh);

	/*
	 * Must take new environment into use so that .ssh/rc,
	 * /etc/ssh/sshrc and xauth are run in the proper environment.
	 */
	environ = env;

#যদি defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	যদি (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != ফাঁকা)) {
		অক্ষর cell[64];

		debug("Getting AFS token");

		k_setpag();

		যদি (k_afs_cell_of_file(pw->pw_dir, cell, আকার(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, ফাঁকা);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, ফাঁকা, ফাঁকা, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	যদি (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		যদি (r || !in_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		যদি (r)
			exit(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	যদি (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(ফাঁকা);
		exit(1);
	} অন্যথা যদি (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		বাহ্যিক পূর্ণসংখ্যা optind, optreset;
		পূর্ণসংখ্যা sftp_argc;
		অক্ষর **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		যদি (argv_split(command == ফাঁকা ? "sftp-server" : command,
		    &sftp_argc, &sftp_argv, 1) != 0) {
			error("internal error: can't split internal-sftp "
			    "arguments");
			exit(1);
		}
		optind = optreset = 1;
		__progname = sftp_argv[0];
#ifdef WITH_SELINUX
		ssh_selinux_change_context("sftpd_t");
#endif
		exit(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}

	fflush(ফাঁকা);

	/* Get the last component of the shell name. */
	যদি ((shell0 = strrchr(shell, '/')) != ফাঁকা)
		shell0++;
	অন্যথা
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	যদি (!command) {
		অক্ষর argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		যদি (strlcpy(argv0 + 1, shell0, আকার(argv0) - 1)
		    >= আকার(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = ফাঁকা;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (অক্ষর *) shell0;
	argv[1] = "-c";
	argv[2] = (অক্ষর *) command;
	argv[3] = ফাঁকা;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

শূন্য
session_unused(পূর্ণসংখ্যা id)
{
	debug3_f("session id %d unused", id);
	যদি (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, আকার(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = ফাঁকা;
	sessions[id].পরবর্তী_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(শূন্য)
{
	Session *s, *tmp;

	যদি (sessions_first_unused == -1) {
		যদি (sessions_nalloc >= options.max_sessions)
			ফেরত ফাঁকা;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, আকার(*sessions));
		যদি (tmp == ফাঁকা) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			ফেরত ফাঁকা;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	যদি (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	যদি (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->পরবর্তী_unused;
	s->used = 1;
	s->পরবর্তী_unused = -1;
	debug("session_new: session %d", s->self);

	ফেরত s;
}

স্থির শূন্য
session_dump(শূন্য)
{
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->used,
		    s->পরবর্তী_unused,
		    s->self,
		    s->chanid,
		    (long)s->pid);
	}
}

পূর্ণসংখ্যা
session_open(Authctxt *authctxt, পূর্ণসংখ্যা chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	যদি (s == ফাঁকা) {
		error("no more sessions");
		ফেরত 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	যদি (s->pw == ফাঁকা || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	ফেরত 1;
}

Session *
session_by_tty(অক্ষর *tty)
{
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		যদি (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			ফেরত s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	ফেরত ফাঁকা;
}

স্থির Session *
session_by_channel(পূর্ণসংখ্যা id)
{
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		যদি (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			ফেরত s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	ফেরত ফাঁকা;
}

স্থির Session *
session_by_x11_channel(পূর্ণসংখ্যা id)
{
	পূর্ণসংখ্যা i, j;

	জন্য (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		যদি (s->x11_chanids == ফাঁকা || !s->used)
			চালু;
		জন্য (j = 0; s->x11_chanids[j] != -1; j++) {
			যদি (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				ফেরত s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	ফেরত ফাঁকা;
}

স্থির Session *
session_by_pid(pid_t pid)
{
	পূর্ণসংখ্যা i;
	debug("session_by_pid: pid %ld", (long)pid);
	জন্য (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		যদি (s->used && s->pid == pid)
			ফেরত s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	ফেরত ফাঁকা;
}

স্থির পূর্ণসংখ্যা
session_window_change_req(কাঠামো ssh *ssh, Session *s)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_আকার(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
session_pty_req(কাঠামো ssh *ssh, Session *s)
{
	পূর্ণসংখ্যা r;

	যদি (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		ফেরত 0;
	}
	যদি (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		ফেরত 0;
	}

	যদি ((r = sshpkt_get_cstring(ssh, &s->term, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	যদি (strcmp(s->term, "") == 0) {
		মুক্ত(s->term);
		s->term = ফাঁকা;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	যদি (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, আকার(s->tty))) {
		মুক্ত(s->term);
		s->term = ফাঁকা;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		ফেরত 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	যদি ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_আকার(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
session_subsystem_req(কাঠামো ssh *ssh, Session *s)
{
	কাঠামো stat st;
	পূর্ণসংখ্যা r, success = 0, found = 0;
	অক্ষর *prog, *cmd, *type;
	u_int i;

	যদি ((r = sshpkt_get_cstring(ssh, &s->subsys, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	জন্য (i = 0; i < options.অঙ্ক_subsystems; i++) {
		যদি (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			চালু;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		যদি (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} অন্যথা {
			যদি (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		মুক্ত(type);
		success = do_exec(ssh, s, cmd) == 0;
		বিরতি;
	}

	যদি (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	ফেরত success;
}

স্থির পূর্ণসংখ্যা
session_x11_req(কাঠামো ssh *ssh, Session *s)
{
	পূর্ণসংখ্যা r, success;
	u_char single_connection = 0;

	যদি (s->auth_proto != ফাঁকা || s->auth_তথ্য != ফাঁকা) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		ফেরত 0;
	}
	যদি ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_তথ্য, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	যদি (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_তথ্য))
		success = session_setup_x11fwd(ssh, s);
	অন্যথা {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	যদি (!success) {
		মুক্ত(s->auth_proto);
		মুক্ত(s->auth_তথ্য);
		s->auth_proto = ফাঁকা;
		s->auth_তথ্য = ফাঁকা;
	}
	ফেরত success;
}

স্থির পূর্ণসংখ্যা
session_shell_req(কাঠামো ssh *ssh, Session *s)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	ফেরত do_exec(ssh, s, ফাঁকা) == 0;
}

স্থির পূর্ণসংখ্যা
session_exec_req(কাঠামো ssh *ssh, Session *s)
{
	u_int success;
	পূর্ণসংখ্যা r;
	অক্ষর *command = ফাঁকা;

	যদি ((r = sshpkt_get_cstring(ssh, &command, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	মুক্ত(command);
	ফেরত success;
}

স্থির পূর্ণসংখ্যা
session_break_req(কাঠামো ssh *ssh, Session *s)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_get_u32(ssh, ফাঁকা)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	যদি (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		ফেরত 0;
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
session_env_req(কাঠামো ssh *ssh, Session *s)
{
	অক্ষর *name, *val;
	u_int i;
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_get_cstring(ssh, &name, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	যদি (s->অঙ্ক_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		যাও fail;
	}

	জন্য (i = 0; i < options.অঙ্ক_accept_env; i++) {
		যদি (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->অঙ্ক_env, name, val);
			s->env = xrecallocarray(s->env, s->অঙ্ক_env,
			    s->অঙ্ক_env + 1, আকার(*s->env));
			s->env[s->অঙ্ক_env].name = name;
			s->env[s->অঙ্ক_env].val = val;
			s->অঙ্ক_env++;
			ফেরত (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	মুক্ত(name);
	মুক্ত(val);
	ফেরত (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
স্থির পূর্ণসংখ্যা
name2sig(অক্ষর *name)
{
#define SSH_SIG(x) যদি (strcmp(name, #x) == 0) ফেরত SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	যদি (strcmp(name, "INFO@openssh.com") == 0)
		ফেরত SIGINFO;
#endif
	ফেরত -1;
}

স্থির পূর্ণসংখ্যা
session_signal_req(কাঠামো ssh *ssh, Session *s)
{
	অক্ষর *signame = ফাঁকা;
	পূর্ণসংখ্যা r, sig, success = 0;

	যদি ((r = sshpkt_get_cstring(ssh, &signame, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		যাও out;
	}
	যদি ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		যাও out;
	}
	যদি (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		যাও out;
	}
	যদি (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		যাও out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (long)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	যদি (r != 0) {
		error_f("killpg(%ld, %d): %s", (long)s->pid,
		    sig, strerror(errno));
		যাও out;
	}

	/* success */
	success = 1;
 out:
	মুক্ত(signame);
	ফেরত success;
}

স্থির পূর্ণসংখ্যা
session_auth_agent_req(কাঠামো ssh *ssh, Session *s, পূর্ণসংখ্যা agent_new)
{
	স্থির পূর্ণসংখ্যা called = 0;
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	যদি (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		ফেরত 0;
	}
	যদি (called)
		ফেরত 0;

	called = 1;
	ফেরত auth_প্রবেশ_request_forwarding(ssh, s->pw, agent_new);
}

পূর্ণসংখ্যা
session_প্রবেশ_channel_req(কাঠামো ssh *ssh, Channel *c, ধ্রুবক অক্ষর *rtype)
{
	পূর্ণসংখ্যা success = 0;
	Session *s;

	যদি ((s = session_by_channel(c->self)) == ফাঁকা) {
		logit_f("no session %d req %.100s", c->self, rtype);
		ফেরত 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	যদি (c->type == SSH_CHANNEL_LARVAL) {
		যদি (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} অন্যথা যদি (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} অন্যথা যদি (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} অন্যথা যদি (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} অন্যথা যদি (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} অন্যথা যদি (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} অন্যথা যদি (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} অন্যথা যদি (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	যদি (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} অন্যথা যদি (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} অন্যথা যদি (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	ফেরত success;
}

শূন্য
session_set_fds(কাঠামো ssh *ssh, Session *s,
    পূর্ণসংখ্যা fdin, পূর্ণসংখ্যা fdout, পূর্ণসংখ্যা fderr, পূর্ণসংখ্যা ignore_fderr, পূর্ণসংখ্যা is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	যদি (s->chanid == -1)
		fatal("no channel for session %d", s->self);
	channel_set_fds(ssh, s->chanid,
	    fdout, fdin, fderr,
	    ignore_fderr ? CHAN_EXTENDED_IGNORE : CHAN_EXTENDED_READ,
	    1, is_tty, CHAN_SES_WINDOW_DEFAULT);
}

/*
 * Function to perform pty cleanup. Also called if we get aborted abnormally
 * (e.g., due to a dropped connection).
 */
শূন্য
session_pty_cleanup2(Session *s)
{
	যদি (s == ফাঁকা) {
		error_f("no session");
		ফেরত;
	}
	যদি (s->ttyfd == -1)
		ফেরত;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	যদি (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	যদি (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	যদি (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

শূন্য
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

স্থির অক্ষর *
sig2name(পূর্ণসংখ্যা sig)
{
#define SSH_SIG(x) যদি (sig == SIG ## x) ফেরত #x
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
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
	ফেরত "SIG@openssh.com";
}

স্থির শূন্য
session_close_x11(কাঠামো ssh *ssh, পূর্ণসংখ্যা id)
{
	Channel *c;

	যদি ((c = channel_by_id(ssh, id)) == ফাঁকা) {
		debug_f("x11 channel %d missing", id);
	} অন্যথা {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		যদি (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

স্থির শূন্য
session_close_single_x11(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা force, শূন্য *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	যদি ((s = session_by_x11_channel(id)) == ফাঁকা)
		fatal_f("no x11 channel %d", id);
	জন্য (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		যদি (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	মুক্ত(s->x11_chanids);
	s->x11_chanids = ফাঁকা;
	মুক্ত(s->display);
	s->display = ফাঁকা;
	মুক্ত(s->auth_proto);
	s->auth_proto = ফাঁকা;
	মুক্ত(s->auth_তথ্য);
	s->auth_তথ্য = ফাঁকা;
	মুক্ত(s->auth_display);
	s->auth_display = ফাঁকা;
}

স্থির শূন্য
session_exit_message(কাঠামো ssh *ssh, Session *s, পূর্ণসংখ্যা status)
{
	Channel *c;
	পূর্ণসংখ্যা r;
	অক্ষর *note = ফাঁকা;

	যদি ((c = channel_lookup(ssh, s->chanid)) == ফাঁকা)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	যদি (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		যদি ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} অন্যথা যদি (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		যদি ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} অন্যথা {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (long)s->pid, note == ফাঁকা ? "UNKNOWN" : note);
	মুক্ত(note);

	/* disconnect channel */
	debug_f("release channel %d", s->chanid);

	/*
	 * Adjust cleanup callback attachment to send close messages when
	 * the channel gets EOF. The session will be then be closed
	 * by session_close_by_channel when the child sessions close their fds.
	 */
	channel_register_cleanup(ssh, c->self, session_close_by_channel, 1);

	/*
	 * emulate a write failure with 'chan_write_failed', nobody will be
	 * interested in data we write.
	 * Note that we must not call 'chan_read_failed', since there could
	 * be some more data waiting in the pipe.
	 */
	যদি (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

শূন্য
session_close(কাঠামো ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	যদি (s->ttyfd != -1)
		session_pty_cleanup(s);
	মুক্ত(s->term);
	মুক্ত(s->display);
	মুক্ত(s->x11_chanids);
	মুক্ত(s->auth_display);
	মুক্ত(s->auth_তথ্য);
	মুক্ত(s->auth_proto);
	মুক্ত(s->subsys);
	যদি (s->env != ফাঁকা) {
		জন্য (i = 0; i < s->অঙ্ক_env; i++) {
			মুক্ত(s->env[i].name);
			মুক্ত(s->env[i].val);
		}
		মুক্ত(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

শূন্য
session_close_by_pid(কাঠামো ssh *ssh, pid_t pid, পূর্ণসংখ্যা status)
{
	Session *s = session_by_pid(pid);
	যদি (s == ফাঁকা) {
		debug_f("no session for pid %ld", (long)pid);
		ফেরত;
	}
	যদি (s->chanid != -1)
		session_exit_message(ssh, s, status);
	যদি (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
শূন্য
session_close_by_channel(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা force, শূন্য *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	যদি (s == ফাঁকা) {
		debug_f("no session for id %d", id);
		ফেরত;
	}
	debug_f("channel %d child %ld", id, (long)s->pid);
	যদি (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		যদি (s->ttyfd != -1)
			session_pty_cleanup(s);
		যদি (!force)
			ফেরত;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	যদি (s->x11_chanids != ফাঁকা) {
		জন্য (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

শূন্য
session_destroy_all(কাঠামো ssh *ssh, শূন্য (*closefunc)(Session *))
{
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		যদি (s->used) {
			যদি (closefunc != ফাঁকা)
				closefunc(s);
			অন্যথা
				session_close(ssh, s);
		}
	}
}

স্থির অক্ষর *
session_tty_list(শূন্য)
{
	স্থির অক্ষর buf[1024];
	পূর্ণসংখ্যা i;
	অক্ষর *cp;

	buf[0] = '\0';
	জন্য (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		যদি (s->used && s->ttyfd != -1) {

			যদি (strncmp(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == ফাঁকা) ? s->tty : cp + 1;
			} অন্যথা
				cp = s->tty + 5;

			যদি (buf[0] != '\0')
				strlcat(buf, ",", আকার buf);
			strlcat(buf, cp, আকার buf);
		}
	}
	যদি (buf[0] == '\0')
		strlcpy(buf, "notty", আকার buf);
	ফেরত buf;
}

শূন্য
session_proctitle(Session *s)
{
	যদি (s->pw == ফাঁকা)
		error("no user for session %d", s->self);
	অন্যথা
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

পূর্ণসংখ্যা
session_setup_x11fwd(কাঠামো ssh *ssh, Session *s)
{
	কাঠামো stat st;
	অক্ষর display[512], auth_display[512];
	অক্ষর hostname[NI_MAXHOST];
	u_int i;

	যদি (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		ফেরত 0;
	}
	যদি (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		ফেরত 0;
	}
	যদি (options.xauth_location == ফাঁকা ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		ফেরত 0;
	}
	যদি (s->display != ফাঁকা) {
		debug("X11 display already set.");
		ফেরত 0;
	}
	যদি (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_সংখ্যা, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		ফেরত 0;
	}
	জন্য (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	যদি (gethostname(hostname, আকার(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	যদি (options.x11_use_localhost) {
		snprintf(display, আকার display, "localhost:%u.%u",
		    s->display_সংখ্যা, s->screen);
		snprintf(auth_display, আকার auth_display, "unix:%u.%u",
		    s->display_সংখ্যা, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} অন্যথা {
#ifdef IPADDR_IN_DISPLAY
		কাঠামো hostent *he;
		কাঠামো in_addr my_addr;

		he = gethostbyname(hostname);
		যদি (he == ফাঁকা) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			ফেরত 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], আকার(কাঠামো in_addr));
		snprintf(display, আকার display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_সংখ্যা, s->screen);
#অন্যথা
		snprintf(display, আকার display, "%.400s:%u.%u", hostname,
		    s->display_সংখ্যা, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	ফেরত 1;
}

স্থির শূন্য
do_authenticated2(কাঠামো ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

শূন্য
do_cleanup(কাঠামো ssh *ssh, Authctxt *authctxt)
{
	স্থির পূর্ণসংখ্যা called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	যদি (is_child)
		ফেরত;

	/* avoid double cleanup */
	যদি (called)
		ফেরত;
	called = 1;

	যদি (authctxt == ফাঁকা)
		ফেরত;

#ifdef USE_PAM
	যদি (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	যদি (!authctxt->authenticated)
		ফেরত;

#ifdef KRB5
	যদি (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	যদি (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	যদি (auth_info_file != ফাঁকা) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		মুক্ত(auth_info_file);
		auth_info_file = ফাঁকা;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	যদি (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

ধ্রুবক অক্ষর *
session_get_remote_name_or_ip(কাঠামো ssh *ssh, u_int utmp_আকার, পূর্ণসংখ্যা use_dns)
{
	ধ্রুবক অক্ষর *remote = "";

	যদি (utmp_আকার > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	যদি (utmp_আকার == 0 || strlen(remote) > utmp_আকার)
		remote = ssh_remote_ipaddr(ssh);
	ফেরত remote;
}

