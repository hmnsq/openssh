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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/wait.h>
#شامل <sys/un.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/queue.h>

#شامل <arpa/inet.h>

#شامل <ctype.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <grp.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>
#شامل <limits.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "sshpty.h"
#شامل "packet.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "match.h"
#شامل "uidswap.h"
#شامل "channels.h"
#شامل "sshkey.h"
#شامل "cipher.h"
#شامل "kex.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-options.h"
#شامل "authfd.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "sshlogin.h"
#شامل "serverloop.h"
#شامل "canohost.h"
#شامل "session.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "sftp.h"
#شامل "atomicio.h"

#اگر defined(KRB5) && defined(USE_AFS)
#شامل <kafs.h>
#endif

#ifdef WITH_SELINUX
#شامل <selinux/selinux.h>
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
	(!strncmp(c, INTERNAL_SFTP_NAME, اندازه(INTERNAL_SFTP_NAME) - 1) && \
	 (c[اندازه(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[اندازه(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[اندازه(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(تهی);
تهی	session_set_fds(ساختار ssh *, Session *, صحیح, صحیح, صحیح, صحیح, صحیح);
تهی	session_pty_cleanup(Session *);
تهی	session_proctitle(Session *);
صحیح	session_setup_x11fwd(ساختار ssh *, Session *);
صحیح	do_exec_pty(ساختار ssh *, Session *, ثابت نویسه *);
صحیح	do_exec_no_pty(ساختار ssh *, Session *, ثابت نویسه *);
صحیح	do_exec(ساختار ssh *, Session *, ثابت نویسه *);
تهی	do_login(ساختار ssh *, Session *, ثابت نویسه *);
تهی	do_child(ساختار ssh *, Session *, ثابت نویسه *);
تهی	do_motd(تهی);
صحیح	check_quietlogin(Session *, ثابت نویسه *);

ایستا تهی do_authenticated2(ساختار ssh *, Authctxt *);

ایستا صحیح session_pty_req(ساختار ssh *, Session *);

/* import */
بیرونی ServerOptions options;
بیرونی نویسه *__progname;
بیرونی صحیح debug_flag;
بیرونی ساختار sshbuf *loginmsg;
بیرونی ساختار sshauthopt *auth_opts;
بیرونی نویسه *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
ثابت نویسه *original_command = پوچ;

/* data */
ایستا صحیح sessions_first_unused = -1;
ایستا صحیح sessions_nalloc = 0;
ایستا Session *sessions = پوچ;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

ایستا صحیح is_child = 0;
ایستا صحیح in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
ایستا نویسه *auth_info_file = پوچ;

/* Name and directory of socket for authentication agent forwarding. */
ایستا نویسه *auth_sock_name = پوچ;
ایستا نویسه *auth_sock_dir = پوچ; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

ایستا تهی
auth_sock_cleanup_proc(ساختار passwd *pw)
{
	اگر (auth_sock_name != پوچ) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		آزاد(auth_sock_name);
		auth_sock_name = پوچ;
		restore_uid();
	}
}

ایستا صحیح
auth_درون_داد_request_forwarding(ساختار ssh *ssh, ساختار passwd *pw, صحیح agent_new)
{
	Channel *nc;
	صحیح sock = -1;

	اگر (auth_sock_name != پوچ) {
		error("authentication forwarding requested twice.");
		بازگشت 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	اگر (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		برو authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	بازگشت 1;

 authsock_err:
	آزاد(auth_sock_name);
	اگر (sock != -1)
		close(sock);
	auth_sock_name = پوچ;
	بازگشت 0;
}

ایستا تهی
display_loginmsg(تهی)
{
	صحیح r;

	اگر (sshbuf_len(loginmsg) == 0)
		بازگشت;
	اگر ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	printf("%s", (نویسه *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

ایستا تهی
prepare_auth_info_file(ساختار passwd *pw, ساختار sshbuf *info)
{
	صحیح fd = -1, success = 0;

	اگر (!options.expose_userauth_info || info == پوچ)
		بازگشت;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	اگر ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		برو out;
	}
	اگر (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		برو out;
	}
	اگر (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		برو out;
	}
	success = 1;
 out:
	اگر (!success) {
		اگر (fd != -1)
			close(fd);
		آزاد(auth_info_file);
		auth_info_file = پوچ;
	}
	restore_uid();
}

ایستا تهی
set_fwdpermit_from_authopts(ساختار ssh *ssh, ثابت ساختار sshauthopt *opts)
{
	نویسه *tmp, *cp, *host;
	صحیح port;
	size_t i;

	اگر ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		برای (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			اگر ((host = hpdelim2(&cp, پوچ)) == پوچ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			اگر (cp == پوچ || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			آزاد(tmp);
		}
	}
	اگر ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		برای (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			اگر ((host = hpdelim(&cp)) == پوچ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			اگر (cp == پوچ || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			آزاد(tmp);
		}
	}
}

تهی
do_authenticated(ساختار ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	اگر (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} وگرنه {
		اگر ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		وگرنه
			channel_permit_all(ssh, FORWARD_LOCAL);
		اگر ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		وگرنه
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
ایستا صحیح
xauth_valid_string(ثابت نویسه *s)
{
	size_t i;

	برای (i = 0; s[i] != '\0'; i++) {
		اگر (!isalnum((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			بازگشت 0;
	}
	بازگشت 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
صحیح
do_exec_no_pty(ساختار ssh *ssh, Session *s, ثابت نویسه *command)
{
	pid_t pid;
#ifdef USE_PIPES
	صحیح pin[2], pout[2], perr[2];

	اگر (s == پوچ)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	اگر (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		بازگشت -1;
	}
	اگر (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		بازگشت -1;
	}
	اگر (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		بازگشت -1;
	}
#وگرنه
	صحیح inout[2], err[2];

	اگر (s == پوچ)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		بازگشت -1;
	}
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		بازگشت -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	انتخاب ((pid = fork())) {
	حالت -1:
		error_f("fork: %.100s", strerror(errno));
#ifdef USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#وگرنه
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#endif
		بازگشت -1;
	حالت 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		اگر (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		اگر (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		اگر (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		اگر (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#وگرنه
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		اگر (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		اگر (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		اگر (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	پیشفرض:
		بشکن;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_مقدار);
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
#وگرنه
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
	بازگشت 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
صحیح
do_exec_pty(ساختار ssh *ssh, Session *s, ثابت نویسه *command)
{
	صحیح fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	اگر (s == پوچ)
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
	اگر ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		بازگشت -1;
	}
	/* we keep a reference to the pty master */
	اگر ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		بازگشت -1;
	}

	/* Fork the child. */
	انتخاب ((pid = fork())) {
	حالت -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		بازگشت -1;
	حالت 0:
		is_child = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		اگر (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		اگر (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		اگر (dup2(ttyfd, 2) == -1)
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
	پیشفرض:
		بشکن;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_مقدار);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	بازگشت 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
صحیح
do_exec(ساختار ssh *ssh, Session *s, ثابت نویسه *command)
{
	صحیح ret;
	ثابت نویسه *forced = پوچ, *tty = پوچ;
	نویسه session_type[1024];

	اگر (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} وگرنه اگر (auth_opts->force_command != پوچ) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	اگر (forced != پوچ) {
		s->forced = 1;
		اگر (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} وگرنه اگر (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, اندازه(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} وگرنه اگر (s->is_subsystem) {
		snprintf(session_type, اندازه(session_type),
		    "subsystem '%.900s'", s->subsys);
	} وگرنه اگر (command == پوچ) {
		snprintf(session_type, اندازه(session_type), "shell");
	} وگرنه {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, اندازه(session_type), "command");
	}

	اگر (s->ttyfd != -1) {
		tty = s->tty;
		اگر (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == پوچ ? "" : " on ",
	    tty == پوچ ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	اگر (command != پوچ)
		mm_audit_run_command(command);
	وگرنه اگر (s->ttyfd == -1) {
		نویسه *shell = s->pw->pw_shell;

		اگر (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	اگر (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	وگرنه
		ret = do_exec_no_pty(ssh, s, command);

	original_command = پوچ;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	بازگشت ret;
}

/* administrative, login(1)-like work */
تهی
do_login(ساختار ssh *ssh, Session *s, ثابت نویسه *command)
{
	socklen_t fromlen;
	ساختار sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, اندازه(from));
	fromlen = اندازه(from);
	اگر (ssh_packet_connection_is_on_socket(ssh)) {
		اگر (getpeername(ssh_packet_get_connection_in(ssh),
		    (ساختار sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	اگر (check_quietlogin(s, command))
		بازگشت;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
تهی
do_motd(تهی)
{
	FILE *f;
	نویسه buf[256];

	اگر (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#وگرنه
		f = fopen("/etc/motd", "r");
#endif
		اگر (f) {
			وقتی (fgets(buf, اندازه(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
صحیح
check_quietlogin(Session *s, ثابت نویسه *command)
{
	نویسه buf[256];
	ساختار passwd *pw = s->pw;
	ساختار stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	اگر (command != پوچ)
		بازگشت 1;
	snprintf(buf, اندازه(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	اگر (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		بازگشت 1;
#وگرنه
	اگر (stat(buf, &st) >= 0)
		بازگشت 1;
#endif
	بازگشت 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
ایستا تهی
read_environment_file(نویسه ***env, u_int *envsize,
	ثابت نویسه *filename, ثابت نویسه *allowlist)
{
	FILE *f;
	نویسه *سطر = پوچ, *cp, *مقدار;
	size_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	اگر (!f)
		بازگشت;

	وقتی (getline(&سطر, &linesize, f) != -1) {
		اگر (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		برای (cp = سطر; *cp == ' ' || *cp == '\t'; cp++)
			;
		اگر (!*cp || *cp == '#' || *cp == '\n')
			ادامه;

		cp[strcspn(cp, "\n")] = '\0';

		مقدار = strchr(cp, '=');
		اگر (مقدار == پوچ) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			ادامه;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*مقدار = '\0';
		مقدار++;
		اگر (allowlist != پوچ &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			ادامه;
		child_set_env(env, envsize, cp, مقدار);
	}
	آزاد(سطر);
	fclose(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
ایستا نویسه *
child_get_env(نویسه **env, ثابت نویسه *name)
{
	صحیح i;
	size_t len;

	len = strlen(name);
	برای (i=0; env[i] != پوچ; i++)
		اگر (strncmp(name, env[i], len) == 0 && env[i][len] == '=')
			بازگشت(env[i] + len + 1);
	بازگشت پوچ;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
ایستا تهی
read_etc_default_login(نویسه ***env, u_int *envsize, uid_t uid)
{
	نویسه **tmpenv = پوچ, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	اگر (tmpenv == پوچ)
		بازگشت;

	اگر (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	وگرنه
		var = child_get_env(tmpenv, "PATH");
	اگر (var != پوچ)
		child_set_env(env, envsize, "PATH", var);

	اگر ((var = child_get_env(tmpenv, "UMASK")) != پوچ)
		اگر (sscanf(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	برای (i = 0; tmpenv[i] != پوچ; i++)
		آزاد(tmpenv[i]);
	آزاد(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#اگر defined(USE_PAM) || defined(HAVE_CYGWIN)
ایستا تهی
copy_environment_denylist(نویسه **source, نویسه ***env, u_int *envsize,
    ثابت نویسه *denylist)
{
	نویسه *var_name, *var_val;
	صحیح i;

	اگر (source == پوچ)
		بازگشت;

	برای(i = 0; source[i] != پوچ; i++) {
		var_name = xstrdup(source[i]);
		اگر ((var_val = strstr(var_name, "=")) == پوچ) {
			آزاد(var_name);
			ادامه;
		}
		*var_val++ = '\0';

		اگر (denylist == پوچ ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		آزاد(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
ایستا تهی
copy_environment(نویسه **source, نویسه ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, پوچ);
}
#endif

ایستا نویسه **
do_setup_env(ساختار ssh *ssh, Session *s, ثابت نویسه *shell)
{
	نویسه buf[256];
	size_t n;
	u_int i, envsize;
	نویسه *ocp, *cp, *مقدار, **env, *laddr;
	ساختار passwd *pw = s->pw;
#اگر !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	نویسه *path = پوچ;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, اندازه(نویسه *));
	env[0] = پوچ;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		نویسه **p;

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
	برای (i = 0; i < s->رقم_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	اگر (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	وگرنه
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#وگرنه /* HAVE_LOGIN_CAP */
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
	اگر (path == پوچ || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	اگر (!options.use_pam) {
		snprintf(buf, اندازه buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	اگر (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
#ifdef HAVE_LOGIN_CAP
	اگر (getenv("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	اگر (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	اگر (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		نویسه *cp;

		اگر ((cp = getenv("KRB5CCNAME")) != پوچ)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		نویسه *cp;

		اگر ((cp = getenv("AUTHSTATE")) != پوچ)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	اگر (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	اگر (auth_sock_name != پوچ)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	اگر (options.permit_user_env) {
		برای (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			اگر (cp != پوچ) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				اگر (options.permit_user_env_allowlist == پوچ ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			آزاد(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	اگر (options.permit_user_env) {
		snprintf(buf, اندازه buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	اگر (options.use_pam) {
		نویسه **p;

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
	برای (i = 0; i < options.رقم_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		اگر ((مقدار = strchr(cp, '=')) == پوچ) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*مقدار++ = '\0';
		child_set_env(&env, &envsize, cp, مقدار);
		آزاد(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, اندازه buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, اندازه buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	آزاد(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	اگر (tun_fwd_ifnames != پوچ)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	اگر (auth_info_file != پوچ)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	اگر (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	اگر (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	اگر (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		برای (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	بازگشت env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
ایستا تهی
do_rc_files(ساختار ssh *ssh, Session *s, ثابت نویسه *shell)
{
	FILE *f = پوچ;
	نویسه *cmd = پوچ, *user_rc = پوچ;
	صحیح do_xauth;
	ساختار stat st;

	do_xauth =
	    s->display != پوچ && s->auth_proto != پوچ && s->auth_data != پوچ;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	اگر (!s->is_subsystem && options.adm_forced_command == پوچ &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		اگر (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		اگر (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		اگر (f) {
			اگر (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} وگرنه
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} وگرنه اگر (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		اگر (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		اگر (f) {
			اگر (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} وگرنه
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} وگرنه اگر (do_xauth && options.xauth_location != پوچ) {
		/* Add authority data to .Xauthority if appropriate. */
		اگر (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		اگر (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		اگر (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} وگرنه {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	آزاد(cmd);
	آزاد(user_rc);
}

ایستا تهی
do_nologin(ساختار passwd *pw)
{
	FILE *f = پوچ;
	نویسه buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	ساختار stat sb;

#ifdef HAVE_LOGIN_CAP
	اگر (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		بازگشت;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#وگرنه
	اگر (pw->pw_uid == 0)
		بازگشت;
	nl = def_nl;
#endif
	اگر (stat(nl, &sb) == -1)
		بازگشت;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	اگر ((f = fopen(nl, "r")) != پوچ) {
		وقتی (fgets(buf, اندازه(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
ایستا تهی
safely_chroot(ثابت نویسه *path, uid_t uid)
{
	ثابت نویسه *cp;
	نویسه component[PATH_MAX];
	ساختار stat st;

	اگر (!path_absolute(path))
		fatal("chroot path does not begin at root");
	اگر (strlen(path) >= اندازه(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	برای (cp = path; cp != پوچ;) {
		اگر ((cp = strchr(cp, '/')) == پوچ)
			strlcpy(component, path, اندازه(component));
		وگرنه {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		اگر (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		اگر (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == پوچ ? "" : "component ", component);
		اگر (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == پوچ ? "" : "component ", component);

	}

	اگر (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	اگر (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	اگر (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
تهی
do_setusercontext(ساختار passwd *pw)
{
	نویسه uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	اگر (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		اگر (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			exit(1);
		}
#وگرنه
		اگر (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		اگر (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			exit(1);
		}
		/* Initialize the group list. */
		اگر (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			exit(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		اگر (!in_chroot && options.chroot_directory != پوچ &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, اندازه(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (نویسه *)پوچ);
			safely_chroot(chroot_path, pw->pw_uid);
			آزاد(tmp);
			آزاد(chroot_path);
			/* Make sure we don't attempt to chroot again */
			آزاد(options.chroot_directory);
			options.chroot_directory = پوچ;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		اگر (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			exit(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(تهی) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#وگرنه
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		اگر (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} وگرنه اگر (options.chroot_directory != پوچ &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	اگر (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

ایستا تهی
do_pwchange(Session *s)
{
	fflush(پوچ);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	اگر (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(پوچ);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (نویسه *)پوچ);
#وگرنه
		execl(_PATH_PASSWD_PROG, "passwd", (نویسه *)پوچ);
#endif
		perror("passwd");
	} وگرنه {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	exit(1);
}

ایستا تهی
child_close_fds(ساختار ssh *ssh)
{
	بیرونی صحیح auth_sock;

	اگر (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	اگر (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	وگرنه {
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
	log_redirect_stderr_to(پوچ);

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
تهی
do_child(ساختار ssh *ssh, Session *s, ثابت نویسه *command)
{
	بیرونی نویسه **environ;
	نویسه **env, *argv[ARGV_MAX], remote_id[512];
	ثابت نویسه *shell, *shell0;
	ساختار passwd *pw = s->pw;
	صحیح r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, اندازه(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_کلیدها(ssh);

	/* Force a password change */
	اگر (s->authctxt->force_pwchange) {
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
	session_setup_sia(pw, s->ttyfd == -1 ? پوچ : s->tty);
	اگر (!check_quietlogin(s, command))
		do_motd();
#وگرنه /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	اگر (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	اگر (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	اگر (options.use_pam && !is_pam_session_open()) {
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
	shell = login_getcapstr(lc, "shell", (نویسه *)shell, (نویسه *)shell);
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

#اگر defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	اگر (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != پوچ)) {
		نویسه cell[64];

		debug("Getting AFS token");

		k_setpag();

		اگر (k_afs_cell_of_file(pw->pw_dir, cell, اندازه(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, پوچ);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, پوچ, پوچ, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	اگر (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		اگر (r || !in_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		اگر (r)
			exit(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	اگر (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(پوچ);
		exit(1);
	} وگرنه اگر (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		بیرونی صحیح optind, optreset;
		صحیح sftp_argc;
		نویسه **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		اگر (argv_split(command == پوچ ? "sftp-server" : command,
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

	fflush(پوچ);

	/* Get the last component of the shell name. */
	اگر ((shell0 = strrchr(shell, '/')) != پوچ)
		shell0++;
	وگرنه
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	اگر (!command) {
		نویسه argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		اگر (strlcpy(argv0 + 1, shell0, اندازه(argv0) - 1)
		    >= اندازه(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = پوچ;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (نویسه *) shell0;
	argv[1] = "-c";
	argv[2] = (نویسه *) command;
	argv[3] = پوچ;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

تهی
session_unused(صحیح id)
{
	debug3_f("session id %d unused", id);
	اگر (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, اندازه(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = پوچ;
	sessions[id].next_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(تهی)
{
	Session *s, *tmp;

	اگر (sessions_first_unused == -1) {
		اگر (sessions_nalloc >= options.max_sessions)
			بازگشت پوچ;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, اندازه(*sessions));
		اگر (tmp == پوچ) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			بازگشت پوچ;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	اگر (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	اگر (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->next_unused;
	s->used = 1;
	s->next_unused = -1;
	debug("session_new: session %d", s->self);

	بازگشت s;
}

ایستا تهی
session_dump(تهی)
{
	صحیح i;
	برای (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->used,
		    s->next_unused,
		    s->self,
		    s->chanid,
		    (long)s->pid);
	}
}

صحیح
session_open(Authctxt *authctxt, صحیح chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	اگر (s == پوچ) {
		error("no more sessions");
		بازگشت 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	اگر (s->pw == پوچ || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	بازگشت 1;
}

Session *
session_by_tty(نویسه *tty)
{
	صحیح i;
	برای (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			بازگشت s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	بازگشت پوچ;
}

ایستا Session *
session_by_channel(صحیح id)
{
	صحیح i;
	برای (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			بازگشت s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	بازگشت پوچ;
}

ایستا Session *
session_by_x11_channel(صحیح id)
{
	صحیح i, j;

	برای (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		اگر (s->x11_chanids == پوچ || !s->used)
			ادامه;
		برای (j = 0; s->x11_chanids[j] != -1; j++) {
			اگر (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				بازگشت s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	بازگشت پوچ;
}

ایستا Session *
session_by_pid(pid_t pid)
{
	صحیح i;
	debug("session_by_pid: pid %ld", (long)pid);
	برای (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->used && s->pid == pid)
			بازگشت s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	بازگشت پوچ;
}

ایستا صحیح
session_window_change_req(ساختار ssh *ssh, Session *s)
{
	صحیح r;

	اگر ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	بازگشت 1;
}

ایستا صحیح
session_pty_req(ساختار ssh *ssh, Session *s)
{
	صحیح r;

	اگر (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		بازگشت 0;
	}
	اگر (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		بازگشت 0;
	}

	اگر ((r = sshpkt_get_cstring(ssh, &s->term, پوچ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	اگر (strcmp(s->term, "") == 0) {
		آزاد(s->term);
		s->term = پوچ;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	اگر (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, اندازه(s->tty))) {
		آزاد(s->term);
		s->term = پوچ;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		بازگشت 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	اگر ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	بازگشت 1;
}

ایستا صحیح
session_subsystem_req(ساختار ssh *ssh, Session *s)
{
	ساختار stat st;
	صحیح r, success = 0, found = 0;
	نویسه *prog, *cmd, *type;
	u_int i;

	اگر ((r = sshpkt_get_cstring(ssh, &s->subsys, پوچ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	برای (i = 0; i < options.رقم_subsystems; i++) {
		اگر (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			ادامه;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		اگر (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} وگرنه {
			اگر (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		آزاد(type);
		success = do_exec(ssh, s, cmd) == 0;
		بشکن;
	}

	اگر (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	بازگشت success;
}

ایستا صحیح
session_x11_req(ساختار ssh *ssh, Session *s)
{
	صحیح r, success;
	u_char single_connection = 0;

	اگر (s->auth_proto != پوچ || s->auth_data != پوچ) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		بازگشت 0;
	}
	اگر ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_data, پوچ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	اگر (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_data))
		success = session_setup_x11fwd(ssh, s);
	وگرنه {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	اگر (!success) {
		آزاد(s->auth_proto);
		آزاد(s->auth_data);
		s->auth_proto = پوچ;
		s->auth_data = پوچ;
	}
	بازگشت success;
}

ایستا صحیح
session_shell_req(ساختار ssh *ssh, Session *s)
{
	صحیح r;

	اگر ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	بازگشت do_exec(ssh, s, پوچ) == 0;
}

ایستا صحیح
session_exec_req(ساختار ssh *ssh, Session *s)
{
	u_int success;
	صحیح r;
	نویسه *command = پوچ;

	اگر ((r = sshpkt_get_cstring(ssh, &command, پوچ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	آزاد(command);
	بازگشت success;
}

ایستا صحیح
session_break_req(ساختار ssh *ssh, Session *s)
{
	صحیح r;

	اگر ((r = sshpkt_get_u32(ssh, پوچ)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	اگر (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		بازگشت 0;
	بازگشت 1;
}

ایستا صحیح
session_env_req(ساختار ssh *ssh, Session *s)
{
	نویسه *name, *val;
	u_int i;
	صحیح r;

	اگر ((r = sshpkt_get_cstring(ssh, &name, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, پوچ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	اگر (s->رقم_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		برو fail;
	}

	برای (i = 0; i < options.رقم_accept_env; i++) {
		اگر (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->رقم_env, name, val);
			s->env = xrecallocarray(s->env, s->رقم_env,
			    s->رقم_env + 1, اندازه(*s->env));
			s->env[s->رقم_env].name = name;
			s->env[s->رقم_env].val = val;
			s->رقم_env++;
			بازگشت (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	آزاد(name);
	آزاد(val);
	بازگشت (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
ایستا صحیح
name2sig(نویسه *name)
{
#define SSH_SIG(x) اگر (strcmp(name, #x) == 0) بازگشت SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	اگر (strcmp(name, "INFO@openssh.com") == 0)
		بازگشت SIGINFO;
#endif
	بازگشت -1;
}

ایستا صحیح
session_signal_req(ساختار ssh *ssh, Session *s)
{
	نویسه *signame = پوچ;
	صحیح r, sig, success = 0;

	اگر ((r = sshpkt_get_cstring(ssh, &signame, پوچ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		برو out;
	}
	اگر ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		برو out;
	}
	اگر (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		برو out;
	}
	اگر (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		برو out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (long)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	اگر (r != 0) {
		error_f("killpg(%ld, %d): %s", (long)s->pid,
		    sig, strerror(errno));
		برو out;
	}

	/* success */
	success = 1;
 out:
	آزاد(signame);
	بازگشت success;
}

ایستا صحیح
session_auth_agent_req(ساختار ssh *ssh, Session *s, صحیح agent_new)
{
	ایستا صحیح called = 0;
	صحیح r;

	اگر ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	اگر (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		بازگشت 0;
	}
	اگر (called)
		بازگشت 0;

	called = 1;
	بازگشت auth_درون_داد_request_forwarding(ssh, s->pw, agent_new);
}

صحیح
session_درون_داد_channel_req(ساختار ssh *ssh, Channel *c, ثابت نویسه *rtype)
{
	صحیح success = 0;
	Session *s;

	اگر ((s = session_by_channel(c->self)) == پوچ) {
		logit_f("no session %d req %.100s", c->self, rtype);
		بازگشت 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	اگر (c->type == SSH_CHANNEL_LARVAL) {
		اگر (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} وگرنه اگر (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} وگرنه اگر (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} وگرنه اگر (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} وگرنه اگر (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} وگرنه اگر (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} وگرنه اگر (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} وگرنه اگر (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	اگر (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} وگرنه اگر (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} وگرنه اگر (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	بازگشت success;
}

تهی
session_set_fds(ساختار ssh *ssh, Session *s,
    صحیح fdin, صحیح fdout, صحیح fderr, صحیح ignore_fderr, صحیح is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	اگر (s->chanid == -1)
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
تهی
session_pty_cleanup2(Session *s)
{
	اگر (s == پوچ) {
		error_f("no session");
		بازگشت;
	}
	اگر (s->ttyfd == -1)
		بازگشت;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	اگر (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	اگر (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	اگر (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

تهی
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

ایستا نویسه *
sig2name(صحیح sig)
{
#define SSH_SIG(x) اگر (sig == SIG ## x) بازگشت #x
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
	بازگشت "SIG@openssh.com";
}

ایستا تهی
session_close_x11(ساختار ssh *ssh, صحیح id)
{
	Channel *c;

	اگر ((c = channel_by_id(ssh, id)) == پوچ) {
		debug_f("x11 channel %d missing", id);
	} وگرنه {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		اگر (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

ایستا تهی
session_close_single_x11(ساختار ssh *ssh, صحیح id, صحیح force, تهی *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	اگر ((s = session_by_x11_channel(id)) == پوچ)
		fatal_f("no x11 channel %d", id);
	برای (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		اگر (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	آزاد(s->x11_chanids);
	s->x11_chanids = پوچ;
	آزاد(s->display);
	s->display = پوچ;
	آزاد(s->auth_proto);
	s->auth_proto = پوچ;
	آزاد(s->auth_data);
	s->auth_data = پوچ;
	آزاد(s->auth_display);
	s->auth_display = پوچ;
}

ایستا تهی
session_exit_message(ساختار ssh *ssh, Session *s, صحیح status)
{
	Channel *c;
	صحیح r;
	نویسه *note = پوچ;

	اگر ((c = channel_lookup(ssh, s->chanid)) == پوچ)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	اگر (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		اگر ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} وگرنه اگر (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		اگر ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} وگرنه {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (long)s->pid, note == پوچ ? "UNKNOWN" : note);
	آزاد(note);

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
	اگر (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

تهی
session_close(ساختار ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	اگر (s->ttyfd != -1)
		session_pty_cleanup(s);
	آزاد(s->term);
	آزاد(s->display);
	آزاد(s->x11_chanids);
	آزاد(s->auth_display);
	آزاد(s->auth_data);
	آزاد(s->auth_proto);
	آزاد(s->subsys);
	اگر (s->env != پوچ) {
		برای (i = 0; i < s->رقم_env; i++) {
			آزاد(s->env[i].name);
			آزاد(s->env[i].val);
		}
		آزاد(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

تهی
session_close_by_pid(ساختار ssh *ssh, pid_t pid, صحیح status)
{
	Session *s = session_by_pid(pid);
	اگر (s == پوچ) {
		debug_f("no session for pid %ld", (long)pid);
		بازگشت;
	}
	اگر (s->chanid != -1)
		session_exit_message(ssh, s, status);
	اگر (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
تهی
session_close_by_channel(ساختار ssh *ssh, صحیح id, صحیح force, تهی *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	اگر (s == پوچ) {
		debug_f("no session for id %d", id);
		بازگشت;
	}
	debug_f("channel %d child %ld", id, (long)s->pid);
	اگر (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		اگر (s->ttyfd != -1)
			session_pty_cleanup(s);
		اگر (!force)
			بازگشت;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	اگر (s->x11_chanids != پوچ) {
		برای (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

تهی
session_destroy_all(ساختار ssh *ssh, تهی (*closefunc)(Session *))
{
	صحیح i;
	برای (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->used) {
			اگر (closefunc != پوچ)
				closefunc(s);
			وگرنه
				session_close(ssh, s);
		}
	}
}

ایستا نویسه *
session_tty_list(تهی)
{
	ایستا نویسه buf[1024];
	صحیح i;
	نویسه *cp;

	buf[0] = '\0';
	برای (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->used && s->ttyfd != -1) {

			اگر (strncmp(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == پوچ) ? s->tty : cp + 1;
			} وگرنه
				cp = s->tty + 5;

			اگر (buf[0] != '\0')
				strlcat(buf, ",", اندازه buf);
			strlcat(buf, cp, اندازه buf);
		}
	}
	اگر (buf[0] == '\0')
		strlcpy(buf, "notty", اندازه buf);
	بازگشت buf;
}

تهی
session_proctitle(Session *s)
{
	اگر (s->pw == پوچ)
		error("no user for session %d", s->self);
	وگرنه
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

صحیح
session_setup_x11fwd(ساختار ssh *ssh, Session *s)
{
	ساختار stat st;
	نویسه display[512], auth_display[512];
	نویسه hostname[NI_MAXHOST];
	u_int i;

	اگر (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		بازگشت 0;
	}
	اگر (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		بازگشت 0;
	}
	اگر (options.xauth_location == پوچ ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		بازگشت 0;
	}
	اگر (s->display != پوچ) {
		debug("X11 display already set.");
		بازگشت 0;
	}
	اگر (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_عدد, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		بازگشت 0;
	}
	برای (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	اگر (gethostname(hostname, اندازه(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	اگر (options.x11_use_localhost) {
		snprintf(display, اندازه display, "localhost:%u.%u",
		    s->display_عدد, s->screen);
		snprintf(auth_display, اندازه auth_display, "unix:%u.%u",
		    s->display_عدد, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} وگرنه {
#ifdef IPADDR_IN_DISPLAY
		ساختار hostent *he;
		ساختار in_addr my_addr;

		he = gethostbyname(hostname);
		اگر (he == پوچ) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			بازگشت 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], اندازه(ساختار in_addr));
		snprintf(display, اندازه display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_عدد, s->screen);
#وگرنه
		snprintf(display, اندازه display, "%.400s:%u.%u", hostname,
		    s->display_عدد, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	بازگشت 1;
}

ایستا تهی
do_authenticated2(ساختار ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

تهی
do_cleanup(ساختار ssh *ssh, Authctxt *authctxt)
{
	ایستا صحیح called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	اگر (is_child)
		بازگشت;

	/* avoid double cleanup */
	اگر (called)
		بازگشت;
	called = 1;

	اگر (authctxt == پوچ)
		بازگشت;

#ifdef USE_PAM
	اگر (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	اگر (!authctxt->authenticated)
		بازگشت;

#ifdef KRB5
	اگر (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	اگر (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	اگر (auth_info_file != پوچ) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		آزاد(auth_info_file);
		auth_info_file = پوچ;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	اگر (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

ثابت نویسه *
session_get_remote_name_or_ip(ساختار ssh *ssh, u_int utmp_size, صحیح use_dns)
{
	ثابت نویسه *remote = "";

	اگر (utmp_size > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	اگر (utmp_size == 0 || strlen(remote) > utmp_size)
		remote = ssh_remote_ipaddr(ssh);
	بازگشت remote;
}

