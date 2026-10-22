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
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "monitor_wrap.h"
#شامل "sftp.h"
#شامل "atomicio.h"

#اگر defined(KRB5) && defined(USE_AFS)
#شامل <kafs.h>
#اگر_ختم

#اگر_تعریف_شدہ WITH_SELINUX
#شامل <selinux/selinux.h>
#اگر_ختم

/*
 * Hack for systems that do not support FD passing: allocate PTYs directly
 * without calling into the monitor. This requires either the post-auth
 * privsep process retain root privileges (see the comment in
 * sshd-session.c:privsep_postauth) or that PTY allocation doesn't require
 * privileges to begin with (e.g. Cygwin).
 */
#اگر_تعریف_شدہ DISABLE_FD_PASSING
#تعریف_کرو mm_pty_allocate pty_allocate
#اگر_ختم

#تعریف_کرو IS_اندرونی_SFTP(c) \
	(!لڑی_موازنہ(c, اندرونی_SFTP_NAME, حجم(اندرونی_SFTP_NAME) - 1) && \
	 (c[حجم(اندرونی_SFTP_NAME) - 1] == '\0' || \
	  c[حجم(اندرونی_SFTP_NAME) - 1] == ' ' || \
	  c[حجم(اندرونی_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(خالی);
خالی	session_سیٹ_fds(ساخت ssh *, Session *, صحیح, صحیح, صحیح, صحیح, صحیح);
خالی	session_pty_cleanup(Session *);
خالی	session_proctitle(Session *);
صحیح	session_تیاری_x11fwd(ساخت ssh *, Session *);
صحیح	do_exec_pty(ساخت ssh *, Session *, ثابت حرف *);
صحیح	do_exec_no_pty(ساخت ssh *, Session *, ثابت حرف *);
صحیح	do_exec(ساخت ssh *, Session *, ثابت حرف *);
خالی	do_login(ساخت ssh *, Session *, ثابت حرف *);
خالی	do_بچہ(ساخت ssh *, Session *, ثابت حرف *);
خالی	do_motd(خالی);
صحیح	check_quietlogin(Session *, ثابت حرف *);

ساکن خالی do_authenticated2(ساخت ssh *, Authctxt *);

ساکن صحیح session_pty_req(ساخت ssh *, Session *);

/* import */
خارجی ServerOptions options;
خارجی حرف *__progname;
خارجی صحیح debug_flag;
خارجی ساخت sshbuf *loginmsg;
خارجی ساخت sshauthopt *auth_opts;
خارجی حرف *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
ثابت حرف *original_command = تہی;

/*ڈیٹا*/
ساکن صحیح sessions_پہلا_غیر_مستعمل = -1;
ساکن صحیح sessions_nalloc = 0;
ساکن Session *sessions = تہی;

#تعریف_کرو SUBSYSTEM_NONE			0
#تعریف_کرو SUBSYSTEM_EXT			1
#تعریف_کرو SUBSYSTEM_INT_SFTP		2
#تعریف_کرو SUBSYSTEM_INT_SFTP_ERROR	3

#اگر_تعریف_شدہ HAVE_LOGIN_CAP
login_cap_t *lc;
#اگر_ختم

ساکن صحیح is_بچہ = 0;
ساکن صحیح اندر_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
ساکن حرف *auth_info_file = تہی;

/* Name and directory of socket for authentication agent forwarding. */
ساکن حرف *auth_sock_name = تہی;
ساکن حرف *auth_sock_dir = تہی; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

ساکن خالی
auth_sock_cleanup_proc(ساخت passwd *pw)
{
	اگر (auth_sock_name != تہی) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_راستہ,
		    auth_sock_name, auth_sock_dir);
		آزاد(auth_sock_name);
		auth_sock_name = تہی;
		restore_uid();
	}
}

ساکن صحیح
auth_داخلہ_request_forwarding(ساخت ssh *ssh, ساخت passwd *pw, صحیح agent_new)
{
	Channel *nc;
	صحیح sock = -1;

	اگر (auth_sock_name != تہی) {
		error("authentication forwarding requested twice.");
		واپس 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	اگر (agent_listener(options.agent_socket_راستہ, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		جاؤ authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_کھڑکی_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->راستہ = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	واپس 1;

 authsock_err:
	آزاد(auth_sock_name);
	اگر (sock != -1)
		close(sock);
	auth_sock_name = تہی;
	واپس 0;
}

ساکن خالی
display_loginmsg(خالی)
{
	صحیح r;

	اگر (sshbuf_len(loginmsg) == 0)
		واپس;
	اگر ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	لکھو("%s", (حرف *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

ساکن خالی
prepare_auth_info_file(ساخت passwd *pw, ساخت sshbuf *info)
{
	صحیح fd = -1, success = 0;

	اگر (!options.expose_userauth_info || info == تہی)
		واپس;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	اگر ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		جاؤ برآمد;
	}
	اگر (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		جاؤ برآمد;
	}
	اگر (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		جاؤ برآمد;
	}
	success = 1;
 برآمد:
	اگر (!success) {
		اگر (fd != -1)
			close(fd);
		آزاد(auth_info_file);
		auth_info_file = تہی;
	}
	restore_uid();
}

ساکن خالی
سیٹ_fwdpermit_from_authopts(ساخت ssh *ssh, ثابت ساخت sshauthopt *opts)
{
	حرف *tmp, *cp, *host;
	صحیح پورٹ;
	سائز_t i;

	اگر ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		برائے (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			اگر ((host = hpdelim2(&cp, تہی)) == تہی)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			اگر (cp == تہی || (پورٹ = permitopen_پورٹ(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_جوڑو_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, پورٹ);
			آزاد(tmp);
		}
	}
	اگر ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		برائے (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			اگر ((host = hpdelim(&cp)) == تہی)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			اگر (cp == تہی || (پورٹ = permitopen_پورٹ(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_جوڑو_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, پورٹ);
			آزاد(tmp);
		}
	}
}

خالی
do_authenticated(ساخت ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	سیٹ_fwdpermit_from_authopts(ssh, auth_opts);

	اگر (!auth_opts->permit_پورٹ_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} ورنہ {
		اگر ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		ورنہ
			channel_permit_all(ssh, FORWARD_LOCAL);
		اگر ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		ورنہ
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
ساکن صحیح
xauth_valid_string(ثابت حرف *s)
{
	سائز_t i;

	برائے (i = 0; s[i] != '\0'; i++) {
		اگر (!حرف_یا_ہندسہ((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			واپس 0;
	}
	واپس 1;
}

#تعریف_کرو USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
صحیح
do_exec_no_pty(ساخت ssh *ssh, Session *s, ثابت حرف *command)
{
	pid_t pid;
#اگر_تعریف_شدہ USE_PIPES
	صحیح pin[2], pout[2], perr[2];

	اگر (s == تہی)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	اگر (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		واپس -1;
	}
	اگر (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		واپس -1;
	}
	اگر (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		واپس -1;
	}
#ورنہ
	صحیح inout[2], err[2];

	اگر (s == تہی)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		واپس -1;
	}
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		واپس -1;
	}
#اگر_ختم

	session_proctitle(s);

	/* Fork the child. */
	انتخاب ((pid = fork())) {
	حالت -1:
		error_f("fork: %.100s", strerror(errno));
#اگر_تعریف_شدہ USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#ورنہ
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#اگر_ختم
		واپس -1;
	حالت 0:
		is_بچہ = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		اگر (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#اگر_تعریف_شدہ USE_PIPES
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
#ورنہ
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
#اگر_ختم

		/* Do processing for the child (exec command etc). */
		do_بچہ(ssh, s, command);
		/* NOTREACHED */
	طےشدہ:
		توڑو;
	}

#اگر_تعریف_شدہ HAVE_CYGWIN
	cygwin_سیٹ_impersonation_token(INVALID_HANDLE_قدر);
#اگر_ختم

	s->pid = pid;

	/*
	 * Clear loginmsg, since it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

#اگر_تعریف_شدہ USE_PIPES
	/* We are the parent.  Close the child sides of the pipes. */
	close(pin[0]);
	close(pout[1]);
	close(perr[1]);

	session_سیٹ_fds(ssh, s, pin[1], pout[0], perr[0],
	    s->is_subsystem, 0);
#ورنہ
	/* We are the parent.  Close the child sides of the socket pairs. */
	close(inout[0]);
	close(err[0]);

	/*
	 * Enter the interactive session.  Note: server_loop must be able to
	 * handle the case that fdin and fdout are the same.
	 */
	session_سیٹ_fds(ssh, s, inout[1], inout[1], err[1],
	    s->is_subsystem, 0);
#اگر_ختم
	واپس 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
صحیح
do_exec_pty(ساخت ssh *ssh, Session *s, ثابت حرف *command)
{
	صحیح fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	اگر (s == تہی)
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
		واپس -1;
	}
	/* we keep a reference to the pty master */
	اگر ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		واپس -1;
	}

	/* Fork the child. */
	انتخاب ((pid = fork())) {
	حالت -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		واپس -1;
	حالت 0:
		is_بچہ = 1;

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
#اگر_غیر_تعریف_شدہ HAVE_OSF_SIA
		do_login(ssh, s, command);
#اگر_ختم
		/*
		 * Do common processing for the child, such as execing
		 * the command.
		 */
		do_بچہ(ssh, s, command);
		/* NOTREACHED */
	طےشدہ:
		توڑو;
	}

#اگر_تعریف_شدہ HAVE_CYGWIN
	cygwin_سیٹ_impersonation_token(INVALID_HANDLE_قدر);
#اگر_ختم

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_سیٹ_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	واپس 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
صحیح
do_exec(ساخت ssh *ssh, Session *s, ثابت حرف *command)
{
	صحیح ret;
	ثابت حرف *forced = تہی, *tty = تہی;
	حرف session_type[1024];

	اگر (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} ورنہ اگر (auth_opts->force_command != تہی) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	اگر (forced != تہی) {
		s->forced = 1;
		اگر (IS_اندرونی_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} ورنہ اگر (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, حجم(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} ورنہ اگر (s->is_subsystem) {
		snprintf(session_type, حجم(session_type),
		    "subsystem '%.900s'", s->subsys);
	} ورنہ اگر (command == تہی) {
		snprintf(session_type, حجم(session_type), "shell");
	} ورنہ {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, حجم(session_type), "command");
	}

	اگر (s->ttyfd != -1) {
		tty = s->tty;
		اگر (لڑی_موازنہ(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == تہی ? "" : " on ",
	    tty == تہی ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_پورٹ(ssh),
	    s->self);

#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
	اگر (command != تہی)
		mm_audit_تسلسل_command(command);
	ورنہ اگر (s->ttyfd == -1) {
		حرف *shell = s->pw->pw_shell;

		اگر (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_تسلسل_command(shell);
	}
#اگر_ختم
	اگر (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	ورنہ
		ret = do_exec_no_pty(ssh, s, command);

	original_command = تہی;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	واپس ret;
}

/* administrative, login(1)-like work */
خالی
do_login(ساخت ssh *ssh, Session *s, ثابت حرف *command)
{
	socklen_t fromlen;
	ساخت sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, حجم(from));
	fromlen = حجم(from);
	اگر (ssh_packet_connection_is_on_socket(ssh)) {
		اگر (getpeername(ssh_packet_get_connection_اندر(ssh),
		    (ساخت sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	اگر (check_quietlogin(s, command))
		واپس;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
خالی
do_motd(خالی)
{
	FILE *f;
	حرف buf[256];

	اگر (options.print_motd) {
#اگر_تعریف_شدہ HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#ورنہ
		f = fopen("/etc/motd", "r");
#اگر_ختم
		اگر (f) {
			جب (fgets(buf, حجم(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
صحیح
check_quietlogin(Session *s, ثابت حرف *command)
{
	حرف buf[256];
	ساخت passwd *pw = s->pw;
	ساخت stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	اگر (command != تہی)
		واپس 1;
	snprintf(buf, حجم(buf), "%.200s/.hushlogin", pw->pw_dir);
#اگر_تعریف_شدہ HAVE_LOGIN_CAP
	اگر (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		واپس 1;
#ورنہ
	اگر (stat(buf, &st) >= 0)
		واپس 1;
#اگر_ختم
	واپس 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
ساکن خالی
read_environment_file(حرف ***env, u_int *envsize,
	ثابت حرف *filename, ثابت حرف *allowlist)
{
	FILE *f;
	حرف *سطر = تہی, *cp, *قدر;
	سائز_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	اگر (!f)
		واپس;

	جب (getline(&سطر, &linesize, f) != -1) {
		اگر (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		برائے (cp = سطر; *cp == ' ' || *cp == '\t'; cp++)
			;
		اگر (!*cp || *cp == '#' || *cp == '\n')
			جاری;

		cp[strcspn(cp, "\n")] = '\0';

		قدر = strchr(cp, '=');
		اگر (قدر == تہی) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			جاری;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*قدر = '\0';
		قدر++;
		اگر (allowlist != تہی &&
		    مطابقت_نمونہ_list(cp, allowlist, 0) != 1)
			جاری;
		بچہ_سیٹ_env(env, envsize, cp, قدر);
	}
	آزاد(سطر);
	fclose(f);
}

#اگر_تعریف_شدہ HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
ساکن حرف *
بچہ_get_env(حرف **env, ثابت حرف *name)
{
	صحیح i;
	سائز_t len;

	len = لڑی_لمبائی(name);
	برائے (i=0; env[i] != تہی; i++)
		اگر (لڑی_موازنہ(name, env[i], len) == 0 && env[i][len] == '=')
			واپس(env[i] + len + 1);
	واپس تہی;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
ساکن خالی
read_etc_default_login(حرف ***env, u_int *envsize, uid_t uid)
{
	حرف **tmpenv = تہی, *var;
	u_int i, tmpenvsize = 0;
	u_long نقاب;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	اگر (tmpenv == تہی)
		واپس;

	اگر (uid == 0)
		var = بچہ_get_env(tmpenv, "SUPATH");
	ورنہ
		var = بچہ_get_env(tmpenv, "PATH");
	اگر (var != تہی)
		بچہ_سیٹ_env(env, envsize, "PATH", var);

	اگر ((var = بچہ_get_env(tmpenv, "UMASK")) != تہی)
		اگر (لڑی_سے_پڑھو(var, "%5lo", &نقاب) == 1)
			umask((منوال_t)نقاب);

	برائے (i = 0; tmpenv[i] != تہی; i++)
		آزاد(tmpenv[i]);
	آزاد(tmpenv);
}
#اگر_ختم /* HAVE_ETC_DEFAULT_LOGIN */

#اگر defined(USE_PAM) || defined(HAVE_CYGWIN)
ساکن خالی
copy_environment_denylist(حرف **ماخذ, حرف ***env, u_int *envsize,
    ثابت حرف *denylist)
{
	حرف *var_name, *var_val;
	صحیح i;

	اگر (ماخذ == تہی)
		واپس;

	برائے(i = 0; ماخذ[i] != تہی; i++) {
		var_name = xstrdup(ماخذ[i]);
		اگر ((var_val = لڑی_تلاش(var_name, "=")) == تہی) {
			آزاد(var_name);
			جاری;
		}
		*var_val++ = '\0';

		اگر (denylist == تہی ||
		    مطابقت_نمونہ_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			بچہ_سیٹ_env(env, envsize, var_name, var_val);
		}

		آزاد(var_name);
	}
}
#اگر_ختم /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#اگر_تعریف_شدہ HAVE_CYGWIN
ساکن خالی
copy_environment(حرف **ماخذ, حرف ***env, u_int *envsize)
{
	copy_environment_denylist(ماخذ, env, envsize, تہی);
}
#اگر_ختم

ساکن حرف **
do_تیاری_env(ساخت ssh *ssh, Session *s, ثابت حرف *shell)
{
	حرف buf[256];
	سائز_t n;
	u_int i, envsize;
	حرف *ocp, *cp, *قدر, **env, *laddr;
	ساخت passwd *pw = s->pw;
#اگر !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	حرف *راستہ = تہی;
#اگر_ختم

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, حجم(حرف *));
	env[0] = تہی;

#اگر_تعریف_شدہ HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		حرف **p;

		p = fetch_windows_environment();
		copy_environment(p, &env, &envsize);
		free_windows_environment(p);
	}
#اگر_ختم

#اگر_تعریف_شدہ GSSAPI
	/* Allow any GSSAPI methods that we've used to alter
	 * the child's environment as they see fit
	 */
	ssh_gssapi_do_بچہ(&env, &envsize);
#اگر_ختم

	/* Set basic environment. */
	برائے (i = 0; i < s->عدد_env; i++)
		بچہ_سیٹ_env(&env, &envsize, s->env[i].name, s->env[i].val);

	بچہ_سیٹ_env(&env, &envsize, "USER", pw->pw_name);
	بچہ_سیٹ_env(&env, &envsize, "LOGNAME", pw->pw_name);
#اگر_تعریف_شدہ _AIX
	بچہ_سیٹ_env(&env, &envsize, "LOGIN", pw->pw_name);
#اگر_ختم
	بچہ_سیٹ_env(&env, &envsize, "HOME", pw->pw_dir);
#اگر_تعریف_شدہ HAVE_LOGIN_CAP
	اگر (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		بچہ_سیٹ_env(&env, &envsize, "PATH", _PATH_STDPATH);
	ورنہ
		بچہ_سیٹ_env(&env, &envsize, "PATH", getenv("PATH"));
#ورنہ /* HAVE_LOGIN_CAP */
# ifndef HAVE_CYGWIN
	/*
	 * There's no standard path on Windows. The path contains
	 * important components pointing to the system directories,
	 * needed for loading shared libraries. So the path better
	 * remains intact here.
	 */
#  ifdef HAVE_ETC_DEFAULT_LOGIN
	read_etc_default_login(&env, &envsize, pw->pw_uid);
	راستہ = بچہ_get_env(env, "PATH");
#  endif /* HAVE_ETC_DEFAULT_LOGIN */
	اگر (راستہ == تہی || *راستہ == '\0') {
		بچہ_سیٹ_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_راستہ : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#اگر_ختم /* HAVE_LOGIN_CAP */

	اگر (!options.use_pam) {
		snprintf(buf, حجم buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		بچہ_سیٹ_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	بچہ_سیٹ_env(&env, &envsize, "SHELL", shell);

	اگر (getenv("TZ"))
		بچہ_سیٹ_env(&env, &envsize, "TZ", getenv("TZ"));
#اگر_تعریف_شدہ HAVE_LOGIN_CAP
	اگر (getenv("XDG_RUNTIME_DIR")) {
		بچہ_سیٹ_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#اگر_ختم /* HAVE_LOGIN_CAP */
	اگر (s->رکن)
		بچہ_سیٹ_env(&env, &envsize, "TERM", s->رکن);
	اگر (s->display)
		بچہ_سیٹ_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		حرف *cp;

		اگر ((cp = getenv("KRB5CCNAME")) != تہی)
			بچہ_سیٹ_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#اگر_تعریف_شدہ _AIX
	{
		حرف *cp;

		اگر ((cp = getenv("AUTHSTATE")) != تہی)
			بچہ_سیٹ_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#اگر_ختم
#اگر_تعریف_شدہ KRB5
	اگر (s->authctxt->krb5_ccname)
		بچہ_سیٹ_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#اگر_ختم
	اگر (auth_sock_name != تہی)
		بچہ_سیٹ_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	اگر (options.permit_user_env) {
		برائے (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			اگر (cp != تہی) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				اگر (options.permit_user_env_allowlist == تہی ||
				    مطابقت_نمونہ_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					بچہ_سیٹ_env(&env, &envsize,
					    ocp, cp + 1);
			}
			آزاد(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	اگر (options.permit_user_env) {
		snprintf(buf, حجم buf, "%.200s/%s/environment",
		    pw->pw_dir, راستہ_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#اگر_تعریف_شدہ USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	اگر (options.use_pam) {
		حرف **p;

		/*
		 * Don't allow PAM-internal env vars to leak
		 * back into the session environment.
		 */
#تعریف_کرو PAM_ENV_DENYLIST  "SSH_AUTH_INFO*,SSH_CONNECTION*"
		p = fetch_pam_بچہ_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);

		p = fetch_pam_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);
	}
#اگر_ختم /* USE_PAM */

	/* Environment specified by admin */
	برائے (i = 0; i < options.عدد_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		اگر ((قدر = strchr(cp, '=')) == تہی) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*قدر++ = '\0';
		بچہ_سیٹ_env(&env, &envsize, cp, قدر);
		آزاد(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, حجم buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
	    ssh_local_پورٹ(ssh));
	بچہ_سیٹ_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_اندر(ssh));
	snprintf(buf, حجم buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
	    laddr, ssh_local_پورٹ(ssh));
	آزاد(laddr);
	بچہ_سیٹ_env(&env, &envsize, "SSH_CONNECTION", buf);

	اگر (tun_fwd_ifnames != تہی)
		بچہ_سیٹ_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	اگر (auth_info_file != تہی)
		بچہ_سیٹ_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	اگر (s->ttyfd != -1)
		بچہ_سیٹ_env(&env, &envsize, "SSH_TTY", s->tty);
	اگر (original_command)
		بچہ_سیٹ_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	اگر (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		برائے (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	واپس env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
ساکن خالی
do_rc_files(ساخت ssh *ssh, Session *s, ثابت حرف *shell)
{
	FILE *f = تہی;
	حرف *cmd = تہی, *user_rc = تہی;
	صحیح do_xauth;
	ساخت stat st;

	do_xauth =
	    s->display != تہی && s->auth_proto != تہی && s->auth_ڈیٹا != تہی;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, راستہ_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	اگر (!s->is_subsystem && options.adm_forced_command == تہی &&
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
				    s->auth_ڈیٹا);
			pclose(f);
		} ورنہ
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} ورنہ اگر (stat(راستہ_SSH_SYSTEM_RC, &st) >= 0) {
		اگر (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    راستہ_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " راستہ_SSH_SYSTEM_RC, "w");
		اگر (f) {
			اگر (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_ڈیٹا);
			pclose(f);
		} ورنہ
			fprintf(stderr, "Could not run %s\n",
			    راستہ_SSH_SYSTEM_RC);
	} ورنہ اگر (do_xauth && options.xauth_location != تہی) {
		/* Add authority data to .Xauthority if appropriate. */
		اگر (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_ڈیٹا);
		}
		اگر (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		اگر (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_ڈیٹا);
			pclose(f);
		} ورنہ {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	آزاد(cmd);
	آزاد(user_rc);
}

ساکن خالی
do_nologin(ساخت passwd *pw)
{
	FILE *f = تہی;
	حرف buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	ساخت stat sb;

#اگر_تعریف_شدہ HAVE_LOGIN_CAP
	اگر (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		واپس;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#ورنہ
	اگر (pw->pw_uid == 0)
		واپس;
	nl = def_nl;
#اگر_ختم
	اگر (stat(nl, &sb) == -1)
		واپس;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	اگر ((f = fopen(nl, "r")) != تہی) {
		جب (fgets(buf, حجم(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	باہر_نکلو(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
ساکن خالی
safely_chroot(ثابت حرف *راستہ, uid_t uid)
{
	ثابت حرف *cp;
	حرف component[PATH_MAX];
	ساخت stat st;

	اگر (!راستہ_absolute(راستہ))
		fatal("chroot path does not begin at root");
	اگر (لڑی_لمبائی(راستہ) >= حجم(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	برائے (cp = راستہ; cp != تہی;) {
		اگر ((cp = strchr(cp, '/')) == تہی)
			strlcpy(component, راستہ, حجم(component));
		ورنہ {
			cp++;
			حافظہ_نقل(component, راستہ, cp - راستہ);
			component[cp - راستہ] = '\0';
		}

		debug3_f("checking '%s'", component);

		اگر (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		اگر (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == تہی ? "" : "component ", component);
		اگر (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == تہی ? "" : "component ", component);

	}

	اگر (chdir(راستہ) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", راستہ, strerror(errno));
	اگر (chroot(راستہ) == -1)
		fatal("chroot(\"%s\"): %s", راستہ, strerror(errno));
	اگر (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", راستہ);
}

/* Set login name, uid, gid, and groups. */
خالی
do_setusercontext(ساخت passwd *pw)
{
	حرف uidstr[32], *chroot_راستہ, *tmp;

	platform_setusercontext(pw);

	اگر (platform_privileged_uidswap()) {
#اگر_تعریف_شدہ HAVE_LOGIN_CAP
		اگر (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			باہر_نکلو(1);
		}
#ورنہ
		اگر (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		اگر (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			باہر_نکلو(1);
		}
		/* Initialize the group list. */
		اگر (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			باہر_نکلو(1);
		}
		endgrent();
#اگر_ختم

		platform_setusercontext_post_groups(pw);

		اگر (!اندر_chroot && options.chroot_directory != تہی &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, حجم(uidstr), "%llu",
			    (غیرعلامتی طویل طویل)pw->pw_uid);
			chroot_راستہ = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (حرف *)تہی);
			safely_chroot(chroot_راستہ, pw->pw_uid);
			آزاد(tmp);
			آزاد(chroot_راستہ);
			/* Make sure we don't attempt to chroot again */
			آزاد(options.chroot_directory);
			options.chroot_directory = تہی;
			اندر_chroot = 1;
		}

#اگر_تعریف_شدہ HAVE_LOGIN_CAP
		اگر (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			باہر_نکلو(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(خالی) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#ورنہ
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		اگر (!اندر_chroot && سیٹ_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_سیٹ_uid(pw);
#اگر_ختم
	} ورنہ اگر (options.chroot_directory != تہی &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	اگر (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

ساکن خالی
do_pwchange(Session *s)
{
	fflush(تہی);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	اگر (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#اگر_تعریف_شدہ WITH_SELINUX
		setexeccon(تہی);
#اگر_ختم
#اگر_تعریف_شدہ PASSWD_NEEDS_USERNAME
		execl(راستہ_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (حرف *)تہی);
#ورنہ
		execl(راستہ_PASSWD_PROG, "passwd", (حرف *)تہی);
#اگر_ختم
		perror("passwd");
	} ورنہ {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	باہر_نکلو(1);
}

ساکن خالی
بچہ_close_fds(ساخت ssh *ssh)
{
	خارجی صحیح auth_sock;

	اگر (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	اگر (ssh_packet_get_connection_اندر(ssh) ==
	    ssh_packet_get_connection_برآمد(ssh))
		close(ssh_packet_get_connection_اندر(ssh));
	ورنہ {
		close(ssh_packet_get_connection_اندر(ssh));
		close(ssh_packet_get_connection_برآمد(ssh));
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
	log_redirect_stderr_مقصد(تہی);

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
#تعریف_کرو ARGV_MAX 10
خالی
do_بچہ(ساخت ssh *ssh, Session *s, ثابت حرف *command)
{
	خارجی حرف **environ;
	حرف **env, *argv[ARGV_MAX], remote_id[512];
	ثابت حرف *shell, *shell0;
	ساخت passwd *pw = s->pw;
	صحیح r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_کلیدیں(ssh);

	/* Force a password change */
	اگر (s->authctxt->force_pwchange) {
		do_setusercontext(pw);
		بچہ_close_fds(ssh);
		do_pwchange(s);
		باہر_نکلو(1);
	}

	/*
	 * Login(1) does this as well, and it needs uid 0 for the "-h"
	 * switch, so we let login(1) to this for us.
	 */
#اگر_تعریف_شدہ HAVE_OSF_SIA
	session_تیاری_sia(pw, s->ttyfd == -1 ? تہی : s->tty);
	اگر (!check_quietlogin(s, command))
		do_motd();
#ورنہ /* HAVE_OSF_SIA */
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
#اگر_ختم /* HAVE_OSF_SIA */

#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam && !is_pam_session_open()) {
		debug3("PAM session not opened, exiting");
		display_loginmsg();
		باہر_نکلو(254);
	}
#اگر_ختم

	/*
	 * Get the shell from the password data.  An empty shell field is
	 * legal, and means /bin/sh.
	 */
	shell = (pw->pw_shell[0] == '\0') ? _PATH_BSHELL : pw->pw_shell;

	/*
	 * Make sure $SHELL points to the shell from the password file,
	 * even if shell is overridden from login.conf
	 */
	env = do_تیاری_env(ssh, s, shell);

#اگر_تعریف_شدہ HAVE_LOGIN_CAP
	shell = login_getcapstr(lc, "shell", (حرف *)shell, (حرف *)shell);
#اگر_ختم

	/*
	 * Close the connection descriptors; note that this is the child, and
	 * the server will still have the socket open, and it is important
	 * that we do not shutdown it.  Note that the descriptors cannot be
	 * closed before building the environment, as we call
	 * ssh_remote_ipaddr there.
	 */
	بچہ_close_fds(ssh);

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
	    (s->authctxt->krb5_ctx != تہی)) {
		حرف cell[64];

		debug("Getting AFS token");

		k_setpag();

		اگر (k_afs_cell_کا_file(pw->pw_dir, cell, حجم(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, تہی);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, تہی, تہی, pw->pw_dir);
	}
#اگر_ختم

	/* Change current directory to the user's home directory. */
	اگر (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#اگر_تعریف_شدہ HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#اگر_ختم
		اگر (r || !اندر_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		اگر (r)
			باہر_نکلو(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	اگر (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		لکھو("This service allows sftp connections only.\n");
		fflush(تہی);
		باہر_نکلو(1);
	} ورنہ اگر (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		خارجی صحیح optind, optreset;
		صحیح sftp_argc;
		حرف **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, اندرونی_SFTP_NAME);
		اگر (argv_بانٹو(command == تہی ? "sftp-server" : command,
		    &sftp_argc, &sftp_argv, 1) != 0) {
			error("internal error: can't split internal-sftp "
			    "arguments");
			باہر_نکلو(1);
		}
		optind = optreset = 1;
		__progname = sftp_argv[0];
#اگر_تعریف_شدہ WITH_SELINUX
		ssh_selinux_change_context("sftpd_t");
#اگر_ختم
		باہر_نکلو(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}

	fflush(تہی);

	/* Get the last component of the shell name. */
	اگر ((shell0 = strrchr(shell, '/')) != تہی)
		shell0++;
	ورنہ
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	اگر (!command) {
		حرف argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		اگر (strlcpy(argv0 + 1, shell0, حجم(argv0) - 1)
		    >= حجم(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			باہر_نکلو(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = تہی;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		باہر_نکلو(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (حرف *) shell0;
	argv[1] = "-c";
	argv[2] = (حرف *) command;
	argv[3] = تہی;
	execve(shell, argv, env);
	perror(shell);
	باہر_نکلو(1);
}

خالی
session_غیر_مستعمل(صحیح id)
{
	debug3_f("session id %d unused", id);
	اگر (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, حجم(*sessions));
	sessions[id].self = id;
	sessions[id].مستعمل = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = تہی;
	sessions[id].اگلا_غیر_مستعمل = sessions_پہلا_غیر_مستعمل;
	sessions_پہلا_غیر_مستعمل = id;
}

Session *
session_new(خالی)
{
	Session *s, *tmp;

	اگر (sessions_پہلا_غیر_مستعمل == -1) {
		اگر (sessions_nalloc >= options.max_sessions)
			واپس تہی;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, حجم(*sessions));
		اگر (tmp == تہی) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			واپس تہی;
		}
		sessions = tmp;
		session_غیر_مستعمل(sessions_nalloc++);
	}

	اگر (sessions_پہلا_غیر_مستعمل >= sessions_nalloc ||
	    sessions_پہلا_غیر_مستعمل < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_پہلا_غیر_مستعمل, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_پہلا_غیر_مستعمل];
	اگر (s->مستعمل)
		fatal_f("session %d already used", sessions_پہلا_غیر_مستعمل);
	sessions_پہلا_غیر_مستعمل = s->اگلا_غیر_مستعمل;
	s->مستعمل = 1;
	s->اگلا_غیر_مستعمل = -1;
	debug("session_new: session %d", s->self);

	واپس s;
}

ساکن خالی
session_dump(خالی)
{
	صحیح i;
	برائے (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->مستعمل,
		    s->اگلا_غیر_مستعمل,
		    s->self,
		    s->chanid,
		    (طویل)s->pid);
	}
}

صحیح
session_open(Authctxt *authctxt, صحیح chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	اگر (s == تہی) {
		error("no more sessions");
		واپس 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	اگر (s->pw == تہی || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	واپس 1;
}

Session *
session_by_tty(حرف *tty)
{
	صحیح i;
	برائے (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->مستعمل && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			واپس s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	واپس تہی;
}

ساکن Session *
session_by_channel(صحیح id)
{
	صحیح i;
	برائے (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->مستعمل && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			واپس s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	واپس تہی;
}

ساکن Session *
session_by_x11_channel(صحیح id)
{
	صحیح i, j;

	برائے (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		اگر (s->x11_chanids == تہی || !s->مستعمل)
			جاری;
		برائے (j = 0; s->x11_chanids[j] != -1; j++) {
			اگر (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				واپس s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	واپس تہی;
}

ساکن Session *
session_by_pid(pid_t pid)
{
	صحیح i;
	debug("session_by_pid: pid %ld", (طویل)pid);
	برائے (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->مستعمل && s->pid == pid)
			واپس s;
	}
	error("session_by_pid: unknown pid %ld", (طویل)pid);
	session_dump();
	واپس تہی;
}

ساکن صحیح
session_کھڑکی_change_req(ساخت ssh *ssh, Session *s)
{
	صحیح r;

	اگر ((r = sshpkt_get_u32(ssh, &s->ستون)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->صف)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_کھڑکی_سائز(s->ptyfd, s->صف, s->ستون, s->xpixel, s->ypixel);
	واپس 1;
}

ساکن صحیح
session_pty_req(ساخت ssh *ssh, Session *s)
{
	صحیح r;

	اگر (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		واپس 0;
	}
	اگر (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		واپس 0;
	}

	اگر ((r = sshpkt_get_cstring(ssh, &s->رکن, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ستون)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->صف)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	اگر (strcmp(s->رکن, "") == 0) {
		آزاد(s->رکن);
		s->رکن = تہی;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	اگر (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, حجم(s->tty))) {
		آزاد(s->رکن);
		s->رکن = تہی;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		واپس 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_کھڑکی_سائز(s->ptyfd, s->صف, s->ستون, s->xpixel, s->ypixel);

	session_proctitle(s);
	واپس 1;
}

ساکن صحیح
session_subsystem_req(ساخت ssh *ssh, Session *s)
{
	ساخت stat st;
	صحیح r, success = 0, ملا = 0;
	حرف *prog, *cmd, *type;
	u_int i;

	اگر ((r = sshpkt_get_cstring(ssh, &s->subsys, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	برائے (i = 0; i < options.عدد_subsystems; i++) {
		اگر (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			جاری;
		ملا = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_دلائل[i];
		اگر (strcmp(اندرونی_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} ورنہ {
			اگر (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_سیٹ_xtype(ssh, s->chanid, type);
		آزاد(type);
		success = do_exec(ssh, s, cmd) == 0;
		توڑو;
	}

	اگر (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    ملا ? "execution failed" : "subsystem not found");
	}

	واپس success;
}

ساکن صحیح
session_x11_req(ساخت ssh *ssh, Session *s)
{
	صحیح r, success;
	u_char single_connection = 0;

	اگر (s->auth_proto != تہی || s->auth_ڈیٹا != تہی) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		واپس 0;
	}
	اگر ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_ڈیٹا, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	اگر (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_ڈیٹا))
		success = session_تیاری_x11fwd(ssh, s);
	ورنہ {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	اگر (!success) {
		آزاد(s->auth_proto);
		آزاد(s->auth_ڈیٹا);
		s->auth_proto = تہی;
		s->auth_ڈیٹا = تہی;
	}
	واپس success;
}

ساکن صحیح
session_shell_req(ساخت ssh *ssh, Session *s)
{
	صحیح r;

	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_سیٹ_xtype(ssh, s->chanid, "session:shell");

	واپس do_exec(ssh, s, تہی) == 0;
}

ساکن صحیح
session_exec_req(ساخت ssh *ssh, Session *s)
{
	u_int success;
	صحیح r;
	حرف *command = تہی;

	اگر ((r = sshpkt_get_cstring(ssh, &command, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_سیٹ_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	آزاد(command);
	واپس success;
}

ساکن صحیح
session_break_req(ساخت ssh *ssh, Session *s)
{
	صحیح r;

	اگر ((r = sshpkt_get_u32(ssh, تہی)) != 0 || /* ignore */
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	اگر (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		واپس 0;
	واپس 1;
}

ساکن صحیح
session_env_req(ساخت ssh *ssh, Session *s)
{
	حرف *name, *val;
	u_int i;
	صحیح r;

	اگر ((r = sshpkt_get_cstring(ssh, &name, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	اگر (s->عدد_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		جاؤ fail;
	}

	برائے (i = 0; i < options.عدد_accept_env; i++) {
		اگر (مطابقت_نمونہ(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->عدد_env, name, val);
			s->env = xrecallocarray(s->env, s->عدد_env,
			    s->عدد_env + 1, حجم(*s->env));
			s->env[s->عدد_env].name = name;
			s->env[s->عدد_env].val = val;
			s->عدد_env++;
			واپس (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	آزاد(name);
	آزاد(val);
	واپس (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
ساکن صحیح
name2sig(حرف *name)
{
#تعریف_کرو SSH_SIG(x) اگر (strcmp(name, #x) == 0) واپس SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(رکن_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#تعریف_منسوخ	SSH_SIG
#اگر_تعریف_شدہ SIGINFO
	اگر (strcmp(name, "INFO@openssh.com") == 0)
		واپس SIGINFO;
#اگر_ختم
	واپس -1;
}

ساکن صحیح
session_signal_req(ساخت ssh *ssh, Session *s)
{
	حرف *signame = تہی;
	صحیح r, sig, success = 0;

	اگر ((r = sshpkt_get_cstring(ssh, &signame, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0) {
		error_fr(r, "parse");
		جاؤ برآمد;
	}
	اگر ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		جاؤ برآمد;
	}
	اگر (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		جاؤ برآمد;
	}
	اگر (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		جاؤ برآمد;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (طویل)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	اگر (r != 0) {
		error_f("killpg(%ld, %d): %s", (طویل)s->pid,
		    sig, strerror(errno));
		جاؤ برآمد;
	}

	/* success */
	success = 1;
 برآمد:
	آزاد(signame);
	واپس success;
}

ساکن صحیح
session_auth_agent_req(ساخت ssh *ssh, Session *s, صحیح agent_new)
{
	ساکن صحیح called = 0;
	صحیح r;

	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	اگر (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		واپس 0;
	}
	اگر (called)
		واپس 0;

	called = 1;
	واپس auth_داخلہ_request_forwarding(ssh, s->pw, agent_new);
}

صحیح
session_داخلہ_channel_req(ساخت ssh *ssh, Channel *c, ثابت حرف *rtype)
{
	صحیح success = 0;
	Session *s;

	اگر ((s = session_by_channel(c->self)) == تہی) {
		logit_f("no session %d req %.100s", c->self, rtype);
		واپس 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	اگر (c->type == SSH_CHANNEL_LARVAL) {
		اگر (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} ورنہ اگر (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} ورنہ اگر (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} ورنہ اگر (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} ورنہ اگر (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} ورنہ اگر (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} ورنہ اگر (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} ورنہ اگر (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	اگر (strcmp(rtype, "window-change") == 0) {
		success = session_کھڑکی_change_req(ssh, s);
	} ورنہ اگر (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} ورنہ اگر (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	واپس success;
}

خالی
session_سیٹ_fds(ساخت ssh *ssh, Session *s,
    صحیح fdin, صحیح fdout, صحیح fderr, صحیح ignore_fderr, صحیح is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	اگر (s->chanid == -1)
		fatal("no channel for session %d", s->self);
	channel_سیٹ_fds(ssh, s->chanid,
	    fdout, fdin, fderr,
	    ignore_fderr ? CHAN_EXTENDED_IGNORE : CHAN_EXTENDED_READ,
	    1, is_tty, CHAN_SES_کھڑکی_DEFAULT);
}

/*
 * Function to perform pty cleanup. Also called if we get aborted abnormally
 * (e.g., due to a dropped connection).
 */
خالی
session_pty_cleanup2(Session *s)
{
	اگر (s == تہی) {
		error_f("no session");
		واپس;
	}
	اگر (s->ttyfd == -1)
		واپس;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	اگر (s->pid != 0)
		ریکارڈ_logout(s->pid, s->tty, s->pw->pw_name);

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

خالی
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

ساکن حرف *
sig2name(صحیح sig)
{
#تعریف_کرو SSH_SIG(x) اگر (sig == SIG ## x) واپس #x
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
	SSH_SIG(رکن_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#تعریف_منسوخ	SSH_SIG
	واپس "SIG@openssh.com";
}

ساکن خالی
session_close_x11(ساخت ssh *ssh, صحیح id)
{
	Channel *c;

	اگر ((c = channel_by_id(ssh, id)) == تہی) {
		debug_f("x11 channel %d missing", id);
	} ورنہ {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		اگر (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

ساکن خالی
session_close_single_x11(ساخت ssh *ssh, صحیح id, صحیح force, خالی *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	اگر ((s = session_by_x11_channel(id)) == تہی)
		fatal_f("no x11 channel %d", id);
	برائے (i = 0; s->x11_chanids[i] != -1; i++) {
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
	s->x11_chanids = تہی;
	آزاد(s->display);
	s->display = تہی;
	آزاد(s->auth_proto);
	s->auth_proto = تہی;
	آزاد(s->auth_ڈیٹا);
	s->auth_ڈیٹا = تہی;
	آزاد(s->auth_display);
	s->auth_display = تہی;
}

ساکن خالی
session_exit_پیغام(ساخت ssh *ssh, Session *s, صحیح حالت_2)
{
	Channel *c;
	صحیح r;
	حرف *note = تہی;

	اگر ((c = channel_lookup(ssh, s->chanid)) == تہی)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	اگر (WIFEXITED(حالت_2)) {
		channel_request_آغاز(ssh, s->chanid, "exit-status", 0);
		اگر ((r = sshpkt_put_u32(ssh, WEXITSTATUS(حالت_2))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(حالت_2));
	} ورنہ اگر (WIFSIGNALED(حالت_2)) {
		channel_request_آغاز(ssh, s->chanid, "exit-signal", 0);
#اگر_غیر_تعریف_شدہ WCOREDUMP
# define WCOREDUMP(x) (0)
#اگر_ختم
		اگر ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(حالت_2)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(حالت_2)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(حالت_2),
		    WCOREDUMP(حالت_2) ? " core dumped" : "");
	} ورنہ {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    حالت_2);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (طویل)s->pid, note == تہی ? "UNKNOWN" : note);
	آزاد(note);

	/* disconnect channel */
	debug_f("release channel %d", s->chanid);

	/*
	 * Adjust cleanup callback attachment to send close messages when
	 * the channel gets EOF. The session will be then be closed
	 * by session_close_by_channel when the child sessions close their fds.
	 */
	channel_رجسٹر_cleanup(ssh, c->self, session_close_by_channel, 1);

	/*
	 * emulate a write failure with 'chan_write_failed', nobody will be
	 * interested in data we write.
	 * Note that we must not call 'chan_read_failed', since there could
	 * be some more data waiting in the pipe.
	 */
	اگر (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

خالی
session_close(ساخت ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_پورٹ(ssh),
	    s->self);

	اگر (s->ttyfd != -1)
		session_pty_cleanup(s);
	آزاد(s->رکن);
	آزاد(s->display);
	آزاد(s->x11_chanids);
	آزاد(s->auth_display);
	آزاد(s->auth_ڈیٹا);
	آزاد(s->auth_proto);
	آزاد(s->subsys);
	اگر (s->env != تہی) {
		برائے (i = 0; i < s->عدد_env; i++) {
			آزاد(s->env[i].name);
			آزاد(s->env[i].val);
		}
		آزاد(s->env);
	}
	session_proctitle(s);
	session_غیر_مستعمل(s->self);
}

خالی
session_close_by_pid(ساخت ssh *ssh, pid_t pid, صحیح حالت_2)
{
	Session *s = session_by_pid(pid);
	اگر (s == تہی) {
		debug_f("no session for pid %ld", (طویل)pid);
		واپس;
	}
	اگر (s->chanid != -1)
		session_exit_پیغام(ssh, s, حالت_2);
	اگر (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
خالی
session_close_by_channel(ساخت ssh *ssh, صحیح id, صحیح force, خالی *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	اگر (s == تہی) {
		debug_f("no session for id %d", id);
		واپس;
	}
	debug_f("channel %d child %ld", id, (طویل)s->pid);
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
			واپس;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	اگر (s->x11_chanids != تہی) {
		برائے (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

خالی
session_destroy_all(ساخت ssh *ssh, خالی (*closefunc)(Session *))
{
	صحیح i;
	برائے (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->مستعمل) {
			اگر (closefunc != تہی)
				closefunc(s);
			ورنہ
				session_close(ssh, s);
		}
	}
}

ساکن حرف *
session_tty_list(خالی)
{
	ساکن حرف buf[1024];
	صحیح i;
	حرف *cp;

	buf[0] = '\0';
	برائے (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		اگر (s->مستعمل && s->ttyfd != -1) {

			اگر (لڑی_موازنہ(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == تہی) ? s->tty : cp + 1;
			} ورنہ
				cp = s->tty + 5;

			اگر (buf[0] != '\0')
				strlcat(buf, ",", حجم buf);
			strlcat(buf, cp, حجم buf);
		}
	}
	اگر (buf[0] == '\0')
		strlcpy(buf, "notty", حجم buf);
	واپس buf;
}

خالی
session_proctitle(Session *s)
{
	اگر (s->pw == تہی)
		error("no user for session %d", s->self);
	ورنہ
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

صحیح
session_تیاری_x11fwd(ساخت ssh *ssh, Session *s)
{
	ساخت stat st;
	حرف display[512], auth_display[512];
	حرف hostname[NI_MAXHOST];
	u_int i;

	اگر (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		واپس 0;
	}
	اگر (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		واپس 0;
	}
	اگر (options.xauth_location == تہی ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		واپس 0;
	}
	اگر (s->display != تہی) {
		debug("X11 display already set.");
		واپس 0;
	}
	اگر (x11_create_display_inet(ssh, options.x11_display_انحراف,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_نمبر, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		واپس 0;
	}
	برائے (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_رجسٹر_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	اگر (gethostname(hostname, حجم(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	اگر (options.x11_use_localhost) {
		snprintf(display, حجم display, "localhost:%u.%u",
		    s->display_نمبر, s->screen);
		snprintf(auth_display, حجم auth_display, "unix:%u.%u",
		    s->display_نمبر, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} ورنہ {
#اگر_تعریف_شدہ IPADDR_اندر_DISPLAY
		ساخت hostent *he;
		ساخت in_addr my_addr;

		he = gethostbyname(hostname);
		اگر (he == تہی) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			واپس 0;
		}
		حافظہ_نقل(&my_addr, he->h_addr_list[0], حجم(ساخت in_addr));
		snprintf(display, حجم display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_نمبر, s->screen);
#ورنہ
		snprintf(display, حجم display, "%.400s:%u.%u", hostname,
		    s->display_نمبر, s->screen);
#اگر_ختم
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	واپس 1;
}

ساکن خالی
do_authenticated2(ساخت ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

خالی
do_cleanup(ساخت ssh *ssh, Authctxt *authctxt)
{
	ساکن صحیح called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	اگر (is_بچہ)
		واپس;

	/* avoid double cleanup */
	اگر (called)
		واپس;
	called = 1;

	اگر (authctxt == تہی)
		واپس;

#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#اگر_ختم

	اگر (!authctxt->authenticated)
		واپس;

#اگر_تعریف_شدہ KRB5
	اگر (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#اگر_ختم

#اگر_تعریف_شدہ GSSAPI
	اگر (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#اگر_ختم

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	اگر (auth_info_file != تہی) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		آزاد(auth_info_file);
		auth_info_file = تہی;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	اگر (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

ثابت حرف *
session_get_remote_name_or_ip(ساخت ssh *ssh, u_int utmp_سائز, صحیح use_dns)
{
	ثابت حرف *remote = "";

	اگر (utmp_سائز > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	اگر (utmp_سائز == 0 || لڑی_لمبائی(remote) > utmp_سائز)
		remote = ssh_remote_ipaddr(ssh);
	واپس remote;
}

