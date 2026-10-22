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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/wait.h>
#ضمن <sys/un.h>
#ضمن <sys/stat.h>
#ضمن <sys/socket.h>
#ضمن <sys/queue.h>

#ضمن <arpa/inet.h>

#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <grp.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>
#ضمن <limits.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "sshpty.h"
#ضمن "packet.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "match.h"
#ضمن "uidswap.h"
#ضمن "channels.h"
#ضمن "sshkey.h"
#ضمن "cipher.h"
#ضمن "kex.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-options.h"
#ضمن "authfd.h"
#ضمن "pathnames.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "sshlogin.h"
#ضمن "serverloop.h"
#ضمن "canohost.h"
#ضمن "session.h"
#که_تعریف_شوی GSSAPI
#ضمن "ssh-gss.h"
#د_که_پای
#ضمن "monitor_wrap.h"
#ضمن "sftp.h"
#ضمن "atomicio.h"

#إذا defined(KRB5) && defined(USE_AFS)
#ضمن <kafs.h>
#د_که_پای

#که_تعریف_شوی WITH_SELINUX
#ضمن <selinux/selinux.h>
#د_که_پای

/*
 * Hack for systems that do not support FD passing: allocate PTYs directly
 * without calling into the monitor. This requires either the post-auth
 * privsep process retain root privileges (see the comment in
 * sshd-session.c:privsep_postauth) or that PTY allocation doesn't require
 * privileges to begin with (e.g. Cygwin).
 */
#که_تعریف_شوی DISABLE_FD_PASSING
#تعریف_کړه mm_pty_allocate pty_allocate
#د_که_پای

#تعریف_کړه IS_دننی_SFTP(c) \
	(!مزي_پرتله(c, دننی_SFTP_NAME, حجم(دننی_SFTP_NAME) - 1) && \
	 (c[حجم(دننی_SFTP_NAME) - 1] == '\0' || \
	  c[حجم(دننی_SFTP_NAME) - 1] == ' ' || \
	  c[حجم(دننی_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(فراغ);
فراغ	session_سېټ_fds(بنية ssh *, Session *, صحيح, صحيح, صحيح, صحيح, صحيح);
فراغ	session_pty_cleanup(Session *);
فراغ	session_proctitle(Session *);
صحيح	session_تیاری_x11fwd(بنية ssh *, Session *);
صحيح	do_exec_pty(بنية ssh *, Session *, ثابت حرف *);
صحيح	do_exec_no_pty(بنية ssh *, Session *, ثابت حرف *);
صحيح	do_exec(بنية ssh *, Session *, ثابت حرف *);
فراغ	do_login(بنية ssh *, Session *, ثابت حرف *);
فراغ	do_ماشوم(بنية ssh *, Session *, ثابت حرف *);
فراغ	do_motd(فراغ);
صحيح	check_quietlogin(Session *, ثابت حرف *);

ساكن فراغ do_authenticated2(بنية ssh *, Authctxt *);

ساكن صحيح session_pty_req(بنية ssh *, Session *);

/* import */
خارجي ServerOptions options;
خارجي حرف *__progname;
خارجي صحيح debug_flag;
خارجي بنية sshbuf *loginmsg;
خارجي بنية sshauthopt *auth_opts;
خارجي حرف *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
ثابت حرف *original_command = عدم;

/*معلومات*/
ساكن صحيح sessions_لومړی_ناکارول_شوی = -1;
ساكن صحيح sessions_nalloc = 0;
ساكن Session *sessions = عدم;

#تعریف_کړه SUBSYSTEM_NONE			0
#تعریف_کړه SUBSYSTEM_EXT			1
#تعریف_کړه SUBSYSTEM_INT_SFTP		2
#تعریف_کړه SUBSYSTEM_INT_SFTP_ERROR	3

#که_تعریف_شوی HAVE_LOGIN_CAP
login_cap_t *lc;
#د_که_پای

ساكن صحيح is_ماشوم = 0;
ساكن صحيح دننه_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
ساكن حرف *auth_info_file = عدم;

/* Name and directory of socket for authentication agent forwarding. */
ساكن حرف *auth_sock_name = عدم;
ساكن حرف *auth_sock_dir = عدم; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

ساكن فراغ
auth_sock_cleanup_proc(بنية passwd *pw)
{
	إذا (auth_sock_name != عدم) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_لار,
		    auth_sock_name, auth_sock_dir);
		حرر(auth_sock_name);
		auth_sock_name = عدم;
		restore_uid();
	}
}

ساكن صحيح
auth_ننوت_request_forwarding(بنية ssh *ssh, بنية passwd *pw, صحيح agent_new)
{
	Channel *nc;
	صحيح sock = -1;

	إذا (auth_sock_name != عدم) {
		error("authentication forwarding requested twice.");
		أرجع 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	إذا (agent_listener(options.agent_socket_لار, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		اذهب authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_کړکۍ_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->لار = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	أرجع 1;

 authsock_err:
	حرر(auth_sock_name);
	إذا (sock != -1)
		close(sock);
	auth_sock_name = عدم;
	أرجع 0;
}

ساكن فراغ
display_loginmsg(فراغ)
{
	صحيح r;

	إذا (sshbuf_len(loginmsg) == 0)
		أرجع;
	إذا ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	چاپ_کړه("%s", (حرف *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

ساكن فراغ
prepare_auth_info_file(بنية passwd *pw, بنية sshbuf *info)
{
	صحيح fd = -1, success = 0;

	إذا (!options.expose_userauth_info || info == عدم)
		أرجع;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	إذا ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		اذهب بهر;
	}
	إذا (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		اذهب بهر;
	}
	إذا (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		اذهب بهر;
	}
	success = 1;
 بهر:
	إذا (!success) {
		إذا (fd != -1)
			close(fd);
		حرر(auth_info_file);
		auth_info_file = عدم;
	}
	restore_uid();
}

ساكن فراغ
سېټ_fwdpermit_from_authopts(بنية ssh *ssh, ثابت بنية sshauthopt *opts)
{
	حرف *tmp, *cp, *host;
	صحيح پورټ;
	اندازه_t i;

	إذا ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		لكل (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			إذا ((host = hpdelim2(&cp, عدم)) == عدم)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			إذا (cp == عدم || (پورټ = permitopen_پورټ(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_جمع_کړه_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, پورټ);
			حرر(tmp);
		}
	}
	إذا ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		لكل (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			إذا ((host = hpdelim(&cp)) == عدم)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			إذا (cp == عدم || (پورټ = permitopen_پورټ(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_جمع_کړه_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, پورټ);
			حرر(tmp);
		}
	}
}

فراغ
do_authenticated(بنية ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	سېټ_fwdpermit_from_authopts(ssh, auth_opts);

	إذا (!auth_opts->permit_پورټ_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} وإلا {
		إذا ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		وإلا
			channel_permit_all(ssh, FORWARD_LOCAL);
		إذا ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		وإلا
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
ساكن صحيح
xauth_valid_string(ثابت حرف *s)
{
	اندازه_t i;

	لكل (i = 0; s[i] != '\0'; i++) {
		إذا (!که_توری_یا_عدد((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			أرجع 0;
	}
	أرجع 1;
}

#تعریف_کړه USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
صحيح
do_exec_no_pty(بنية ssh *ssh, Session *s, ثابت حرف *command)
{
	pid_t pid;
#که_تعریف_شوی USE_PIPES
	صحيح pin[2], pout[2], perr[2];

	إذا (s == عدم)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	إذا (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		أرجع -1;
	}
	إذا (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		أرجع -1;
	}
	إذا (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		أرجع -1;
	}
#وإلا
	صحيح inout[2], err[2];

	إذا (s == عدم)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		أرجع -1;
	}
	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		أرجع -1;
	}
#د_که_پای

	session_proctitle(s);

	/* Fork the child. */
	بدل ((pid = fork())) {
	حالة -1:
		error_f("fork: %.100s", strerror(errno));
#که_تعریف_شوی USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#وإلا
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#د_که_پای
		أرجع -1;
	حالة 0:
		is_ماشوم = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		إذا (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#که_تعریف_شوی USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		إذا (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		إذا (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		إذا (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#وإلا
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		إذا (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		إذا (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		إذا (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#د_که_پای

		/* Do processing for the child (exec command etc). */
		do_ماشوم(ssh, s, command);
		/* NOTREACHED */
	افتراضي:
		اكسر;
	}

#که_تعریف_شوی HAVE_CYGWIN
	cygwin_سېټ_impersonation_token(INVALID_HANDLE_ارزښت);
#د_که_پای

	s->pid = pid;

	/*
	 * Clear loginmsg, since it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

#که_تعریف_شوی USE_PIPES
	/* We are the parent.  Close the child sides of the pipes. */
	close(pin[0]);
	close(pout[1]);
	close(perr[1]);

	session_سېټ_fds(ssh, s, pin[1], pout[0], perr[0],
	    s->is_subsystem, 0);
#وإلا
	/* We are the parent.  Close the child sides of the socket pairs. */
	close(inout[0]);
	close(err[0]);

	/*
	 * Enter the interactive session.  Note: server_loop must be able to
	 * handle the case that fdin and fdout are the same.
	 */
	session_سېټ_fds(ssh, s, inout[1], inout[1], err[1],
	    s->is_subsystem, 0);
#د_که_پای
	أرجع 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
صحيح
do_exec_pty(بنية ssh *ssh, Session *s, ثابت حرف *command)
{
	صحيح fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	إذا (s == عدم)
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
	إذا ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		أرجع -1;
	}
	/* we keep a reference to the pty master */
	إذا ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		أرجع -1;
	}

	/* Fork the child. */
	بدل ((pid = fork())) {
	حالة -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		أرجع -1;
	حالة 0:
		is_ماشوم = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		إذا (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		إذا (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		إذا (dup2(ttyfd, 2) == -1)
			error("dup2 stderr: %s", strerror(errno));

		/* Close the extra descriptor for the pseudo tty. */
		close(ttyfd);

		/* record login, etc. similar to login(1) */
#که_نه_تعریف_شوی HAVE_OSF_SIA
		do_login(ssh, s, command);
#د_که_پای
		/*
		 * Do common processing for the child, such as execing
		 * the command.
		 */
		do_ماشوم(ssh, s, command);
		/* NOTREACHED */
	افتراضي:
		اكسر;
	}

#که_تعریف_شوی HAVE_CYGWIN
	cygwin_سېټ_impersonation_token(INVALID_HANDLE_ارزښت);
#د_که_پای

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_سېټ_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	أرجع 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
صحيح
do_exec(بنية ssh *ssh, Session *s, ثابت حرف *command)
{
	صحيح ret;
	ثابت حرف *forced = عدم, *tty = عدم;
	حرف session_type[1024];

	إذا (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} وإلا إذا (auth_opts->force_command != عدم) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	إذا (forced != عدم) {
		s->forced = 1;
		إذا (IS_دننی_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} وإلا إذا (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, حجم(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} وإلا إذا (s->is_subsystem) {
		snprintf(session_type, حجم(session_type),
		    "subsystem '%.900s'", s->subsys);
	} وإلا إذا (command == عدم) {
		snprintf(session_type, حجم(session_type), "shell");
	} وإلا {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, حجم(session_type), "command");
	}

	إذا (s->ttyfd != -1) {
		tty = s->tty;
		إذا (مزي_پرتله(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == عدم ? "" : " on ",
	    tty == عدم ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_پورټ(ssh),
	    s->self);

#که_تعریف_شوی SSH_AUDIT_EVENTS
	إذا (command != عدم)
		mm_audit_پرلپسې_command(command);
	وإلا إذا (s->ttyfd == -1) {
		حرف *shell = s->pw->pw_shell;

		إذا (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_پرلپسې_command(shell);
	}
#د_که_پای
	إذا (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	وإلا
		ret = do_exec_no_pty(ssh, s, command);

	original_command = عدم;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	أرجع ret;
}

/* administrative, login(1)-like work */
فراغ
do_login(بنية ssh *ssh, Session *s, ثابت حرف *command)
{
	socklen_t fromlen;
	بنية sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, حجم(from));
	fromlen = حجم(from);
	إذا (ssh_packet_connection_is_on_socket(ssh)) {
		إذا (getpeername(ssh_packet_get_connection_دننه(ssh),
		    (بنية sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	إذا (check_quietlogin(s, command))
		أرجع;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
فراغ
do_motd(فراغ)
{
	FILE *f;
	حرف buf[256];

	إذا (options.print_motd) {
#که_تعریف_شوی HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#وإلا
		f = fopen("/etc/motd", "r");
#د_که_پای
		إذا (f) {
			طالما (fgets(buf, حجم(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
صحيح
check_quietlogin(Session *s, ثابت حرف *command)
{
	حرف buf[256];
	بنية passwd *pw = s->pw;
	بنية stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	إذا (command != عدم)
		أرجع 1;
	snprintf(buf, حجم(buf), "%.200s/.hushlogin", pw->pw_dir);
#که_تعریف_شوی HAVE_LOGIN_CAP
	إذا (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		أرجع 1;
#وإلا
	إذا (stat(buf, &st) >= 0)
		أرجع 1;
#د_که_پای
	أرجع 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
ساكن فراغ
read_environment_file(حرف ***env, u_int *envsize,
	ثابت حرف *filename, ثابت حرف *allowlist)
{
	FILE *f;
	حرف *کرښه = عدم, *cp, *ارزښت;
	اندازه_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	إذا (!f)
		أرجع;

	طالما (getline(&کرښه, &linesize, f) != -1) {
		إذا (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		لكل (cp = کرښه; *cp == ' ' || *cp == '\t'; cp++)
			;
		إذا (!*cp || *cp == '#' || *cp == '\n')
			استمر;

		cp[strcspn(cp, "\n")] = '\0';

		ارزښت = strchr(cp, '=');
		إذا (ارزښت == عدم) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			استمر;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*ارزښت = '\0';
		ارزښت++;
		إذا (allowlist != عدم &&
		    سمون_نمونه_list(cp, allowlist, 0) != 1)
			استمر;
		ماشوم_سېټ_env(env, envsize, cp, ارزښت);
	}
	حرر(کرښه);
	fclose(f);
}

#که_تعریف_شوی HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
ساكن حرف *
ماشوم_get_env(حرف **env, ثابت حرف *name)
{
	صحيح i;
	اندازه_t len;

	len = مزي_اوږدوالی(name);
	لكل (i=0; env[i] != عدم; i++)
		إذا (مزي_پرتله(name, env[i], len) == 0 && env[i][len] == '=')
			أرجع(env[i] + len + 1);
	أرجع عدم;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
ساكن فراغ
read_etc_default_login(حرف ***env, u_int *envsize, uid_t uid)
{
	حرف **tmpenv = عدم, *var;
	u_int i, tmpenvsize = 0;
	u_long ماسک;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	إذا (tmpenv == عدم)
		أرجع;

	إذا (uid == 0)
		var = ماشوم_get_env(tmpenv, "SUPATH");
	وإلا
		var = ماشوم_get_env(tmpenv, "PATH");
	إذا (var != عدم)
		ماشوم_سېټ_env(env, envsize, "PATH", var);

	إذا ((var = ماشوم_get_env(tmpenv, "UMASK")) != عدم)
		إذا (له_مزي_ولوله(var, "%5lo", &ماسک) == 1)
			umask((ډېرپېښ_t)ماسک);

	لكل (i = 0; tmpenv[i] != عدم; i++)
		حرر(tmpenv[i]);
	حرر(tmpenv);
}
#د_که_پای /* HAVE_ETC_DEFAULT_LOGIN */

#إذا defined(USE_PAM) || defined(HAVE_CYGWIN)
ساكن فراغ
copy_environment_denylist(حرف **سرچینه, حرف ***env, u_int *envsize,
    ثابت حرف *denylist)
{
	حرف *var_name, *var_val;
	صحيح i;

	إذا (سرچینه == عدم)
		أرجع;

	لكل(i = 0; سرچینه[i] != عدم; i++) {
		var_name = xstrdup(سرچینه[i]);
		إذا ((var_val = مزي_پلټنه(var_name, "=")) == عدم) {
			حرر(var_name);
			استمر;
		}
		*var_val++ = '\0';

		إذا (denylist == عدم ||
		    سمون_نمونه_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			ماشوم_سېټ_env(env, envsize, var_name, var_val);
		}

		حرر(var_name);
	}
}
#د_که_پای /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#که_تعریف_شوی HAVE_CYGWIN
ساكن فراغ
copy_environment(حرف **سرچینه, حرف ***env, u_int *envsize)
{
	copy_environment_denylist(سرچینه, env, envsize, عدم);
}
#د_که_پای

ساكن حرف **
do_تیاری_env(بنية ssh *ssh, Session *s, ثابت حرف *shell)
{
	حرف buf[256];
	اندازه_t n;
	u_int i, envsize;
	حرف *ocp, *cp, *ارزښت, **env, *laddr;
	بنية passwd *pw = s->pw;
#إذا !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	حرف *لار = عدم;
#د_که_پای

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, حجم(حرف *));
	env[0] = عدم;

#که_تعریف_شوی HAVE_CYGWIN
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
#د_که_پای

#که_تعریف_شوی GSSAPI
	/* Allow any GSSAPI methods that we've used to alter
	 * the child's environment as they see fit
	 */
	ssh_gssapi_do_ماشوم(&env, &envsize);
#د_که_پای

	/* Set basic environment. */
	لكل (i = 0; i < s->عدد_env; i++)
		ماشوم_سېټ_env(&env, &envsize, s->env[i].name, s->env[i].val);

	ماشوم_سېټ_env(&env, &envsize, "USER", pw->pw_name);
	ماشوم_سېټ_env(&env, &envsize, "LOGNAME", pw->pw_name);
#که_تعریف_شوی _AIX
	ماشوم_سېټ_env(&env, &envsize, "LOGIN", pw->pw_name);
#د_که_پای
	ماشوم_سېټ_env(&env, &envsize, "HOME", pw->pw_dir);
#که_تعریف_شوی HAVE_LOGIN_CAP
	إذا (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		ماشوم_سېټ_env(&env, &envsize, "PATH", _PATH_STDPATH);
	وإلا
		ماشوم_سېټ_env(&env, &envsize, "PATH", getenv("PATH"));
#وإلا /* HAVE_LOGIN_CAP */
# ifndef HAVE_CYGWIN
	/*
	 * There's no standard path on Windows. The path contains
	 * important components pointing to the system directories,
	 * needed for loading shared libraries. So the path better
	 * remains intact here.
	 */
#  ifdef HAVE_ETC_DEFAULT_LOGIN
	read_etc_default_login(&env, &envsize, pw->pw_uid);
	لار = ماشوم_get_env(env, "PATH");
#  endif /* HAVE_ETC_DEFAULT_LOGIN */
	إذا (لار == عدم || *لار == '\0') {
		ماشوم_سېټ_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_لار : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#د_که_پای /* HAVE_LOGIN_CAP */

	إذا (!options.use_pam) {
		snprintf(buf, حجم buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		ماشوم_سېټ_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	ماشوم_سېټ_env(&env, &envsize, "SHELL", shell);

	إذا (getenv("TZ"))
		ماشوم_سېټ_env(&env, &envsize, "TZ", getenv("TZ"));
#که_تعریف_شوی HAVE_LOGIN_CAP
	إذا (getenv("XDG_RUNTIME_DIR")) {
		ماشوم_سېټ_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#د_که_پای /* HAVE_LOGIN_CAP */
	إذا (s->غړی)
		ماشوم_سېټ_env(&env, &envsize, "TERM", s->غړی);
	إذا (s->display)
		ماشوم_سېټ_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		حرف *cp;

		إذا ((cp = getenv("KRB5CCNAME")) != عدم)
			ماشوم_سېټ_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#که_تعریف_شوی _AIX
	{
		حرف *cp;

		إذا ((cp = getenv("AUTHSTATE")) != عدم)
			ماشوم_سېټ_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#د_که_پای
#که_تعریف_شوی KRB5
	إذا (s->authctxt->krb5_ccname)
		ماشوم_سېټ_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#د_که_پای
	إذا (auth_sock_name != عدم)
		ماشوم_سېټ_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	إذا (options.permit_user_env) {
		لكل (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			إذا (cp != عدم) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				إذا (options.permit_user_env_allowlist == عدم ||
				    سمون_نمونه_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					ماشوم_سېټ_env(&env, &envsize,
					    ocp, cp + 1);
			}
			حرر(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	إذا (options.permit_user_env) {
		snprintf(buf, حجم buf, "%.200s/%s/environment",
		    pw->pw_dir, لار_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#که_تعریف_شوی USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	إذا (options.use_pam) {
		حرف **p;

		/*
		 * Don't allow PAM-internal env vars to leak
		 * back into the session environment.
		 */
#تعریف_کړه PAM_ENV_DENYLIST  "SSH_AUTH_INFO*,SSH_CONNECTION*"
		p = fetch_pam_ماشوم_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);

		p = fetch_pam_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);
	}
#د_که_پای /* USE_PAM */

	/* Environment specified by admin */
	لكل (i = 0; i < options.عدد_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		إذا ((ارزښت = strchr(cp, '=')) == عدم) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*ارزښت++ = '\0';
		ماشوم_سېټ_env(&env, &envsize, cp, ارزښت);
		حرر(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, حجم buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورټ(ssh),
	    ssh_local_پورټ(ssh));
	ماشوم_سېټ_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_دننه(ssh));
	snprintf(buf, حجم buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورټ(ssh),
	    laddr, ssh_local_پورټ(ssh));
	حرر(laddr);
	ماشوم_سېټ_env(&env, &envsize, "SSH_CONNECTION", buf);

	إذا (tun_fwd_ifnames != عدم)
		ماشوم_سېټ_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	إذا (auth_info_file != عدم)
		ماشوم_سېټ_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	إذا (s->ttyfd != -1)
		ماشوم_سېټ_env(&env, &envsize, "SSH_TTY", s->tty);
	إذا (original_command)
		ماشوم_سېټ_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	إذا (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		لكل (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	أرجع env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
ساكن فراغ
do_rc_files(بنية ssh *ssh, Session *s, ثابت حرف *shell)
{
	FILE *f = عدم;
	حرف *cmd = عدم, *user_rc = عدم;
	صحيح do_xauth;
	بنية stat st;

	do_xauth =
	    s->display != عدم && s->auth_proto != عدم && s->auth_معلومات != عدم;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, لار_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	إذا (!s->is_subsystem && options.adm_forced_command == عدم &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		إذا (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		إذا (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		إذا (f) {
			إذا (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_معلومات);
			pclose(f);
		} وإلا
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} وإلا إذا (stat(لار_SSH_SYSTEM_RC, &st) >= 0) {
		إذا (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    لار_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " لار_SSH_SYSTEM_RC, "w");
		إذا (f) {
			إذا (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_معلومات);
			pclose(f);
		} وإلا
			fprintf(stderr, "Could not run %s\n",
			    لار_SSH_SYSTEM_RC);
	} وإلا إذا (do_xauth && options.xauth_location != عدم) {
		/* Add authority data to .Xauthority if appropriate. */
		إذا (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_معلومات);
		}
		إذا (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		إذا (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_معلومات);
			pclose(f);
		} وإلا {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	حرر(cmd);
	حرر(user_rc);
}

ساكن فراغ
do_nologin(بنية passwd *pw)
{
	FILE *f = عدم;
	حرف buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	بنية stat sb;

#که_تعریف_شوی HAVE_LOGIN_CAP
	إذا (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		أرجع;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#وإلا
	إذا (pw->pw_uid == 0)
		أرجع;
	nl = def_nl;
#د_که_پای
	إذا (stat(nl, &sb) == -1)
		أرجع;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	إذا ((f = fopen(nl, "r")) != عدم) {
		طالما (fgets(buf, حجم(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	وتل(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
ساكن فراغ
safely_chroot(ثابت حرف *لار, uid_t uid)
{
	ثابت حرف *cp;
	حرف component[PATH_MAX];
	بنية stat st;

	إذا (!لار_absolute(لار))
		fatal("chroot path does not begin at root");
	إذا (مزي_اوږدوالی(لار) >= حجم(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	لكل (cp = لار; cp != عدم;) {
		إذا ((cp = strchr(cp, '/')) == عدم)
			strlcpy(component, لار, حجم(component));
		وإلا {
			cp++;
			حافظه_نقل(component, لار, cp - لار);
			component[cp - لار] = '\0';
		}

		debug3_f("checking '%s'", component);

		إذا (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		إذا (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == عدم ? "" : "component ", component);
		إذا (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == عدم ? "" : "component ", component);

	}

	إذا (chdir(لار) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", لار, strerror(errno));
	إذا (chroot(لار) == -1)
		fatal("chroot(\"%s\"): %s", لار, strerror(errno));
	إذا (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", لار);
}

/* Set login name, uid, gid, and groups. */
فراغ
do_setusercontext(بنية passwd *pw)
{
	حرف uidstr[32], *chroot_لار, *tmp;

	platform_setusercontext(pw);

	إذا (platform_privileged_uidswap()) {
#که_تعریف_شوی HAVE_LOGIN_CAP
		إذا (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			وتل(1);
		}
#وإلا
		إذا (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		إذا (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			وتل(1);
		}
		/* Initialize the group list. */
		إذا (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			وتل(1);
		}
		endgrent();
#د_که_پای

		platform_setusercontext_post_groups(pw);

		إذا (!دننه_chroot && options.chroot_directory != عدم &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, حجم(uidstr), "%llu",
			    (بینښه اوږد اوږد)pw->pw_uid);
			chroot_لار = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (حرف *)عدم);
			safely_chroot(chroot_لار, pw->pw_uid);
			حرر(tmp);
			حرر(chroot_لار);
			/* Make sure we don't attempt to chroot again */
			حرر(options.chroot_directory);
			options.chroot_directory = عدم;
			دننه_chroot = 1;
		}

#که_تعریف_شوی HAVE_LOGIN_CAP
		إذا (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			وتل(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(فراغ) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#وإلا
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		إذا (!دننه_chroot && سېټ_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_سېټ_uid(pw);
#د_که_پای
	} وإلا إذا (options.chroot_directory != عدم &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	إذا (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

ساكن فراغ
do_pwchange(Session *s)
{
	fflush(عدم);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	إذا (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#که_تعریف_شوی WITH_SELINUX
		setexeccon(عدم);
#د_که_پای
#که_تعریف_شوی PASSWD_NEEDS_USERNAME
		execl(لار_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (حرف *)عدم);
#وإلا
		execl(لار_PASSWD_PROG, "passwd", (حرف *)عدم);
#د_که_پای
		perror("passwd");
	} وإلا {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	وتل(1);
}

ساكن فراغ
ماشوم_close_fds(بنية ssh *ssh)
{
	خارجي صحيح auth_sock;

	إذا (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	إذا (ssh_packet_get_connection_دننه(ssh) ==
	    ssh_packet_get_connection_بهر(ssh))
		close(ssh_packet_get_connection_دننه(ssh));
	وإلا {
		close(ssh_packet_get_connection_دننه(ssh));
		close(ssh_packet_get_connection_بهر(ssh));
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
	log_redirect_stderr_منزل(عدم);

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
#تعریف_کړه ARGV_MAX 10
فراغ
do_ماشوم(بنية ssh *ssh, Session *s, ثابت حرف *command)
{
	خارجي حرف **environ;
	حرف **env, *argv[ARGV_MAX], remote_id[512];
	ثابت حرف *shell, *shell0;
	بنية passwd *pw = s->pw;
	صحيح r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_کلیګانې(ssh);

	/* Force a password change */
	إذا (s->authctxt->force_pwchange) {
		do_setusercontext(pw);
		ماشوم_close_fds(ssh);
		do_pwchange(s);
		وتل(1);
	}

	/*
	 * Login(1) does this as well, and it needs uid 0 for the "-h"
	 * switch, so we let login(1) to this for us.
	 */
#که_تعریف_شوی HAVE_OSF_SIA
	session_تیاری_sia(pw, s->ttyfd == -1 ? عدم : s->tty);
	إذا (!check_quietlogin(s, command))
		do_motd();
#وإلا /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	إذا (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	إذا (!check_quietlogin(s, command))
		display_loginmsg();
#د_که_پای /* HAVE_OSF_SIA */

#که_تعریف_شوی USE_PAM
	إذا (options.use_pam && !is_pam_session_open()) {
		debug3("PAM session not opened, exiting");
		display_loginmsg();
		وتل(254);
	}
#د_که_پای

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

#که_تعریف_شوی HAVE_LOGIN_CAP
	shell = login_getcapstr(lc, "shell", (حرف *)shell, (حرف *)shell);
#د_که_پای

	/*
	 * Close the connection descriptors; note that this is the child, and
	 * the server will still have the socket open, and it is important
	 * that we do not shutdown it.  Note that the descriptors cannot be
	 * closed before building the environment, as we call
	 * ssh_remote_ipaddr there.
	 */
	ماشوم_close_fds(ssh);

	/*
	 * Must take new environment into use so that .ssh/rc,
	 * /etc/ssh/sshrc and xauth are run in the proper environment.
	 */
	environ = env;

#إذا defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	إذا (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != عدم)) {
		حرف cell[64];

		debug("Getting AFS token");

		k_setpag();

		إذا (k_afs_cell_د_file(pw->pw_dir, cell, حجم(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, عدم);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, عدم, عدم, pw->pw_dir);
	}
#د_که_پای

	/* Change current directory to the user's home directory. */
	إذا (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#که_تعریف_شوی HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#د_که_پای
		إذا (r || !دننه_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		إذا (r)
			وتل(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	إذا (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		چاپ_کړه("This service allows sftp connections only.\n");
		fflush(عدم);
		وتل(1);
	} وإلا إذا (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		خارجي صحيح optind, optreset;
		صحيح sftp_argc;
		حرف **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, دننی_SFTP_NAME);
		إذا (argv_وېشل(command == عدم ? "sftp-server" : command,
		    &sftp_argc, &sftp_argv, 1) != 0) {
			error("internal error: can't split internal-sftp "
			    "arguments");
			وتل(1);
		}
		optind = optreset = 1;
		__progname = sftp_argv[0];
#که_تعریف_شوی WITH_SELINUX
		ssh_selinux_change_context("sftpd_t");
#د_که_پای
		وتل(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}

	fflush(عدم);

	/* Get the last component of the shell name. */
	إذا ((shell0 = strrchr(shell, '/')) != عدم)
		shell0++;
	وإلا
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	إذا (!command) {
		حرف argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		إذا (strlcpy(argv0 + 1, shell0, حجم(argv0) - 1)
		    >= حجم(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			وتل(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = عدم;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		وتل(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (حرف *) shell0;
	argv[1] = "-c";
	argv[2] = (حرف *) command;
	argv[3] = عدم;
	execve(shell, argv, env);
	perror(shell);
	وتل(1);
}

فراغ
session_ناکارول_شوی(صحيح id)
{
	debug3_f("session id %d unused", id);
	إذا (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, حجم(*sessions));
	sessions[id].self = id;
	sessions[id].کارول_شوی = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = عدم;
	sessions[id].بل_ناکارول_شوی = sessions_لومړی_ناکارول_شوی;
	sessions_لومړی_ناکارول_شوی = id;
}

Session *
session_new(فراغ)
{
	Session *s, *tmp;

	إذا (sessions_لومړی_ناکارول_شوی == -1) {
		إذا (sessions_nalloc >= options.max_sessions)
			أرجع عدم;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, حجم(*sessions));
		إذا (tmp == عدم) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			أرجع عدم;
		}
		sessions = tmp;
		session_ناکارول_شوی(sessions_nalloc++);
	}

	إذا (sessions_لومړی_ناکارول_شوی >= sessions_nalloc ||
	    sessions_لومړی_ناکارول_شوی < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_لومړی_ناکارول_شوی, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_لومړی_ناکارول_شوی];
	إذا (s->کارول_شوی)
		fatal_f("session %d already used", sessions_لومړی_ناکارول_شوی);
	sessions_لومړی_ناکارول_شوی = s->بل_ناکارول_شوی;
	s->کارول_شوی = 1;
	s->بل_ناکارول_شوی = -1;
	debug("session_new: session %d", s->self);

	أرجع s;
}

ساكن فراغ
session_dump(فراغ)
{
	صحيح i;
	لكل (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->کارول_شوی,
		    s->بل_ناکارول_شوی,
		    s->self,
		    s->chanid,
		    (اوږد)s->pid);
	}
}

صحيح
session_open(Authctxt *authctxt, صحيح chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	إذا (s == عدم) {
		error("no more sessions");
		أرجع 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	إذا (s->pw == عدم || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	أرجع 1;
}

Session *
session_by_tty(حرف *tty)
{
	صحيح i;
	لكل (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		إذا (s->کارول_شوی && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			أرجع s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	أرجع عدم;
}

ساكن Session *
session_by_channel(صحيح id)
{
	صحيح i;
	لكل (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		إذا (s->کارول_شوی && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			أرجع s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	أرجع عدم;
}

ساكن Session *
session_by_x11_channel(صحيح id)
{
	صحيح i, j;

	لكل (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		إذا (s->x11_chanids == عدم || !s->کارول_شوی)
			استمر;
		لكل (j = 0; s->x11_chanids[j] != -1; j++) {
			إذا (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				أرجع s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	أرجع عدم;
}

ساكن Session *
session_by_pid(pid_t pid)
{
	صحيح i;
	debug("session_by_pid: pid %ld", (اوږد)pid);
	لكل (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		إذا (s->کارول_شوی && s->pid == pid)
			أرجع s;
	}
	error("session_by_pid: unknown pid %ld", (اوږد)pid);
	session_dump();
	أرجع عدم;
}

ساكن صحيح
session_کړکۍ_change_req(بنية ssh *ssh, Session *s)
{
	صحيح r;

	إذا ((r = sshpkt_get_u32(ssh, &s->ستون)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->لیکه)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_کړکۍ_اندازه(s->ptyfd, s->لیکه, s->ستون, s->xpixel, s->ypixel);
	أرجع 1;
}

ساكن صحيح
session_pty_req(بنية ssh *ssh, Session *s)
{
	صحيح r;

	إذا (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		أرجع 0;
	}
	إذا (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		أرجع 0;
	}

	إذا ((r = sshpkt_get_cstring(ssh, &s->غړی, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ستون)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->لیکه)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	إذا (strcmp(s->غړی, "") == 0) {
		حرر(s->غړی);
		s->غړی = عدم;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	إذا (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, حجم(s->tty))) {
		حرر(s->غړی);
		s->غړی = عدم;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		أرجع 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	إذا ((r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_کړکۍ_اندازه(s->ptyfd, s->لیکه, s->ستون, s->xpixel, s->ypixel);

	session_proctitle(s);
	أرجع 1;
}

ساكن صحيح
session_subsystem_req(بنية ssh *ssh, Session *s)
{
	بنية stat st;
	صحيح r, success = 0, وموندل = 0;
	حرف *prog, *cmd, *type;
	u_int i;

	إذا ((r = sshpkt_get_cstring(ssh, &s->subsys, عدم)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	لكل (i = 0; i < options.عدد_subsystems; i++) {
		إذا (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			استمر;
		وموندل = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_دلیلونه[i];
		إذا (strcmp(دننی_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} وإلا {
			إذا (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_سېټ_xtype(ssh, s->chanid, type);
		حرر(type);
		success = do_exec(ssh, s, cmd) == 0;
		اكسر;
	}

	إذا (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    وموندل ? "execution failed" : "subsystem not found");
	}

	أرجع success;
}

ساكن صحيح
session_x11_req(بنية ssh *ssh, Session *s)
{
	صحيح r, success;
	u_char single_connection = 0;

	إذا (s->auth_proto != عدم || s->auth_معلومات != عدم) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		أرجع 0;
	}
	إذا ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_معلومات, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	إذا (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_معلومات))
		success = session_تیاری_x11fwd(ssh, s);
	وإلا {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	إذا (!success) {
		حرر(s->auth_proto);
		حرر(s->auth_معلومات);
		s->auth_proto = عدم;
		s->auth_معلومات = عدم;
	}
	أرجع success;
}

ساكن صحيح
session_shell_req(بنية ssh *ssh, Session *s)
{
	صحيح r;

	إذا ((r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_سېټ_xtype(ssh, s->chanid, "session:shell");

	أرجع do_exec(ssh, s, عدم) == 0;
}

ساكن صحيح
session_exec_req(بنية ssh *ssh, Session *s)
{
	u_int success;
	صحيح r;
	حرف *command = عدم;

	إذا ((r = sshpkt_get_cstring(ssh, &command, عدم)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_سېټ_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	حرر(command);
	أرجع success;
}

ساكن صحيح
session_break_req(بنية ssh *ssh, Session *s)
{
	صحيح r;

	إذا ((r = sshpkt_get_u32(ssh, عدم)) != 0 || /* ignore */
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	إذا (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		أرجع 0;
	أرجع 1;
}

ساكن صحيح
session_env_req(بنية ssh *ssh, Session *s)
{
	حرف *name, *val;
	u_int i;
	صحيح r;

	إذا ((r = sshpkt_get_cstring(ssh, &name, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, عدم)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	إذا (s->عدد_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		اذهب fail;
	}

	لكل (i = 0; i < options.عدد_accept_env; i++) {
		إذا (سمون_نمونه(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->عدد_env, name, val);
			s->env = xrecallocarray(s->env, s->عدد_env,
			    s->عدد_env + 1, حجم(*s->env));
			s->env[s->عدد_env].name = name;
			s->env[s->عدد_env].val = val;
			s->عدد_env++;
			أرجع (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	حرر(name);
	حرر(val);
	أرجع (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
ساكن صحيح
name2sig(حرف *name)
{
#تعریف_کړه SSH_SIG(x) إذا (strcmp(name, #x) == 0) أرجع SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(غړی_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#تعریف_لغوه	SSH_SIG
#که_تعریف_شوی SIGINFO
	إذا (strcmp(name, "INFO@openssh.com") == 0)
		أرجع SIGINFO;
#د_که_پای
	أرجع -1;
}

ساكن صحيح
session_signal_req(بنية ssh *ssh, Session *s)
{
	حرف *signame = عدم;
	صحيح r, sig, success = 0;

	إذا ((r = sshpkt_get_cstring(ssh, &signame, عدم)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0) {
		error_fr(r, "parse");
		اذهب بهر;
	}
	إذا ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		اذهب بهر;
	}
	إذا (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		اذهب بهر;
	}
	إذا (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		اذهب بهر;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (اوږد)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	إذا (r != 0) {
		error_f("killpg(%ld, %d): %s", (اوږد)s->pid,
		    sig, strerror(errno));
		اذهب بهر;
	}

	/* success */
	success = 1;
 بهر:
	حرر(signame);
	أرجع success;
}

ساكن صحيح
session_auth_agent_req(بنية ssh *ssh, Session *s, صحيح agent_new)
{
	ساكن صحيح called = 0;
	صحيح r;

	إذا ((r = sshpkt_get_پای_ټکی(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	إذا (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		أرجع 0;
	}
	إذا (called)
		أرجع 0;

	called = 1;
	أرجع auth_ننوت_request_forwarding(ssh, s->pw, agent_new);
}

صحيح
session_ننوت_channel_req(بنية ssh *ssh, Channel *c, ثابت حرف *rtype)
{
	صحيح success = 0;
	Session *s;

	إذا ((s = session_by_channel(c->self)) == عدم) {
		logit_f("no session %d req %.100s", c->self, rtype);
		أرجع 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	إذا (c->type == SSH_CHANNEL_LARVAL) {
		إذا (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} وإلا إذا (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} وإلا إذا (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} وإلا إذا (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} وإلا إذا (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} وإلا إذا (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} وإلا إذا (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} وإلا إذا (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	إذا (strcmp(rtype, "window-change") == 0) {
		success = session_کړکۍ_change_req(ssh, s);
	} وإلا إذا (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} وإلا إذا (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	أرجع success;
}

فراغ
session_سېټ_fds(بنية ssh *ssh, Session *s,
    صحيح fdin, صحيح fdout, صحيح fderr, صحيح ignore_fderr, صحيح is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	إذا (s->chanid == -1)
		fatal("no channel for session %d", s->self);
	channel_سېټ_fds(ssh, s->chanid,
	    fdout, fdin, fderr,
	    ignore_fderr ? CHAN_EXTENDED_IGNORE : CHAN_EXTENDED_READ,
	    1, is_tty, CHAN_SES_کړکۍ_DEFAULT);
}

/*
 * Function to perform pty cleanup. Also called if we get aborted abnormally
 * (e.g., due to a dropped connection).
 */
فراغ
session_pty_cleanup2(Session *s)
{
	إذا (s == عدم) {
		error_f("no session");
		أرجع;
	}
	إذا (s->ttyfd == -1)
		أرجع;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	إذا (s->pid != 0)
		ریکارډ_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	إذا (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	إذا (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

فراغ
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

ساكن حرف *
sig2name(صحيح sig)
{
#تعریف_کړه SSH_SIG(x) إذا (sig == SIG ## x) أرجع #x
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
	SSH_SIG(غړی_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#تعریف_لغوه	SSH_SIG
	أرجع "SIG@openssh.com";
}

ساكن فراغ
session_close_x11(بنية ssh *ssh, صحيح id)
{
	Channel *c;

	إذا ((c = channel_by_id(ssh, id)) == عدم) {
		debug_f("x11 channel %d missing", id);
	} وإلا {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		إذا (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

ساكن فراغ
session_close_single_x11(بنية ssh *ssh, صحيح id, صحيح force, فراغ *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	إذا ((s = session_by_x11_channel(id)) == عدم)
		fatal_f("no x11 channel %d", id);
	لكل (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		إذا (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	حرر(s->x11_chanids);
	s->x11_chanids = عدم;
	حرر(s->display);
	s->display = عدم;
	حرر(s->auth_proto);
	s->auth_proto = عدم;
	حرر(s->auth_معلومات);
	s->auth_معلومات = عدم;
	حرر(s->auth_display);
	s->auth_display = عدم;
}

ساكن فراغ
session_exit_پیغام(بنية ssh *ssh, Session *s, صحيح حالت)
{
	Channel *c;
	صحيح r;
	حرف *note = عدم;

	إذا ((c = channel_lookup(ssh, s->chanid)) == عدم)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	إذا (WIFEXITED(حالت)) {
		channel_request_پیل(ssh, s->chanid, "exit-status", 0);
		إذا ((r = sshpkt_put_u32(ssh, WEXITSTATUS(حالت))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(حالت));
	} وإلا إذا (WIFSIGNALED(حالت)) {
		channel_request_پیل(ssh, s->chanid, "exit-signal", 0);
#که_نه_تعریف_شوی WCOREDUMP
# define WCOREDUMP(x) (0)
#د_که_پای
		إذا ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(حالت)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(حالت)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(حالت),
		    WCOREDUMP(حالت) ? " core dumped" : "");
	} وإلا {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    حالت);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (اوږد)s->pid, note == عدم ? "UNKNOWN" : note);
	حرر(note);

	/* disconnect channel */
	debug_f("release channel %d", s->chanid);

	/*
	 * Adjust cleanup callback attachment to send close messages when
	 * the channel gets EOF. The session will be then be closed
	 * by session_close_by_channel when the child sessions close their fds.
	 */
	channel_ثبتوونکی_cleanup(ssh, c->self, session_close_by_channel, 1);

	/*
	 * emulate a write failure with 'chan_write_failed', nobody will be
	 * interested in data we write.
	 * Note that we must not call 'chan_read_failed', since there could
	 * be some more data waiting in the pipe.
	 */
	إذا (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

فراغ
session_close(بنية ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_پورټ(ssh),
	    s->self);

	إذا (s->ttyfd != -1)
		session_pty_cleanup(s);
	حرر(s->غړی);
	حرر(s->display);
	حرر(s->x11_chanids);
	حرر(s->auth_display);
	حرر(s->auth_معلومات);
	حرر(s->auth_proto);
	حرر(s->subsys);
	إذا (s->env != عدم) {
		لكل (i = 0; i < s->عدد_env; i++) {
			حرر(s->env[i].name);
			حرر(s->env[i].val);
		}
		حرر(s->env);
	}
	session_proctitle(s);
	session_ناکارول_شوی(s->self);
}

فراغ
session_close_by_pid(بنية ssh *ssh, pid_t pid, صحيح حالت)
{
	Session *s = session_by_pid(pid);
	إذا (s == عدم) {
		debug_f("no session for pid %ld", (اوږد)pid);
		أرجع;
	}
	إذا (s->chanid != -1)
		session_exit_پیغام(ssh, s, حالت);
	إذا (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
فراغ
session_close_by_channel(بنية ssh *ssh, صحيح id, صحيح force, فراغ *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	إذا (s == عدم) {
		debug_f("no session for id %d", id);
		أرجع;
	}
	debug_f("channel %d child %ld", id, (اوږد)s->pid);
	إذا (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		إذا (s->ttyfd != -1)
			session_pty_cleanup(s);
		إذا (!force)
			أرجع;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	إذا (s->x11_chanids != عدم) {
		لكل (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

فراغ
session_destroy_all(بنية ssh *ssh, فراغ (*closefunc)(Session *))
{
	صحيح i;
	لكل (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		إذا (s->کارول_شوی) {
			إذا (closefunc != عدم)
				closefunc(s);
			وإلا
				session_close(ssh, s);
		}
	}
}

ساكن حرف *
session_tty_list(فراغ)
{
	ساكن حرف buf[1024];
	صحيح i;
	حرف *cp;

	buf[0] = '\0';
	لكل (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		إذا (s->کارول_شوی && s->ttyfd != -1) {

			إذا (مزي_پرتله(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == عدم) ? s->tty : cp + 1;
			} وإلا
				cp = s->tty + 5;

			إذا (buf[0] != '\0')
				strlcat(buf, ",", حجم buf);
			strlcat(buf, cp, حجم buf);
		}
	}
	إذا (buf[0] == '\0')
		strlcpy(buf, "notty", حجم buf);
	أرجع buf;
}

فراغ
session_proctitle(Session *s)
{
	إذا (s->pw == عدم)
		error("no user for session %d", s->self);
	وإلا
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

صحيح
session_تیاری_x11fwd(بنية ssh *ssh, Session *s)
{
	بنية stat st;
	حرف display[512], auth_display[512];
	حرف hostname[NI_MAXHOST];
	u_int i;

	إذا (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		أرجع 0;
	}
	إذا (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		أرجع 0;
	}
	إذا (options.xauth_location == عدم ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		أرجع 0;
	}
	إذا (s->display != عدم) {
		debug("X11 display already set.");
		أرجع 0;
	}
	إذا (x11_create_display_inet(ssh, options.x11_display_دننه_واټن,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_شمېره, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		أرجع 0;
	}
	لكل (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_ثبتوونکی_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	إذا (gethostname(hostname, حجم(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	إذا (options.x11_use_localhost) {
		snprintf(display, حجم display, "localhost:%u.%u",
		    s->display_شمېره, s->screen);
		snprintf(auth_display, حجم auth_display, "unix:%u.%u",
		    s->display_شمېره, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} وإلا {
#که_تعریف_شوی IPADDR_دننه_DISPLAY
		بنية hostent *he;
		بنية in_addr my_addr;

		he = gethostbyname(hostname);
		إذا (he == عدم) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			أرجع 0;
		}
		حافظه_نقل(&my_addr, he->h_addr_list[0], حجم(بنية in_addr));
		snprintf(display, حجم display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_شمېره, s->screen);
#وإلا
		snprintf(display, حجم display, "%.400s:%u.%u", hostname,
		    s->display_شمېره, s->screen);
#د_که_پای
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	أرجع 1;
}

ساكن فراغ
do_authenticated2(بنية ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

فراغ
do_cleanup(بنية ssh *ssh, Authctxt *authctxt)
{
	ساكن صحيح called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	إذا (is_ماشوم)
		أرجع;

	/* avoid double cleanup */
	إذا (called)
		أرجع;
	called = 1;

	إذا (authctxt == عدم)
		أرجع;

#که_تعریف_شوی USE_PAM
	إذا (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#د_که_پای

	إذا (!authctxt->authenticated)
		أرجع;

#که_تعریف_شوی KRB5
	إذا (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#د_که_پای

#که_تعریف_شوی GSSAPI
	إذا (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#د_که_پای

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	إذا (auth_info_file != عدم) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		حرر(auth_info_file);
		auth_info_file = عدم;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	إذا (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

ثابت حرف *
session_get_remote_name_or_ip(بنية ssh *ssh, u_int utmp_اندازه, صحيح use_dns)
{
	ثابت حرف *remote = "";

	إذا (utmp_اندازه > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	إذا (utmp_اندازه == 0 || مزي_اوږدوالی(remote) > utmp_اندازه)
		remote = ssh_remote_ipaddr(ssh);
	أرجع remote;
}

