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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/un.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <grp.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshpty.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "sshlogin.h"
#அந்தர்பாவ "serverloop.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "session.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "sftp.h"
#அந்தர்பாவ "atomicio.h"

#எனில் defined(KRB5) && defined(USE_AFS)
#அந்தர்பாவ <kafs.h>
#endif

#ifdef WITH_SELINUX
#அந்தர்பாவ <selinux/selinux.h>
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
	(!strncmp(c, INTERNAL_SFTP_NAME, அளவு(INTERNAL_SFTP_NAME) - 1) && \
	 (c[அளவு(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[அளவு(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[அளவு(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(வெறுமை);
வெறுமை	session_set_fds(கட்டமைப்பு ssh *, Session *, முழு, முழு, முழு, முழு, முழு);
வெறுமை	session_pty_cleanup(Session *);
வெறுமை	session_proctitle(Session *);
முழு	session_setup_x11fwd(கட்டமைப்பு ssh *, Session *);
முழு	do_exec_pty(கட்டமைப்பு ssh *, Session *, மாறிலி எழுத்து *);
முழு	do_exec_no_pty(கட்டமைப்பு ssh *, Session *, மாறிலி எழுத்து *);
முழு	do_exec(கட்டமைப்பு ssh *, Session *, மாறிலி எழுத்து *);
வெறுமை	do_login(கட்டமைப்பு ssh *, Session *, மாறிலி எழுத்து *);
வெறுமை	do_child(கட்டமைப்பு ssh *, Session *, மாறிலி எழுத்து *);
வெறுமை	do_motd(வெறுமை);
முழு	check_quietlogin(Session *, மாறிலி எழுத்து *);

நிலையான வெறுமை do_authenticated2(கட்டமைப்பு ssh *, Authctxt *);

நிலையான முழு session_pty_req(கட்டமைப்பு ssh *, Session *);

/* import */
வெளி ServerOptions options;
வெளி எழுத்து *__progname;
வெளி முழு debug_flag;
வெளி கட்டமைப்பு sshbuf *loginmsg;
வெளி கட்டமைப்பு sshauthopt *auth_opts;
வெளி எழுத்து *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
மாறிலி எழுத்து *original_command = வெற்று;

/* data */
நிலையான முழு sessions_first_unused = -1;
நிலையான முழு sessions_nalloc = 0;
நிலையான Session *sessions = வெற்று;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

நிலையான முழு is_child = 0;
நிலையான முழு in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
நிலையான எழுத்து *auth_info_file = வெற்று;

/* Name and directory of socket for authentication agent forwarding. */
நிலையான எழுத்து *auth_sock_name = வெற்று;
நிலையான எழுத்து *auth_sock_dir = வெற்று; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

நிலையான வெறுமை
auth_sock_cleanup_proc(கட்டமைப்பு passwd *pw)
{
	எனில் (auth_sock_name != வெற்று) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		விடுவி(auth_sock_name);
		auth_sock_name = வெற்று;
		restore_uid();
	}
}

நிலையான முழு
auth_உள்ளீடு_request_forwarding(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *pw, முழு agent_new)
{
	Channel *nc;
	முழு sock = -1;

	எனில் (auth_sock_name != வெற்று) {
		error("authentication forwarding requested twice.");
		திரும்பு 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	எனில் (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		செல் authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	திரும்பு 1;

 authsock_err:
	விடுவி(auth_sock_name);
	எனில் (sock != -1)
		close(sock);
	auth_sock_name = வெற்று;
	திரும்பு 0;
}

நிலையான வெறுமை
display_loginmsg(வெறுமை)
{
	முழு r;

	எனில் (sshbuf_len(loginmsg) == 0)
		திரும்பு;
	எனில் ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	printf("%s", (எழுத்து *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

நிலையான வெறுமை
prepare_auth_info_file(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshbuf *info)
{
	முழு fd = -1, success = 0;

	எனில் (!options.expose_userauth_info || info == வெற்று)
		திரும்பு;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	எனில் ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		செல் out;
	}
	எனில் (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		செல் out;
	}
	எனில் (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		செல் out;
	}
	success = 1;
 out:
	எனில் (!success) {
		எனில் (fd != -1)
			close(fd);
		விடுவி(auth_info_file);
		auth_info_file = வெற்று;
	}
	restore_uid();
}

நிலையான வெறுமை
set_fwdpermit_from_authopts(கட்டமைப்பு ssh *ssh, மாறிலி கட்டமைப்பு sshauthopt *opts)
{
	எழுத்து *tmp, *cp, *host;
	முழு port;
	size_t i;

	எனில் ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		க்கு (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			எனில் ((host = hpdelim2(&cp, வெற்று)) == வெற்று)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			எனில் (cp == வெற்று || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			விடுவி(tmp);
		}
	}
	எனில் ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		க்கு (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			எனில் ((host = hpdelim(&cp)) == வெற்று)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			எனில் (cp == வெற்று || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			விடுவி(tmp);
		}
	}
}

வெறுமை
do_authenticated(கட்டமைப்பு ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	எனில் (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} இல்லையெனில் {
		எனில் ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		இல்லையெனில்
			channel_permit_all(ssh, FORWARD_LOCAL);
		எனில் ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		இல்லையெனில்
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
நிலையான முழு
xauth_valid_string(மாறிலி எழுத்து *s)
{
	size_t i;

	க்கு (i = 0; s[i] != '\0'; i++) {
		எனில் (!isalnum((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			திரும்பு 0;
	}
	திரும்பு 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
முழு
do_exec_no_pty(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *command)
{
	pid_t pid;
#ifdef USE_PIPES
	முழு pin[2], pout[2], perr[2];

	எனில் (s == வெற்று)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	எனில் (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		திரும்பு -1;
	}
	எனில் (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		திரும்பு -1;
	}
	எனில் (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		திரும்பு -1;
	}
#இல்லையெனில்
	முழு inout[2], err[2];

	எனில் (s == வெற்று)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		திரும்பு -1;
	}
	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		திரும்பு -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	தேர்வு ((pid = fork())) {
	நிலை -1:
		error_f("fork: %.100s", strerror(errno));
#ifdef USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#இல்லையெனில்
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#endif
		திரும்பு -1;
	நிலை 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		எனில் (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		எனில் (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		எனில் (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		எனில் (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#இல்லையெனில்
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		எனில் (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		எனில் (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		எனில் (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	இயல்பு:
		நிறுத்து;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_மதிப்பு);
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
#இல்லையெனில்
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
	திரும்பு 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
முழு
do_exec_pty(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *command)
{
	முழு fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	எனில் (s == வெற்று)
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
	எனில் ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		திரும்பு -1;
	}
	/* we keep a reference to the pty master */
	எனில் ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		திரும்பு -1;
	}

	/* Fork the child. */
	தேர்வு ((pid = fork())) {
	நிலை -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		திரும்பு -1;
	நிலை 0:
		is_child = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		எனில் (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		எனில் (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		எனில் (dup2(ttyfd, 2) == -1)
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
	இயல்பு:
		நிறுத்து;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_மதிப்பு);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	திரும்பு 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
முழு
do_exec(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *command)
{
	முழு ret;
	மாறிலி எழுத்து *forced = வெற்று, *tty = வெற்று;
	எழுத்து session_type[1024];

	எனில் (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} இல்லையெனில் எனில் (auth_opts->force_command != வெற்று) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	எனில் (forced != வெற்று) {
		s->forced = 1;
		எனில் (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} இல்லையெனில் எனில் (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, அளவு(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} இல்லையெனில் எனில் (s->is_subsystem) {
		snprintf(session_type, அளவு(session_type),
		    "subsystem '%.900s'", s->subsys);
	} இல்லையெனில் எனில் (command == வெற்று) {
		snprintf(session_type, அளவு(session_type), "shell");
	} இல்லையெனில் {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, அளவு(session_type), "command");
	}

	எனில் (s->ttyfd != -1) {
		tty = s->tty;
		எனில் (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == வெற்று ? "" : " on ",
	    tty == வெற்று ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	எனில் (command != வெற்று)
		mm_audit_run_command(command);
	இல்லையெனில் எனில் (s->ttyfd == -1) {
		எழுத்து *shell = s->pw->pw_shell;

		எனில் (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	எனில் (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	இல்லையெனில்
		ret = do_exec_no_pty(ssh, s, command);

	original_command = வெற்று;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	திரும்பு ret;
}

/* administrative, login(1)-like work */
வெறுமை
do_login(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *command)
{
	socklen_t fromlen;
	கட்டமைப்பு sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, அளவு(from));
	fromlen = அளவு(from);
	எனில் (ssh_packet_connection_is_on_socket(ssh)) {
		எனில் (getpeername(ssh_packet_get_connection_in(ssh),
		    (கட்டமைப்பு sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	எனில் (check_quietlogin(s, command))
		திரும்பு;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
வெறுமை
do_motd(வெறுமை)
{
	FILE *f;
	எழுத்து buf[256];

	எனில் (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#இல்லையெனில்
		f = fopen("/etc/motd", "r");
#endif
		எனில் (f) {
			போது (fgets(buf, அளவு(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
முழு
check_quietlogin(Session *s, மாறிலி எழுத்து *command)
{
	எழுத்து buf[256];
	கட்டமைப்பு passwd *pw = s->pw;
	கட்டமைப்பு stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	எனில் (command != வெற்று)
		திரும்பு 1;
	snprintf(buf, அளவு(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	எனில் (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		திரும்பு 1;
#இல்லையெனில்
	எனில் (stat(buf, &st) >= 0)
		திரும்பு 1;
#endif
	திரும்பு 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
நிலையான வெறுமை
read_environment_file(எழுத்து ***env, u_int *envsize,
	மாறிலி எழுத்து *filename, மாறிலி எழுத்து *allowlist)
{
	FILE *f;
	எழுத்து *வரி = வெற்று, *cp, *மதிப்பு;
	size_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	எனில் (!f)
		திரும்பு;

	போது (getline(&வரி, &linesize, f) != -1) {
		எனில் (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		க்கு (cp = வரி; *cp == ' ' || *cp == '\t'; cp++)
			;
		எனில் (!*cp || *cp == '#' || *cp == '\n')
			தொடர்;

		cp[strcspn(cp, "\n")] = '\0';

		மதிப்பு = strchr(cp, '=');
		எனில் (மதிப்பு == வெற்று) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			தொடர்;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*மதிப்பு = '\0';
		மதிப்பு++;
		எனில் (allowlist != வெற்று &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			தொடர்;
		child_set_env(env, envsize, cp, மதிப்பு);
	}
	விடுவி(வரி);
	fclose(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
நிலையான எழுத்து *
child_get_env(எழுத்து **env, மாறிலி எழுத்து *name)
{
	முழு i;
	size_t len;

	len = strlen(name);
	க்கு (i=0; env[i] != வெற்று; i++)
		எனில் (strncmp(name, env[i], len) == 0 && env[i][len] == '=')
			திரும்பு(env[i] + len + 1);
	திரும்பு வெற்று;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
நிலையான வெறுமை
read_etc_default_login(எழுத்து ***env, u_int *envsize, uid_t uid)
{
	எழுத்து **tmpenv = வெற்று, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	எனில் (tmpenv == வெற்று)
		திரும்பு;

	எனில் (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	இல்லையெனில்
		var = child_get_env(tmpenv, "PATH");
	எனில் (var != வெற்று)
		child_set_env(env, envsize, "PATH", var);

	எனில் ((var = child_get_env(tmpenv, "UMASK")) != வெற்று)
		எனில் (sscanf(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	க்கு (i = 0; tmpenv[i] != வெற்று; i++)
		விடுவி(tmpenv[i]);
	விடுவி(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#எனில் defined(USE_PAM) || defined(HAVE_CYGWIN)
நிலையான வெறுமை
copy_environment_denylist(எழுத்து **source, எழுத்து ***env, u_int *envsize,
    மாறிலி எழுத்து *denylist)
{
	எழுத்து *var_name, *var_val;
	முழு i;

	எனில் (source == வெற்று)
		திரும்பு;

	க்கு(i = 0; source[i] != வெற்று; i++) {
		var_name = xstrdup(source[i]);
		எனில் ((var_val = strstr(var_name, "=")) == வெற்று) {
			விடுவி(var_name);
			தொடர்;
		}
		*var_val++ = '\0';

		எனில் (denylist == வெற்று ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		விடுவி(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
நிலையான வெறுமை
copy_environment(எழுத்து **source, எழுத்து ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, வெற்று);
}
#endif

நிலையான எழுத்து **
do_setup_env(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *shell)
{
	எழுத்து buf[256];
	size_t n;
	u_int i, envsize;
	எழுத்து *ocp, *cp, *மதிப்பு, **env, *laddr;
	கட்டமைப்பு passwd *pw = s->pw;
#எனில் !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	எழுத்து *path = வெற்று;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, அளவு(எழுத்து *));
	env[0] = வெற்று;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		எழுத்து **p;

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
	க்கு (i = 0; i < s->இலக்கம்_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	எனில் (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	இல்லையெனில்
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#இல்லையெனில் /* HAVE_LOGIN_CAP */
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
	எனில் (path == வெற்று || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	எனில் (!options.use_pam) {
		snprintf(buf, அளவு buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	எனில் (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
#ifdef HAVE_LOGIN_CAP
	எனில் (getenv("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	எனில் (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	எனில் (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		எழுத்து *cp;

		எனில் ((cp = getenv("KRB5CCNAME")) != வெற்று)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		எழுத்து *cp;

		எனில் ((cp = getenv("AUTHSTATE")) != வெற்று)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	எனில் (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	எனில் (auth_sock_name != வெற்று)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	எனில் (options.permit_user_env) {
		க்கு (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			எனில் (cp != வெற்று) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				எனில் (options.permit_user_env_allowlist == வெற்று ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			விடுவி(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	எனில் (options.permit_user_env) {
		snprintf(buf, அளவு buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	எனில் (options.use_pam) {
		எழுத்து **p;

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
	க்கு (i = 0; i < options.இலக்கம்_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		எனில் ((மதிப்பு = strchr(cp, '=')) == வெற்று) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*மதிப்பு++ = '\0';
		child_set_env(&env, &envsize, cp, மதிப்பு);
		விடுவி(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, அளவு buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, அளவு buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	விடுவி(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	எனில் (tun_fwd_ifnames != வெற்று)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	எனில் (auth_info_file != வெற்று)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	எனில் (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	எனில் (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	எனில் (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		க்கு (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	திரும்பு env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
நிலையான வெறுமை
do_rc_files(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *shell)
{
	FILE *f = வெற்று;
	எழுத்து *cmd = வெற்று, *user_rc = வெற்று;
	முழு do_xauth;
	கட்டமைப்பு stat st;

	do_xauth =
	    s->display != வெற்று && s->auth_proto != வெற்று && s->auth_data != வெற்று;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	எனில் (!s->is_subsystem && options.adm_forced_command == வெற்று &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		எனில் (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		எனில் (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		எனில் (f) {
			எனில் (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} இல்லையெனில்
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} இல்லையெனில் எனில் (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		எனில் (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		எனில் (f) {
			எனில் (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} இல்லையெனில்
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} இல்லையெனில் எனில் (do_xauth && options.xauth_location != வெற்று) {
		/* Add authority data to .Xauthority if appropriate. */
		எனில் (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		எனில் (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		எனில் (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} இல்லையெனில் {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	விடுவி(cmd);
	விடுவி(user_rc);
}

நிலையான வெறுமை
do_nologin(கட்டமைப்பு passwd *pw)
{
	FILE *f = வெற்று;
	எழுத்து buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	கட்டமைப்பு stat sb;

#ifdef HAVE_LOGIN_CAP
	எனில் (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		திரும்பு;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#இல்லையெனில்
	எனில் (pw->pw_uid == 0)
		திரும்பு;
	nl = def_nl;
#endif
	எனில் (stat(nl, &sb) == -1)
		திரும்பு;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	எனில் ((f = fopen(nl, "r")) != வெற்று) {
		போது (fgets(buf, அளவு(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
நிலையான வெறுமை
safely_chroot(மாறிலி எழுத்து *path, uid_t uid)
{
	மாறிலி எழுத்து *cp;
	எழுத்து component[PATH_MAX];
	கட்டமைப்பு stat st;

	எனில் (!path_absolute(path))
		fatal("chroot path does not begin at root");
	எனில் (strlen(path) >= அளவு(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	க்கு (cp = path; cp != வெற்று;) {
		எனில் ((cp = strchr(cp, '/')) == வெற்று)
			strlcpy(component, path, அளவு(component));
		இல்லையெனில் {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		எனில் (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		எனில் (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == வெற்று ? "" : "component ", component);
		எனில் (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == வெற்று ? "" : "component ", component);

	}

	எனில் (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	எனில் (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	எனில் (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
வெறுமை
do_setusercontext(கட்டமைப்பு passwd *pw)
{
	எழுத்து uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	எனில் (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		எனில் (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			exit(1);
		}
#இல்லையெனில்
		எனில் (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		எனில் (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			exit(1);
		}
		/* Initialize the group list. */
		எனில் (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			exit(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		எனில் (!in_chroot && options.chroot_directory != வெற்று &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, அளவு(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (எழுத்து *)வெற்று);
			safely_chroot(chroot_path, pw->pw_uid);
			விடுவி(tmp);
			விடுவி(chroot_path);
			/* Make sure we don't attempt to chroot again */
			விடுவி(options.chroot_directory);
			options.chroot_directory = வெற்று;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		எனில் (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			exit(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(வெறுமை) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#இல்லையெனில்
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		எனில் (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} இல்லையெனில் எனில் (options.chroot_directory != வெற்று &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	எனில் (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

நிலையான வெறுமை
do_pwchange(Session *s)
{
	fflush(வெற்று);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	எனில் (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(வெற்று);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (எழுத்து *)வெற்று);
#இல்லையெனில்
		execl(_PATH_PASSWD_PROG, "passwd", (எழுத்து *)வெற்று);
#endif
		perror("passwd");
	} இல்லையெனில் {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	exit(1);
}

நிலையான வெறுமை
child_close_fds(கட்டமைப்பு ssh *ssh)
{
	வெளி முழு auth_sock;

	எனில் (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	எனில் (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	இல்லையெனில் {
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
	log_redirect_stderr_to(வெற்று);

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
வெறுமை
do_child(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *command)
{
	வெளி எழுத்து **environ;
	எழுத்து **env, *argv[ARGV_MAX], remote_id[512];
	மாறிலி எழுத்து *shell, *shell0;
	கட்டமைப்பு passwd *pw = s->pw;
	முழு r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, அளவு(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_சாவிகள்(ssh);

	/* Force a password change */
	எனில் (s->authctxt->force_pwchange) {
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
	session_setup_sia(pw, s->ttyfd == -1 ? வெற்று : s->tty);
	எனில் (!check_quietlogin(s, command))
		do_motd();
#இல்லையெனில் /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	எனில் (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	எனில் (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	எனில் (options.use_pam && !is_pam_session_open()) {
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
	shell = login_getcapstr(lc, "shell", (எழுத்து *)shell, (எழுத்து *)shell);
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

#எனில் defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	எனில் (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != வெற்று)) {
		எழுத்து cell[64];

		debug("Getting AFS token");

		k_setpag();

		எனில் (k_afs_cell_of_file(pw->pw_dir, cell, அளவு(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, வெற்று);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, வெற்று, வெற்று, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	எனில் (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		எனில் (r || !in_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		எனில் (r)
			exit(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	எனில் (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(வெற்று);
		exit(1);
	} இல்லையெனில் எனில் (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		வெளி முழு optind, optreset;
		முழு sftp_argc;
		எழுத்து **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		எனில் (argv_split(command == வெற்று ? "sftp-server" : command,
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

	fflush(வெற்று);

	/* Get the last component of the shell name. */
	எனில் ((shell0 = strrchr(shell, '/')) != வெற்று)
		shell0++;
	இல்லையெனில்
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	எனில் (!command) {
		எழுத்து argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		எனில் (strlcpy(argv0 + 1, shell0, அளவு(argv0) - 1)
		    >= அளவு(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = வெற்று;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (எழுத்து *) shell0;
	argv[1] = "-c";
	argv[2] = (எழுத்து *) command;
	argv[3] = வெற்று;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

வெறுமை
session_unused(முழு id)
{
	debug3_f("session id %d unused", id);
	எனில் (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, அளவு(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = வெற்று;
	sessions[id].next_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(வெறுமை)
{
	Session *s, *tmp;

	எனில் (sessions_first_unused == -1) {
		எனில் (sessions_nalloc >= options.max_sessions)
			திரும்பு வெற்று;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, அளவு(*sessions));
		எனில் (tmp == வெற்று) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			திரும்பு வெற்று;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	எனில் (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	எனில் (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->next_unused;
	s->used = 1;
	s->next_unused = -1;
	debug("session_new: session %d", s->self);

	திரும்பு s;
}

நிலையான வெறுமை
session_dump(வெறுமை)
{
	முழு i;
	க்கு (i = 0; i < sessions_nalloc; i++) {
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

முழு
session_open(Authctxt *authctxt, முழு chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	எனில் (s == வெற்று) {
		error("no more sessions");
		திரும்பு 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	எனில் (s->pw == வெற்று || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	திரும்பு 1;
}

Session *
session_by_tty(எழுத்து *tty)
{
	முழு i;
	க்கு (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		எனில் (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			திரும்பு s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	திரும்பு வெற்று;
}

நிலையான Session *
session_by_channel(முழு id)
{
	முழு i;
	க்கு (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		எனில் (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			திரும்பு s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	திரும்பு வெற்று;
}

நிலையான Session *
session_by_x11_channel(முழு id)
{
	முழு i, j;

	க்கு (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		எனில் (s->x11_chanids == வெற்று || !s->used)
			தொடர்;
		க்கு (j = 0; s->x11_chanids[j] != -1; j++) {
			எனில் (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				திரும்பு s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	திரும்பு வெற்று;
}

நிலையான Session *
session_by_pid(pid_t pid)
{
	முழு i;
	debug("session_by_pid: pid %ld", (long)pid);
	க்கு (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		எனில் (s->used && s->pid == pid)
			திரும்பு s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	திரும்பு வெற்று;
}

நிலையான முழு
session_window_change_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	முழு r;

	எனில் ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	திரும்பு 1;
}

நிலையான முழு
session_pty_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	முழு r;

	எனில் (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		திரும்பு 0;
	}
	எனில் (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		திரும்பு 0;
	}

	எனில் ((r = sshpkt_get_cstring(ssh, &s->term, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	எனில் (strcmp(s->term, "") == 0) {
		விடுவி(s->term);
		s->term = வெற்று;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	எனில் (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, அளவு(s->tty))) {
		விடுவி(s->term);
		s->term = வெற்று;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		திரும்பு 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	திரும்பு 1;
}

நிலையான முழு
session_subsystem_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	கட்டமைப்பு stat st;
	முழு r, success = 0, found = 0;
	எழுத்து *prog, *cmd, *type;
	u_int i;

	எனில் ((r = sshpkt_get_cstring(ssh, &s->subsys, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	க்கு (i = 0; i < options.இலக்கம்_subsystems; i++) {
		எனில் (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			தொடர்;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		எனில் (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} இல்லையெனில் {
			எனில் (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		விடுவி(type);
		success = do_exec(ssh, s, cmd) == 0;
		நிறுத்து;
	}

	எனில் (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	திரும்பு success;
}

நிலையான முழு
session_x11_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	முழு r, success;
	u_char single_connection = 0;

	எனில் (s->auth_proto != வெற்று || s->auth_data != வெற்று) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		திரும்பு 0;
	}
	எனில் ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_data, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	எனில் (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_data))
		success = session_setup_x11fwd(ssh, s);
	இல்லையெனில் {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	எனில் (!success) {
		விடுவி(s->auth_proto);
		விடுவி(s->auth_data);
		s->auth_proto = வெற்று;
		s->auth_data = வெற்று;
	}
	திரும்பு success;
}

நிலையான முழு
session_shell_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	முழு r;

	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	திரும்பு do_exec(ssh, s, வெற்று) == 0;
}

நிலையான முழு
session_exec_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	u_int success;
	முழு r;
	எழுத்து *command = வெற்று;

	எனில் ((r = sshpkt_get_cstring(ssh, &command, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	விடுவி(command);
	திரும்பு success;
}

நிலையான முழு
session_break_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	முழு r;

	எனில் ((r = sshpkt_get_u32(ssh, வெற்று)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	எனில் (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான முழு
session_env_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	எழுத்து *name, *val;
	u_int i;
	முழு r;

	எனில் ((r = sshpkt_get_cstring(ssh, &name, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	எனில் (s->இலக்கம்_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		செல் fail;
	}

	க்கு (i = 0; i < options.இலக்கம்_accept_env; i++) {
		எனில் (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->இலக்கம்_env, name, val);
			s->env = xrecallocarray(s->env, s->இலக்கம்_env,
			    s->இலக்கம்_env + 1, அளவு(*s->env));
			s->env[s->இலக்கம்_env].name = name;
			s->env[s->இலக்கம்_env].val = val;
			s->இலக்கம்_env++;
			திரும்பு (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	விடுவி(name);
	விடுவி(val);
	திரும்பு (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
நிலையான முழு
name2sig(எழுத்து *name)
{
#define SSH_SIG(x) எனில் (strcmp(name, #x) == 0) திரும்பு SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	எனில் (strcmp(name, "INFO@openssh.com") == 0)
		திரும்பு SIGINFO;
#endif
	திரும்பு -1;
}

நிலையான முழு
session_signal_req(கட்டமைப்பு ssh *ssh, Session *s)
{
	எழுத்து *signame = வெற்று;
	முழு r, sig, success = 0;

	எனில் ((r = sshpkt_get_cstring(ssh, &signame, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		செல் out;
	}
	எனில் ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		செல் out;
	}
	எனில் (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		செல் out;
	}
	எனில் (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		செல் out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (long)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	எனில் (r != 0) {
		error_f("killpg(%ld, %d): %s", (long)s->pid,
		    sig, strerror(errno));
		செல் out;
	}

	/* success */
	success = 1;
 out:
	விடுவி(signame);
	திரும்பு success;
}

நிலையான முழு
session_auth_agent_req(கட்டமைப்பு ssh *ssh, Session *s, முழு agent_new)
{
	நிலையான முழு called = 0;
	முழு r;

	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	எனில் (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		திரும்பு 0;
	}
	எனில் (called)
		திரும்பு 0;

	called = 1;
	திரும்பு auth_உள்ளீடு_request_forwarding(ssh, s->pw, agent_new);
}

முழு
session_உள்ளீடு_channel_req(கட்டமைப்பு ssh *ssh, Channel *c, மாறிலி எழுத்து *rtype)
{
	முழு success = 0;
	Session *s;

	எனில் ((s = session_by_channel(c->self)) == வெற்று) {
		logit_f("no session %d req %.100s", c->self, rtype);
		திரும்பு 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	எனில் (c->type == SSH_CHANNEL_LARVAL) {
		எனில் (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} இல்லையெனில் எனில் (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} இல்லையெனில் எனில் (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} இல்லையெனில் எனில் (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} இல்லையெனில் எனில் (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} இல்லையெனில் எனில் (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} இல்லையெனில் எனில் (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} இல்லையெனில் எனில் (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	எனில் (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} இல்லையெனில் எனில் (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} இல்லையெனில் எனில் (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	திரும்பு success;
}

வெறுமை
session_set_fds(கட்டமைப்பு ssh *ssh, Session *s,
    முழு fdin, முழு fdout, முழு fderr, முழு ignore_fderr, முழு is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	எனில் (s->chanid == -1)
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
வெறுமை
session_pty_cleanup2(Session *s)
{
	எனில் (s == வெற்று) {
		error_f("no session");
		திரும்பு;
	}
	எனில் (s->ttyfd == -1)
		திரும்பு;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	எனில் (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	எனில் (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	எனில் (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

வெறுமை
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

நிலையான எழுத்து *
sig2name(முழு sig)
{
#define SSH_SIG(x) எனில் (sig == SIG ## x) திரும்பு #x
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
	திரும்பு "SIG@openssh.com";
}

நிலையான வெறுமை
session_close_x11(கட்டமைப்பு ssh *ssh, முழு id)
{
	Channel *c;

	எனில் ((c = channel_by_id(ssh, id)) == வெற்று) {
		debug_f("x11 channel %d missing", id);
	} இல்லையெனில் {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		எனில் (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

நிலையான வெறுமை
session_close_single_x11(கட்டமைப்பு ssh *ssh, முழு id, முழு force, வெறுமை *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	எனில் ((s = session_by_x11_channel(id)) == வெற்று)
		fatal_f("no x11 channel %d", id);
	க்கு (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		எனில் (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	விடுவி(s->x11_chanids);
	s->x11_chanids = வெற்று;
	விடுவி(s->display);
	s->display = வெற்று;
	விடுவி(s->auth_proto);
	s->auth_proto = வெற்று;
	விடுவி(s->auth_data);
	s->auth_data = வெற்று;
	விடுவி(s->auth_display);
	s->auth_display = வெற்று;
}

நிலையான வெறுமை
session_exit_message(கட்டமைப்பு ssh *ssh, Session *s, முழு status)
{
	Channel *c;
	முழு r;
	எழுத்து *note = வெற்று;

	எனில் ((c = channel_lookup(ssh, s->chanid)) == வெற்று)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	எனில் (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		எனில் ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} இல்லையெனில் எனில் (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		எனில் ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} இல்லையெனில் {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (long)s->pid, note == வெற்று ? "UNKNOWN" : note);
	விடுவி(note);

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
	எனில் (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

வெறுமை
session_close(கட்டமைப்பு ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	எனில் (s->ttyfd != -1)
		session_pty_cleanup(s);
	விடுவி(s->term);
	விடுவி(s->display);
	விடுவி(s->x11_chanids);
	விடுவி(s->auth_display);
	விடுவி(s->auth_data);
	விடுவி(s->auth_proto);
	விடுவி(s->subsys);
	எனில் (s->env != வெற்று) {
		க்கு (i = 0; i < s->இலக்கம்_env; i++) {
			விடுவி(s->env[i].name);
			விடுவி(s->env[i].val);
		}
		விடுவி(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

வெறுமை
session_close_by_pid(கட்டமைப்பு ssh *ssh, pid_t pid, முழு status)
{
	Session *s = session_by_pid(pid);
	எனில் (s == வெற்று) {
		debug_f("no session for pid %ld", (long)pid);
		திரும்பு;
	}
	எனில் (s->chanid != -1)
		session_exit_message(ssh, s, status);
	எனில் (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
வெறுமை
session_close_by_channel(கட்டமைப்பு ssh *ssh, முழு id, முழு force, வெறுமை *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	எனில் (s == வெற்று) {
		debug_f("no session for id %d", id);
		திரும்பு;
	}
	debug_f("channel %d child %ld", id, (long)s->pid);
	எனில் (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		எனில் (s->ttyfd != -1)
			session_pty_cleanup(s);
		எனில் (!force)
			திரும்பு;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	எனில் (s->x11_chanids != வெற்று) {
		க்கு (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

வெறுமை
session_destroy_all(கட்டமைப்பு ssh *ssh, வெறுமை (*closefunc)(Session *))
{
	முழு i;
	க்கு (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		எனில் (s->used) {
			எனில் (closefunc != வெற்று)
				closefunc(s);
			இல்லையெனில்
				session_close(ssh, s);
		}
	}
}

நிலையான எழுத்து *
session_tty_list(வெறுமை)
{
	நிலையான எழுத்து buf[1024];
	முழு i;
	எழுத்து *cp;

	buf[0] = '\0';
	க்கு (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		எனில் (s->used && s->ttyfd != -1) {

			எனில் (strncmp(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == வெற்று) ? s->tty : cp + 1;
			} இல்லையெனில்
				cp = s->tty + 5;

			எனில் (buf[0] != '\0')
				strlcat(buf, ",", அளவு buf);
			strlcat(buf, cp, அளவு buf);
		}
	}
	எனில் (buf[0] == '\0')
		strlcpy(buf, "notty", அளவு buf);
	திரும்பு buf;
}

வெறுமை
session_proctitle(Session *s)
{
	எனில் (s->pw == வெற்று)
		error("no user for session %d", s->self);
	இல்லையெனில்
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

முழு
session_setup_x11fwd(கட்டமைப்பு ssh *ssh, Session *s)
{
	கட்டமைப்பு stat st;
	எழுத்து display[512], auth_display[512];
	எழுத்து hostname[NI_MAXHOST];
	u_int i;

	எனில் (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		திரும்பு 0;
	}
	எனில் (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		திரும்பு 0;
	}
	எனில் (options.xauth_location == வெற்று ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		திரும்பு 0;
	}
	எனில் (s->display != வெற்று) {
		debug("X11 display already set.");
		திரும்பு 0;
	}
	எனில் (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_எண், &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		திரும்பு 0;
	}
	க்கு (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	எனில் (gethostname(hostname, அளவு(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	எனில் (options.x11_use_localhost) {
		snprintf(display, அளவு display, "localhost:%u.%u",
		    s->display_எண், s->screen);
		snprintf(auth_display, அளவு auth_display, "unix:%u.%u",
		    s->display_எண், s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} இல்லையெனில் {
#ifdef IPADDR_IN_DISPLAY
		கட்டமைப்பு hostent *he;
		கட்டமைப்பு in_addr my_addr;

		he = gethostbyname(hostname);
		எனில் (he == வெற்று) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			திரும்பு 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], அளவு(கட்டமைப்பு in_addr));
		snprintf(display, அளவு display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_எண், s->screen);
#இல்லையெனில்
		snprintf(display, அளவு display, "%.400s:%u.%u", hostname,
		    s->display_எண், s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	திரும்பு 1;
}

நிலையான வெறுமை
do_authenticated2(கட்டமைப்பு ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

வெறுமை
do_cleanup(கட்டமைப்பு ssh *ssh, Authctxt *authctxt)
{
	நிலையான முழு called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	எனில் (is_child)
		திரும்பு;

	/* avoid double cleanup */
	எனில் (called)
		திரும்பு;
	called = 1;

	எனில் (authctxt == வெற்று)
		திரும்பு;

#ifdef USE_PAM
	எனில் (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	எனில் (!authctxt->authenticated)
		திரும்பு;

#ifdef KRB5
	எனில் (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	எனில் (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	எனில் (auth_info_file != வெற்று) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		விடுவி(auth_info_file);
		auth_info_file = வெற்று;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	எனில் (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

மாறிலி எழுத்து *
session_get_remote_name_or_ip(கட்டமைப்பு ssh *ssh, u_int utmp_size, முழு use_dns)
{
	மாறிலி எழுத்து *remote = "";

	எனில் (utmp_size > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	எனில் (utmp_size == 0 || strlen(remote) > utmp_size)
		remote = ssh_remote_ipaddr(ssh);
	திரும்பு remote;
}

