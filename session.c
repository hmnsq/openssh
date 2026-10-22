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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/un.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <grp.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "sshpty.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "uidswap.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "sshlogin.h"
#અન્તર્ભાવ "serverloop.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "session.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "sftp.h"
#અન્તર્ભાવ "atomicio.h"

#જો defined(KRB5) && defined(USE_AFS)
#અન્તર્ભાવ <kafs.h>
#endif

#ifdef WITH_SELINUX
#અન્તર્ભાવ <selinux/selinux.h>
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
	(!strncmp(c, INTERNAL_SFTP_NAME, કદ(INTERNAL_SFTP_NAME) - 1) && \
	 (c[કદ(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[કદ(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[કદ(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(શૂન્ય);
શૂન્ય	session_set_fds(સંરચના ssh *, Session *, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);
શૂન્ય	session_pty_cleanup(Session *);
શૂન્ય	session_proctitle(Session *);
પૂર્ણાંક	session_setup_x11fwd(સંરચના ssh *, Session *);
પૂર્ણાંક	do_exec_pty(સંરચના ssh *, Session *, અચલ અક્ષર *);
પૂર્ણાંક	do_exec_no_pty(સંરચના ssh *, Session *, અચલ અક્ષર *);
પૂર્ણાંક	do_exec(સંરચના ssh *, Session *, અચલ અક્ષર *);
શૂન્ય	do_login(સંરચના ssh *, Session *, અચલ અક્ષર *);
શૂન્ય	do_child(સંરચના ssh *, Session *, અચલ અક્ષર *);
શૂન્ય	do_motd(શૂન્ય);
પૂર્ણાંક	check_quietlogin(Session *, અચલ અક્ષર *);

સ્થિર શૂન્ય do_authenticated2(સંરચના ssh *, Authctxt *);

સ્થિર પૂર્ણાંક session_pty_req(સંરચના ssh *, Session *);

/* import */
બાહ્ય ServerOptions options;
બાહ્ય અક્ષર *__progname;
બાહ્ય પૂર્ણાંક debug_flag;
બાહ્ય સંરચના sshbuf *loginmsg;
બાહ્ય સંરચના sshauthopt *auth_opts;
બાહ્ય અક્ષર *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
અચલ અક્ષર *original_command = ખાલી;

/* data */
સ્થિર પૂર્ણાંક sessions_first_unused = -1;
સ્થિર પૂર્ણાંક sessions_nalloc = 0;
સ્થિર Session *sessions = ખાલી;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

સ્થિર પૂર્ણાંક is_child = 0;
સ્થિર પૂર્ણાંક in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
સ્થિર અક્ષર *auth_info_file = ખાલી;

/* Name and directory of socket for authentication agent forwarding. */
સ્થિર અક્ષર *auth_sock_name = ખાલી;
સ્થિર અક્ષર *auth_sock_dir = ખાલી; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

સ્થિર શૂન્ય
auth_sock_cleanup_proc(સંરચના passwd *pw)
{
	જો (auth_sock_name != ખાલી) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		મુક્ત(auth_sock_name);
		auth_sock_name = ખાલી;
		restore_uid();
	}
}

સ્થિર પૂર્ણાંક
auth_આગત_request_forwarding(સંરચના ssh *ssh, સંરચના passwd *pw, પૂર્ણાંક agent_new)
{
	Channel *nc;
	પૂર્ણાંક sock = -1;

	જો (auth_sock_name != ખાલી) {
		error("authentication forwarding requested twice.");
		પાછા 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	જો (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		જાઓ authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	પાછા 1;

 authsock_err:
	મુક્ત(auth_sock_name);
	જો (sock != -1)
		close(sock);
	auth_sock_name = ખાલી;
	પાછા 0;
}

સ્થિર શૂન્ય
display_loginmsg(શૂન્ય)
{
	પૂર્ણાંક r;

	જો (sshbuf_len(loginmsg) == 0)
		પાછા;
	જો ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	printf("%s", (અક્ષર *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

સ્થિર શૂન્ય
prepare_auth_info_file(સંરચના passwd *pw, સંરચના sshbuf *info)
{
	પૂર્ણાંક fd = -1, success = 0;

	જો (!options.expose_userauth_info || info == ખાલી)
		પાછા;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	જો ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		જાઓ out;
	}
	જો (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		જાઓ out;
	}
	જો (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		જાઓ out;
	}
	success = 1;
 out:
	જો (!success) {
		જો (fd != -1)
			close(fd);
		મુક્ત(auth_info_file);
		auth_info_file = ખાલી;
	}
	restore_uid();
}

સ્થિર શૂન્ય
set_fwdpermit_from_authopts(સંરચના ssh *ssh, અચલ સંરચના sshauthopt *opts)
{
	અક્ષર *tmp, *cp, *host;
	પૂર્ણાંક port;
	size_t i;

	જો ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		માટે (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			જો ((host = hpdelim2(&cp, ખાલી)) == ખાલી)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			જો (cp == ખાલી || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			મુક્ત(tmp);
		}
	}
	જો ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		માટે (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			જો ((host = hpdelim(&cp)) == ખાલી)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			જો (cp == ખાલી || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			મુક્ત(tmp);
		}
	}
}

શૂન્ય
do_authenticated(સંરચના ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	જો (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} નહીંતર {
		જો ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		નહીંતર
			channel_permit_all(ssh, FORWARD_LOCAL);
		જો ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		નહીંતર
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
સ્થિર પૂર્ણાંક
xauth_valid_string(અચલ અક્ષર *s)
{
	size_t i;

	માટે (i = 0; s[i] != '\0'; i++) {
		જો (!isalnum((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			પાછા 0;
	}
	પાછા 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
પૂર્ણાંક
do_exec_no_pty(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *command)
{
	pid_t pid;
#ifdef USE_PIPES
	પૂર્ણાંક pin[2], pout[2], perr[2];

	જો (s == ખાલી)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	જો (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		પાછા -1;
	}
	જો (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		પાછા -1;
	}
	જો (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		પાછા -1;
	}
#નહીંતર
	પૂર્ણાંક inout[2], err[2];

	જો (s == ખાલી)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		પાછા -1;
	}
	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		પાછા -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	પસંદગી ((pid = fork())) {
	સ્થિતિ -1:
		error_f("fork: %.100s", strerror(errno));
#ifdef USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#નહીંતર
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#endif
		પાછા -1;
	સ્થિતિ 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		જો (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		જો (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		જો (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		જો (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#નહીંતર
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		જો (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		જો (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		જો (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	મૂળભૂત:
		તોડો;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_કિંમત);
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
#નહીંતર
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
	પાછા 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
પૂર્ણાંક
do_exec_pty(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *command)
{
	પૂર્ણાંક fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	જો (s == ખાલી)
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
	જો ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		પાછા -1;
	}
	/* we keep a reference to the pty master */
	જો ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		પાછા -1;
	}

	/* Fork the child. */
	પસંદગી ((pid = fork())) {
	સ્થિતિ -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		પાછા -1;
	સ્થિતિ 0:
		is_child = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		જો (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		જો (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		જો (dup2(ttyfd, 2) == -1)
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
	મૂળભૂત:
		તોડો;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_કિંમત);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	પાછા 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
પૂર્ણાંક
do_exec(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *command)
{
	પૂર્ણાંક ret;
	અચલ અક્ષર *forced = ખાલી, *tty = ખાલી;
	અક્ષર session_type[1024];

	જો (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} નહીંતર જો (auth_opts->force_command != ખાલી) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	જો (forced != ખાલી) {
		s->forced = 1;
		જો (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} નહીંતર જો (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, કદ(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} નહીંતર જો (s->is_subsystem) {
		snprintf(session_type, કદ(session_type),
		    "subsystem '%.900s'", s->subsys);
	} નહીંતર જો (command == ખાલી) {
		snprintf(session_type, કદ(session_type), "shell");
	} નહીંતર {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, કદ(session_type), "command");
	}

	જો (s->ttyfd != -1) {
		tty = s->tty;
		જો (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == ખાલી ? "" : " on ",
	    tty == ખાલી ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	જો (command != ખાલી)
		mm_audit_run_command(command);
	નહીંતર જો (s->ttyfd == -1) {
		અક્ષર *shell = s->pw->pw_shell;

		જો (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	જો (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	નહીંતર
		ret = do_exec_no_pty(ssh, s, command);

	original_command = ખાલી;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	પાછા ret;
}

/* administrative, login(1)-like work */
શૂન્ય
do_login(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *command)
{
	socklen_t fromlen;
	સંરચના sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, કદ(from));
	fromlen = કદ(from);
	જો (ssh_packet_connection_is_on_socket(ssh)) {
		જો (getpeername(ssh_packet_get_connection_in(ssh),
		    (સંરચના sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	જો (check_quietlogin(s, command))
		પાછા;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
શૂન્ય
do_motd(શૂન્ય)
{
	FILE *f;
	અક્ષર buf[256];

	જો (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#નહીંતર
		f = fopen("/etc/motd", "r");
#endif
		જો (f) {
			જ્યારે (fgets(buf, કદ(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
પૂર્ણાંક
check_quietlogin(Session *s, અચલ અક્ષર *command)
{
	અક્ષર buf[256];
	સંરચના passwd *pw = s->pw;
	સંરચના stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	જો (command != ખાલી)
		પાછા 1;
	snprintf(buf, કદ(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	જો (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		પાછા 1;
#નહીંતર
	જો (stat(buf, &st) >= 0)
		પાછા 1;
#endif
	પાછા 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
સ્થિર શૂન્ય
read_environment_file(અક્ષર ***env, u_int *envsize,
	અચલ અક્ષર *filename, અચલ અક્ષર *allowlist)
{
	FILE *f;
	અક્ષર *લીટી = ખાલી, *cp, *કિંમત;
	size_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	જો (!f)
		પાછા;

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		જો (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		માટે (cp = લીટી; *cp == ' ' || *cp == '\t'; cp++)
			;
		જો (!*cp || *cp == '#' || *cp == '\n')
			ચાલુ;

		cp[strcspn(cp, "\n")] = '\0';

		કિંમત = strchr(cp, '=');
		જો (કિંમત == ખાલી) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			ચાલુ;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*કિંમત = '\0';
		કિંમત++;
		જો (allowlist != ખાલી &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			ચાલુ;
		child_set_env(env, envsize, cp, કિંમત);
	}
	મુક્ત(લીટી);
	fclose(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
સ્થિર અક્ષર *
child_get_env(અક્ષર **env, અચલ અક્ષર *name)
{
	પૂર્ણાંક i;
	size_t len;

	len = strlen(name);
	માટે (i=0; env[i] != ખાલી; i++)
		જો (strncmp(name, env[i], len) == 0 && env[i][len] == '=')
			પાછા(env[i] + len + 1);
	પાછા ખાલી;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
સ્થિર શૂન્ય
read_etc_default_login(અક્ષર ***env, u_int *envsize, uid_t uid)
{
	અક્ષર **tmpenv = ખાલી, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	જો (tmpenv == ખાલી)
		પાછા;

	જો (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	નહીંતર
		var = child_get_env(tmpenv, "PATH");
	જો (var != ખાલી)
		child_set_env(env, envsize, "PATH", var);

	જો ((var = child_get_env(tmpenv, "UMASK")) != ખાલી)
		જો (sscanf(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	માટે (i = 0; tmpenv[i] != ખાલી; i++)
		મુક્ત(tmpenv[i]);
	મુક્ત(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#જો defined(USE_PAM) || defined(HAVE_CYGWIN)
સ્થિર શૂન્ય
copy_environment_denylist(અક્ષર **source, અક્ષર ***env, u_int *envsize,
    અચલ અક્ષર *denylist)
{
	અક્ષર *var_name, *var_val;
	પૂર્ણાંક i;

	જો (source == ખાલી)
		પાછા;

	માટે(i = 0; source[i] != ખાલી; i++) {
		var_name = xstrdup(source[i]);
		જો ((var_val = strstr(var_name, "=")) == ખાલી) {
			મુક્ત(var_name);
			ચાલુ;
		}
		*var_val++ = '\0';

		જો (denylist == ખાલી ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		મુક્ત(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
સ્થિર શૂન્ય
copy_environment(અક્ષર **source, અક્ષર ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, ખાલી);
}
#endif

સ્થિર અક્ષર **
do_setup_env(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *shell)
{
	અક્ષર buf[256];
	size_t n;
	u_int i, envsize;
	અક્ષર *ocp, *cp, *કિંમત, **env, *laddr;
	સંરચના passwd *pw = s->pw;
#જો !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	અક્ષર *path = ખાલી;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, કદ(અક્ષર *));
	env[0] = ખાલી;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		અક્ષર **p;

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
	માટે (i = 0; i < s->અંક_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	જો (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	નહીંતર
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#નહીંતર /* HAVE_LOGIN_CAP */
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
	જો (path == ખાલી || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	જો (!options.use_pam) {
		snprintf(buf, કદ buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	જો (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
#ifdef HAVE_LOGIN_CAP
	જો (getenv("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	જો (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	જો (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		અક્ષર *cp;

		જો ((cp = getenv("KRB5CCNAME")) != ખાલી)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		અક્ષર *cp;

		જો ((cp = getenv("AUTHSTATE")) != ખાલી)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	જો (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	જો (auth_sock_name != ખાલી)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	જો (options.permit_user_env) {
		માટે (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			જો (cp != ખાલી) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				જો (options.permit_user_env_allowlist == ખાલી ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			મુક્ત(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	જો (options.permit_user_env) {
		snprintf(buf, કદ buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	જો (options.use_pam) {
		અક્ષર **p;

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
	માટે (i = 0; i < options.અંક_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		જો ((કિંમત = strchr(cp, '=')) == ખાલી) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*કિંમત++ = '\0';
		child_set_env(&env, &envsize, cp, કિંમત);
		મુક્ત(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, કદ buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, કદ buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	મુક્ત(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	જો (tun_fwd_ifnames != ખાલી)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	જો (auth_info_file != ખાલી)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	જો (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	જો (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	જો (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		માટે (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	પાછા env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
સ્થિર શૂન્ય
do_rc_files(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *shell)
{
	FILE *f = ખાલી;
	અક્ષર *cmd = ખાલી, *user_rc = ખાલી;
	પૂર્ણાંક do_xauth;
	સંરચના stat st;

	do_xauth =
	    s->display != ખાલી && s->auth_proto != ખાલી && s->auth_data != ખાલી;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	જો (!s->is_subsystem && options.adm_forced_command == ખાલી &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		જો (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		જો (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		જો (f) {
			જો (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} નહીંતર
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} નહીંતર જો (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		જો (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		જો (f) {
			જો (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} નહીંતર
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} નહીંતર જો (do_xauth && options.xauth_location != ખાલી) {
		/* Add authority data to .Xauthority if appropriate. */
		જો (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		જો (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		જો (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} નહીંતર {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	મુક્ત(cmd);
	મુક્ત(user_rc);
}

સ્થિર શૂન્ય
do_nologin(સંરચના passwd *pw)
{
	FILE *f = ખાલી;
	અક્ષર buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	સંરચના stat sb;

#ifdef HAVE_LOGIN_CAP
	જો (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		પાછા;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#નહીંતર
	જો (pw->pw_uid == 0)
		પાછા;
	nl = def_nl;
#endif
	જો (stat(nl, &sb) == -1)
		પાછા;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	જો ((f = fopen(nl, "r")) != ખાલી) {
		જ્યારે (fgets(buf, કદ(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
સ્થિર શૂન્ય
safely_chroot(અચલ અક્ષર *path, uid_t uid)
{
	અચલ અક્ષર *cp;
	અક્ષર component[PATH_MAX];
	સંરચના stat st;

	જો (!path_absolute(path))
		fatal("chroot path does not begin at root");
	જો (strlen(path) >= કદ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	માટે (cp = path; cp != ખાલી;) {
		જો ((cp = strchr(cp, '/')) == ખાલી)
			strlcpy(component, path, કદ(component));
		નહીંતર {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		જો (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		જો (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ખાલી ? "" : "component ", component);
		જો (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ખાલી ? "" : "component ", component);

	}

	જો (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	જો (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	જો (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
શૂન્ય
do_setusercontext(સંરચના passwd *pw)
{
	અક્ષર uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	જો (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		જો (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			exit(1);
		}
#નહીંતર
		જો (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		જો (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			exit(1);
		}
		/* Initialize the group list. */
		જો (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			exit(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		જો (!in_chroot && options.chroot_directory != ખાલી &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, કદ(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (અક્ષર *)ખાલી);
			safely_chroot(chroot_path, pw->pw_uid);
			મુક્ત(tmp);
			મુક્ત(chroot_path);
			/* Make sure we don't attempt to chroot again */
			મુક્ત(options.chroot_directory);
			options.chroot_directory = ખાલી;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		જો (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			exit(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(શૂન્ય) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#નહીંતર
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		જો (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} નહીંતર જો (options.chroot_directory != ખાલી &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	જો (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

સ્થિર શૂન્ય
do_pwchange(Session *s)
{
	fflush(ખાલી);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	જો (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(ખાલી);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (અક્ષર *)ખાલી);
#નહીંતર
		execl(_PATH_PASSWD_PROG, "passwd", (અક્ષર *)ખાલી);
#endif
		perror("passwd");
	} નહીંતર {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	exit(1);
}

સ્થિર શૂન્ય
child_close_fds(સંરચના ssh *ssh)
{
	બાહ્ય પૂર્ણાંક auth_sock;

	જો (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	જો (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	નહીંતર {
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
	log_redirect_stderr_to(ખાલી);

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
શૂન્ય
do_child(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *command)
{
	બાહ્ય અક્ષર **environ;
	અક્ષર **env, *argv[ARGV_MAX], remote_id[512];
	અચલ અક્ષર *shell, *shell0;
	સંરચના passwd *pw = s->pw;
	પૂર્ણાંક r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, કદ(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_ચાવીઓ(ssh);

	/* Force a password change */
	જો (s->authctxt->force_pwchange) {
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
	session_setup_sia(pw, s->ttyfd == -1 ? ખાલી : s->tty);
	જો (!check_quietlogin(s, command))
		do_motd();
#નહીંતર /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	જો (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	જો (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	જો (options.use_pam && !is_pam_session_open()) {
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
	shell = login_getcapstr(lc, "shell", (અક્ષર *)shell, (અક્ષર *)shell);
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

#જો defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	જો (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != ખાલી)) {
		અક્ષર cell[64];

		debug("Getting AFS token");

		k_setpag();

		જો (k_afs_cell_of_file(pw->pw_dir, cell, કદ(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, ખાલી);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, ખાલી, ખાલી, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	જો (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		જો (r || !in_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		જો (r)
			exit(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	જો (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(ખાલી);
		exit(1);
	} નહીંતર જો (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		બાહ્ય પૂર્ણાંક optind, optreset;
		પૂર્ણાંક sftp_argc;
		અક્ષર **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		જો (argv_split(command == ખાલી ? "sftp-server" : command,
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

	fflush(ખાલી);

	/* Get the last component of the shell name. */
	જો ((shell0 = strrchr(shell, '/')) != ખાલી)
		shell0++;
	નહીંતર
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	જો (!command) {
		અક્ષર argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		જો (strlcpy(argv0 + 1, shell0, કદ(argv0) - 1)
		    >= કદ(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = ખાલી;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (અક્ષર *) shell0;
	argv[1] = "-c";
	argv[2] = (અક્ષર *) command;
	argv[3] = ખાલી;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

શૂન્ય
session_unused(પૂર્ણાંક id)
{
	debug3_f("session id %d unused", id);
	જો (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, કદ(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = ખાલી;
	sessions[id].next_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(શૂન્ય)
{
	Session *s, *tmp;

	જો (sessions_first_unused == -1) {
		જો (sessions_nalloc >= options.max_sessions)
			પાછા ખાલી;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, કદ(*sessions));
		જો (tmp == ખાલી) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			પાછા ખાલી;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	જો (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	જો (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->next_unused;
	s->used = 1;
	s->next_unused = -1;
	debug("session_new: session %d", s->self);

	પાછા s;
}

સ્થિર શૂન્ય
session_dump(શૂન્ય)
{
	પૂર્ણાંક i;
	માટે (i = 0; i < sessions_nalloc; i++) {
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

પૂર્ણાંક
session_open(Authctxt *authctxt, પૂર્ણાંક chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	જો (s == ખાલી) {
		error("no more sessions");
		પાછા 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	જો (s->pw == ખાલી || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	પાછા 1;
}

Session *
session_by_tty(અક્ષર *tty)
{
	પૂર્ણાંક i;
	માટે (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		જો (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			પાછા s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	પાછા ખાલી;
}

સ્થિર Session *
session_by_channel(પૂર્ણાંક id)
{
	પૂર્ણાંક i;
	માટે (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		જો (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			પાછા s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	પાછા ખાલી;
}

સ્થિર Session *
session_by_x11_channel(પૂર્ણાંક id)
{
	પૂર્ણાંક i, j;

	માટે (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		જો (s->x11_chanids == ખાલી || !s->used)
			ચાલુ;
		માટે (j = 0; s->x11_chanids[j] != -1; j++) {
			જો (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				પાછા s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	પાછા ખાલી;
}

સ્થિર Session *
session_by_pid(pid_t pid)
{
	પૂર્ણાંક i;
	debug("session_by_pid: pid %ld", (long)pid);
	માટે (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		જો (s->used && s->pid == pid)
			પાછા s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	પાછા ખાલી;
}

સ્થિર પૂર્ણાંક
session_window_change_req(સંરચના ssh *ssh, Session *s)
{
	પૂર્ણાંક r;

	જો ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	પાછા 1;
}

સ્થિર પૂર્ણાંક
session_pty_req(સંરચના ssh *ssh, Session *s)
{
	પૂર્ણાંક r;

	જો (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		પાછા 0;
	}
	જો (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		પાછા 0;
	}

	જો ((r = sshpkt_get_cstring(ssh, &s->term, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	જો (strcmp(s->term, "") == 0) {
		મુક્ત(s->term);
		s->term = ખાલી;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	જો (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, કદ(s->tty))) {
		મુક્ત(s->term);
		s->term = ખાલી;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		પાછા 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	જો ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	પાછા 1;
}

સ્થિર પૂર્ણાંક
session_subsystem_req(સંરચના ssh *ssh, Session *s)
{
	સંરચના stat st;
	પૂર્ણાંક r, success = 0, found = 0;
	અક્ષર *prog, *cmd, *type;
	u_int i;

	જો ((r = sshpkt_get_cstring(ssh, &s->subsys, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	માટે (i = 0; i < options.અંક_subsystems; i++) {
		જો (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			ચાલુ;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		જો (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} નહીંતર {
			જો (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		મુક્ત(type);
		success = do_exec(ssh, s, cmd) == 0;
		તોડો;
	}

	જો (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	પાછા success;
}

સ્થિર પૂર્ણાંક
session_x11_req(સંરચના ssh *ssh, Session *s)
{
	પૂર્ણાંક r, success;
	u_char single_connection = 0;

	જો (s->auth_proto != ખાલી || s->auth_data != ખાલી) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		પાછા 0;
	}
	જો ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_data, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	જો (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_data))
		success = session_setup_x11fwd(ssh, s);
	નહીંતર {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	જો (!success) {
		મુક્ત(s->auth_proto);
		મુક્ત(s->auth_data);
		s->auth_proto = ખાલી;
		s->auth_data = ખાલી;
	}
	પાછા success;
}

સ્થિર પૂર્ણાંક
session_shell_req(સંરચના ssh *ssh, Session *s)
{
	પૂર્ણાંક r;

	જો ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	પાછા do_exec(ssh, s, ખાલી) == 0;
}

સ્થિર પૂર્ણાંક
session_exec_req(સંરચના ssh *ssh, Session *s)
{
	u_int success;
	પૂર્ણાંક r;
	અક્ષર *command = ખાલી;

	જો ((r = sshpkt_get_cstring(ssh, &command, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	મુક્ત(command);
	પાછા success;
}

સ્થિર પૂર્ણાંક
session_break_req(સંરચના ssh *ssh, Session *s)
{
	પૂર્ણાંક r;

	જો ((r = sshpkt_get_u32(ssh, ખાલી)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	જો (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		પાછા 0;
	પાછા 1;
}

સ્થિર પૂર્ણાંક
session_env_req(સંરચના ssh *ssh, Session *s)
{
	અક્ષર *name, *val;
	u_int i;
	પૂર્ણાંક r;

	જો ((r = sshpkt_get_cstring(ssh, &name, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	જો (s->અંક_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		જાઓ fail;
	}

	માટે (i = 0; i < options.અંક_accept_env; i++) {
		જો (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->અંક_env, name, val);
			s->env = xrecallocarray(s->env, s->અંક_env,
			    s->અંક_env + 1, કદ(*s->env));
			s->env[s->અંક_env].name = name;
			s->env[s->અંક_env].val = val;
			s->અંક_env++;
			પાછા (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	મુક્ત(name);
	મુક્ત(val);
	પાછા (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
સ્થિર પૂર્ણાંક
name2sig(અક્ષર *name)
{
#define SSH_SIG(x) જો (strcmp(name, #x) == 0) પાછા SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	જો (strcmp(name, "INFO@openssh.com") == 0)
		પાછા SIGINFO;
#endif
	પાછા -1;
}

સ્થિર પૂર્ણાંક
session_signal_req(સંરચના ssh *ssh, Session *s)
{
	અક્ષર *signame = ખાલી;
	પૂર્ણાંક r, sig, success = 0;

	જો ((r = sshpkt_get_cstring(ssh, &signame, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		જાઓ out;
	}
	જો ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		જાઓ out;
	}
	જો (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		જાઓ out;
	}
	જો (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		જાઓ out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (long)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	જો (r != 0) {
		error_f("killpg(%ld, %d): %s", (long)s->pid,
		    sig, strerror(errno));
		જાઓ out;
	}

	/* success */
	success = 1;
 out:
	મુક્ત(signame);
	પાછા success;
}

સ્થિર પૂર્ણાંક
session_auth_agent_req(સંરચના ssh *ssh, Session *s, પૂર્ણાંક agent_new)
{
	સ્થિર પૂર્ણાંક called = 0;
	પૂર્ણાંક r;

	જો ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	જો (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		પાછા 0;
	}
	જો (called)
		પાછા 0;

	called = 1;
	પાછા auth_આગત_request_forwarding(ssh, s->pw, agent_new);
}

પૂર્ણાંક
session_આગત_channel_req(સંરચના ssh *ssh, Channel *c, અચલ અક્ષર *rtype)
{
	પૂર્ણાંક success = 0;
	Session *s;

	જો ((s = session_by_channel(c->self)) == ખાલી) {
		logit_f("no session %d req %.100s", c->self, rtype);
		પાછા 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	જો (c->type == SSH_CHANNEL_LARVAL) {
		જો (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} નહીંતર જો (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} નહીંતર જો (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} નહીંતર જો (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} નહીંતર જો (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} નહીંતર જો (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} નહીંતર જો (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} નહીંતર જો (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	જો (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} નહીંતર જો (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} નહીંતર જો (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	પાછા success;
}

શૂન્ય
session_set_fds(સંરચના ssh *ssh, Session *s,
    પૂર્ણાંક fdin, પૂર્ણાંક fdout, પૂર્ણાંક fderr, પૂર્ણાંક ignore_fderr, પૂર્ણાંક is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	જો (s->chanid == -1)
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
શૂન્ય
session_pty_cleanup2(Session *s)
{
	જો (s == ખાલી) {
		error_f("no session");
		પાછા;
	}
	જો (s->ttyfd == -1)
		પાછા;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	જો (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	જો (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	જો (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

શૂન્ય
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

સ્થિર અક્ષર *
sig2name(પૂર્ણાંક sig)
{
#define SSH_SIG(x) જો (sig == SIG ## x) પાછા #x
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
	પાછા "SIG@openssh.com";
}

સ્થિર શૂન્ય
session_close_x11(સંરચના ssh *ssh, પૂર્ણાંક id)
{
	Channel *c;

	જો ((c = channel_by_id(ssh, id)) == ખાલી) {
		debug_f("x11 channel %d missing", id);
	} નહીંતર {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		જો (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

સ્થિર શૂન્ય
session_close_single_x11(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક force, શૂન્ય *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	જો ((s = session_by_x11_channel(id)) == ખાલી)
		fatal_f("no x11 channel %d", id);
	માટે (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		જો (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	મુક્ત(s->x11_chanids);
	s->x11_chanids = ખાલી;
	મુક્ત(s->display);
	s->display = ખાલી;
	મુક્ત(s->auth_proto);
	s->auth_proto = ખાલી;
	મુક્ત(s->auth_data);
	s->auth_data = ખાલી;
	મુક્ત(s->auth_display);
	s->auth_display = ખાલી;
}

સ્થિર શૂન્ય
session_exit_message(સંરચના ssh *ssh, Session *s, પૂર્ણાંક status)
{
	Channel *c;
	પૂર્ણાંક r;
	અક્ષર *note = ખાલી;

	જો ((c = channel_lookup(ssh, s->chanid)) == ખાલી)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	જો (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		જો ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} નહીંતર જો (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		જો ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} નહીંતર {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (long)s->pid, note == ખાલી ? "UNKNOWN" : note);
	મુક્ત(note);

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
	જો (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

શૂન્ય
session_close(સંરચના ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	જો (s->ttyfd != -1)
		session_pty_cleanup(s);
	મુક્ત(s->term);
	મુક્ત(s->display);
	મુક્ત(s->x11_chanids);
	મુક્ત(s->auth_display);
	મુક્ત(s->auth_data);
	મુક્ત(s->auth_proto);
	મુક્ત(s->subsys);
	જો (s->env != ખાલી) {
		માટે (i = 0; i < s->અંક_env; i++) {
			મુક્ત(s->env[i].name);
			મુક્ત(s->env[i].val);
		}
		મુક્ત(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

શૂન્ય
session_close_by_pid(સંરચના ssh *ssh, pid_t pid, પૂર્ણાંક status)
{
	Session *s = session_by_pid(pid);
	જો (s == ખાલી) {
		debug_f("no session for pid %ld", (long)pid);
		પાછા;
	}
	જો (s->chanid != -1)
		session_exit_message(ssh, s, status);
	જો (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
શૂન્ય
session_close_by_channel(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક force, શૂન્ય *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	જો (s == ખાલી) {
		debug_f("no session for id %d", id);
		પાછા;
	}
	debug_f("channel %d child %ld", id, (long)s->pid);
	જો (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		જો (s->ttyfd != -1)
			session_pty_cleanup(s);
		જો (!force)
			પાછા;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	જો (s->x11_chanids != ખાલી) {
		માટે (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

શૂન્ય
session_destroy_all(સંરચના ssh *ssh, શૂન્ય (*closefunc)(Session *))
{
	પૂર્ણાંક i;
	માટે (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		જો (s->used) {
			જો (closefunc != ખાલી)
				closefunc(s);
			નહીંતર
				session_close(ssh, s);
		}
	}
}

સ્થિર અક્ષર *
session_tty_list(શૂન્ય)
{
	સ્થિર અક્ષર buf[1024];
	પૂર્ણાંક i;
	અક્ષર *cp;

	buf[0] = '\0';
	માટે (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		જો (s->used && s->ttyfd != -1) {

			જો (strncmp(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == ખાલી) ? s->tty : cp + 1;
			} નહીંતર
				cp = s->tty + 5;

			જો (buf[0] != '\0')
				strlcat(buf, ",", કદ buf);
			strlcat(buf, cp, કદ buf);
		}
	}
	જો (buf[0] == '\0')
		strlcpy(buf, "notty", કદ buf);
	પાછા buf;
}

શૂન્ય
session_proctitle(Session *s)
{
	જો (s->pw == ખાલી)
		error("no user for session %d", s->self);
	નહીંતર
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

પૂર્ણાંક
session_setup_x11fwd(સંરચના ssh *ssh, Session *s)
{
	સંરચના stat st;
	અક્ષર display[512], auth_display[512];
	અક્ષર hostname[NI_MAXHOST];
	u_int i;

	જો (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		પાછા 0;
	}
	જો (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		પાછા 0;
	}
	જો (options.xauth_location == ખાલી ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		પાછા 0;
	}
	જો (s->display != ખાલી) {
		debug("X11 display already set.");
		પાછા 0;
	}
	જો (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_સંખ્યા, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		પાછા 0;
	}
	માટે (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	જો (gethostname(hostname, કદ(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	જો (options.x11_use_localhost) {
		snprintf(display, કદ display, "localhost:%u.%u",
		    s->display_સંખ્યા, s->screen);
		snprintf(auth_display, કદ auth_display, "unix:%u.%u",
		    s->display_સંખ્યા, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} નહીંતર {
#ifdef IPADDR_IN_DISPLAY
		સંરચના hostent *he;
		સંરચના in_addr my_addr;

		he = gethostbyname(hostname);
		જો (he == ખાલી) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			પાછા 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], કદ(સંરચના in_addr));
		snprintf(display, કદ display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_સંખ્યા, s->screen);
#નહીંતર
		snprintf(display, કદ display, "%.400s:%u.%u", hostname,
		    s->display_સંખ્યા, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	પાછા 1;
}

સ્થિર શૂન્ય
do_authenticated2(સંરચના ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

શૂન્ય
do_cleanup(સંરચના ssh *ssh, Authctxt *authctxt)
{
	સ્થિર પૂર્ણાંક called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	જો (is_child)
		પાછા;

	/* avoid double cleanup */
	જો (called)
		પાછા;
	called = 1;

	જો (authctxt == ખાલી)
		પાછા;

#ifdef USE_PAM
	જો (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	જો (!authctxt->authenticated)
		પાછા;

#ifdef KRB5
	જો (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	જો (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	જો (auth_info_file != ખાલી) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		મુક્ત(auth_info_file);
		auth_info_file = ખાલી;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	જો (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

અચલ અક્ષર *
session_get_remote_name_or_ip(સંરચના ssh *ssh, u_int utmp_size, પૂર્ણાંક use_dns)
{
	અચલ અક્ષર *remote = "";

	જો (utmp_size > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	જો (utmp_size == 0 || strlen(remote) > utmp_size)
		remote = ssh_remote_ipaddr(ssh);
	પાછા remote;
}

