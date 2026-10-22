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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/un.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <grp.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "sshpty.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "sshlogin.h"
#അന്തര്ഭാവ "serverloop.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "session.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "sftp.h"
#അന്തര്ഭാവ "atomicio.h"

#എങ്കിൽ defined(KRB5) && defined(USE_AFS)
#അന്തര്ഭാവ <kafs.h>
#endif

#ifdef WITH_SELINUX
#അന്തര്ഭാവ <selinux/selinux.h>
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
	(!strncmp(c, INTERNAL_SFTP_NAME, വലുപ്പം(INTERNAL_SFTP_NAME) - 1) && \
	 (c[വലുപ്പം(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[വലുപ്പം(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[വലുപ്പം(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(ശൂന്യം);
ശൂന്യം	session_set_fds(ഘടന ssh *, Session *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
ശൂന്യം	session_pty_cleanup(Session *);
ശൂന്യം	session_proctitle(Session *);
പൂർണ്ണസംഖ്യ	session_setup_x11fwd(ഘടന ssh *, Session *);
പൂർണ്ണസംഖ്യ	do_exec_pty(ഘടന ssh *, Session *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	do_exec_no_pty(ഘടന ssh *, Session *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	do_exec(ഘടന ssh *, Session *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	do_login(ഘടന ssh *, Session *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	do_child(ഘടന ssh *, Session *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	do_motd(ശൂന്യം);
പൂർണ്ണസംഖ്യ	check_quietlogin(Session *, സ്ഥിരം അക്ഷരം *);

സ്ഥിതം ശൂന്യം do_authenticated2(ഘടന ssh *, Authctxt *);

സ്ഥിതം പൂർണ്ണസംഖ്യ session_pty_req(ഘടന ssh *, Session *);

/* import */
ബാഹ്യ ServerOptions options;
ബാഹ്യ അക്ഷരം *__progname;
ബാഹ്യ പൂർണ്ണസംഖ്യ debug_flag;
ബാഹ്യ ഘടന sshbuf *loginmsg;
ബാഹ്യ ഘടന sshauthopt *auth_opts;
ബാഹ്യ അക്ഷരം *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
സ്ഥിരം അക്ഷരം *original_command = ശൂന്യ;

/* data */
സ്ഥിതം പൂർണ്ണസംഖ്യ sessions_first_unused = -1;
സ്ഥിതം പൂർണ്ണസംഖ്യ sessions_nalloc = 0;
സ്ഥിതം Session *sessions = ശൂന്യ;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

സ്ഥിതം പൂർണ്ണസംഖ്യ is_child = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
സ്ഥിതം അക്ഷരം *auth_info_file = ശൂന്യ;

/* Name and directory of socket for authentication agent forwarding. */
സ്ഥിതം അക്ഷരം *auth_sock_name = ശൂന്യ;
സ്ഥിതം അക്ഷരം *auth_sock_dir = ശൂന്യ; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

സ്ഥിതം ശൂന്യം
auth_sock_cleanup_proc(ഘടന passwd *pw)
{
	എങ്കിൽ (auth_sock_name != ശൂന്യ) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		സ്വതന്ത്രം(auth_sock_name);
		auth_sock_name = ശൂന്യ;
		restore_uid();
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
auth_നിവേശം_request_forwarding(ഘടന ssh *ssh, ഘടന passwd *pw, പൂർണ്ണസംഖ്യ agent_new)
{
	Channel *nc;
	പൂർണ്ണസംഖ്യ sock = -1;

	എങ്കിൽ (auth_sock_name != ശൂന്യ) {
		error("authentication forwarding requested twice.");
		തിരികെ 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	എങ്കിൽ (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		പോകുക authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	തിരികെ 1;

 authsock_err:
	സ്വതന്ത്രം(auth_sock_name);
	എങ്കിൽ (sock != -1)
		close(sock);
	auth_sock_name = ശൂന്യ;
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
display_loginmsg(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (sshbuf_len(loginmsg) == 0)
		തിരികെ;
	എങ്കിൽ ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	printf("%s", (അക്ഷരം *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

സ്ഥിതം ശൂന്യം
prepare_auth_info_file(ഘടന passwd *pw, ഘടന sshbuf *info)
{
	പൂർണ്ണസംഖ്യ fd = -1, success = 0;

	എങ്കിൽ (!options.expose_userauth_info || info == ശൂന്യ)
		തിരികെ;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	എങ്കിൽ ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		പോകുക out;
	}
	success = 1;
 out:
	എങ്കിൽ (!success) {
		എങ്കിൽ (fd != -1)
			close(fd);
		സ്വതന്ത്രം(auth_info_file);
		auth_info_file = ശൂന്യ;
	}
	restore_uid();
}

സ്ഥിതം ശൂന്യം
set_fwdpermit_from_authopts(ഘടന ssh *ssh, സ്ഥിരം ഘടന sshauthopt *opts)
{
	അക്ഷരം *tmp, *cp, *host;
	പൂർണ്ണസംഖ്യ port;
	size_t i;

	എങ്കിൽ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		വേണ്ടി (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			എങ്കിൽ ((host = hpdelim2(&cp, ശൂന്യ)) == ശൂന്യ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			എങ്കിൽ (cp == ശൂന്യ || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			സ്വതന്ത്രം(tmp);
		}
	}
	എങ്കിൽ ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		വേണ്ടി (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			എങ്കിൽ ((host = hpdelim(&cp)) == ശൂന്യ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			എങ്കിൽ (cp == ശൂന്യ || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			സ്വതന്ത്രം(tmp);
		}
	}
}

ശൂന്യം
do_authenticated(ഘടന ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	എങ്കിൽ (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		അല്ലെങ്കിൽ
			channel_permit_all(ssh, FORWARD_LOCAL);
		എങ്കിൽ ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		അല്ലെങ്കിൽ
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
സ്ഥിതം പൂർണ്ണസംഖ്യ
xauth_valid_string(സ്ഥിരം അക്ഷരം *s)
{
	size_t i;

	വേണ്ടി (i = 0; s[i] != '\0'; i++) {
		എങ്കിൽ (!isalnum((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			തിരികെ 0;
	}
	തിരികെ 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
പൂർണ്ണസംഖ്യ
do_exec_no_pty(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *command)
{
	pid_t pid;
#ifdef USE_PIPES
	പൂർണ്ണസംഖ്യ pin[2], pout[2], perr[2];

	എങ്കിൽ (s == ശൂന്യ)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	എങ്കിൽ (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		തിരികെ -1;
	}
	എങ്കിൽ (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		തിരികെ -1;
	}
#അല്ലെങ്കിൽ
	പൂർണ്ണസംഖ്യ inout[2], err[2];

	എങ്കിൽ (s == ശൂന്യ)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		തിരികെ -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	തിരഞ്ഞെടുപ്പ് ((pid = fork())) {
	അവസ്ഥ -1:
		error_f("fork: %.100s", strerror(errno));
#ifdef USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#അല്ലെങ്കിൽ
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#endif
		തിരികെ -1;
	അവസ്ഥ 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		എങ്കിൽ (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		എങ്കിൽ (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		എങ്കിൽ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		എങ്കിൽ (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#അല്ലെങ്കിൽ
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		എങ്കിൽ (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		എങ്കിൽ (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		എങ്കിൽ (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	സ്ഥിരസ്ഥിതി:
		നിർത്തുക;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_മൂല്യം);
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
#അല്ലെങ്കിൽ
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
	തിരികെ 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
പൂർണ്ണസംഖ്യ
do_exec_pty(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *command)
{
	പൂർണ്ണസംഖ്യ fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	എങ്കിൽ (s == ശൂന്യ)
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
	എങ്കിൽ ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		തിരികെ -1;
	}
	/* we keep a reference to the pty master */
	എങ്കിൽ ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		തിരികെ -1;
	}

	/* Fork the child. */
	തിരഞ്ഞെടുപ്പ് ((pid = fork())) {
	അവസ്ഥ -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		തിരികെ -1;
	അവസ്ഥ 0:
		is_child = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		എങ്കിൽ (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		എങ്കിൽ (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		എങ്കിൽ (dup2(ttyfd, 2) == -1)
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
	സ്ഥിരസ്ഥിതി:
		നിർത്തുക;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_മൂല്യം);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	തിരികെ 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
പൂർണ്ണസംഖ്യ
do_exec(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *command)
{
	പൂർണ്ണസംഖ്യ ret;
	സ്ഥിരം അക്ഷരം *forced = ശൂന്യ, *tty = ശൂന്യ;
	അക്ഷരം session_type[1024];

	എങ്കിൽ (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} അല്ലെങ്കിൽ എങ്കിൽ (auth_opts->force_command != ശൂന്യ) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	എങ്കിൽ (forced != ശൂന്യ) {
		s->forced = 1;
		എങ്കിൽ (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} അല്ലെങ്കിൽ എങ്കിൽ (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, വലുപ്പം(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} അല്ലെങ്കിൽ എങ്കിൽ (s->is_subsystem) {
		snprintf(session_type, വലുപ്പം(session_type),
		    "subsystem '%.900s'", s->subsys);
	} അല്ലെങ്കിൽ എങ്കിൽ (command == ശൂന്യ) {
		snprintf(session_type, വലുപ്പം(session_type), "shell");
	} അല്ലെങ്കിൽ {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, വലുപ്പം(session_type), "command");
	}

	എങ്കിൽ (s->ttyfd != -1) {
		tty = s->tty;
		എങ്കിൽ (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == ശൂന്യ ? "" : " on ",
	    tty == ശൂന്യ ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	എങ്കിൽ (command != ശൂന്യ)
		mm_audit_run_command(command);
	അല്ലെങ്കിൽ എങ്കിൽ (s->ttyfd == -1) {
		അക്ഷരം *shell = s->pw->pw_shell;

		എങ്കിൽ (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	എങ്കിൽ (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	അല്ലെങ്കിൽ
		ret = do_exec_no_pty(ssh, s, command);

	original_command = ശൂന്യ;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	തിരികെ ret;
}

/* administrative, login(1)-like work */
ശൂന്യം
do_login(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *command)
{
	socklen_t fromlen;
	ഘടന sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, വലുപ്പം(from));
	fromlen = വലുപ്പം(from);
	എങ്കിൽ (ssh_packet_connection_is_on_socket(ssh)) {
		എങ്കിൽ (getpeername(ssh_packet_get_connection_in(ssh),
		    (ഘടന sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	എങ്കിൽ (check_quietlogin(s, command))
		തിരികെ;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
ശൂന്യം
do_motd(ശൂന്യം)
{
	FILE *f;
	അക്ഷരം buf[256];

	എങ്കിൽ (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#അല്ലെങ്കിൽ
		f = fopen("/etc/motd", "r");
#endif
		എങ്കിൽ (f) {
			ആകുമ്പോൾ (fgets(buf, വലുപ്പം(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
പൂർണ്ണസംഖ്യ
check_quietlogin(Session *s, സ്ഥിരം അക്ഷരം *command)
{
	അക്ഷരം buf[256];
	ഘടന passwd *pw = s->pw;
	ഘടന stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	എങ്കിൽ (command != ശൂന്യ)
		തിരികെ 1;
	snprintf(buf, വലുപ്പം(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	എങ്കിൽ (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		തിരികെ 1;
#അല്ലെങ്കിൽ
	എങ്കിൽ (stat(buf, &st) >= 0)
		തിരികെ 1;
#endif
	തിരികെ 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
സ്ഥിതം ശൂന്യം
read_environment_file(അക്ഷരം ***env, u_int *envsize,
	സ്ഥിരം അക്ഷരം *filename, സ്ഥിരം അക്ഷരം *allowlist)
{
	FILE *f;
	അക്ഷരം *വരി = ശൂന്യ, *cp, *മൂല്യം;
	size_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	എങ്കിൽ (!f)
		തിരികെ;

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		എങ്കിൽ (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		വേണ്ടി (cp = വരി; *cp == ' ' || *cp == '\t'; cp++)
			;
		എങ്കിൽ (!*cp || *cp == '#' || *cp == '\n')
			തുടരുക;

		cp[strcspn(cp, "\n")] = '\0';

		മൂല്യം = strchr(cp, '=');
		എങ്കിൽ (മൂല്യം == ശൂന്യ) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			തുടരുക;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*മൂല്യം = '\0';
		മൂല്യം++;
		എങ്കിൽ (allowlist != ശൂന്യ &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			തുടരുക;
		child_set_env(env, envsize, cp, മൂല്യം);
	}
	സ്വതന്ത്രം(വരി);
	fclose(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
സ്ഥിതം അക്ഷരം *
child_get_env(അക്ഷരം **env, സ്ഥിരം അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ i;
	size_t len;

	len = strlen(name);
	വേണ്ടി (i=0; env[i] != ശൂന്യ; i++)
		എങ്കിൽ (strncmp(name, env[i], len) == 0 && env[i][len] == '=')
			തിരികെ(env[i] + len + 1);
	തിരികെ ശൂന്യ;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
സ്ഥിതം ശൂന്യം
read_etc_default_login(അക്ഷരം ***env, u_int *envsize, uid_t uid)
{
	അക്ഷരം **tmpenv = ശൂന്യ, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	എങ്കിൽ (tmpenv == ശൂന്യ)
		തിരികെ;

	എങ്കിൽ (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	അല്ലെങ്കിൽ
		var = child_get_env(tmpenv, "PATH");
	എങ്കിൽ (var != ശൂന്യ)
		child_set_env(env, envsize, "PATH", var);

	എങ്കിൽ ((var = child_get_env(tmpenv, "UMASK")) != ശൂന്യ)
		എങ്കിൽ (sscanf(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	വേണ്ടി (i = 0; tmpenv[i] != ശൂന്യ; i++)
		സ്വതന്ത്രം(tmpenv[i]);
	സ്വതന്ത്രം(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#എങ്കിൽ defined(USE_PAM) || defined(HAVE_CYGWIN)
സ്ഥിതം ശൂന്യം
copy_environment_denylist(അക്ഷരം **source, അക്ഷരം ***env, u_int *envsize,
    സ്ഥിരം അക്ഷരം *denylist)
{
	അക്ഷരം *var_name, *var_val;
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (source == ശൂന്യ)
		തിരികെ;

	വേണ്ടി(i = 0; source[i] != ശൂന്യ; i++) {
		var_name = xstrdup(source[i]);
		എങ്കിൽ ((var_val = strstr(var_name, "=")) == ശൂന്യ) {
			സ്വതന്ത്രം(var_name);
			തുടരുക;
		}
		*var_val++ = '\0';

		എങ്കിൽ (denylist == ശൂന്യ ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		സ്വതന്ത്രം(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
സ്ഥിതം ശൂന്യം
copy_environment(അക്ഷരം **source, അക്ഷരം ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, ശൂന്യ);
}
#endif

സ്ഥിതം അക്ഷരം **
do_setup_env(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *shell)
{
	അക്ഷരം buf[256];
	size_t n;
	u_int i, envsize;
	അക്ഷരം *ocp, *cp, *മൂല്യം, **env, *laddr;
	ഘടന passwd *pw = s->pw;
#എങ്കിൽ !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	അക്ഷരം *path = ശൂന്യ;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, വലുപ്പം(അക്ഷരം *));
	env[0] = ശൂന്യ;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		അക്ഷരം **p;

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
	വേണ്ടി (i = 0; i < s->അക്കം_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	എങ്കിൽ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	അല്ലെങ്കിൽ
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#അല്ലെങ്കിൽ /* HAVE_LOGIN_CAP */
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
	എങ്കിൽ (path == ശൂന്യ || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	എങ്കിൽ (!options.use_pam) {
		snprintf(buf, വലുപ്പം buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	എങ്കിൽ (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
#ifdef HAVE_LOGIN_CAP
	എങ്കിൽ (getenv("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	എങ്കിൽ (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	എങ്കിൽ (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		അക്ഷരം *cp;

		എങ്കിൽ ((cp = getenv("KRB5CCNAME")) != ശൂന്യ)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		അക്ഷരം *cp;

		എങ്കിൽ ((cp = getenv("AUTHSTATE")) != ശൂന്യ)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	എങ്കിൽ (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	എങ്കിൽ (auth_sock_name != ശൂന്യ)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	എങ്കിൽ (options.permit_user_env) {
		വേണ്ടി (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			എങ്കിൽ (cp != ശൂന്യ) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				എങ്കിൽ (options.permit_user_env_allowlist == ശൂന്യ ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			സ്വതന്ത്രം(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	എങ്കിൽ (options.permit_user_env) {
		snprintf(buf, വലുപ്പം buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	എങ്കിൽ (options.use_pam) {
		അക്ഷരം **p;

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
	വേണ്ടി (i = 0; i < options.അക്കം_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		എങ്കിൽ ((മൂല്യം = strchr(cp, '=')) == ശൂന്യ) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*മൂല്യം++ = '\0';
		child_set_env(&env, &envsize, cp, മൂല്യം);
		സ്വതന്ത്രം(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, വലുപ്പം buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, വലുപ്പം buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	സ്വതന്ത്രം(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	എങ്കിൽ (tun_fwd_ifnames != ശൂന്യ)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	എങ്കിൽ (auth_info_file != ശൂന്യ)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	എങ്കിൽ (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	എങ്കിൽ (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	എങ്കിൽ (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		വേണ്ടി (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	തിരികെ env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
സ്ഥിതം ശൂന്യം
do_rc_files(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *shell)
{
	FILE *f = ശൂന്യ;
	അക്ഷരം *cmd = ശൂന്യ, *user_rc = ശൂന്യ;
	പൂർണ്ണസംഖ്യ do_xauth;
	ഘടന stat st;

	do_xauth =
	    s->display != ശൂന്യ && s->auth_proto != ശൂന്യ && s->auth_data != ശൂന്യ;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	എങ്കിൽ (!s->is_subsystem && options.adm_forced_command == ശൂന്യ &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		എങ്കിൽ (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		എങ്കിൽ (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		എങ്കിൽ (f) {
			എങ്കിൽ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} അല്ലെങ്കിൽ
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} അല്ലെങ്കിൽ എങ്കിൽ (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		എങ്കിൽ (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		എങ്കിൽ (f) {
			എങ്കിൽ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} അല്ലെങ്കിൽ
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} അല്ലെങ്കിൽ എങ്കിൽ (do_xauth && options.xauth_location != ശൂന്യ) {
		/* Add authority data to .Xauthority if appropriate. */
		എങ്കിൽ (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		എങ്കിൽ (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		എങ്കിൽ (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} അല്ലെങ്കിൽ {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	സ്വതന്ത്രം(cmd);
	സ്വതന്ത്രം(user_rc);
}

സ്ഥിതം ശൂന്യം
do_nologin(ഘടന passwd *pw)
{
	FILE *f = ശൂന്യ;
	അക്ഷരം buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	ഘടന stat sb;

#ifdef HAVE_LOGIN_CAP
	എങ്കിൽ (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		തിരികെ;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#അല്ലെങ്കിൽ
	എങ്കിൽ (pw->pw_uid == 0)
		തിരികെ;
	nl = def_nl;
#endif
	എങ്കിൽ (stat(nl, &sb) == -1)
		തിരികെ;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	എങ്കിൽ ((f = fopen(nl, "r")) != ശൂന്യ) {
		ആകുമ്പോൾ (fgets(buf, വലുപ്പം(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
സ്ഥിതം ശൂന്യം
safely_chroot(സ്ഥിരം അക്ഷരം *path, uid_t uid)
{
	സ്ഥിരം അക്ഷരം *cp;
	അക്ഷരം component[PATH_MAX];
	ഘടന stat st;

	എങ്കിൽ (!path_absolute(path))
		fatal("chroot path does not begin at root");
	എങ്കിൽ (strlen(path) >= വലുപ്പം(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	വേണ്ടി (cp = path; cp != ശൂന്യ;) {
		എങ്കിൽ ((cp = strchr(cp, '/')) == ശൂന്യ)
			strlcpy(component, path, വലുപ്പം(component));
		അല്ലെങ്കിൽ {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		എങ്കിൽ (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		എങ്കിൽ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ശൂന്യ ? "" : "component ", component);
		എങ്കിൽ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ശൂന്യ ? "" : "component ", component);

	}

	എങ്കിൽ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	എങ്കിൽ (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	എങ്കിൽ (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
ശൂന്യം
do_setusercontext(ഘടന passwd *pw)
{
	അക്ഷരം uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	എങ്കിൽ (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		എങ്കിൽ (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			exit(1);
		}
#അല്ലെങ്കിൽ
		എങ്കിൽ (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		എങ്കിൽ (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			exit(1);
		}
		/* Initialize the group list. */
		എങ്കിൽ (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			exit(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		എങ്കിൽ (!in_chroot && options.chroot_directory != ശൂന്യ &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, വലുപ്പം(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (അക്ഷരം *)ശൂന്യ);
			safely_chroot(chroot_path, pw->pw_uid);
			സ്വതന്ത്രം(tmp);
			സ്വതന്ത്രം(chroot_path);
			/* Make sure we don't attempt to chroot again */
			സ്വതന്ത്രം(options.chroot_directory);
			options.chroot_directory = ശൂന്യ;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		എങ്കിൽ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			exit(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(ശൂന്യം) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#അല്ലെങ്കിൽ
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		എങ്കിൽ (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} അല്ലെങ്കിൽ എങ്കിൽ (options.chroot_directory != ശൂന്യ &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	എങ്കിൽ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

സ്ഥിതം ശൂന്യം
do_pwchange(Session *s)
{
	fflush(ശൂന്യ);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	എങ്കിൽ (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(ശൂന്യ);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (അക്ഷരം *)ശൂന്യ);
#അല്ലെങ്കിൽ
		execl(_PATH_PASSWD_PROG, "passwd", (അക്ഷരം *)ശൂന്യ);
#endif
		perror("passwd");
	} അല്ലെങ്കിൽ {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	exit(1);
}

സ്ഥിതം ശൂന്യം
child_close_fds(ഘടന ssh *ssh)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ auth_sock;

	എങ്കിൽ (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	എങ്കിൽ (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	അല്ലെങ്കിൽ {
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
	log_redirect_stderr_to(ശൂന്യ);

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
ശൂന്യം
do_child(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *command)
{
	ബാഹ്യ അക്ഷരം **environ;
	അക്ഷരം **env, *argv[ARGV_MAX], remote_id[512];
	സ്ഥിരം അക്ഷരം *shell, *shell0;
	ഘടന passwd *pw = s->pw;
	പൂർണ്ണസംഖ്യ r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, വലുപ്പം(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_താക്കോലുകൾ(ssh);

	/* Force a password change */
	എങ്കിൽ (s->authctxt->force_pwchange) {
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
	session_setup_sia(pw, s->ttyfd == -1 ? ശൂന്യ : s->tty);
	എങ്കിൽ (!check_quietlogin(s, command))
		do_motd();
#അല്ലെങ്കിൽ /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	എങ്കിൽ (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	എങ്കിൽ (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	എങ്കിൽ (options.use_pam && !is_pam_session_open()) {
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
	shell = login_getcapstr(lc, "shell", (അക്ഷരം *)shell, (അക്ഷരം *)shell);
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

#എങ്കിൽ defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	എങ്കിൽ (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != ശൂന്യ)) {
		അക്ഷരം cell[64];

		debug("Getting AFS token");

		k_setpag();

		എങ്കിൽ (k_afs_cell_of_file(pw->pw_dir, cell, വലുപ്പം(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, ശൂന്യ);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, ശൂന്യ, ശൂന്യ, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	എങ്കിൽ (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		എങ്കിൽ (r || !in_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		എങ്കിൽ (r)
			exit(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	എങ്കിൽ (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(ശൂന്യ);
		exit(1);
	} അല്ലെങ്കിൽ എങ്കിൽ (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		ബാഹ്യ പൂർണ്ണസംഖ്യ optind, optreset;
		പൂർണ്ണസംഖ്യ sftp_argc;
		അക്ഷരം **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		എങ്കിൽ (argv_split(command == ശൂന്യ ? "sftp-server" : command,
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

	fflush(ശൂന്യ);

	/* Get the last component of the shell name. */
	എങ്കിൽ ((shell0 = strrchr(shell, '/')) != ശൂന്യ)
		shell0++;
	അല്ലെങ്കിൽ
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	എങ്കിൽ (!command) {
		അക്ഷരം argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		എങ്കിൽ (strlcpy(argv0 + 1, shell0, വലുപ്പം(argv0) - 1)
		    >= വലുപ്പം(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = ശൂന്യ;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (അക്ഷരം *) shell0;
	argv[1] = "-c";
	argv[2] = (അക്ഷരം *) command;
	argv[3] = ശൂന്യ;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

ശൂന്യം
session_unused(പൂർണ്ണസംഖ്യ id)
{
	debug3_f("session id %d unused", id);
	എങ്കിൽ (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, വലുപ്പം(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = ശൂന്യ;
	sessions[id].next_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(ശൂന്യം)
{
	Session *s, *tmp;

	എങ്കിൽ (sessions_first_unused == -1) {
		എങ്കിൽ (sessions_nalloc >= options.max_sessions)
			തിരികെ ശൂന്യ;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, വലുപ്പം(*sessions));
		എങ്കിൽ (tmp == ശൂന്യ) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			തിരികെ ശൂന്യ;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	എങ്കിൽ (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	എങ്കിൽ (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->next_unused;
	s->used = 1;
	s->next_unused = -1;
	debug("session_new: session %d", s->self);

	തിരികെ s;
}

സ്ഥിതം ശൂന്യം
session_dump(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < sessions_nalloc; i++) {
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

പൂർണ്ണസംഖ്യ
session_open(Authctxt *authctxt, പൂർണ്ണസംഖ്യ chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	എങ്കിൽ (s == ശൂന്യ) {
		error("no more sessions");
		തിരികെ 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	എങ്കിൽ (s->pw == ശൂന്യ || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	തിരികെ 1;
}

Session *
session_by_tty(അക്ഷരം *tty)
{
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		എങ്കിൽ (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			തിരികെ s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	തിരികെ ശൂന്യ;
}

സ്ഥിതം Session *
session_by_channel(പൂർണ്ണസംഖ്യ id)
{
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		എങ്കിൽ (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			തിരികെ s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	തിരികെ ശൂന്യ;
}

സ്ഥിതം Session *
session_by_x11_channel(പൂർണ്ണസംഖ്യ id)
{
	പൂർണ്ണസംഖ്യ i, j;

	വേണ്ടി (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		എങ്കിൽ (s->x11_chanids == ശൂന്യ || !s->used)
			തുടരുക;
		വേണ്ടി (j = 0; s->x11_chanids[j] != -1; j++) {
			എങ്കിൽ (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				തിരികെ s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	തിരികെ ശൂന്യ;
}

സ്ഥിതം Session *
session_by_pid(pid_t pid)
{
	പൂർണ്ണസംഖ്യ i;
	debug("session_by_pid: pid %ld", (long)pid);
	വേണ്ടി (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		എങ്കിൽ (s->used && s->pid == pid)
			തിരികെ s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	തിരികെ ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_window_change_req(ഘടന ssh *ssh, Session *s)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_pty_req(ഘടന ssh *ssh, Session *s)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		തിരികെ 0;
	}
	എങ്കിൽ (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		തിരികെ 0;
	}

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &s->term, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	എങ്കിൽ (strcmp(s->term, "") == 0) {
		സ്വതന്ത്രം(s->term);
		s->term = ശൂന്യ;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	എങ്കിൽ (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, വലുപ്പം(s->tty))) {
		സ്വതന്ത്രം(s->term);
		s->term = ശൂന്യ;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		തിരികെ 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_subsystem_req(ഘടന ssh *ssh, Session *s)
{
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ r, success = 0, found = 0;
	അക്ഷരം *prog, *cmd, *type;
	u_int i;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &s->subsys, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	വേണ്ടി (i = 0; i < options.അക്കം_subsystems; i++) {
		എങ്കിൽ (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			തുടരുക;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		എങ്കിൽ (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		സ്വതന്ത്രം(type);
		success = do_exec(ssh, s, cmd) == 0;
		നിർത്തുക;
	}

	എങ്കിൽ (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	തിരികെ success;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_x11_req(ഘടന ssh *ssh, Session *s)
{
	പൂർണ്ണസംഖ്യ r, success;
	u_char single_connection = 0;

	എങ്കിൽ (s->auth_proto != ശൂന്യ || s->auth_data != ശൂന്യ) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		തിരികെ 0;
	}
	എങ്കിൽ ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_data, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	എങ്കിൽ (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_data))
		success = session_setup_x11fwd(ssh, s);
	അല്ലെങ്കിൽ {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	എങ്കിൽ (!success) {
		സ്വതന്ത്രം(s->auth_proto);
		സ്വതന്ത്രം(s->auth_data);
		s->auth_proto = ശൂന്യ;
		s->auth_data = ശൂന്യ;
	}
	തിരികെ success;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_shell_req(ഘടന ssh *ssh, Session *s)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	തിരികെ do_exec(ssh, s, ശൂന്യ) == 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_exec_req(ഘടന ssh *ssh, Session *s)
{
	u_int success;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *command = ശൂന്യ;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &command, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	സ്വതന്ത്രം(command);
	തിരികെ success;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_break_req(ഘടന ssh *ssh, Session *s)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, ശൂന്യ)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	എങ്കിൽ (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_env_req(ഘടന ssh *ssh, Session *s)
{
	അക്ഷരം *name, *val;
	u_int i;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &name, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	എങ്കിൽ (s->അക്കം_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		പോകുക fail;
	}

	വേണ്ടി (i = 0; i < options.അക്കം_accept_env; i++) {
		എങ്കിൽ (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->അക്കം_env, name, val);
			s->env = xrecallocarray(s->env, s->അക്കം_env,
			    s->അക്കം_env + 1, വലുപ്പം(*s->env));
			s->env[s->അക്കം_env].name = name;
			s->env[s->അക്കം_env].val = val;
			s->അക്കം_env++;
			തിരികെ (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	സ്വതന്ത്രം(name);
	സ്വതന്ത്രം(val);
	തിരികെ (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
name2sig(അക്ഷരം *name)
{
#define SSH_SIG(x) എങ്കിൽ (strcmp(name, #x) == 0) തിരികെ SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	എങ്കിൽ (strcmp(name, "INFO@openssh.com") == 0)
		തിരികെ SIGINFO;
#endif
	തിരികെ -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_signal_req(ഘടന ssh *ssh, Session *s)
{
	അക്ഷരം *signame = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, sig, success = 0;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &signame, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		പോകുക out;
	}
	എങ്കിൽ ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		പോകുക out;
	}
	എങ്കിൽ (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		പോകുക out;
	}
	എങ്കിൽ (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		പോകുക out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (long)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	എങ്കിൽ (r != 0) {
		error_f("killpg(%ld, %d): %s", (long)s->pid,
		    sig, strerror(errno));
		പോകുക out;
	}

	/* success */
	success = 1;
 out:
	സ്വതന്ത്രം(signame);
	തിരികെ success;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
session_auth_agent_req(ഘടന ssh *ssh, Session *s, പൂർണ്ണസംഖ്യ agent_new)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ called = 0;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	എങ്കിൽ (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		തിരികെ 0;
	}
	എങ്കിൽ (called)
		തിരികെ 0;

	called = 1;
	തിരികെ auth_നിവേശം_request_forwarding(ssh, s->pw, agent_new);
}

പൂർണ്ണസംഖ്യ
session_നിവേശം_channel_req(ഘടന ssh *ssh, Channel *c, സ്ഥിരം അക്ഷരം *rtype)
{
	പൂർണ്ണസംഖ്യ success = 0;
	Session *s;

	എങ്കിൽ ((s = session_by_channel(c->self)) == ശൂന്യ) {
		logit_f("no session %d req %.100s", c->self, rtype);
		തിരികെ 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	എങ്കിൽ (c->type == SSH_CHANNEL_LARVAL) {
		എങ്കിൽ (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	എങ്കിൽ (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	തിരികെ success;
}

ശൂന്യം
session_set_fds(ഘടന ssh *ssh, Session *s,
    പൂർണ്ണസംഖ്യ fdin, പൂർണ്ണസംഖ്യ fdout, പൂർണ്ണസംഖ്യ fderr, പൂർണ്ണസംഖ്യ ignore_fderr, പൂർണ്ണസംഖ്യ is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	എങ്കിൽ (s->chanid == -1)
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
ശൂന്യം
session_pty_cleanup2(Session *s)
{
	എങ്കിൽ (s == ശൂന്യ) {
		error_f("no session");
		തിരികെ;
	}
	എങ്കിൽ (s->ttyfd == -1)
		തിരികെ;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	എങ്കിൽ (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	എങ്കിൽ (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	എങ്കിൽ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

ശൂന്യം
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

സ്ഥിതം അക്ഷരം *
sig2name(പൂർണ്ണസംഖ്യ sig)
{
#define SSH_SIG(x) എങ്കിൽ (sig == SIG ## x) തിരികെ #x
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
	തിരികെ "SIG@openssh.com";
}

സ്ഥിതം ശൂന്യം
session_close_x11(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id)
{
	Channel *c;

	എങ്കിൽ ((c = channel_by_id(ssh, id)) == ശൂന്യ) {
		debug_f("x11 channel %d missing", id);
	} അല്ലെങ്കിൽ {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		എങ്കിൽ (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

സ്ഥിതം ശൂന്യം
session_close_single_x11(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ force, ശൂന്യം *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	എങ്കിൽ ((s = session_by_x11_channel(id)) == ശൂന്യ)
		fatal_f("no x11 channel %d", id);
	വേണ്ടി (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		എങ്കിൽ (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	സ്വതന്ത്രം(s->x11_chanids);
	s->x11_chanids = ശൂന്യ;
	സ്വതന്ത്രം(s->display);
	s->display = ശൂന്യ;
	സ്വതന്ത്രം(s->auth_proto);
	s->auth_proto = ശൂന്യ;
	സ്വതന്ത്രം(s->auth_data);
	s->auth_data = ശൂന്യ;
	സ്വതന്ത്രം(s->auth_display);
	s->auth_display = ശൂന്യ;
}

സ്ഥിതം ശൂന്യം
session_exit_message(ഘടന ssh *ssh, Session *s, പൂർണ്ണസംഖ്യ status)
{
	Channel *c;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *note = ശൂന്യ;

	എങ്കിൽ ((c = channel_lookup(ssh, s->chanid)) == ശൂന്യ)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	എങ്കിൽ (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		എങ്കിൽ ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} അല്ലെങ്കിൽ എങ്കിൽ (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} അല്ലെങ്കിൽ {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (long)s->pid, note == ശൂന്യ ? "UNKNOWN" : note);
	സ്വതന്ത്രം(note);

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
	എങ്കിൽ (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

ശൂന്യം
session_close(ഘടന ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	എങ്കിൽ (s->ttyfd != -1)
		session_pty_cleanup(s);
	സ്വതന്ത്രം(s->term);
	സ്വതന്ത്രം(s->display);
	സ്വതന്ത്രം(s->x11_chanids);
	സ്വതന്ത്രം(s->auth_display);
	സ്വതന്ത്രം(s->auth_data);
	സ്വതന്ത്രം(s->auth_proto);
	സ്വതന്ത്രം(s->subsys);
	എങ്കിൽ (s->env != ശൂന്യ) {
		വേണ്ടി (i = 0; i < s->അക്കം_env; i++) {
			സ്വതന്ത്രം(s->env[i].name);
			സ്വതന്ത്രം(s->env[i].val);
		}
		സ്വതന്ത്രം(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

ശൂന്യം
session_close_by_pid(ഘടന ssh *ssh, pid_t pid, പൂർണ്ണസംഖ്യ status)
{
	Session *s = session_by_pid(pid);
	എങ്കിൽ (s == ശൂന്യ) {
		debug_f("no session for pid %ld", (long)pid);
		തിരികെ;
	}
	എങ്കിൽ (s->chanid != -1)
		session_exit_message(ssh, s, status);
	എങ്കിൽ (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
ശൂന്യം
session_close_by_channel(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ force, ശൂന്യം *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	എങ്കിൽ (s == ശൂന്യ) {
		debug_f("no session for id %d", id);
		തിരികെ;
	}
	debug_f("channel %d child %ld", id, (long)s->pid);
	എങ്കിൽ (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		എങ്കിൽ (s->ttyfd != -1)
			session_pty_cleanup(s);
		എങ്കിൽ (!force)
			തിരികെ;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	എങ്കിൽ (s->x11_chanids != ശൂന്യ) {
		വേണ്ടി (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

ശൂന്യം
session_destroy_all(ഘടന ssh *ssh, ശൂന്യം (*closefunc)(Session *))
{
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		എങ്കിൽ (s->used) {
			എങ്കിൽ (closefunc != ശൂന്യ)
				closefunc(s);
			അല്ലെങ്കിൽ
				session_close(ssh, s);
		}
	}
}

സ്ഥിതം അക്ഷരം *
session_tty_list(ശൂന്യം)
{
	സ്ഥിതം അക്ഷരം buf[1024];
	പൂർണ്ണസംഖ്യ i;
	അക്ഷരം *cp;

	buf[0] = '\0';
	വേണ്ടി (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		എങ്കിൽ (s->used && s->ttyfd != -1) {

			എങ്കിൽ (strncmp(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == ശൂന്യ) ? s->tty : cp + 1;
			} അല്ലെങ്കിൽ
				cp = s->tty + 5;

			എങ്കിൽ (buf[0] != '\0')
				strlcat(buf, ",", വലുപ്പം buf);
			strlcat(buf, cp, വലുപ്പം buf);
		}
	}
	എങ്കിൽ (buf[0] == '\0')
		strlcpy(buf, "notty", വലുപ്പം buf);
	തിരികെ buf;
}

ശൂന്യം
session_proctitle(Session *s)
{
	എങ്കിൽ (s->pw == ശൂന്യ)
		error("no user for session %d", s->self);
	അല്ലെങ്കിൽ
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

പൂർണ്ണസംഖ്യ
session_setup_x11fwd(ഘടന ssh *ssh, Session *s)
{
	ഘടന stat st;
	അക്ഷരം display[512], auth_display[512];
	അക്ഷരം hostname[NI_MAXHOST];
	u_int i;

	എങ്കിൽ (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		തിരികെ 0;
	}
	എങ്കിൽ (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		തിരികെ 0;
	}
	എങ്കിൽ (options.xauth_location == ശൂന്യ ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		തിരികെ 0;
	}
	എങ്കിൽ (s->display != ശൂന്യ) {
		debug("X11 display already set.");
		തിരികെ 0;
	}
	എങ്കിൽ (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_സംഖ്യ, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		തിരികെ 0;
	}
	വേണ്ടി (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	എങ്കിൽ (gethostname(hostname, വലുപ്പം(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	എങ്കിൽ (options.x11_use_localhost) {
		snprintf(display, വലുപ്പം display, "localhost:%u.%u",
		    s->display_സംഖ്യ, s->screen);
		snprintf(auth_display, വലുപ്പം auth_display, "unix:%u.%u",
		    s->display_സംഖ്യ, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} അല്ലെങ്കിൽ {
#ifdef IPADDR_IN_DISPLAY
		ഘടന hostent *he;
		ഘടന in_addr my_addr;

		he = gethostbyname(hostname);
		എങ്കിൽ (he == ശൂന്യ) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			തിരികെ 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], വലുപ്പം(ഘടന in_addr));
		snprintf(display, വലുപ്പം display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_സംഖ്യ, s->screen);
#അല്ലെങ്കിൽ
		snprintf(display, വലുപ്പം display, "%.400s:%u.%u", hostname,
		    s->display_സംഖ്യ, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
do_authenticated2(ഘടന ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

ശൂന്യം
do_cleanup(ഘടന ssh *ssh, Authctxt *authctxt)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	എങ്കിൽ (is_child)
		തിരികെ;

	/* avoid double cleanup */
	എങ്കിൽ (called)
		തിരികെ;
	called = 1;

	എങ്കിൽ (authctxt == ശൂന്യ)
		തിരികെ;

#ifdef USE_PAM
	എങ്കിൽ (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	എങ്കിൽ (!authctxt->authenticated)
		തിരികെ;

#ifdef KRB5
	എങ്കിൽ (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	എങ്കിൽ (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	എങ്കിൽ (auth_info_file != ശൂന്യ) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		സ്വതന്ത്രം(auth_info_file);
		auth_info_file = ശൂന്യ;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	എങ്കിൽ (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

സ്ഥിരം അക്ഷരം *
session_get_remote_name_or_ip(ഘടന ssh *ssh, u_int utmp_size, പൂർണ്ണസംഖ്യ use_dns)
{
	സ്ഥിരം അക്ഷരം *remote = "";

	എങ്കിൽ (utmp_size > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	എങ്കിൽ (utmp_size == 0 || strlen(remote) > utmp_size)
		remote = ssh_remote_ipaddr(ssh);
	തിരികെ remote;
}

