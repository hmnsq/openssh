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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "sshlogin.h"
#ಅನ್ತರ್ಭಾವ "serverloop.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "session.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"

#ಯದಿ defined(KRB5) && defined(USE_AFS)
#ಅನ್ತರ್ಭಾವ <kafs.h>
#endif

#ifdef WITH_SELINUX
#ಅನ್ತರ್ಭಾವ <selinux/selinux.h>
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
	(!strncmp(c, INTERNAL_SFTP_NAME, ಪರಿಮಾಣ(INTERNAL_SFTP_NAME) - 1) && \
	 (c[ಪರಿಮಾಣ(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[ಪರಿಮಾಣ(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[ಪರಿಮಾಣ(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(ಶೂನ್ಯ);
ಶೂನ್ಯ	session_set_fds(ಸಂರಚನಾ ssh *, Session *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	session_pty_cleanup(Session *);
ಶೂನ್ಯ	session_proctitle(Session *);
ಪೂರ್ಣಾಙ್ಕ	session_setup_x11fwd(ಸಂರಚನಾ ssh *, Session *);
ಪೂರ್ಣಾಙ್ಕ	do_exec_pty(ಸಂರಚನಾ ssh *, Session *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	do_exec_no_pty(ಸಂರಚನಾ ssh *, Session *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	do_exec(ಸಂರಚನಾ ssh *, Session *, ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ	do_login(ಸಂರಚನಾ ssh *, Session *, ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ	do_child(ಸಂರಚನಾ ssh *, Session *, ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ	do_motd(ಶೂನ್ಯ);
ಪೂರ್ಣಾಙ್ಕ	check_quietlogin(Session *, ಧ್ರುವ ವರ್ಣ *);

ಸ್ಥಿರ ಶೂನ್ಯ do_authenticated2(ಸಂರಚನಾ ssh *, Authctxt *);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ session_pty_req(ಸಂರಚನಾ ssh *, Session *);

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ವರ್ಣ *__progname;
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ debug_flag;
ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *loginmsg;
ಬಾಹ್ಯ ಸಂರಚನಾ sshauthopt *auth_opts;
ಬಾಹ್ಯ ವರ್ಣ *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
ಧ್ರುವ ವರ್ಣ *original_command = ರಿಕ್ತ;

/* data */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sessions_first_unused = -1;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sessions_nalloc = 0;
ಸ್ಥಿರ Session *sessions = ರಿಕ್ತ;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ is_child = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
ಸ್ಥಿರ ವರ್ಣ *auth_info_file = ರಿಕ್ತ;

/* Name and directory of socket for authentication agent forwarding. */
ಸ್ಥಿರ ವರ್ಣ *auth_sock_name = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *auth_sock_dir = ರಿಕ್ತ; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

ಸ್ಥಿರ ಶೂನ್ಯ
auth_sock_cleanup_proc(ಸಂರಚನಾ passwd *pw)
{
	ಯದಿ (auth_sock_name != ರಿಕ್ತ) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		ಮುಕ್ತ(auth_sock_name);
		auth_sock_name = ರಿಕ್ತ;
		restore_uid();
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
auth_ಒಳಹರಿವು_request_forwarding(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *pw, ಪೂರ್ಣಾಙ್ಕ agent_new)
{
	Channel *nc;
	ಪೂರ್ಣಾಙ್ಕ sock = -1;

	ಯದಿ (auth_sock_name != ರಿಕ್ತ) {
		error("authentication forwarding requested twice.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	ಯದಿ (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		ಗಚ್ಛ authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	ಪ್ರತ್ಯಾಗಮ 1;

 authsock_err:
	ಮುಕ್ತ(auth_sock_name);
	ಯದಿ (sock != -1)
		close(sock);
	auth_sock_name = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
display_loginmsg(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (sshbuf_len(loginmsg) == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	printf("%s", (ವರ್ಣ *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

ಸ್ಥಿರ ಶೂನ್ಯ
prepare_auth_info_file(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshbuf *info)
{
	ಪೂರ್ಣಾಙ್ಕ fd = -1, success = 0;

	ಯದಿ (!options.expose_userauth_info || info == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	ಯದಿ ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		ಗಚ್ಛ out;
	}
	success = 1;
 out:
	ಯದಿ (!success) {
		ಯದಿ (fd != -1)
			close(fd);
		ಮುಕ್ತ(auth_info_file);
		auth_info_file = ರಿಕ್ತ;
	}
	restore_uid();
}

ಸ್ಥಿರ ಶೂನ್ಯ
set_fwdpermit_from_authopts(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಸಂರಚನಾ sshauthopt *opts)
{
	ವರ್ಣ *tmp, *cp, *host;
	ಪೂರ್ಣಾಙ್ಕ port;
	size_t i;

	ಯದಿ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		ಪ್ರತಿ (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			ಯದಿ ((host = hpdelim2(&cp, ರಿಕ್ತ)) == ರಿಕ್ತ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ಯದಿ (cp == ರಿಕ್ತ || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			ಮುಕ್ತ(tmp);
		}
	}
	ಯದಿ ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		ಪ್ರತಿ (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			ಯದಿ ((host = hpdelim(&cp)) == ರಿಕ್ತ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ಯದಿ (cp == ರಿಕ್ತ || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			ಮುಕ್ತ(tmp);
		}
	}
}

ಶೂನ್ಯ
do_authenticated(ಸಂರಚನಾ ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	ಯದಿ (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} ಅನ್ಯಥಾ {
		ಯದಿ ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		ಅನ್ಯಥಾ
			channel_permit_all(ssh, FORWARD_LOCAL);
		ಯದಿ ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		ಅನ್ಯಥಾ
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
xauth_valid_string(ಧ್ರುವ ವರ್ಣ *s)
{
	size_t i;

	ಪ್ರತಿ (i = 0; s[i] != '\0'; i++) {
		ಯದಿ (!isalnum((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
ಪೂರ್ಣಾಙ್ಕ
do_exec_no_pty(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	pid_t pid;
#ifdef USE_PIPES
	ಪೂರ್ಣಾಙ್ಕ pin[2], pout[2], perr[2];

	ಯದಿ (s == ರಿಕ್ತ)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	ಯದಿ (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
#ಅನ್ಯಥಾ
	ಪೂರ್ಣಾಙ್ಕ inout[2], err[2];

	ಯದಿ (s == ರಿಕ್ತ)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	ವಿಕಲ್ಪ ((pid = fork())) {
	ಪಕ್ಷ -1:
		error_f("fork: %.100s", strerror(errno));
#ifdef USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#ಅನ್ಯಥಾ
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#endif
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪಕ್ಷ 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		ಯದಿ (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		ಯದಿ (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		ಯದಿ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		ಯದಿ (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#ಅನ್ಯಥಾ
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		ಯದಿ (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		ಯದಿ (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		ಯದಿ (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	ಸ್ವಭಾವ:
		ಭಙ್ಗ;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_ಮೌಲ್ಯ);
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
#ಅನ್ಯಥಾ
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
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
ಪೂರ್ಣಾಙ್ಕ
do_exec_pty(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	ಪೂರ್ಣಾಙ್ಕ fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	ಯದಿ (s == ರಿಕ್ತ)
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
	ಯದಿ ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* we keep a reference to the pty master */
	ಯದಿ ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Fork the child. */
	ವಿಕಲ್ಪ ((pid = fork())) {
	ಪಕ್ಷ -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪಕ್ಷ 0:
		is_child = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		ಯದಿ (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		ಯದಿ (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		ಯದಿ (dup2(ttyfd, 2) == -1)
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
	ಸ್ವಭಾವ:
		ಭಙ್ಗ;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_ಮೌಲ್ಯ);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
ಪೂರ್ಣಾಙ್ಕ
do_exec(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	ಪೂರ್ಣಾಙ್ಕ ret;
	ಧ್ರುವ ವರ್ಣ *forced = ರಿಕ್ತ, *tty = ರಿಕ್ತ;
	ವರ್ಣ session_type[1024];

	ಯದಿ (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} ಅನ್ಯಥಾ ಯದಿ (auth_opts->force_command != ರಿಕ್ತ) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	ಯದಿ (forced != ರಿಕ್ತ) {
		s->forced = 1;
		ಯದಿ (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} ಅನ್ಯಥಾ ಯದಿ (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, ಪರಿಮಾಣ(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} ಅನ್ಯಥಾ ಯದಿ (s->is_subsystem) {
		snprintf(session_type, ಪರಿಮಾಣ(session_type),
		    "subsystem '%.900s'", s->subsys);
	} ಅನ್ಯಥಾ ಯದಿ (command == ರಿಕ್ತ) {
		snprintf(session_type, ಪರಿಮಾಣ(session_type), "shell");
	} ಅನ್ಯಥಾ {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, ಪರಿಮಾಣ(session_type), "command");
	}

	ಯದಿ (s->ttyfd != -1) {
		tty = s->tty;
		ಯದಿ (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == ರಿಕ್ತ ? "" : " on ",
	    tty == ರಿಕ್ತ ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	ಯದಿ (command != ರಿಕ್ತ)
		mm_audit_run_command(command);
	ಅನ್ಯಥಾ ಯದಿ (s->ttyfd == -1) {
		ವರ್ಣ *shell = s->pw->pw_shell;

		ಯದಿ (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	ಯದಿ (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	ಅನ್ಯಥಾ
		ret = do_exec_no_pty(ssh, s, command);

	original_command = ರಿಕ್ತ;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	ಪ್ರತ್ಯಾಗಮ ret;
}

/* administrative, login(1)-like work */
ಶೂನ್ಯ
do_login(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	socklen_t fromlen;
	ಸಂರಚನಾ sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, ಪರಿಮಾಣ(from));
	fromlen = ಪರಿಮಾಣ(from);
	ಯದಿ (ssh_packet_connection_is_on_socket(ssh)) {
		ಯದಿ (getpeername(ssh_packet_get_connection_in(ssh),
		    (ಸಂರಚನಾ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	ಯದಿ (check_quietlogin(s, command))
		ಪ್ರತ್ಯಾಗಮ;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
ಶೂನ್ಯ
do_motd(ಶೂನ್ಯ)
{
	FILE *f;
	ವರ್ಣ buf[256];

	ಯದಿ (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#ಅನ್ಯಥಾ
		f = fopen("/etc/motd", "r");
#endif
		ಯದಿ (f) {
			ಯಾವತ್ (fgets(buf, ಪರಿಮಾಣ(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
ಪೂರ್ಣಾಙ್ಕ
check_quietlogin(Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	ವರ್ಣ buf[256];
	ಸಂರಚನಾ passwd *pw = s->pw;
	ಸಂರಚನಾ stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	ಯದಿ (command != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 1;
	snprintf(buf, ಪರಿಮಾಣ(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	ಯದಿ (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		ಪ್ರತ್ಯಾಗಮ 1;
#ಅನ್ಯಥಾ
	ಯದಿ (stat(buf, &st) >= 0)
		ಪ್ರತ್ಯಾಗಮ 1;
#endif
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
read_environment_file(ವರ್ಣ ***env, u_int *envsize,
	ಧ್ರುವ ವರ್ಣ *filename, ಧ್ರುವ ವರ್ಣ *allowlist)
{
	FILE *f;
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ, *cp, *ಮೌಲ್ಯ;
	size_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	ಯದಿ (!f)
		ಪ್ರತ್ಯಾಗಮ;

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		ಯದಿ (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		ಪ್ರತಿ (cp = ಸಾಲು; *cp == ' ' || *cp == '\t'; cp++)
			;
		ಯದಿ (!*cp || *cp == '#' || *cp == '\n')
			ಅನುವರ್ತ;

		cp[strcspn(cp, "\n")] = '\0';

		ಮೌಲ್ಯ = strchr(cp, '=');
		ಯದಿ (ಮೌಲ್ಯ == ರಿಕ್ತ) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			ಅನುವರ್ತ;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*ಮೌಲ್ಯ = '\0';
		ಮೌಲ್ಯ++;
		ಯದಿ (allowlist != ರಿಕ್ತ &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			ಅನುವರ್ತ;
		child_set_env(env, envsize, cp, ಮೌಲ್ಯ);
	}
	ಮುಕ್ತ(ಸಾಲು);
	fclose(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
ಸ್ಥಿರ ವರ್ಣ *
child_get_env(ವರ್ಣ **env, ಧ್ರುವ ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	size_t len;

	len = strlen(name);
	ಪ್ರತಿ (i=0; env[i] != ರಿಕ್ತ; i++)
		ಯದಿ (strncmp(name, env[i], len) == 0 && env[i][len] == '=')
			ಪ್ರತ್ಯಾಗಮ(env[i] + len + 1);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
read_etc_default_login(ವರ್ಣ ***env, u_int *envsize, uid_t uid)
{
	ವರ್ಣ **tmpenv = ರಿಕ್ತ, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	ಯದಿ (tmpenv == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	ಅನ್ಯಥಾ
		var = child_get_env(tmpenv, "PATH");
	ಯದಿ (var != ರಿಕ್ತ)
		child_set_env(env, envsize, "PATH", var);

	ಯದಿ ((var = child_get_env(tmpenv, "UMASK")) != ರಿಕ್ತ)
		ಯದಿ (sscanf(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	ಪ್ರತಿ (i = 0; tmpenv[i] != ರಿಕ್ತ; i++)
		ಮುಕ್ತ(tmpenv[i]);
	ಮುಕ್ತ(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#ಯದಿ defined(USE_PAM) || defined(HAVE_CYGWIN)
ಸ್ಥಿರ ಶೂನ್ಯ
copy_environment_denylist(ವರ್ಣ **source, ವರ್ಣ ***env, u_int *envsize,
    ಧ್ರುವ ವರ್ಣ *denylist)
{
	ವರ್ಣ *var_name, *var_val;
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (source == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಪ್ರತಿ(i = 0; source[i] != ರಿಕ್ತ; i++) {
		var_name = xstrdup(source[i]);
		ಯದಿ ((var_val = strstr(var_name, "=")) == ರಿಕ್ತ) {
			ಮುಕ್ತ(var_name);
			ಅನುವರ್ತ;
		}
		*var_val++ = '\0';

		ಯದಿ (denylist == ರಿಕ್ತ ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		ಮುಕ್ತ(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
ಸ್ಥಿರ ಶೂನ್ಯ
copy_environment(ವರ್ಣ **source, ವರ್ಣ ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, ರಿಕ್ತ);
}
#endif

ಸ್ಥಿರ ವರ್ಣ **
do_setup_env(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *shell)
{
	ವರ್ಣ buf[256];
	size_t n;
	u_int i, envsize;
	ವರ್ಣ *ocp, *cp, *ಮೌಲ್ಯ, **env, *laddr;
	ಸಂರಚನಾ passwd *pw = s->pw;
#ಯದಿ !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	ವರ್ಣ *path = ರಿಕ್ತ;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, ಪರಿಮಾಣ(ವರ್ಣ *));
	env[0] = ರಿಕ್ತ;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		ವರ್ಣ **p;

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
	ಪ್ರತಿ (i = 0; i < s->ಅಂಕೆ_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	ಯದಿ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	ಅನ್ಯಥಾ
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#ಅನ್ಯಥಾ /* HAVE_LOGIN_CAP */
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
	ಯದಿ (path == ರಿಕ್ತ || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	ಯದಿ (!options.use_pam) {
		snprintf(buf, ಪರಿಮಾಣ buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	ಯದಿ (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
#ifdef HAVE_LOGIN_CAP
	ಯದಿ (getenv("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	ಯದಿ (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	ಯದಿ (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		ವರ್ಣ *cp;

		ಯದಿ ((cp = getenv("KRB5CCNAME")) != ರಿಕ್ತ)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		ವರ್ಣ *cp;

		ಯದಿ ((cp = getenv("AUTHSTATE")) != ರಿಕ್ತ)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	ಯದಿ (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	ಯದಿ (auth_sock_name != ರಿಕ್ತ)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	ಯದಿ (options.permit_user_env) {
		ಪ್ರತಿ (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			ಯದಿ (cp != ರಿಕ್ತ) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				ಯದಿ (options.permit_user_env_allowlist == ರಿಕ್ತ ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			ಮುಕ್ತ(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	ಯದಿ (options.permit_user_env) {
		snprintf(buf, ಪರಿಮಾಣ buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	ಯದಿ (options.use_pam) {
		ವರ್ಣ **p;

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
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		ಯದಿ ((ಮೌಲ್ಯ = strchr(cp, '=')) == ರಿಕ್ತ) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*ಮೌಲ್ಯ++ = '\0';
		child_set_env(&env, &envsize, cp, ಮೌಲ್ಯ);
		ಮುಕ್ತ(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, ಪರಿಮಾಣ buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, ಪರಿಮಾಣ buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	ಮುಕ್ತ(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	ಯದಿ (tun_fwd_ifnames != ರಿಕ್ತ)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	ಯದಿ (auth_info_file != ರಿಕ್ತ)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	ಯದಿ (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	ಯದಿ (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	ಯದಿ (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		ಪ್ರತಿ (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	ಪ್ರತ್ಯಾಗಮ env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
do_rc_files(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *shell)
{
	FILE *f = ರಿಕ್ತ;
	ವರ್ಣ *cmd = ರಿಕ್ತ, *user_rc = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ do_xauth;
	ಸಂರಚನಾ stat st;

	do_xauth =
	    s->display != ರಿಕ್ತ && s->auth_proto != ರಿಕ್ತ && s->auth_data != ರಿಕ್ತ;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	ಯದಿ (!s->is_subsystem && options.adm_forced_command == ರಿಕ್ತ &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		ಯದಿ (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		ಯದಿ (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		ಯದಿ (f) {
			ಯದಿ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} ಅನ್ಯಥಾ
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} ಅನ್ಯಥಾ ಯದಿ (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		ಯದಿ (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		ಯದಿ (f) {
			ಯದಿ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} ಅನ್ಯಥಾ
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} ಅನ್ಯಥಾ ಯದಿ (do_xauth && options.xauth_location != ರಿಕ್ತ) {
		/* Add authority data to .Xauthority if appropriate. */
		ಯದಿ (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		ಯದಿ (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		ಯದಿ (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} ಅನ್ಯಥಾ {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	ಮುಕ್ತ(cmd);
	ಮುಕ್ತ(user_rc);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_nologin(ಸಂರಚನಾ passwd *pw)
{
	FILE *f = ರಿಕ್ತ;
	ವರ್ಣ buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	ಸಂರಚನಾ stat sb;

#ifdef HAVE_LOGIN_CAP
	ಯದಿ (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		ಪ್ರತ್ಯಾಗಮ;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#ಅನ್ಯಥಾ
	ಯದಿ (pw->pw_uid == 0)
		ಪ್ರತ್ಯಾಗಮ;
	nl = def_nl;
#endif
	ಯದಿ (stat(nl, &sb) == -1)
		ಪ್ರತ್ಯಾಗಮ;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	ಯದಿ ((f = fopen(nl, "r")) != ರಿಕ್ತ) {
		ಯಾವತ್ (fgets(buf, ಪರಿಮಾಣ(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
safely_chroot(ಧ್ರುವ ವರ್ಣ *path, uid_t uid)
{
	ಧ್ರುವ ವರ್ಣ *cp;
	ವರ್ಣ component[PATH_MAX];
	ಸಂರಚನಾ stat st;

	ಯದಿ (!path_absolute(path))
		fatal("chroot path does not begin at root");
	ಯದಿ (strlen(path) >= ಪರಿಮಾಣ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ಪ್ರತಿ (cp = path; cp != ರಿಕ್ತ;) {
		ಯದಿ ((cp = strchr(cp, '/')) == ರಿಕ್ತ)
			strlcpy(component, path, ಪರಿಮಾಣ(component));
		ಅನ್ಯಥಾ {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		ಯದಿ (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		ಯದಿ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ರಿಕ್ತ ? "" : "component ", component);
		ಯದಿ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ರಿಕ್ತ ? "" : "component ", component);

	}

	ಯದಿ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	ಯದಿ (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	ಯದಿ (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
ಶೂನ್ಯ
do_setusercontext(ಸಂರಚನಾ passwd *pw)
{
	ವರ್ಣ uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	ಯದಿ (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		ಯದಿ (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			exit(1);
		}
#ಅನ್ಯಥಾ
		ಯದಿ (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		ಯದಿ (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			exit(1);
		}
		/* Initialize the group list. */
		ಯದಿ (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			exit(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		ಯದಿ (!in_chroot && options.chroot_directory != ರಿಕ್ತ &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, ಪರಿಮಾಣ(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (ವರ್ಣ *)ರಿಕ್ತ);
			safely_chroot(chroot_path, pw->pw_uid);
			ಮುಕ್ತ(tmp);
			ಮುಕ್ತ(chroot_path);
			/* Make sure we don't attempt to chroot again */
			ಮುಕ್ತ(options.chroot_directory);
			options.chroot_directory = ರಿಕ್ತ;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		ಯದಿ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			exit(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(ಶೂನ್ಯ) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#ಅನ್ಯಥಾ
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		ಯದಿ (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} ಅನ್ಯಥಾ ಯದಿ (options.chroot_directory != ರಿಕ್ತ &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	ಯದಿ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_pwchange(Session *s)
{
	fflush(ರಿಕ್ತ);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	ಯದಿ (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(ರಿಕ್ತ);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (ವರ್ಣ *)ರಿಕ್ತ);
#ಅನ್ಯಥಾ
		execl(_PATH_PASSWD_PROG, "passwd", (ವರ್ಣ *)ರಿಕ್ತ);
#endif
		perror("passwd");
	} ಅನ್ಯಥಾ {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	exit(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
child_close_fds(ಸಂರಚನಾ ssh *ssh)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ auth_sock;

	ಯದಿ (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	ಯದಿ (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	ಅನ್ಯಥಾ {
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
	log_redirect_stderr_to(ರಿಕ್ತ);

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
ಶೂನ್ಯ
do_child(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	ಬಾಹ್ಯ ವರ್ಣ **environ;
	ವರ್ಣ **env, *argv[ARGV_MAX], remote_id[512];
	ಧ್ರುವ ವರ್ಣ *shell, *shell0;
	ಸಂರಚನಾ passwd *pw = s->pw;
	ಪೂರ್ಣಾಙ್ಕ r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, ಪರಿಮಾಣ(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_ಕೀಲಿಗಳು(ssh);

	/* Force a password change */
	ಯದಿ (s->authctxt->force_pwchange) {
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
	session_setup_sia(pw, s->ttyfd == -1 ? ರಿಕ್ತ : s->tty);
	ಯದಿ (!check_quietlogin(s, command))
		do_motd();
#ಅನ್ಯಥಾ /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	ಯದಿ (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	ಯದಿ (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	ಯದಿ (options.use_pam && !is_pam_session_open()) {
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
	shell = login_getcapstr(lc, "shell", (ವರ್ಣ *)shell, (ವರ್ಣ *)shell);
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

#ಯದಿ defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	ಯದಿ (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != ರಿಕ್ತ)) {
		ವರ್ಣ cell[64];

		debug("Getting AFS token");

		k_setpag();

		ಯದಿ (k_afs_cell_of_file(pw->pw_dir, cell, ಪರಿಮಾಣ(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, ರಿಕ್ತ);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, ರಿಕ್ತ, ರಿಕ್ತ, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	ಯದಿ (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		ಯದಿ (r || !in_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		ಯದಿ (r)
			exit(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	ಯದಿ (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(ರಿಕ್ತ);
		exit(1);
	} ಅನ್ಯಥಾ ಯದಿ (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind, optreset;
		ಪೂರ್ಣಾಙ್ಕ sftp_argc;
		ವರ್ಣ **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		ಯದಿ (argv_split(command == ರಿಕ್ತ ? "sftp-server" : command,
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

	fflush(ರಿಕ್ತ);

	/* Get the last component of the shell name. */
	ಯದಿ ((shell0 = strrchr(shell, '/')) != ರಿಕ್ತ)
		shell0++;
	ಅನ್ಯಥಾ
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	ಯದಿ (!command) {
		ವರ್ಣ argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		ಯದಿ (strlcpy(argv0 + 1, shell0, ಪರಿಮಾಣ(argv0) - 1)
		    >= ಪರಿಮಾಣ(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = ರಿಕ್ತ;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (ವರ್ಣ *) shell0;
	argv[1] = "-c";
	argv[2] = (ವರ್ಣ *) command;
	argv[3] = ರಿಕ್ತ;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

ಶೂನ್ಯ
session_unused(ಪೂರ್ಣಾಙ್ಕ id)
{
	debug3_f("session id %d unused", id);
	ಯದಿ (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, ಪರಿಮಾಣ(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = ರಿಕ್ತ;
	sessions[id].next_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(ಶೂನ್ಯ)
{
	Session *s, *tmp;

	ಯದಿ (sessions_first_unused == -1) {
		ಯದಿ (sessions_nalloc >= options.max_sessions)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, ಪರಿಮಾಣ(*sessions));
		ಯದಿ (tmp == ರಿಕ್ತ) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	ಯದಿ (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	ಯದಿ (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->next_unused;
	s->used = 1;
	s->next_unused = -1;
	debug("session_new: session %d", s->self);

	ಪ್ರತ್ಯಾಗಮ s;
}

ಸ್ಥಿರ ಶೂನ್ಯ
session_dump(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < sessions_nalloc; i++) {
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

ಪೂರ್ಣಾಙ್ಕ
session_open(Authctxt *authctxt, ಪೂರ್ಣಾಙ್ಕ chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	ಯದಿ (s == ರಿಕ್ತ) {
		error("no more sessions");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	ಯದಿ (s->pw == ರಿಕ್ತ || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	ಪ್ರತ್ಯಾಗಮ 1;
}

Session *
session_by_tty(ವರ್ಣ *tty)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಯದಿ (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			ಪ್ರತ್ಯಾಗಮ s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ Session *
session_by_channel(ಪೂರ್ಣಾಙ್ಕ id)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಯದಿ (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			ಪ್ರತ್ಯಾಗಮ s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ Session *
session_by_x11_channel(ಪೂರ್ಣಾಙ್ಕ id)
{
	ಪೂರ್ಣಾಙ್ಕ i, j;

	ಪ್ರತಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		ಯದಿ (s->x11_chanids == ರಿಕ್ತ || !s->used)
			ಅನುವರ್ತ;
		ಪ್ರತಿ (j = 0; s->x11_chanids[j] != -1; j++) {
			ಯದಿ (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				ಪ್ರತ್ಯಾಗಮ s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ Session *
session_by_pid(pid_t pid)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	debug("session_by_pid: pid %ld", (long)pid);
	ಪ್ರತಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಯದಿ (s->used && s->pid == pid)
			ಪ್ರತ್ಯಾಗಮ s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_window_change_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_pty_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &s->term, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ಯದಿ (strcmp(s->term, "") == 0) {
		ಮುಕ್ತ(s->term);
		s->term = ರಿಕ್ತ;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	ಯದಿ (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, ಪರಿಮಾಣ(s->tty))) {
		ಮುಕ್ತ(s->term);
		s->term = ರಿಕ್ತ;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_subsystem_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ r, success = 0, found = 0;
	ವರ್ಣ *prog, *cmd, *type;
	u_int i;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &s->subsys, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_subsystems; i++) {
		ಯದಿ (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			ಅನುವರ್ತ;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		ಯದಿ (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} ಅನ್ಯಥಾ {
			ಯದಿ (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		ಮುಕ್ತ(type);
		success = do_exec(ssh, s, cmd) == 0;
		ಭಙ್ಗ;
	}

	ಯದಿ (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	ಪ್ರತ್ಯಾಗಮ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_x11_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಙ್ಕ r, success;
	u_char single_connection = 0;

	ಯದಿ (s->auth_proto != ರಿಕ್ತ || s->auth_data != ರಿಕ್ತ) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_data, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	ಯದಿ (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_data))
		success = session_setup_x11fwd(ssh, s);
	ಅನ್ಯಥಾ {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	ಯದಿ (!success) {
		ಮುಕ್ತ(s->auth_proto);
		ಮುಕ್ತ(s->auth_data);
		s->auth_proto = ರಿಕ್ತ;
		s->auth_data = ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_shell_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	ಪ್ರತ್ಯಾಗಮ do_exec(ssh, s, ರಿಕ್ತ) == 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_exec_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	u_int success;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *command = ರಿಕ್ತ;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &command, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	ಮುಕ್ತ(command);
	ಪ್ರತ್ಯಾಗಮ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_break_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_get_u32(ssh, ರಿಕ್ತ)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ಯದಿ (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_env_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ವರ್ಣ *name, *val;
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &name, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	ಯದಿ (s->ಅಂಕೆ_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		ಗಚ್ಛ fail;
	}

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_accept_env; i++) {
		ಯದಿ (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->ಅಂಕೆ_env, name, val);
			s->env = xrecallocarray(s->env, s->ಅಂಕೆ_env,
			    s->ಅಂಕೆ_env + 1, ಪರಿಮಾಣ(*s->env));
			s->env[s->ಅಂಕೆ_env].name = name;
			s->env[s->ಅಂಕೆ_env].val = val;
			s->ಅಂಕೆ_env++;
			ಪ್ರತ್ಯಾಗಮ (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	ಮುಕ್ತ(name);
	ಮುಕ್ತ(val);
	ಪ್ರತ್ಯಾಗಮ (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
name2sig(ವರ್ಣ *name)
{
#define SSH_SIG(x) ಯದಿ (strcmp(name, #x) == 0) ಪ್ರತ್ಯಾಗಮ SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	ಯದಿ (strcmp(name, "INFO@openssh.com") == 0)
		ಪ್ರತ್ಯಾಗಮ SIGINFO;
#endif
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_signal_req(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ವರ್ಣ *signame = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, sig, success = 0;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &signame, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		ಗಚ್ಛ out;
	}
	ಯದಿ (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		ಗಚ್ಛ out;
	}
	ಯದಿ (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		ಗಚ್ಛ out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (long)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	ಯದಿ (r != 0) {
		error_f("killpg(%ld, %d): %s", (long)s->pid,
		    sig, strerror(errno));
		ಗಚ್ಛ out;
	}

	/* success */
	success = 1;
 out:
	ಮುಕ್ತ(signame);
	ಪ್ರತ್ಯಾಗಮ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
session_auth_agent_req(ಸಂರಚನಾ ssh *ssh, Session *s, ಪೂರ್ಣಾಙ್ಕ agent_new)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ called = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ಯದಿ (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (called)
		ಪ್ರತ್ಯಾಗಮ 0;

	called = 1;
	ಪ್ರತ್ಯಾಗಮ auth_ಒಳಹರಿವು_request_forwarding(ssh, s->pw, agent_new);
}

ಪೂರ್ಣಾಙ್ಕ
session_ಒಳಹರಿವು_channel_req(ಸಂರಚನಾ ssh *ssh, Channel *c, ಧ್ರುವ ವರ್ಣ *rtype)
{
	ಪೂರ್ಣಾಙ್ಕ success = 0;
	Session *s;

	ಯದಿ ((s = session_by_channel(c->self)) == ರಿಕ್ತ) {
		logit_f("no session %d req %.100s", c->self, rtype);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	ಯದಿ (c->type == SSH_CHANNEL_LARVAL) {
		ಯದಿ (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	ಯದಿ (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	ಪ್ರತ್ಯಾಗಮ success;
}

ಶೂನ್ಯ
session_set_fds(ಸಂರಚನಾ ssh *ssh, Session *s,
    ಪೂರ್ಣಾಙ್ಕ fdin, ಪೂರ್ಣಾಙ್ಕ fdout, ಪೂರ್ಣಾಙ್ಕ fderr, ಪೂರ್ಣಾಙ್ಕ ignore_fderr, ಪೂರ್ಣಾಙ್ಕ is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	ಯದಿ (s->chanid == -1)
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
ಶೂನ್ಯ
session_pty_cleanup2(Session *s)
{
	ಯದಿ (s == ರಿಕ್ತ) {
		error_f("no session");
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (s->ttyfd == -1)
		ಪ್ರತ್ಯಾಗಮ;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	ಯದಿ (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	ಯದಿ (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	ಯದಿ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

ಶೂನ್ಯ
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

ಸ್ಥಿರ ವರ್ಣ *
sig2name(ಪೂರ್ಣಾಙ್ಕ sig)
{
#define SSH_SIG(x) ಯದಿ (sig == SIG ## x) ಪ್ರತ್ಯಾಗಮ #x
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
	ಪ್ರತ್ಯಾಗಮ "SIG@openssh.com";
}

ಸ್ಥಿರ ಶೂನ್ಯ
session_close_x11(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id)
{
	Channel *c;

	ಯದಿ ((c = channel_by_id(ssh, id)) == ರಿಕ್ತ) {
		debug_f("x11 channel %d missing", id);
	} ಅನ್ಯಥಾ {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		ಯದಿ (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
session_close_single_x11(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ force, ಶೂನ್ಯ *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	ಯದಿ ((s = session_by_x11_channel(id)) == ರಿಕ್ತ)
		fatal_f("no x11 channel %d", id);
	ಪ್ರತಿ (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		ಯದಿ (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	ಮುಕ್ತ(s->x11_chanids);
	s->x11_chanids = ರಿಕ್ತ;
	ಮುಕ್ತ(s->display);
	s->display = ರಿಕ್ತ;
	ಮುಕ್ತ(s->auth_proto);
	s->auth_proto = ರಿಕ್ತ;
	ಮುಕ್ತ(s->auth_data);
	s->auth_data = ರಿಕ್ತ;
	ಮುಕ್ತ(s->auth_display);
	s->auth_display = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
session_exit_message(ಸಂರಚನಾ ssh *ssh, Session *s, ಪೂರ್ಣಾಙ್ಕ status)
{
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *note = ರಿಕ್ತ;

	ಯದಿ ((c = channel_lookup(ssh, s->chanid)) == ರಿಕ್ತ)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	ಯದಿ (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		ಯದಿ ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} ಅನ್ಯಥಾ ಯದಿ (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		ಯದಿ ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} ಅನ್ಯಥಾ {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (long)s->pid, note == ರಿಕ್ತ ? "UNKNOWN" : note);
	ಮುಕ್ತ(note);

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
	ಯದಿ (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

ಶೂನ್ಯ
session_close(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	ಯದಿ (s->ttyfd != -1)
		session_pty_cleanup(s);
	ಮುಕ್ತ(s->term);
	ಮುಕ್ತ(s->display);
	ಮುಕ್ತ(s->x11_chanids);
	ಮುಕ್ತ(s->auth_display);
	ಮುಕ್ತ(s->auth_data);
	ಮುಕ್ತ(s->auth_proto);
	ಮುಕ್ತ(s->subsys);
	ಯದಿ (s->env != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; i < s->ಅಂಕೆ_env; i++) {
			ಮುಕ್ತ(s->env[i].name);
			ಮುಕ್ತ(s->env[i].val);
		}
		ಮುಕ್ತ(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

ಶೂನ್ಯ
session_close_by_pid(ಸಂರಚನಾ ssh *ssh, pid_t pid, ಪೂರ್ಣಾಙ್ಕ status)
{
	Session *s = session_by_pid(pid);
	ಯದಿ (s == ರಿಕ್ತ) {
		debug_f("no session for pid %ld", (long)pid);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (s->chanid != -1)
		session_exit_message(ssh, s, status);
	ಯದಿ (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
ಶೂನ್ಯ
session_close_by_channel(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ force, ಶೂನ್ಯ *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	ಯದಿ (s == ರಿಕ್ತ) {
		debug_f("no session for id %d", id);
		ಪ್ರತ್ಯಾಗಮ;
	}
	debug_f("channel %d child %ld", id, (long)s->pid);
	ಯದಿ (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		ಯದಿ (s->ttyfd != -1)
			session_pty_cleanup(s);
		ಯದಿ (!force)
			ಪ್ರತ್ಯಾಗಮ;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	ಯದಿ (s->x11_chanids != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

ಶೂನ್ಯ
session_destroy_all(ಸಂರಚನಾ ssh *ssh, ಶೂನ್ಯ (*closefunc)(Session *))
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಯದಿ (s->used) {
			ಯದಿ (closefunc != ರಿಕ್ತ)
				closefunc(s);
			ಅನ್ಯಥಾ
				session_close(ssh, s);
		}
	}
}

ಸ್ಥಿರ ವರ್ಣ *
session_tty_list(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ವರ್ಣ buf[1024];
	ಪೂರ್ಣಾಙ್ಕ i;
	ವರ್ಣ *cp;

	buf[0] = '\0';
	ಪ್ರತಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಯದಿ (s->used && s->ttyfd != -1) {

			ಯದಿ (strncmp(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == ರಿಕ್ತ) ? s->tty : cp + 1;
			} ಅನ್ಯಥಾ
				cp = s->tty + 5;

			ಯದಿ (buf[0] != '\0')
				strlcat(buf, ",", ಪರಿಮಾಣ buf);
			strlcat(buf, cp, ಪರಿಮಾಣ buf);
		}
	}
	ಯದಿ (buf[0] == '\0')
		strlcpy(buf, "notty", ಪರಿಮಾಣ buf);
	ಪ್ರತ್ಯಾಗಮ buf;
}

ಶೂನ್ಯ
session_proctitle(Session *s)
{
	ಯದಿ (s->pw == ರಿಕ್ತ)
		error("no user for session %d", s->self);
	ಅನ್ಯಥಾ
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

ಪೂರ್ಣಾಙ್ಕ
session_setup_x11fwd(ಸಂರಚನಾ ssh *ssh, Session *s)
{
	ಸಂರಚನಾ stat st;
	ವರ್ಣ display[512], auth_display[512];
	ವರ್ಣ hostname[NI_MAXHOST];
	u_int i;

	ಯದಿ (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (options.xauth_location == ರಿಕ್ತ ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (s->display != ರಿಕ್ತ) {
		debug("X11 display already set.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_ಸಂಖ್ಯೆ, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತಿ (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	ಯದಿ (gethostname(hostname, ಪರಿಮಾಣ(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	ಯದಿ (options.x11_use_localhost) {
		snprintf(display, ಪರಿಮಾಣ display, "localhost:%u.%u",
		    s->display_ಸಂಖ್ಯೆ, s->screen);
		snprintf(auth_display, ಪರಿಮಾಣ auth_display, "unix:%u.%u",
		    s->display_ಸಂಖ್ಯೆ, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} ಅನ್ಯಥಾ {
#ifdef IPADDR_IN_DISPLAY
		ಸಂರಚನಾ hostent *he;
		ಸಂರಚನಾ in_addr my_addr;

		he = gethostbyname(hostname);
		ಯದಿ (he == ರಿಕ್ತ) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], ಪರಿಮಾಣ(ಸಂರಚನಾ in_addr));
		snprintf(display, ಪರಿಮಾಣ display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_ಸಂಖ್ಯೆ, s->screen);
#ಅನ್ಯಥಾ
		snprintf(display, ಪರಿಮಾಣ display, "%.400s:%u.%u", hostname,
		    s->display_ಸಂಖ್ಯೆ, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_authenticated2(ಸಂರಚನಾ ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

ಶೂನ್ಯ
do_cleanup(ಸಂರಚನಾ ssh *ssh, Authctxt *authctxt)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	ಯದಿ (is_child)
		ಪ್ರತ್ಯಾಗಮ;

	/* avoid double cleanup */
	ಯದಿ (called)
		ಪ್ರತ್ಯಾಗಮ;
	called = 1;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

#ifdef USE_PAM
	ಯದಿ (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	ಯದಿ (!authctxt->authenticated)
		ಪ್ರತ್ಯಾಗಮ;

#ifdef KRB5
	ಯದಿ (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	ಯದಿ (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	ಯದಿ (auth_info_file != ರಿಕ್ತ) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		ಮುಕ್ತ(auth_info_file);
		auth_info_file = ರಿಕ್ತ;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	ಯದಿ (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

ಧ್ರುವ ವರ್ಣ *
session_get_remote_name_or_ip(ಸಂರಚನಾ ssh *ssh, u_int utmp_size, ಪೂರ್ಣಾಙ್ಕ use_dns)
{
	ಧ್ರುವ ವರ್ಣ *remote = "";

	ಯದಿ (utmp_size > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	ಯದಿ (utmp_size == 0 || strlen(remote) > utmp_size)
		remote = ssh_remote_ipaddr(ssh);
	ಪ್ರತ್ಯಾಗಮ remote;
}

