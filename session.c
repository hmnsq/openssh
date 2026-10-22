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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"

#ಆದರೆ defined(KRB5) && defined(USE_AFS)
#ಅನ್ತರ್ಭಾವ <kafs.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
#ಅನ್ತರ್ಭಾವ <selinux/selinux.h>
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Hack for systems that do not support FD passing: allocate PTYs directly
 * without calling into the monitor. This requires either the post-auth
 * privsep process retain root privileges (see the comment in
 * sshd-session.c:privsep_postauth) or that PTY allocation doesn't require
 * privileges to begin with (e.g. Cygwin).
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DISABLE_FD_PASSING
#ವ್ಯಾಖ್ಯಾನಿಸು mm_pty_allocate pty_allocate
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು IS_ಆಂತರಿಕ_SFTP(c) \
	(!ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(c, ಆಂತರಿಕ_SFTP_NAME, ಗಾತ್ರ(ಆಂತರಿಕ_SFTP_NAME) - 1) && \
	 (c[ಗಾತ್ರ(ಆಂತರಿಕ_SFTP_NAME) - 1] == '\0' || \
	  c[ಗಾತ್ರ(ಆಂತರಿಕ_SFTP_NAME) - 1] == ' ' || \
	  c[ಗಾತ್ರ(ಆಂತರಿಕ_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(ಶೂನ್ಯ);
ಶೂನ್ಯ	session_ಗಣ_fds(ರಚನೆ ssh *, Session *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	session_pty_cleanup(Session *);
ಶೂನ್ಯ	session_proctitle(Session *);
ಪೂರ್ಣಾಂಕ	session_ಸಿದ್ಧತೆ_x11fwd(ರಚನೆ ssh *, Session *);
ಪೂರ್ಣಾಂಕ	do_exec_pty(ರಚನೆ ssh *, Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	do_exec_no_pty(ರಚನೆ ssh *, Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	do_exec(ರಚನೆ ssh *, Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	do_login(ರಚನೆ ssh *, Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	do_ಮಗು(ರಚನೆ ssh *, Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	do_motd(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ	check_quietlogin(Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಸ್ಥಿರ ಶೂನ್ಯ do_authenticated2(ರಚನೆ ssh *, Authctxt *);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ session_pty_req(ರಚನೆ ssh *, Session *);

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ debug_flag;
ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;
ಬಾಹ್ಯ ರಚನೆ sshauthopt *auth_opts;
ಬಾಹ್ಯ ಅಕ್ಷರ *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_command = ಖಾಲಿ;

/*ದತ್ತಾಂಶ*/
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sessions_ಮೊದಲ_ಬಳಸದ = -1;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sessions_nalloc = 0;
ಸ್ಥಿರ Session *sessions = ಖಾಲಿ;

#ವ್ಯಾಖ್ಯಾನಿಸು SUBSYSTEM_NONE			0
#ವ್ಯಾಖ್ಯಾನಿಸು SUBSYSTEM_EXT			1
#ವ್ಯಾಖ್ಯಾನಿಸು SUBSYSTEM_INT_SFTP		2
#ವ್ಯಾಖ್ಯಾನಿಸು SUBSYSTEM_INT_SFTP_ERROR	3

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
login_cap_t *lc;
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ is_ಮಗು = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳ_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
ಸ್ಥಿರ ಅಕ್ಷರ *auth_info_file = ಖಾಲಿ;

/* Name and directory of socket for authentication agent forwarding. */
ಸ್ಥಿರ ಅಕ್ಷರ *auth_sock_name = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *auth_sock_dir = ಖಾಲಿ; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

ಸ್ಥಿರ ಶೂನ್ಯ
auth_sock_cleanup_proc(ರಚನೆ passwd *pw)
{
	ಆದರೆ (auth_sock_name != ಖಾಲಿ) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_ಮಾರ್ಗ,
		    auth_sock_name, auth_sock_dir);
		ಬಿಡುಗಡೆ(auth_sock_name);
		auth_sock_name = ಖಾಲಿ;
		restore_uid();
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
auth_ಒಳಹರಿವು_request_forwarding(ರಚನೆ ssh *ssh, ರಚನೆ passwd *pw, ಪೂರ್ಣಾಂಕ agent_new)
{
	Channel *nc;
	ಪೂರ್ಣಾಂಕ sock = -1;

	ಆದರೆ (auth_sock_name != ಖಾಲಿ) {
		error("authentication forwarding requested twice.");
		ಹಿಂತಿರುಗಿ 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	ಆದರೆ (agent_listener(options.agent_socket_ಮಾರ್ಗ, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		ಹೋಗು authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_ಕಿಟಕಿ_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->ಮಾರ್ಗ = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	ಹಿಂತಿರುಗಿ 1;

 authsock_err:
	ಬಿಡುಗಡೆ(auth_sock_name);
	ಆದರೆ (sock != -1)
		close(sock);
	auth_sock_name = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
display_loginmsg(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (sshbuf_len(loginmsg) == 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	ಬರೆ("%s", (ಅಕ್ಷರ *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

ಸ್ಥಿರ ಶೂನ್ಯ
prepare_auth_info_file(ರಚನೆ passwd *pw, ರಚನೆ sshbuf *info)
{
	ಪೂರ್ಣಾಂಕ fd = -1, success = 0;

	ಆದರೆ (!options.expose_userauth_info || info == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	ಆದರೆ ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	success = 1;
 ಹೊರಹೋಗು:
	ಆದರೆ (!success) {
		ಆದರೆ (fd != -1)
			close(fd);
		ಬಿಡುಗಡೆ(auth_info_file);
		auth_info_file = ಖಾಲಿ;
	}
	restore_uid();
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಗಣ_fwdpermit_from_authopts(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *opts)
{
	ಅಕ್ಷರ *tmp, *cp, *host;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್;
	ಗಾತ್ರ_t i;

	ಆದರೆ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		ಗಾಗಿ (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			ಆದರೆ ((host = hpdelim2(&cp, ಖಾಲಿ)) == ಖಾಲಿ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ಆದರೆ (cp == ಖಾಲಿ || (ಪೋರ್ಟ್ = permitopen_ಪೋರ್ಟ್(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_ಕೂಡಿಸು_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, ಪೋರ್ಟ್);
			ಬಿಡುಗಡೆ(tmp);
		}
	}
	ಆದರೆ ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		ಗಾಗಿ (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			ಆದರೆ ((host = hpdelim(&cp)) == ಖಾಲಿ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ಆದರೆ (cp == ಖಾಲಿ || (ಪೋರ್ಟ್ = permitopen_ಪೋರ್ಟ್(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_ಕೂಡಿಸು_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, ಪೋರ್ಟ್);
			ಬಿಡುಗಡೆ(tmp);
		}
	}
}

ಶೂನ್ಯ
do_authenticated(ರಚನೆ ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	ಗಣ_fwdpermit_from_authopts(ssh, auth_opts);

	ಆದರೆ (!auth_opts->permit_ಪೋರ್ಟ್_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		ಇಲ್ಲದಿದ್ದರೆ
			channel_permit_all(ssh, FORWARD_LOCAL);
		ಆದರೆ ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		ಇಲ್ಲದಿದ್ದರೆ
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
xauth_valid_string(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; s[i] != '\0'; i++) {
		ಆದರೆ (!ಅಕ್ಷರವೇ_ಅಂಕಿಯೇ((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ 1;
}

#ವ್ಯಾಖ್ಯಾನಿಸು USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
ಪೂರ್ಣಾಂಕ
do_exec_no_pty(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	pid_t pid;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
	ಪೂರ್ಣಾಂಕ pin[2], pout[2], perr[2];

	ಆದರೆ (s == ಖಾಲಿ)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	ಆದರೆ (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		ಹಿಂತಿರುಗಿ -1;
	}
#ಇಲ್ಲದಿದ್ದರೆ
	ಪೂರ್ಣಾಂಕ inout[2], err[2];

	ಆದರೆ (s == ಖಾಲಿ)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		ಹಿಂತಿರುಗಿ -1;
	}
#ಆದರೆ_ಅಂತ್ಯ

	session_proctitle(s);

	/* Fork the child. */
	ಆಯ್ಕೆ ((pid = fork())) {
	ಸ್ಥಿತಿ -1:
		error_f("fork: %.100s", strerror(errno));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#ಇಲ್ಲದಿದ್ದರೆ
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#ಆದರೆ_ಅಂತ್ಯ
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಥಿತಿ 0:
		is_ಮಗು = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		ಆದರೆ (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		ಆದರೆ (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		ಆದರೆ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		ಆದರೆ (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#ಇಲ್ಲದಿದ್ದರೆ
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		ಆದರೆ (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		ಆದರೆ (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		ಆದರೆ (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#ಆದರೆ_ಅಂತ್ಯ

		/* Do processing for the child (exec command etc). */
		do_ಮಗು(ssh, s, command);
		/* NOTREACHED */
	ಪೂರ್ವನಿಯೋಜಿತ:
		ನಿಲ್ಲಿಸು;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	cygwin_ಗಣ_impersonation_token(INVALID_HANDLE_ಮೌಲ್ಯ);
#ಆದರೆ_ಅಂತ್ಯ

	s->pid = pid;

	/*
	 * Clear loginmsg, since it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
	/* We are the parent.  Close the child sides of the pipes. */
	close(pin[0]);
	close(pout[1]);
	close(perr[1]);

	session_ಗಣ_fds(ssh, s, pin[1], pout[0], perr[0],
	    s->is_subsystem, 0);
#ಇಲ್ಲದಿದ್ದರೆ
	/* We are the parent.  Close the child sides of the socket pairs. */
	close(inout[0]);
	close(err[0]);

	/*
	 * Enter the interactive session.  Note: server_loop must be able to
	 * handle the case that fdin and fdout are the same.
	 */
	session_ಗಣ_fds(ssh, s, inout[1], inout[1], err[1],
	    s->is_subsystem, 0);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
ಪೂರ್ಣಾಂಕ
do_exec_pty(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	ಪೂರ್ಣಾಂಕ fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	ಆದರೆ (s == ಖಾಲಿ)
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
	ಆದರೆ ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		ಹಿಂತಿರುಗಿ -1;
	}
	/* we keep a reference to the pty master */
	ಆದರೆ ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Fork the child. */
	ಆಯ್ಕೆ ((pid = fork())) {
	ಸ್ಥಿತಿ -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಥಿತಿ 0:
		is_ಮಗು = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		ಆದರೆ (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		ಆದರೆ (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		ಆದರೆ (dup2(ttyfd, 2) == -1)
			error("dup2 stderr: %s", strerror(errno));

		/* Close the extra descriptor for the pseudo tty. */
		close(ttyfd);

		/* record login, etc. similar to login(1) */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_OSF_SIA
		do_login(ssh, s, command);
#ಆದರೆ_ಅಂತ್ಯ
		/*
		 * Do common processing for the child, such as execing
		 * the command.
		 */
		do_ಮಗು(ssh, s, command);
		/* NOTREACHED */
	ಪೂರ್ವನಿಯೋಜಿತ:
		ನಿಲ್ಲಿಸು;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	cygwin_ಗಣ_impersonation_token(INVALID_HANDLE_ಮೌಲ್ಯ);
#ಆದರೆ_ಅಂತ್ಯ

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_ಗಣ_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
ಪೂರ್ಣಾಂಕ
do_exec(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	ಪೂರ್ಣಾಂಕ ret;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *forced = ಖಾಲಿ, *tty = ಖಾಲಿ;
	ಅಕ್ಷರ session_type[1024];

	ಆದರೆ (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (auth_opts->force_command != ಖಾಲಿ) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	ಆದರೆ (forced != ಖಾಲಿ) {
		s->forced = 1;
		ಆದರೆ (IS_ಆಂತರಿಕ_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, ಗಾತ್ರ(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (s->is_subsystem) {
		snprintf(session_type, ಗಾತ್ರ(session_type),
		    "subsystem '%.900s'", s->subsys);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (command == ಖಾಲಿ) {
		snprintf(session_type, ಗಾತ್ರ(session_type), "shell");
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, ಗಾತ್ರ(session_type), "command");
	}

	ಆದರೆ (s->ttyfd != -1) {
		tty = s->tty;
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == ಖಾಲಿ ? "" : " on ",
	    tty == ಖಾಲಿ ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_ಪೋರ್ಟ್(ssh),
	    s->self);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
	ಆದರೆ (command != ಖಾಲಿ)
		mm_audit_ಸತತ_command(command);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (s->ttyfd == -1) {
		ಅಕ್ಷರ *shell = s->pw->pw_shell;

		ಆದರೆ (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_ಸತತ_command(shell);
	}
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	ಇಲ್ಲದಿದ್ದರೆ
		ret = do_exec_no_pty(ssh, s, command);

	original_command = ಖಾಲಿ;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	ಹಿಂತಿರುಗಿ ret;
}

/* administrative, login(1)-like work */
ಶೂನ್ಯ
do_login(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	socklen_t fromlen;
	ರಚನೆ sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, ಗಾತ್ರ(from));
	fromlen = ಗಾತ್ರ(from);
	ಆದರೆ (ssh_packet_connection_is_on_socket(ssh)) {
		ಆದರೆ (getpeername(ssh_packet_get_connection_ಒಳ(ssh),
		    (ರಚನೆ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	ಆದರೆ (check_quietlogin(s, command))
		ಹಿಂತಿರುಗಿ;

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
	ಅಕ್ಷರ buf[256];

	ಆದರೆ (options.print_motd) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#ಇಲ್ಲದಿದ್ದರೆ
		f = fopen("/etc/motd", "r");
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (f) {
			ಆಗ (fgets(buf, ಗಾತ್ರ(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
ಪೂರ್ಣಾಂಕ
check_quietlogin(Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	ಅಕ್ಷರ buf[256];
	ರಚನೆ passwd *pw = s->pw;
	ರಚನೆ stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	ಆದರೆ (command != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;
	snprintf(buf, ಗಾತ್ರ(buf), "%.200s/.hushlogin", pw->pw_dir);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
	ಆದರೆ (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		ಹಿಂತಿರುಗಿ 1;
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (stat(buf, &st) >= 0)
		ಹಿಂತಿರುಗಿ 1;
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ 0;
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
read_environment_file(ಅಕ್ಷರ ***env, u_int *envsize,
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *allowlist)
{
	FILE *f;
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ, *cp, *ಮೌಲ್ಯ;
	ಗಾತ್ರ_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	ಆದರೆ (!f)
		ಹಿಂತಿರುಗಿ;

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		ಆದರೆ (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		ಗಾಗಿ (cp = ಸಾಲು; *cp == ' ' || *cp == '\t'; cp++)
			;
		ಆದರೆ (!*cp || *cp == '#' || *cp == '\n')
			ಮುಂದುವರಿ;

		cp[strcspn(cp, "\n")] = '\0';

		ಮೌಲ್ಯ = strchr(cp, '=');
		ಆದರೆ (ಮೌಲ್ಯ == ಖಾಲಿ) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			ಮುಂದುವರಿ;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*ಮೌಲ್ಯ = '\0';
		ಮೌಲ್ಯ++;
		ಆದರೆ (allowlist != ಖಾಲಿ &&
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(cp, allowlist, 0) != 1)
			ಮುಂದುವರಿ;
		ಮಗು_ಗಣ_env(env, envsize, cp, ಮೌಲ್ಯ);
	}
	ಬಿಡುಗಡೆ(ಸಾಲು);
	fclose(f);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
ಮಗು_get_env(ಅಕ್ಷರ **env, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ i;
	ಗಾತ್ರ_t len;

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name);
	ಗಾಗಿ (i=0; env[i] != ಖಾಲಿ; i++)
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(name, env[i], len) == 0 && env[i][len] == '=')
			ಹಿಂತಿರುಗಿ(env[i] + len + 1);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
read_etc_default_login(ಅಕ್ಷರ ***env, u_int *envsize, uid_t uid)
{
	ಅಕ್ಷರ **tmpenv = ಖಾಲಿ, *var;
	u_int i, tmpenvsize = 0;
	u_long ಮುಖವಾಡ;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	ಆದರೆ (tmpenv == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ (uid == 0)
		var = ಮಗು_get_env(tmpenv, "SUPATH");
	ಇಲ್ಲದಿದ್ದರೆ
		var = ಮಗು_get_env(tmpenv, "PATH");
	ಆದರೆ (var != ಖಾಲಿ)
		ಮಗು_ಗಣ_env(env, envsize, "PATH", var);

	ಆದರೆ ((var = ಮಗು_get_env(tmpenv, "UMASK")) != ಖಾಲಿ)
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಓದು(var, "%5lo", &ಮುಖವಾಡ) == 1)
			umask((ಬಹುಲಕ_t)ಮುಖವಾಡ);

	ಗಾಗಿ (i = 0; tmpenv[i] != ಖಾಲಿ; i++)
		ಬಿಡುಗಡೆ(tmpenv[i]);
	ಬಿಡುಗಡೆ(tmpenv);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_ETC_DEFAULT_LOGIN */

#ಆದರೆ defined(USE_PAM) || defined(HAVE_CYGWIN)
ಸ್ಥಿರ ಶೂನ್ಯ
copy_environment_denylist(ಅಕ್ಷರ **ಮೂಲ, ಅಕ್ಷರ ***env, u_int *envsize,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *denylist)
{
	ಅಕ್ಷರ *var_name, *var_val;
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (ಮೂಲ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಗಾಗಿ(i = 0; ಮೂಲ[i] != ಖಾಲಿ; i++) {
		var_name = xstrdup(ಮೂಲ[i]);
		ಆದರೆ ((var_val = ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(var_name, "=")) == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(var_name);
			ಮುಂದುವರಿ;
		}
		*var_val++ = '\0';

		ಆದರೆ (denylist == ಖಾಲಿ ||
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			ಮಗು_ಗಣ_env(env, envsize, var_name, var_val);
		}

		ಬಿಡುಗಡೆ(var_name);
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
ಸ್ಥಿರ ಶೂನ್ಯ
copy_environment(ಅಕ್ಷರ **ಮೂಲ, ಅಕ್ಷರ ***env, u_int *envsize)
{
	copy_environment_denylist(ಮೂಲ, env, envsize, ಖಾಲಿ);
}
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಅಕ್ಷರ **
do_ಸಿದ್ಧತೆ_env(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *shell)
{
	ಅಕ್ಷರ buf[256];
	ಗಾತ್ರ_t n;
	u_int i, envsize;
	ಅಕ್ಷರ *ocp, *cp, *ಮೌಲ್ಯ, **env, *laddr;
	ರಚನೆ passwd *pw = s->pw;
#ಆದರೆ !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	ಅಕ್ಷರ *ಮಾರ್ಗ = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, ಗಾತ್ರ(ಅಕ್ಷರ *));
	env[0] = ಖಾಲಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		ಅಕ್ಷರ **p;

		p = fetch_windows_environment();
		copy_environment(p, &env, &envsize);
		free_windows_environment(p);
	}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	/* Allow any GSSAPI methods that we've used to alter
	 * the child's environment as they see fit
	 */
	ssh_gssapi_do_ಮಗು(&env, &envsize);
#ಆದರೆ_ಅಂತ್ಯ

	/* Set basic environment. */
	ಗಾಗಿ (i = 0; i < s->ಅಂಕೆ_env; i++)
		ಮಗು_ಗಣ_env(&env, &envsize, s->env[i].name, s->env[i].val);

	ಮಗು_ಗಣ_env(&env, &envsize, "USER", pw->pw_name);
	ಮಗು_ಗಣ_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _AIX
	ಮಗು_ಗಣ_env(&env, &envsize, "LOGIN", pw->pw_name);
#ಆದರೆ_ಅಂತ್ಯ
	ಮಗು_ಗಣ_env(&env, &envsize, "HOME", pw->pw_dir);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
	ಆದರೆ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		ಮಗು_ಗಣ_env(&env, &envsize, "PATH", _PATH_STDPATH);
	ಇಲ್ಲದಿದ್ದರೆ
		ಮಗು_ಗಣ_env(&env, &envsize, "PATH", getenv("PATH"));
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_LOGIN_CAP */
# ifndef HAVE_CYGWIN
	/*
	 * There's no standard path on Windows. The path contains
	 * important components pointing to the system directories,
	 * needed for loading shared libraries. So the path better
	 * remains intact here.
	 */
#  ifdef HAVE_ETC_DEFAULT_LOGIN
	read_etc_default_login(&env, &envsize, pw->pw_uid);
	ಮಾರ್ಗ = ಮಗು_get_env(env, "PATH");
#  endif /* HAVE_ETC_DEFAULT_LOGIN */
	ಆದರೆ (ಮಾರ್ಗ == ಖಾಲಿ || *ಮಾರ್ಗ == '\0') {
		ಮಗು_ಗಣ_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_ಮಾರ್ಗ : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_LOGIN_CAP */

	ಆದರೆ (!options.use_pam) {
		snprintf(buf, ಗಾತ್ರ buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		ಮಗು_ಗಣ_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	ಮಗು_ಗಣ_env(&env, &envsize, "SHELL", shell);

	ಆದರೆ (getenv("TZ"))
		ಮಗು_ಗಣ_env(&env, &envsize, "TZ", getenv("TZ"));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
	ಆದರೆ (getenv("XDG_RUNTIME_DIR")) {
		ಮಗು_ಗಣ_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_LOGIN_CAP */
	ಆದರೆ (s->ಪದ)
		ಮಗು_ಗಣ_env(&env, &envsize, "TERM", s->ಪದ);
	ಆದರೆ (s->display)
		ಮಗು_ಗಣ_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		ಅಕ್ಷರ *cp;

		ಆದರೆ ((cp = getenv("KRB5CCNAME")) != ಖಾಲಿ)
			ಮಗು_ಗಣ_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _AIX
	{
		ಅಕ್ಷರ *cp;

		ಆದರೆ ((cp = getenv("AUTHSTATE")) != ಖಾಲಿ)
			ಮಗು_ಗಣ_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
	ಆದರೆ (s->authctxt->krb5_ccname)
		ಮಗು_ಗಣ_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (auth_sock_name != ಖಾಲಿ)
		ಮಗು_ಗಣ_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	ಆದರೆ (options.permit_user_env) {
		ಗಾಗಿ (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			ಆದರೆ (cp != ಖಾಲಿ) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				ಆದರೆ (options.permit_user_env_allowlist == ಖಾಲಿ ||
				    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					ಮಗು_ಗಣ_env(&env, &envsize,
					    ocp, cp + 1);
			}
			ಬಿಡುಗಡೆ(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	ಆದರೆ (options.permit_user_env) {
		snprintf(buf, ಗಾತ್ರ buf, "%.200s/%s/environment",
		    pw->pw_dir, ಮಾರ್ಗ_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	ಆದರೆ (options.use_pam) {
		ಅಕ್ಷರ **p;

		/*
		 * Don't allow PAM-internal env vars to leak
		 * back into the session environment.
		 */
#ವ್ಯಾಖ್ಯಾನಿಸು PAM_ENV_DENYLIST  "SSH_AUTH_INFO*,SSH_CONNECTION*"
		p = fetch_pam_ಮಗು_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);

		p = fetch_pam_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);
	}
#ಆದರೆ_ಅಂತ್ಯ /* USE_PAM */

	/* Environment specified by admin */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		ಆದರೆ ((ಮೌಲ್ಯ = strchr(cp, '=')) == ಖಾಲಿ) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*ಮೌಲ್ಯ++ = '\0';
		ಮಗು_ಗಣ_env(&env, &envsize, cp, ಮೌಲ್ಯ);
		ಬಿಡುಗಡೆ(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, ಗಾತ್ರ buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
	    ssh_local_ಪೋರ್ಟ್(ssh));
	ಮಗು_ಗಣ_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_ಒಳ(ssh));
	snprintf(buf, ಗಾತ್ರ buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
	    laddr, ssh_local_ಪೋರ್ಟ್(ssh));
	ಬಿಡುಗಡೆ(laddr);
	ಮಗು_ಗಣ_env(&env, &envsize, "SSH_CONNECTION", buf);

	ಆದರೆ (tun_fwd_ifnames != ಖಾಲಿ)
		ಮಗು_ಗಣ_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	ಆದರೆ (auth_info_file != ಖಾಲಿ)
		ಮಗು_ಗಣ_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	ಆದರೆ (s->ttyfd != -1)
		ಮಗು_ಗಣ_env(&env, &envsize, "SSH_TTY", s->tty);
	ಆದರೆ (original_command)
		ಮಗು_ಗಣ_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	ಆದರೆ (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		ಗಾಗಿ (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	ಹಿಂತಿರುಗಿ env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
do_rc_files(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *shell)
{
	FILE *f = ಖಾಲಿ;
	ಅಕ್ಷರ *cmd = ಖಾಲಿ, *user_rc = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ do_xauth;
	ರಚನೆ stat st;

	do_xauth =
	    s->display != ಖಾಲಿ && s->auth_proto != ಖಾಲಿ && s->auth_ದತ್ತಾಂಶ != ಖಾಲಿ;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, ಮಾರ್ಗ_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	ಆದರೆ (!s->is_subsystem && options.adm_forced_command == ಖಾಲಿ &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		ಆದರೆ (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		ಆದರೆ (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		ಆದರೆ (f) {
			ಆದರೆ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_ದತ್ತಾಂಶ);
			pclose(f);
		} ಇಲ್ಲದಿದ್ದರೆ
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (stat(ಮಾರ್ಗ_SSH_SYSTEM_RC, &st) >= 0) {
		ಆದರೆ (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    ಮಾರ್ಗ_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " ಮಾರ್ಗ_SSH_SYSTEM_RC, "w");
		ಆದರೆ (f) {
			ಆದರೆ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_ದತ್ತಾಂಶ);
			pclose(f);
		} ಇಲ್ಲದಿದ್ದರೆ
			fprintf(stderr, "Could not run %s\n",
			    ಮಾರ್ಗ_SSH_SYSTEM_RC);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (do_xauth && options.xauth_location != ಖಾಲಿ) {
		/* Add authority data to .Xauthority if appropriate. */
		ಆದರೆ (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_ದತ್ತಾಂಶ);
		}
		ಆದರೆ (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		ಆದರೆ (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_ದತ್ತಾಂಶ);
			pclose(f);
		} ಇಲ್ಲದಿದ್ದರೆ {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	ಬಿಡುಗಡೆ(cmd);
	ಬಿಡುಗಡೆ(user_rc);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_nologin(ರಚನೆ passwd *pw)
{
	FILE *f = ಖಾಲಿ;
	ಅಕ್ಷರ buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	ರಚನೆ stat sb;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
	ಆದರೆ (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		ಹಿಂತಿರುಗಿ;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (pw->pw_uid == 0)
		ಹಿಂತಿರುಗಿ;
	nl = def_nl;
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (stat(nl, &sb) == -1)
		ಹಿಂತಿರುಗಿ;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	ಆದರೆ ((f = fopen(nl, "r")) != ಖಾಲಿ) {
		ಆಗ (fgets(buf, ಗಾತ್ರ(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	ನಿರ್ಗಮಿಸು(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
safely_chroot(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, uid_t uid)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp;
	ಅಕ್ಷರ component[PATH_MAX];
	ರಚನೆ stat st;

	ಆದರೆ (!ಮಾರ್ಗ_absolute(ಮಾರ್ಗ))
		fatal("chroot path does not begin at root");
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ) >= ಗಾತ್ರ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ಗಾಗಿ (cp = ಮಾರ್ಗ; cp != ಖಾಲಿ;) {
		ಆದರೆ ((cp = strchr(cp, '/')) == ಖಾಲಿ)
			strlcpy(component, ಮಾರ್ಗ, ಗಾತ್ರ(component));
		ಇಲ್ಲದಿದ್ದರೆ {
			cp++;
			ಸ್ಮರಣೆ_ನಕಲು(component, ಮಾರ್ಗ, cp - ಮಾರ್ಗ);
			component[cp - ಮಾರ್ಗ] = '\0';
		}

		debug3_f("checking '%s'", component);

		ಆದರೆ (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		ಆದರೆ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ಖಾಲಿ ? "" : "component ", component);
		ಆದರೆ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ಖಾಲಿ ? "" : "component ", component);

	}

	ಆದರೆ (chdir(ಮಾರ್ಗ) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", ಮಾರ್ಗ, strerror(errno));
	ಆದರೆ (chroot(ಮಾರ್ಗ) == -1)
		fatal("chroot(\"%s\"): %s", ಮಾರ್ಗ, strerror(errno));
	ಆದರೆ (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", ಮಾರ್ಗ);
}

/* Set login name, uid, gid, and groups. */
ಶೂನ್ಯ
do_setusercontext(ರಚನೆ passwd *pw)
{
	ಅಕ್ಷರ uidstr[32], *chroot_ಮಾರ್ಗ, *tmp;

	platform_setusercontext(pw);

	ಆದರೆ (platform_privileged_uidswap()) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
		ಆದರೆ (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			ನಿರ್ಗಮಿಸು(1);
		}
#ಇಲ್ಲದಿದ್ದರೆ
		ಆದರೆ (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		ಆದರೆ (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			ನಿರ್ಗಮಿಸು(1);
		}
		/* Initialize the group list. */
		ಆದರೆ (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			ನಿರ್ಗಮಿಸು(1);
		}
		endgrent();
#ಆದರೆ_ಅಂತ್ಯ

		platform_setusercontext_post_groups(pw);

		ಆದರೆ (!ಒಳ_chroot && options.chroot_directory != ಖಾಲಿ &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, ಗಾತ್ರ(uidstr), "%llu",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)pw->pw_uid);
			chroot_ಮಾರ್ಗ = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (ಅಕ್ಷರ *)ಖಾಲಿ);
			safely_chroot(chroot_ಮಾರ್ಗ, pw->pw_uid);
			ಬಿಡುಗಡೆ(tmp);
			ಬಿಡುಗಡೆ(chroot_ಮಾರ್ಗ);
			/* Make sure we don't attempt to chroot again */
			ಬಿಡುಗಡೆ(options.chroot_directory);
			options.chroot_directory = ಖಾಲಿ;
			ಒಳ_chroot = 1;
		}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
		ಆದರೆ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			ನಿರ್ಗಮಿಸು(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(ಶೂನ್ಯ) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#ಇಲ್ಲದಿದ್ದರೆ
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		ಆದರೆ (!ಒಳ_chroot && ಗಣ_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_ಗಣ_uid(pw);
#ಆದರೆ_ಅಂತ್ಯ
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.chroot_directory != ಖಾಲಿ &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	ಆದರೆ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_pwchange(Session *s)
{
	fflush(ಖಾಲಿ);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	ಆದರೆ (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
		setexeccon(ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PASSWD_NEEDS_USERNAME
		execl(ಮಾರ್ಗ_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (ಅಕ್ಷರ *)ಖಾಲಿ);
#ಇಲ್ಲದಿದ್ದರೆ
		execl(ಮಾರ್ಗ_PASSWD_PROG, "passwd", (ಅಕ್ಷರ *)ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ
		perror("passwd");
	} ಇಲ್ಲದಿದ್ದರೆ {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	ನಿರ್ಗಮಿಸು(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಮಗು_close_fds(ರಚನೆ ssh *ssh)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ auth_sock;

	ಆದರೆ (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	ಆದರೆ (ssh_packet_get_connection_ಒಳ(ssh) ==
	    ssh_packet_get_connection_ಹೊರಹೋಗು(ssh))
		close(ssh_packet_get_connection_ಒಳ(ssh));
	ಇಲ್ಲದಿದ್ದರೆ {
		close(ssh_packet_get_connection_ಒಳ(ssh));
		close(ssh_packet_get_connection_ಹೊರಹೋಗು(ssh));
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
	log_redirect_stderr_ಗಮ್ಯ(ಖಾಲಿ);

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
#ವ್ಯಾಖ್ಯಾನಿಸು ARGV_MAX 10
ಶೂನ್ಯ
do_ಮಗು(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	ಬಾಹ್ಯ ಅಕ್ಷರ **environ;
	ಅಕ್ಷರ **env, *argv[ARGV_MAX], remote_id[512];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *shell, *shell0;
	ರಚನೆ passwd *pw = s->pw;
	ಪೂರ್ಣಾಂಕ r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, ಗಾತ್ರ(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_ಕೀಲಿಗಳು(ssh);

	/* Force a password change */
	ಆದರೆ (s->authctxt->force_pwchange) {
		do_setusercontext(pw);
		ಮಗು_close_fds(ssh);
		do_pwchange(s);
		ನಿರ್ಗಮಿಸು(1);
	}

	/*
	 * Login(1) does this as well, and it needs uid 0 for the "-h"
	 * switch, so we let login(1) to this for us.
	 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_OSF_SIA
	session_ಸಿದ್ಧತೆ_sia(pw, s->ttyfd == -1 ? ಖಾಲಿ : s->tty);
	ಆದರೆ (!check_quietlogin(s, command))
		do_motd();
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	ಆದರೆ (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	ಆದರೆ (!check_quietlogin(s, command))
		display_loginmsg();
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_OSF_SIA */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam && !is_pam_session_open()) {
		debug3("PAM session not opened, exiting");
		display_loginmsg();
		ನಿರ್ಗಮಿಸು(254);
	}
#ಆದರೆ_ಅಂತ್ಯ

	/*
	 * Get the shell from the password data.  An empty shell field is
	 * legal, and means /bin/sh.
	 */
	shell = (pw->pw_shell[0] == '\0') ? _PATH_BSHELL : pw->pw_shell;

	/*
	 * Make sure $SHELL points to the shell from the password file,
	 * even if shell is overridden from login.conf
	 */
	env = do_ಸಿದ್ಧತೆ_env(ssh, s, shell);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
	shell = login_getcapstr(lc, "shell", (ಅಕ್ಷರ *)shell, (ಅಕ್ಷರ *)shell);
#ಆದರೆ_ಅಂತ್ಯ

	/*
	 * Close the connection descriptors; note that this is the child, and
	 * the server will still have the socket open, and it is important
	 * that we do not shutdown it.  Note that the descriptors cannot be
	 * closed before building the environment, as we call
	 * ssh_remote_ipaddr there.
	 */
	ಮಗು_close_fds(ssh);

	/*
	 * Must take new environment into use so that .ssh/rc,
	 * /etc/ssh/sshrc and xauth are run in the proper environment.
	 */
	environ = env;

#ಆದರೆ defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	ಆದರೆ (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != ಖಾಲಿ)) {
		ಅಕ್ಷರ cell[64];

		debug("Getting AFS token");

		k_setpag();

		ಆದರೆ (k_afs_cell_ದ_file(pw->pw_dir, cell, ಗಾತ್ರ(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, ಖಾಲಿ);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, ಖಾಲಿ, ಖಾಲಿ, pw->pw_dir);
	}
#ಆದರೆ_ಅಂತ್ಯ

	/* Change current directory to the user's home directory. */
	ಆದರೆ (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (r || !ಒಳ_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		ಆದರೆ (r)
			ನಿರ್ಗಮಿಸು(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	ಆದರೆ (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		ಬರೆ("This service allows sftp connections only.\n");
		fflush(ಖಾಲಿ);
		ನಿರ್ಗಮಿಸು(1);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind, optreset;
		ಪೂರ್ಣಾಂಕ sftp_argc;
		ಅಕ್ಷರ **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, ಆಂತರಿಕ_SFTP_NAME);
		ಆದರೆ (argv_ವಿಭಜಿಸು(command == ಖಾಲಿ ? "sftp-server" : command,
		    &sftp_argc, &sftp_argv, 1) != 0) {
			error("internal error: can't split internal-sftp "
			    "arguments");
			ನಿರ್ಗಮಿಸು(1);
		}
		optind = optreset = 1;
		__progname = sftp_argv[0];
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
		ssh_selinux_change_context("sftpd_t");
#ಆದರೆ_ಅಂತ್ಯ
		ನಿರ್ಗಮಿಸು(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}

	fflush(ಖಾಲಿ);

	/* Get the last component of the shell name. */
	ಆದರೆ ((shell0 = strrchr(shell, '/')) != ಖಾಲಿ)
		shell0++;
	ಇಲ್ಲದಿದ್ದರೆ
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	ಆದರೆ (!command) {
		ಅಕ್ಷರ argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		ಆದರೆ (strlcpy(argv0 + 1, shell0, ಗಾತ್ರ(argv0) - 1)
		    >= ಗಾತ್ರ(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			ನಿರ್ಗಮಿಸು(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = ಖಾಲಿ;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		ನಿರ್ಗಮಿಸು(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (ಅಕ್ಷರ *) shell0;
	argv[1] = "-c";
	argv[2] = (ಅಕ್ಷರ *) command;
	argv[3] = ಖಾಲಿ;
	execve(shell, argv, env);
	perror(shell);
	ನಿರ್ಗಮಿಸು(1);
}

ಶೂನ್ಯ
session_ಬಳಸದ(ಪೂರ್ಣಾಂಕ id)
{
	debug3_f("session id %d unused", id);
	ಆದರೆ (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, ಗಾತ್ರ(*sessions));
	sessions[id].self = id;
	sessions[id].ಬಳಸಿದ = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = ಖಾಲಿ;
	sessions[id].ಮುಂದಿನ_ಬಳಸದ = sessions_ಮೊದಲ_ಬಳಸದ;
	sessions_ಮೊದಲ_ಬಳಸದ = id;
}

Session *
session_new(ಶೂನ್ಯ)
{
	Session *s, *tmp;

	ಆದರೆ (sessions_ಮೊದಲ_ಬಳಸದ == -1) {
		ಆದರೆ (sessions_nalloc >= options.max_sessions)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, ಗಾತ್ರ(*sessions));
		ಆದರೆ (tmp == ಖಾಲಿ) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
		sessions = tmp;
		session_ಬಳಸದ(sessions_nalloc++);
	}

	ಆದರೆ (sessions_ಮೊದಲ_ಬಳಸದ >= sessions_nalloc ||
	    sessions_ಮೊದಲ_ಬಳಸದ < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_ಮೊದಲ_ಬಳಸದ, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_ಮೊದಲ_ಬಳಸದ];
	ಆದರೆ (s->ಬಳಸಿದ)
		fatal_f("session %d already used", sessions_ಮೊದಲ_ಬಳಸದ);
	sessions_ಮೊದಲ_ಬಳಸದ = s->ಮುಂದಿನ_ಬಳಸದ;
	s->ಬಳಸಿದ = 1;
	s->ಮುಂದಿನ_ಬಳಸದ = -1;
	debug("session_new: session %d", s->self);

	ಹಿಂತಿರುಗಿ s;
}

ಸ್ಥಿರ ಶೂನ್ಯ
session_dump(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->ಬಳಸಿದ,
		    s->ಮುಂದಿನ_ಬಳಸದ,
		    s->self,
		    s->chanid,
		    (ದೀರ್ಘ)s->pid);
	}
}

ಪೂರ್ಣಾಂಕ
session_open(Authctxt *authctxt, ಪೂರ್ಣಾಂಕ chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	ಆದರೆ (s == ಖಾಲಿ) {
		error("no more sessions");
		ಹಿಂತಿರುಗಿ 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	ಆದರೆ (s->pw == ಖಾಲಿ || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	ಹಿಂತಿರುಗಿ 1;
}

Session *
session_by_tty(ಅಕ್ಷರ *tty)
{
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಆದರೆ (s->ಬಳಸಿದ && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			ಹಿಂತಿರುಗಿ s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ Session *
session_by_channel(ಪೂರ್ಣಾಂಕ id)
{
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಆದರೆ (s->ಬಳಸಿದ && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			ಹಿಂತಿರುಗಿ s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ Session *
session_by_x11_channel(ಪೂರ್ಣಾಂಕ id)
{
	ಪೂರ್ಣಾಂಕ i, j;

	ಗಾಗಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		ಆದರೆ (s->x11_chanids == ಖಾಲಿ || !s->ಬಳಸಿದ)
			ಮುಂದುವರಿ;
		ಗಾಗಿ (j = 0; s->x11_chanids[j] != -1; j++) {
			ಆದರೆ (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				ಹಿಂತಿರುಗಿ s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ Session *
session_by_pid(pid_t pid)
{
	ಪೂರ್ಣಾಂಕ i;
	debug("session_by_pid: pid %ld", (ದೀರ್ಘ)pid);
	ಗಾಗಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಆದರೆ (s->ಬಳಸಿದ && s->pid == pid)
			ಹಿಂತಿರುಗಿ s;
	}
	error("session_by_pid: unknown pid %ld", (ದೀರ್ಘ)pid);
	session_dump();
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_ಕಿಟಕಿ_change_req(ರಚನೆ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &s->ಲಂಬಸಾಲು)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ಅಡ್ಡಸಾಲು)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_ಕಿಟಕಿ_ಗಾತ್ರ(s->ptyfd, s->ಅಡ್ಡಸಾಲು, s->ಲಂಬಸಾಲು, s->xpixel, s->ypixel);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_pty_req(ರಚನೆ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &s->ಪದ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ಲಂಬಸಾಲು)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ಅಡ್ಡಸಾಲು)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ಆದರೆ (strcmp(s->ಪದ, "") == 0) {
		ಬಿಡುಗಡೆ(s->ಪದ);
		s->ಪದ = ಖಾಲಿ;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	ಆದರೆ (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, ಗಾತ್ರ(s->tty))) {
		ಬಿಡುಗಡೆ(s->ಪದ);
		s->ಪದ = ಖಾಲಿ;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		ಹಿಂತಿರುಗಿ 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_ಕಿಟಕಿ_ಗಾತ್ರ(s->ptyfd, s->ಅಡ್ಡಸಾಲು, s->ಲಂಬಸಾಲು, s->xpixel, s->ypixel);

	session_proctitle(s);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_subsystem_req(ರಚನೆ ssh *ssh, Session *s)
{
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ r, success = 0, ಸಿಕ್ಕಿತು = 0;
	ಅಕ್ಷರ *prog, *cmd, *type;
	u_int i;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &s->subsys, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_subsystems; i++) {
		ಆದರೆ (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			ಮುಂದುವರಿ;
		ಸಿಕ್ಕಿತು = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_ವಾದಗಳು[i];
		ಆದರೆ (strcmp(ಆಂತರಿಕ_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_ಗಣ_xtype(ssh, s->chanid, type);
		ಬಿಡುಗಡೆ(type);
		success = do_exec(ssh, s, cmd) == 0;
		ನಿಲ್ಲಿಸು;
	}

	ಆದರೆ (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    ಸಿಕ್ಕಿತು ? "execution failed" : "subsystem not found");
	}

	ಹಿಂತಿರುಗಿ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_x11_req(ರಚನೆ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಂಕ r, success;
	u_char single_connection = 0;

	ಆದರೆ (s->auth_proto != ಖಾಲಿ || s->auth_ದತ್ತಾಂಶ != ಖಾಲಿ) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_ದತ್ತಾಂಶ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	ಆದರೆ (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_ದತ್ತಾಂಶ))
		success = session_ಸಿದ್ಧತೆ_x11fwd(ssh, s);
	ಇಲ್ಲದಿದ್ದರೆ {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	ಆದರೆ (!success) {
		ಬಿಡುಗಡೆ(s->auth_proto);
		ಬಿಡುಗಡೆ(s->auth_ದತ್ತಾಂಶ);
		s->auth_proto = ಖಾಲಿ;
		s->auth_ದತ್ತಾಂಶ = ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_shell_req(ರಚನೆ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_ಗಣ_xtype(ssh, s->chanid, "session:shell");

	ಹಿಂತಿರುಗಿ do_exec(ssh, s, ಖಾಲಿ) == 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_exec_req(ರಚನೆ ssh *ssh, Session *s)
{
	u_int success;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *command = ಖಾಲಿ;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &command, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_ಗಣ_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	ಬಿಡುಗಡೆ(command);
	ಹಿಂತಿರುಗಿ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_break_req(ರಚನೆ ssh *ssh, Session *s)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_get_u32(ssh, ಖಾಲಿ)) != 0 || /* ignore */
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ಆದರೆ (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_env_req(ರಚನೆ ssh *ssh, Session *s)
{
	ಅಕ್ಷರ *name, *val;
	u_int i;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &name, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	ಆದರೆ (s->ಅಂಕೆ_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		ಹೋಗು fail;
	}

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_accept_env; i++) {
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->ಅಂಕೆ_env, name, val);
			s->env = xrecallocarray(s->env, s->ಅಂಕೆ_env,
			    s->ಅಂಕೆ_env + 1, ಗಾತ್ರ(*s->env));
			s->env[s->ಅಂಕೆ_env].name = name;
			s->env[s->ಅಂಕೆ_env].val = val;
			s->ಅಂಕೆ_env++;
			ಹಿಂತಿರುಗಿ (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	ಬಿಡುಗಡೆ(name);
	ಬಿಡುಗಡೆ(val);
	ಹಿಂತಿರುಗಿ (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
name2sig(ಅಕ್ಷರ *name)
{
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SIG(x) ಆದರೆ (strcmp(name, #x) == 0) ಹಿಂತಿರುಗಿ SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(ಪದ_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು	SSH_SIG
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
	ಆದರೆ (strcmp(name, "INFO@openssh.com") == 0)
		ಹಿಂತಿರುಗಿ SIGINFO;
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_signal_req(ರಚನೆ ssh *ssh, Session *s)
{
	ಅಕ್ಷರ *signame = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, sig, success = 0;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &signame, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		error_fr(r, "parse");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (ದೀರ್ಘ)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	ಆದರೆ (r != 0) {
		error_f("killpg(%ld, %d): %s", (ದೀರ್ಘ)s->pid,
		    sig, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* success */
	success = 1;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(signame);
	ಹಿಂತಿರುಗಿ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
session_auth_agent_req(ರಚನೆ ssh *ssh, Session *s, ಪೂರ್ಣಾಂಕ agent_new)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ called = 0;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ಆದರೆ (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (called)
		ಹಿಂತಿರುಗಿ 0;

	called = 1;
	ಹಿಂತಿರುಗಿ auth_ಒಳಹರಿವು_request_forwarding(ssh, s->pw, agent_new);
}

ಪೂರ್ಣಾಂಕ
session_ಒಳಹರಿವು_channel_req(ರಚನೆ ssh *ssh, Channel *c, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rtype)
{
	ಪೂರ್ಣಾಂಕ success = 0;
	Session *s;

	ಆದರೆ ((s = session_by_channel(c->self)) == ಖಾಲಿ) {
		logit_f("no session %d req %.100s", c->self, rtype);
		ಹಿಂತಿರುಗಿ 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	ಆದರೆ (c->type == SSH_CHANNEL_LARVAL) {
		ಆದರೆ (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	ಆದರೆ (strcmp(rtype, "window-change") == 0) {
		success = session_ಕಿಟಕಿ_change_req(ssh, s);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	ಹಿಂತಿರುಗಿ success;
}

ಶೂನ್ಯ
session_ಗಣ_fds(ರಚನೆ ssh *ssh, Session *s,
    ಪೂರ್ಣಾಂಕ fdin, ಪೂರ್ಣಾಂಕ fdout, ಪೂರ್ಣಾಂಕ fderr, ಪೂರ್ಣಾಂಕ ignore_fderr, ಪೂರ್ಣಾಂಕ is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	ಆದರೆ (s->chanid == -1)
		fatal("no channel for session %d", s->self);
	channel_ಗಣ_fds(ssh, s->chanid,
	    fdout, fdin, fderr,
	    ignore_fderr ? CHAN_EXTENDED_IGNORE : CHAN_EXTENDED_READ,
	    1, is_tty, CHAN_SES_ಕಿಟಕಿ_DEFAULT);
}

/*
 * Function to perform pty cleanup. Also called if we get aborted abnormally
 * (e.g., due to a dropped connection).
 */
ಶೂನ್ಯ
session_pty_cleanup2(Session *s)
{
	ಆದರೆ (s == ಖಾಲಿ) {
		error_f("no session");
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (s->ttyfd == -1)
		ಹಿಂತಿರುಗಿ;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	ಆದರೆ (s->pid != 0)
		ದಾಖಲೆ_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	ಆದರೆ (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	ಆದರೆ (s->ptymaster != -1 && close(s->ptymaster) == -1)
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

ಸ್ಥಿರ ಅಕ್ಷರ *
sig2name(ಪೂರ್ಣಾಂಕ sig)
{
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SIG(x) ಆದರೆ (sig == SIG ## x) ಹಿಂತಿರುಗಿ #x
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
	SSH_SIG(ಪದ_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು	SSH_SIG
	ಹಿಂತಿರುಗಿ "SIG@openssh.com";
}

ಸ್ಥಿರ ಶೂನ್ಯ
session_close_x11(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id)
{
	Channel *c;

	ಆದರೆ ((c = channel_by_id(ssh, id)) == ಖಾಲಿ) {
		debug_f("x11 channel %d missing", id);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		ಆದರೆ (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
session_close_single_x11(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ force, ಶೂನ್ಯ *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	ಆದರೆ ((s = session_by_x11_channel(id)) == ಖಾಲಿ)
		fatal_f("no x11 channel %d", id);
	ಗಾಗಿ (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		ಆದರೆ (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	ಬಿಡುಗಡೆ(s->x11_chanids);
	s->x11_chanids = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(s->display);
	s->display = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(s->auth_proto);
	s->auth_proto = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(s->auth_ದತ್ತಾಂಶ);
	s->auth_ದತ್ತಾಂಶ = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(s->auth_display);
	s->auth_display = ಖಾಲಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
session_exit_ಸಂದೇಶ(ರಚನೆ ssh *ssh, Session *s, ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2)
{
	Channel *c;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *note = ಖಾಲಿ;

	ಆದರೆ ((c = channel_lookup(ssh, s->chanid)) == ಖಾಲಿ)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	ಆದರೆ (WIFEXITED(ಸ್ಥಿತಿ_2)) {
		channel_request_ಆರಂಭ(ssh, s->chanid, "exit-status", 0);
		ಆದರೆ ((r = sshpkt_put_u32(ssh, WEXITSTATUS(ಸ್ಥಿತಿ_2))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(ಸ್ಥಿತಿ_2));
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (WIFSIGNALED(ಸ್ಥಿತಿ_2)) {
		channel_request_ಆರಂಭ(ssh, s->chanid, "exit-signal", 0);
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WCOREDUMP
# define WCOREDUMP(x) (0)
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(ಸ್ಥಿತಿ_2)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(ಸ್ಥಿತಿ_2)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(ಸ್ಥಿತಿ_2),
		    WCOREDUMP(ಸ್ಥಿತಿ_2) ? " core dumped" : "");
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    ಸ್ಥಿತಿ_2);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (ದೀರ್ಘ)s->pid, note == ಖಾಲಿ ? "UNKNOWN" : note);
	ಬಿಡುಗಡೆ(note);

	/* disconnect channel */
	debug_f("release channel %d", s->chanid);

	/*
	 * Adjust cleanup callback attachment to send close messages when
	 * the channel gets EOF. The session will be then be closed
	 * by session_close_by_channel when the child sessions close their fds.
	 */
	channel_ರಿಜಿಸ್ಟರ್_cleanup(ssh, c->self, session_close_by_channel, 1);

	/*
	 * emulate a write failure with 'chan_write_failed', nobody will be
	 * interested in data we write.
	 * Note that we must not call 'chan_read_failed', since there could
	 * be some more data waiting in the pipe.
	 */
	ಆದರೆ (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

ಶೂನ್ಯ
session_close(ರಚನೆ ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_ಪೋರ್ಟ್(ssh),
	    s->self);

	ಆದರೆ (s->ttyfd != -1)
		session_pty_cleanup(s);
	ಬಿಡುಗಡೆ(s->ಪದ);
	ಬಿಡುಗಡೆ(s->display);
	ಬಿಡುಗಡೆ(s->x11_chanids);
	ಬಿಡುಗಡೆ(s->auth_display);
	ಬಿಡುಗಡೆ(s->auth_ದತ್ತಾಂಶ);
	ಬಿಡುಗಡೆ(s->auth_proto);
	ಬಿಡುಗಡೆ(s->subsys);
	ಆದರೆ (s->env != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; i < s->ಅಂಕೆ_env; i++) {
			ಬಿಡುಗಡೆ(s->env[i].name);
			ಬಿಡುಗಡೆ(s->env[i].val);
		}
		ಬಿಡುಗಡೆ(s->env);
	}
	session_proctitle(s);
	session_ಬಳಸದ(s->self);
}

ಶೂನ್ಯ
session_close_by_pid(ರಚನೆ ssh *ssh, pid_t pid, ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2)
{
	Session *s = session_by_pid(pid);
	ಆದರೆ (s == ಖಾಲಿ) {
		debug_f("no session for pid %ld", (ದೀರ್ಘ)pid);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (s->chanid != -1)
		session_exit_ಸಂದೇಶ(ssh, s, ಸ್ಥಿತಿ_2);
	ಆದರೆ (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
ಶೂನ್ಯ
session_close_by_channel(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ force, ಶೂನ್ಯ *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	ಆದರೆ (s == ಖಾಲಿ) {
		debug_f("no session for id %d", id);
		ಹಿಂತಿರುಗಿ;
	}
	debug_f("channel %d child %ld", id, (ದೀರ್ಘ)s->pid);
	ಆದರೆ (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		ಆದರೆ (s->ttyfd != -1)
			session_pty_cleanup(s);
		ಆದರೆ (!force)
			ಹಿಂತಿರುಗಿ;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	ಆದರೆ (s->x11_chanids != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

ಶೂನ್ಯ
session_destroy_all(ರಚನೆ ssh *ssh, ಶೂನ್ಯ (*closefunc)(Session *))
{
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಆದರೆ (s->ಬಳಸಿದ) {
			ಆದರೆ (closefunc != ಖಾಲಿ)
				closefunc(s);
			ಇಲ್ಲದಿದ್ದರೆ
				session_close(ssh, s);
		}
	}
}

ಸ್ಥಿರ ಅಕ್ಷರ *
session_tty_list(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಅಕ್ಷರ buf[1024];
	ಪೂರ್ಣಾಂಕ i;
	ಅಕ್ಷರ *cp;

	buf[0] = '\0';
	ಗಾಗಿ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ಆದರೆ (s->ಬಳಸಿದ && s->ttyfd != -1) {

			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == ಖಾಲಿ) ? s->tty : cp + 1;
			} ಇಲ್ಲದಿದ್ದರೆ
				cp = s->tty + 5;

			ಆದರೆ (buf[0] != '\0')
				strlcat(buf, ",", ಗಾತ್ರ buf);
			strlcat(buf, cp, ಗಾತ್ರ buf);
		}
	}
	ಆದರೆ (buf[0] == '\0')
		strlcpy(buf, "notty", ಗಾತ್ರ buf);
	ಹಿಂತಿರುಗಿ buf;
}

ಶೂನ್ಯ
session_proctitle(Session *s)
{
	ಆದರೆ (s->pw == ಖಾಲಿ)
		error("no user for session %d", s->self);
	ಇಲ್ಲದಿದ್ದರೆ
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

ಪೂರ್ಣಾಂಕ
session_ಸಿದ್ಧತೆ_x11fwd(ರಚನೆ ssh *ssh, Session *s)
{
	ರಚನೆ stat st;
	ಅಕ್ಷರ display[512], auth_display[512];
	ಅಕ್ಷರ hostname[NI_MAXHOST];
	u_int i;

	ಆದರೆ (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (options.xauth_location == ಖಾಲಿ ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (s->display != ಖಾಲಿ) {
		debug("X11 display already set.");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (x11_create_display_inet(ssh, options.x11_display_ಸ್ಥಾನಾಂತರ,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_ಸಂಖ್ಯೆ, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಗಾಗಿ (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_ರಿಜಿಸ್ಟರ್_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	ಆದರೆ (gethostname(hostname, ಗಾತ್ರ(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	ಆದರೆ (options.x11_use_localhost) {
		snprintf(display, ಗಾತ್ರ display, "localhost:%u.%u",
		    s->display_ಸಂಖ್ಯೆ, s->screen);
		snprintf(auth_display, ಗಾತ್ರ auth_display, "unix:%u.%u",
		    s->display_ಸಂಖ್ಯೆ, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} ಇಲ್ಲದಿದ್ದರೆ {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ IPADDR_ಒಳ_DISPLAY
		ರಚನೆ hostent *he;
		ರಚನೆ in_addr my_addr;

		he = gethostbyname(hostname);
		ಆದರೆ (he == ಖಾಲಿ) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			ಹಿಂತಿರುಗಿ 0;
		}
		ಸ್ಮರಣೆ_ನಕಲು(&my_addr, he->h_addr_list[0], ಗಾತ್ರ(ರಚನೆ in_addr));
		snprintf(display, ಗಾತ್ರ display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_ಸಂಖ್ಯೆ, s->screen);
#ಇಲ್ಲದಿದ್ದರೆ
		snprintf(display, ಗಾತ್ರ display, "%.400s:%u.%u", hostname,
		    s->display_ಸಂಖ್ಯೆ, s->screen);
#ಆದರೆ_ಅಂತ್ಯ
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_authenticated2(ರಚನೆ ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

ಶೂನ್ಯ
do_cleanup(ರಚನೆ ssh *ssh, Authctxt *authctxt)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	ಆದರೆ (is_ಮಗು)
		ಹಿಂತಿರುಗಿ;

	/* avoid double cleanup */
	ಆದರೆ (called)
		ಹಿಂತಿರುಗಿ;
	called = 1;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (!authctxt->authenticated)
		ಹಿಂತಿರುಗಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
	ಆದರೆ (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	ಆದರೆ (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#ಆದರೆ_ಅಂತ್ಯ

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	ಆದರೆ (auth_info_file != ಖಾಲಿ) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		ಬಿಡುಗಡೆ(auth_info_file);
		auth_info_file = ಖಾಲಿ;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	ಆದರೆ (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
session_get_remote_name_or_ip(ರಚನೆ ssh *ssh, u_int utmp_ಗಾತ್ರ, ಪೂರ್ಣಾಂಕ use_dns)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote = "";

	ಆದರೆ (utmp_ಗಾತ್ರ > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	ಆದರೆ (utmp_ಗಾತ್ರ == 0 || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(remote) > utmp_ಗಾತ್ರ)
		remote = ssh_remote_ipaddr(ssh);
	ಹಿಂತಿರುಗಿ remote;
}

