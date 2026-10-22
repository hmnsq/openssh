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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshlogin.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "serverloop.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"

#ਜੇ defined(KRB5) && defined(USE_AFS)
#ਅਨ੍ਤਰ੍ਭਾਵ <kafs.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
#ਅਨ੍ਤਰ੍ਭਾਵ <selinux/selinux.h>
#ਜੇ_ਅੰਤ

/*
 * Hack for systems that do not support FD passing: allocate PTYs directly
 * without calling into the monitor. This requires either the post-auth
 * privsep process retain root privileges (see the comment in
 * sshd-session.c:privsep_postauth) or that PTY allocation doesn't require
 * privileges to begin with (e.g. Cygwin).
 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DISABLE_FD_PASSING
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ mm_pty_allocate pty_allocate
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ IS_ਅੰਦਰੂਨੀ_SFTP(c) \
	(!ਲੜੀ_ਤੁਲਨਾ(c, ਅੰਦਰੂਨੀ_SFTP_NAME, ਆਕਾਰ(ਅੰਦਰੂਨੀ_SFTP_NAME) - 1) && \
	 (c[ਆਕਾਰ(ਅੰਦਰੂਨੀ_SFTP_NAME) - 1] == '\0' || \
	  c[ਆਕਾਰ(ਅੰਦਰੂਨੀ_SFTP_NAME) - 1] == ' ' || \
	  c[ਆਕਾਰ(ਅੰਦਰੂਨੀ_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(ਖਾਲੀ);
ਖਾਲੀ	session_ਸੈੱਟ_fds(ਬਣਤਰ ssh *, Session *, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);
ਖਾਲੀ	session_pty_cleanup(Session *);
ਖਾਲੀ	session_proctitle(Session *);
ਪੂਰਨ	session_ਤਿਆਰੀ_x11fwd(ਬਣਤਰ ssh *, Session *);
ਪੂਰਨ	do_exec_pty(ਬਣਤਰ ssh *, Session *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	do_exec_no_pty(ਬਣਤਰ ssh *, Session *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	do_exec(ਬਣਤਰ ssh *, Session *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	do_login(ਬਣਤਰ ssh *, Session *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	do_ਬੱਚਾ(ਬਣਤਰ ssh *, Session *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	do_motd(ਖਾਲੀ);
ਪੂਰਨ	check_quietlogin(Session *, ਅਚਲ ਅੱਖਰ *);

ਸਥਿਰ ਖਾਲੀ do_authenticated2(ਬਣਤਰ ssh *, Authctxt *);

ਸਥਿਰ ਪੂਰਨ session_pty_req(ਬਣਤਰ ssh *, Session *);

/* import */
ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ ਅੱਖਰ *__progname;
ਬਾਹਰੀ ਪੂਰਨ debug_flag;
ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;
ਬਾਹਰੀ ਬਣਤਰ sshauthopt *auth_opts;
ਬਾਹਰੀ ਅੱਖਰ *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
ਅਚਲ ਅੱਖਰ *original_command = ਨਿਰਾ;

/*ਅੰਕੜੇ*/
ਸਥਿਰ ਪੂਰਨ sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ = -1;
ਸਥਿਰ ਪੂਰਨ sessions_nalloc = 0;
ਸਥਿਰ Session *sessions = ਨਿਰਾ;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUBSYSTEM_NONE			0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUBSYSTEM_EXT			1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUBSYSTEM_INT_SFTP		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUBSYSTEM_INT_SFTP_ERROR	3

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
login_cap_t *lc;
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਪੂਰਨ is_ਬੱਚਾ = 0;
ਸਥਿਰ ਪੂਰਨ ਵਿੱਚ_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
ਸਥਿਰ ਅੱਖਰ *auth_info_file = ਨਿਰਾ;

/* Name and directory of socket for authentication agent forwarding. */
ਸਥਿਰ ਅੱਖਰ *auth_sock_name = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *auth_sock_dir = ਨਿਰਾ; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

ਸਥਿਰ ਖਾਲੀ
auth_sock_cleanup_proc(ਬਣਤਰ passwd *pw)
{
	ਜੇ (auth_sock_name != ਨਿਰਾ) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_ਰਸਤਾ,
		    auth_sock_name, auth_sock_dir);
		ਮੁਕਤ(auth_sock_name);
		auth_sock_name = ਨਿਰਾ;
		restore_uid();
	}
}

ਸਥਿਰ ਪੂਰਨ
auth_ਨਿਵੇਸ਼_request_forwarding(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *pw, ਪੂਰਨ agent_new)
{
	Channel *nc;
	ਪੂਰਨ sock = -1;

	ਜੇ (auth_sock_name != ਨਿਰਾ) {
		error("authentication forwarding requested twice.");
		ਵਾਪਸ 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	ਜੇ (agent_listener(options.agent_socket_ਰਸਤਾ, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		ਜਾਓ authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_ਖਿੜਕੀ_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->ਰਸਤਾ = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	ਵਾਪਸ 1;

 authsock_err:
	ਮੁਕਤ(auth_sock_name);
	ਜੇ (sock != -1)
		close(sock);
	auth_sock_name = ਨਿਰਾ;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
display_loginmsg(ਖਾਲੀ)
{
	ਪੂਰਨ r;

	ਜੇ (sshbuf_len(loginmsg) == 0)
		ਵਾਪਸ;
	ਜੇ ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	ਲਿਖੋ("%s", (ਅੱਖਰ *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

ਸਥਿਰ ਖਾਲੀ
prepare_auth_info_file(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshbuf *info)
{
	ਪੂਰਨ fd = -1, success = 0;

	ਜੇ (!options.expose_userauth_info || info == ਨਿਰਾ)
		ਵਾਪਸ;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	ਜੇ ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	success = 1;
 ਬਾਹਰਲਾ:
	ਜੇ (!success) {
		ਜੇ (fd != -1)
			close(fd);
		ਮੁਕਤ(auth_info_file);
		auth_info_file = ਨਿਰਾ;
	}
	restore_uid();
}

ਸਥਿਰ ਖਾਲੀ
ਸੈੱਟ_fwdpermit_from_authopts(ਬਣਤਰ ssh *ssh, ਅਚਲ ਬਣਤਰ sshauthopt *opts)
{
	ਅੱਖਰ *tmp, *cp, *host;
	ਪੂਰਨ ਪੋਰਟ;
	ਮਾਪ_t i;

	ਜੇ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		ਲਈ (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			ਜੇ ((host = hpdelim2(&cp, ਨਿਰਾ)) == ਨਿਰਾ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ਜੇ (cp == ਨਿਰਾ || (ਪੋਰਟ = permitopen_ਪੋਰਟ(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_ਜੋੜੋ_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, ਪੋਰਟ);
			ਮੁਕਤ(tmp);
		}
	}
	ਜੇ ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		ਲਈ (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			ਜੇ ((host = hpdelim(&cp)) == ਨਿਰਾ)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ਜੇ (cp == ਨਿਰਾ || (ਪੋਰਟ = permitopen_ਪੋਰਟ(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_ਜੋੜੋ_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, ਪੋਰਟ);
			ਮੁਕਤ(tmp);
		}
	}
}

ਖਾਲੀ
do_authenticated(ਬਣਤਰ ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	ਸੈੱਟ_fwdpermit_from_authopts(ssh, auth_opts);

	ਜੇ (!auth_opts->permit_ਪੋਰਟ_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		ਨਹੀਂਤਾਂ
			channel_permit_all(ssh, FORWARD_LOCAL);
		ਜੇ ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		ਨਹੀਂਤਾਂ
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
ਸਥਿਰ ਪੂਰਨ
xauth_valid_string(ਅਚਲ ਅੱਖਰ *s)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; s[i] != '\0'; i++) {
		ਜੇ (!ਅੱਖਰ_ਜਾਂ_ਅੰਕ((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			ਵਾਪਸ 0;
	}
	ਵਾਪਸ 1;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
ਪੂਰਨ
do_exec_no_pty(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	pid_t pid;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
	ਪੂਰਨ pin[2], pout[2], perr[2];

	ਜੇ (s == ਨਿਰਾ)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	ਜੇ (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		ਵਾਪਸ -1;
	}
	ਜੇ (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		ਵਾਪਸ -1;
	}
#ਨਹੀਂਤਾਂ
	ਪੂਰਨ inout[2], err[2];

	ਜੇ (s == ਨਿਰਾ)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		ਵਾਪਸ -1;
	}
#ਜੇ_ਅੰਤ

	session_proctitle(s);

	/* Fork the child. */
	ਚੋਣ ((pid = fork())) {
	ਹਾਲਤ -1:
		error_f("fork: %.100s", strerror(errno));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#ਨਹੀਂਤਾਂ
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#ਜੇ_ਅੰਤ
		ਵਾਪਸ -1;
	ਹਾਲਤ 0:
		is_ਬੱਚਾ = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		ਜੇ (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		ਜੇ (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		ਜੇ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		ਜੇ (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#ਨਹੀਂਤਾਂ
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		ਜੇ (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		ਜੇ (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		ਜੇ (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#ਜੇ_ਅੰਤ

		/* Do processing for the child (exec command etc). */
		do_ਬੱਚਾ(ssh, s, command);
		/* NOTREACHED */
	ਮੂਲ:
		ਰੋਕੋ;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	cygwin_ਸੈੱਟ_impersonation_token(INVALID_HANDLE_ਮੁੱਲ);
#ਜੇ_ਅੰਤ

	s->pid = pid;

	/*
	 * Clear loginmsg, since it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
	/* We are the parent.  Close the child sides of the pipes. */
	close(pin[0]);
	close(pout[1]);
	close(perr[1]);

	session_ਸੈੱਟ_fds(ssh, s, pin[1], pout[0], perr[0],
	    s->is_subsystem, 0);
#ਨਹੀਂਤਾਂ
	/* We are the parent.  Close the child sides of the socket pairs. */
	close(inout[0]);
	close(err[0]);

	/*
	 * Enter the interactive session.  Note: server_loop must be able to
	 * handle the case that fdin and fdout are the same.
	 */
	session_ਸੈੱਟ_fds(ssh, s, inout[1], inout[1], err[1],
	    s->is_subsystem, 0);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
ਪੂਰਨ
do_exec_pty(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	ਪੂਰਨ fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	ਜੇ (s == ਨਿਰਾ)
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
	ਜੇ ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		ਵਾਪਸ -1;
	}
	/* we keep a reference to the pty master */
	ਜੇ ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		ਵਾਪਸ -1;
	}

	/* Fork the child. */
	ਚੋਣ ((pid = fork())) {
	ਹਾਲਤ -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		ਵਾਪਸ -1;
	ਹਾਲਤ 0:
		is_ਬੱਚਾ = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		ਜੇ (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		ਜੇ (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		ਜੇ (dup2(ttyfd, 2) == -1)
			error("dup2 stderr: %s", strerror(errno));

		/* Close the extra descriptor for the pseudo tty. */
		close(ttyfd);

		/* record login, etc. similar to login(1) */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_OSF_SIA
		do_login(ssh, s, command);
#ਜੇ_ਅੰਤ
		/*
		 * Do common processing for the child, such as execing
		 * the command.
		 */
		do_ਬੱਚਾ(ssh, s, command);
		/* NOTREACHED */
	ਮੂਲ:
		ਰੋਕੋ;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	cygwin_ਸੈੱਟ_impersonation_token(INVALID_HANDLE_ਮੁੱਲ);
#ਜੇ_ਅੰਤ

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_ਸੈੱਟ_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	ਵਾਪਸ 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
ਪੂਰਨ
do_exec(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	ਪੂਰਨ ret;
	ਅਚਲ ਅੱਖਰ *forced = ਨਿਰਾ, *tty = ਨਿਰਾ;
	ਅੱਖਰ session_type[1024];

	ਜੇ (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} ਨਹੀਂਤਾਂ ਜੇ (auth_opts->force_command != ਨਿਰਾ) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	ਜੇ (forced != ਨਿਰਾ) {
		s->forced = 1;
		ਜੇ (IS_ਅੰਦਰੂਨੀ_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} ਨਹੀਂਤਾਂ ਜੇ (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, ਆਕਾਰ(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} ਨਹੀਂਤਾਂ ਜੇ (s->is_subsystem) {
		snprintf(session_type, ਆਕਾਰ(session_type),
		    "subsystem '%.900s'", s->subsys);
	} ਨਹੀਂਤਾਂ ਜੇ (command == ਨਿਰਾ) {
		snprintf(session_type, ਆਕਾਰ(session_type), "shell");
	} ਨਹੀਂਤਾਂ {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, ਆਕਾਰ(session_type), "command");
	}

	ਜੇ (s->ttyfd != -1) {
		tty = s->tty;
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == ਨਿਰਾ ? "" : " on ",
	    tty == ਨਿਰਾ ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_ਪੋਰਟ(ssh),
	    s->self);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
	ਜੇ (command != ਨਿਰਾ)
		mm_audit_ਲੜੀਵਾਰ_command(command);
	ਨਹੀਂਤਾਂ ਜੇ (s->ttyfd == -1) {
		ਅੱਖਰ *shell = s->pw->pw_shell;

		ਜੇ (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_ਲੜੀਵਾਰ_command(shell);
	}
#ਜੇ_ਅੰਤ
	ਜੇ (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	ਨਹੀਂਤਾਂ
		ret = do_exec_no_pty(ssh, s, command);

	original_command = ਨਿਰਾ;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	ਵਾਪਸ ret;
}

/* administrative, login(1)-like work */
ਖਾਲੀ
do_login(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	socklen_t fromlen;
	ਬਣਤਰ sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, ਆਕਾਰ(from));
	fromlen = ਆਕਾਰ(from);
	ਜੇ (ssh_packet_connection_is_on_socket(ssh)) {
		ਜੇ (getpeername(ssh_packet_get_connection_ਵਿੱਚ(ssh),
		    (ਬਣਤਰ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	ਜੇ (check_quietlogin(s, command))
		ਵਾਪਸ;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
ਖਾਲੀ
do_motd(ਖਾਲੀ)
{
	FILE *f;
	ਅੱਖਰ buf[256];

	ਜੇ (options.print_motd) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#ਨਹੀਂਤਾਂ
		f = fopen("/etc/motd", "r");
#ਜੇ_ਅੰਤ
		ਜੇ (f) {
			ਜਦੋਂ (fgets(buf, ਆਕਾਰ(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
ਪੂਰਨ
check_quietlogin(Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	ਅੱਖਰ buf[256];
	ਬਣਤਰ passwd *pw = s->pw;
	ਬਣਤਰ stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	ਜੇ (command != ਨਿਰਾ)
		ਵਾਪਸ 1;
	snprintf(buf, ਆਕਾਰ(buf), "%.200s/.hushlogin", pw->pw_dir);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
	ਜੇ (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		ਵਾਪਸ 1;
#ਨਹੀਂਤਾਂ
	ਜੇ (stat(buf, &st) >= 0)
		ਵਾਪਸ 1;
#ਜੇ_ਅੰਤ
	ਵਾਪਸ 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
ਸਥਿਰ ਖਾਲੀ
read_environment_file(ਅੱਖਰ ***env, u_int *envsize,
	ਅਚਲ ਅੱਖਰ *filename, ਅਚਲ ਅੱਖਰ *allowlist)
{
	FILE *f;
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ, *cp, *ਮੁੱਲ;
	ਮਾਪ_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	ਜੇ (!f)
		ਵਾਪਸ;

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		ਜੇ (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		ਲਈ (cp = ਸਤਰ; *cp == ' ' || *cp == '\t'; cp++)
			;
		ਜੇ (!*cp || *cp == '#' || *cp == '\n')
			ਜਾਰੀ;

		cp[strcspn(cp, "\n")] = '\0';

		ਮੁੱਲ = strchr(cp, '=');
		ਜੇ (ਮੁੱਲ == ਨਿਰਾ) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			ਜਾਰੀ;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*ਮੁੱਲ = '\0';
		ਮੁੱਲ++;
		ਜੇ (allowlist != ਨਿਰਾ &&
		    ਮੇਲ_ਨਮੂਨਾ_list(cp, allowlist, 0) != 1)
			ਜਾਰੀ;
		ਬੱਚਾ_ਸੈੱਟ_env(env, envsize, cp, ਮੁੱਲ);
	}
	ਮੁਕਤ(ਸਤਰ);
	fclose(f);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
ਸਥਿਰ ਅੱਖਰ *
ਬੱਚਾ_get_env(ਅੱਖਰ **env, ਅਚਲ ਅੱਖਰ *name)
{
	ਪੂਰਨ i;
	ਮਾਪ_t len;

	len = ਲੜੀ_ਲੰਬਾਈ(name);
	ਲਈ (i=0; env[i] != ਨਿਰਾ; i++)
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(name, env[i], len) == 0 && env[i][len] == '=')
			ਵਾਪਸ(env[i] + len + 1);
	ਵਾਪਸ ਨਿਰਾ;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
ਸਥਿਰ ਖਾਲੀ
read_etc_default_login(ਅੱਖਰ ***env, u_int *envsize, uid_t uid)
{
	ਅੱਖਰ **tmpenv = ਨਿਰਾ, *var;
	u_int i, tmpenvsize = 0;
	u_long ਨਕਾਬ;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	ਜੇ (tmpenv == ਨਿਰਾ)
		ਵਾਪਸ;

	ਜੇ (uid == 0)
		var = ਬੱਚਾ_get_env(tmpenv, "SUPATH");
	ਨਹੀਂਤਾਂ
		var = ਬੱਚਾ_get_env(tmpenv, "PATH");
	ਜੇ (var != ਨਿਰਾ)
		ਬੱਚਾ_ਸੈੱਟ_env(env, envsize, "PATH", var);

	ਜੇ ((var = ਬੱਚਾ_get_env(tmpenv, "UMASK")) != ਨਿਰਾ)
		ਜੇ (ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(var, "%5lo", &ਨਕਾਬ) == 1)
			umask((ਬਹੁਲਕ_t)ਨਕਾਬ);

	ਲਈ (i = 0; tmpenv[i] != ਨਿਰਾ; i++)
		ਮੁਕਤ(tmpenv[i]);
	ਮੁਕਤ(tmpenv);
}
#ਜੇ_ਅੰਤ /* HAVE_ETC_DEFAULT_LOGIN */

#ਜੇ defined(USE_PAM) || defined(HAVE_CYGWIN)
ਸਥਿਰ ਖਾਲੀ
copy_environment_denylist(ਅੱਖਰ **ਸਰੋਤ, ਅੱਖਰ ***env, u_int *envsize,
    ਅਚਲ ਅੱਖਰ *denylist)
{
	ਅੱਖਰ *var_name, *var_val;
	ਪੂਰਨ i;

	ਜੇ (ਸਰੋਤ == ਨਿਰਾ)
		ਵਾਪਸ;

	ਲਈ(i = 0; ਸਰੋਤ[i] != ਨਿਰਾ; i++) {
		var_name = xstrdup(ਸਰੋਤ[i]);
		ਜੇ ((var_val = ਲੜੀ_ਖੋਜ(var_name, "=")) == ਨਿਰਾ) {
			ਮੁਕਤ(var_name);
			ਜਾਰੀ;
		}
		*var_val++ = '\0';

		ਜੇ (denylist == ਨਿਰਾ ||
		    ਮੇਲ_ਨਮੂਨਾ_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			ਬੱਚਾ_ਸੈੱਟ_env(env, envsize, var_name, var_val);
		}

		ਮੁਕਤ(var_name);
	}
}
#ਜੇ_ਅੰਤ /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
ਸਥਿਰ ਖਾਲੀ
copy_environment(ਅੱਖਰ **ਸਰੋਤ, ਅੱਖਰ ***env, u_int *envsize)
{
	copy_environment_denylist(ਸਰੋਤ, env, envsize, ਨਿਰਾ);
}
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਅੱਖਰ **
do_ਤਿਆਰੀ_env(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *shell)
{
	ਅੱਖਰ buf[256];
	ਮਾਪ_t n;
	u_int i, envsize;
	ਅੱਖਰ *ocp, *cp, *ਮੁੱਲ, **env, *laddr;
	ਬਣਤਰ passwd *pw = s->pw;
#ਜੇ !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	ਅੱਖਰ *ਰਸਤਾ = ਨਿਰਾ;
#ਜੇ_ਅੰਤ

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, ਆਕਾਰ(ਅੱਖਰ *));
	env[0] = ਨਿਰਾ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		ਅੱਖਰ **p;

		p = fetch_windows_environment();
		copy_environment(p, &env, &envsize);
		free_windows_environment(p);
	}
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	/* Allow any GSSAPI methods that we've used to alter
	 * the child's environment as they see fit
	 */
	ssh_gssapi_do_ਬੱਚਾ(&env, &envsize);
#ਜੇ_ਅੰਤ

	/* Set basic environment. */
	ਲਈ (i = 0; i < s->ਅੰਕ_env; i++)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, s->env[i].name, s->env[i].val);

	ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "USER", pw->pw_name);
	ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _AIX
	ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "LOGIN", pw->pw_name);
#ਜੇ_ਅੰਤ
	ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "HOME", pw->pw_dir);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
	ਜੇ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "PATH", _PATH_STDPATH);
	ਨਹੀਂਤਾਂ
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "PATH", getenv("PATH"));
#ਨਹੀਂਤਾਂ /* HAVE_LOGIN_CAP */
# ifndef HAVE_CYGWIN
	/*
	 * There's no standard path on Windows. The path contains
	 * important components pointing to the system directories,
	 * needed for loading shared libraries. So the path better
	 * remains intact here.
	 */
#  ifdef HAVE_ETC_DEFAULT_LOGIN
	read_etc_default_login(&env, &envsize, pw->pw_uid);
	ਰਸਤਾ = ਬੱਚਾ_get_env(env, "PATH");
#  endif /* HAVE_ETC_DEFAULT_LOGIN */
	ਜੇ (ਰਸਤਾ == ਨਿਰਾ || *ਰਸਤਾ == '\0') {
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_ਰਸਤਾ : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#ਜੇ_ਅੰਤ /* HAVE_LOGIN_CAP */

	ਜੇ (!options.use_pam) {
		snprintf(buf, ਆਕਾਰ buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "SHELL", shell);

	ਜੇ (getenv("TZ"))
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "TZ", getenv("TZ"));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
	ਜੇ (getenv("XDG_RUNTIME_DIR")) {
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#ਜੇ_ਅੰਤ /* HAVE_LOGIN_CAP */
	ਜੇ (s->ਪਦ)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "TERM", s->ਪਦ);
	ਜੇ (s->display)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		ਅੱਖਰ *cp;

		ਜੇ ((cp = getenv("KRB5CCNAME")) != ਨਿਰਾ)
			ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _AIX
	{
		ਅੱਖਰ *cp;

		ਜੇ ((cp = getenv("AUTHSTATE")) != ਨਿਰਾ)
			ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
	ਜੇ (s->authctxt->krb5_ccname)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#ਜੇ_ਅੰਤ
	ਜੇ (auth_sock_name != ਨਿਰਾ)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	ਜੇ (options.permit_user_env) {
		ਲਈ (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			ਜੇ (cp != ਨਿਰਾ) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				ਜੇ (options.permit_user_env_allowlist == ਨਿਰਾ ||
				    ਮੇਲ_ਨਮੂਨਾ_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize,
					    ocp, cp + 1);
			}
			ਮੁਕਤ(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	ਜੇ (options.permit_user_env) {
		snprintf(buf, ਆਕਾਰ buf, "%.200s/%s/environment",
		    pw->pw_dir, ਰਸਤਾ_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	ਜੇ (options.use_pam) {
		ਅੱਖਰ **p;

		/*
		 * Don't allow PAM-internal env vars to leak
		 * back into the session environment.
		 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PAM_ENV_DENYLIST  "SSH_AUTH_INFO*,SSH_CONNECTION*"
		p = fetch_pam_ਬੱਚਾ_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);

		p = fetch_pam_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);
	}
#ਜੇ_ਅੰਤ /* USE_PAM */

	/* Environment specified by admin */
	ਲਈ (i = 0; i < options.ਅੰਕ_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		ਜੇ ((ਮੁੱਲ = strchr(cp, '=')) == ਨਿਰਾ) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*ਮੁੱਲ++ = '\0';
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, cp, ਮੁੱਲ);
		ਮੁਕਤ(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, ਆਕਾਰ buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
	    ssh_local_ਪੋਰਟ(ssh));
	ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_ਵਿੱਚ(ssh));
	snprintf(buf, ਆਕਾਰ buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
	    laddr, ssh_local_ਪੋਰਟ(ssh));
	ਮੁਕਤ(laddr);
	ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "SSH_CONNECTION", buf);

	ਜੇ (tun_fwd_ifnames != ਨਿਰਾ)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	ਜੇ (auth_info_file != ਨਿਰਾ)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	ਜੇ (s->ttyfd != -1)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "SSH_TTY", s->tty);
	ਜੇ (original_command)
		ਬੱਚਾ_ਸੈੱਟ_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	ਜੇ (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		ਲਈ (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	ਵਾਪਸ env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
ਸਥਿਰ ਖਾਲੀ
do_rc_files(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *shell)
{
	FILE *f = ਨਿਰਾ;
	ਅੱਖਰ *cmd = ਨਿਰਾ, *user_rc = ਨਿਰਾ;
	ਪੂਰਨ do_xauth;
	ਬਣਤਰ stat st;

	do_xauth =
	    s->display != ਨਿਰਾ && s->auth_proto != ਨਿਰਾ && s->auth_ਅੰਕੜੇ != ਨਿਰਾ;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, ਰਸਤਾ_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	ਜੇ (!s->is_subsystem && options.adm_forced_command == ਨਿਰਾ &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		ਜੇ (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		ਜੇ (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		ਜੇ (f) {
			ਜੇ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_ਅੰਕੜੇ);
			pclose(f);
		} ਨਹੀਂਤਾਂ
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} ਨਹੀਂਤਾਂ ਜੇ (stat(ਰਸਤਾ_SSH_SYSTEM_RC, &st) >= 0) {
		ਜੇ (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    ਰਸਤਾ_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " ਰਸਤਾ_SSH_SYSTEM_RC, "w");
		ਜੇ (f) {
			ਜੇ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_ਅੰਕੜੇ);
			pclose(f);
		} ਨਹੀਂਤਾਂ
			fprintf(stderr, "Could not run %s\n",
			    ਰਸਤਾ_SSH_SYSTEM_RC);
	} ਨਹੀਂਤਾਂ ਜੇ (do_xauth && options.xauth_location != ਨਿਰਾ) {
		/* Add authority data to .Xauthority if appropriate. */
		ਜੇ (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_ਅੰਕੜੇ);
		}
		ਜੇ (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		ਜੇ (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_ਅੰਕੜੇ);
			pclose(f);
		} ਨਹੀਂਤਾਂ {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	ਮੁਕਤ(cmd);
	ਮੁਕਤ(user_rc);
}

ਸਥਿਰ ਖਾਲੀ
do_nologin(ਬਣਤਰ passwd *pw)
{
	FILE *f = ਨਿਰਾ;
	ਅੱਖਰ buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	ਬਣਤਰ stat sb;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
	ਜੇ (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		ਵਾਪਸ;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#ਨਹੀਂਤਾਂ
	ਜੇ (pw->pw_uid == 0)
		ਵਾਪਸ;
	nl = def_nl;
#ਜੇ_ਅੰਤ
	ਜੇ (stat(nl, &sb) == -1)
		ਵਾਪਸ;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	ਜੇ ((f = fopen(nl, "r")) != ਨਿਰਾ) {
		ਜਦੋਂ (fgets(buf, ਆਕਾਰ(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	ਬਾਹਰ_ਨਿਕਲੋ(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
ਸਥਿਰ ਖਾਲੀ
safely_chroot(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, uid_t uid)
{
	ਅਚਲ ਅੱਖਰ *cp;
	ਅੱਖਰ component[PATH_MAX];
	ਬਣਤਰ stat st;

	ਜੇ (!ਰਸਤਾ_absolute(ਰਸਤਾ))
		fatal("chroot path does not begin at root");
	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ) >= ਆਕਾਰ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ਲਈ (cp = ਰਸਤਾ; cp != ਨਿਰਾ;) {
		ਜੇ ((cp = strchr(cp, '/')) == ਨਿਰਾ)
			strlcpy(component, ਰਸਤਾ, ਆਕਾਰ(component));
		ਨਹੀਂਤਾਂ {
			cp++;
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(component, ਰਸਤਾ, cp - ਰਸਤਾ);
			component[cp - ਰਸਤਾ] = '\0';
		}

		debug3_f("checking '%s'", component);

		ਜੇ (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		ਜੇ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ਨਿਰਾ ? "" : "component ", component);
		ਜੇ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ਨਿਰਾ ? "" : "component ", component);

	}

	ਜੇ (chdir(ਰਸਤਾ) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", ਰਸਤਾ, strerror(errno));
	ਜੇ (chroot(ਰਸਤਾ) == -1)
		fatal("chroot(\"%s\"): %s", ਰਸਤਾ, strerror(errno));
	ਜੇ (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", ਰਸਤਾ);
}

/* Set login name, uid, gid, and groups. */
ਖਾਲੀ
do_setusercontext(ਬਣਤਰ passwd *pw)
{
	ਅੱਖਰ uidstr[32], *chroot_ਰਸਤਾ, *tmp;

	platform_setusercontext(pw);

	ਜੇ (platform_privileged_uidswap()) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
		ਜੇ (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
#ਨਹੀਂਤਾਂ
		ਜੇ (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		ਜੇ (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		/* Initialize the group list. */
		ਜੇ (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		endgrent();
#ਜੇ_ਅੰਤ

		platform_setusercontext_post_groups(pw);

		ਜੇ (!ਵਿੱਚ_chroot && options.chroot_directory != ਨਿਰਾ &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, ਆਕਾਰ(uidstr), "%llu",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)pw->pw_uid);
			chroot_ਰਸਤਾ = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (ਅੱਖਰ *)ਨਿਰਾ);
			safely_chroot(chroot_ਰਸਤਾ, pw->pw_uid);
			ਮੁਕਤ(tmp);
			ਮੁਕਤ(chroot_ਰਸਤਾ);
			/* Make sure we don't attempt to chroot again */
			ਮੁਕਤ(options.chroot_directory);
			options.chroot_directory = ਨਿਰਾ;
			ਵਿੱਚ_chroot = 1;
		}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
		ਜੇ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(ਖਾਲੀ) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#ਨਹੀਂਤਾਂ
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		ਜੇ (!ਵਿੱਚ_chroot && ਸੈੱਟ_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_ਸੈੱਟ_uid(pw);
#ਜੇ_ਅੰਤ
	} ਨਹੀਂਤਾਂ ਜੇ (options.chroot_directory != ਨਿਰਾ &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	ਜੇ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

ਸਥਿਰ ਖਾਲੀ
do_pwchange(Session *s)
{
	fflush(ਨਿਰਾ);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	ਜੇ (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
		setexeccon(ਨਿਰਾ);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PASSWD_NEEDS_USERNAME
		execl(ਰਸਤਾ_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (ਅੱਖਰ *)ਨਿਰਾ);
#ਨਹੀਂਤਾਂ
		execl(ਰਸਤਾ_PASSWD_PROG, "passwd", (ਅੱਖਰ *)ਨਿਰਾ);
#ਜੇ_ਅੰਤ
		perror("passwd");
	} ਨਹੀਂਤਾਂ {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਸਥਿਰ ਖਾਲੀ
ਬੱਚਾ_close_fds(ਬਣਤਰ ssh *ssh)
{
	ਬਾਹਰੀ ਪੂਰਨ auth_sock;

	ਜੇ (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	ਜੇ (ssh_packet_get_connection_ਵਿੱਚ(ssh) ==
	    ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh))
		close(ssh_packet_get_connection_ਵਿੱਚ(ssh));
	ਨਹੀਂਤਾਂ {
		close(ssh_packet_get_connection_ਵਿੱਚ(ssh));
		close(ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh));
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
	log_redirect_stderr_ਮੰਜ਼ਿਲ(ਨਿਰਾ);

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
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ARGV_MAX 10
ਖਾਲੀ
do_ਬੱਚਾ(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	ਬਾਹਰੀ ਅੱਖਰ **environ;
	ਅੱਖਰ **env, *argv[ARGV_MAX], remote_id[512];
	ਅਚਲ ਅੱਖਰ *shell, *shell0;
	ਬਣਤਰ passwd *pw = s->pw;
	ਪੂਰਨ r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, ਆਕਾਰ(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);

	/* Force a password change */
	ਜੇ (s->authctxt->force_pwchange) {
		do_setusercontext(pw);
		ਬੱਚਾ_close_fds(ssh);
		do_pwchange(s);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	/*
	 * Login(1) does this as well, and it needs uid 0 for the "-h"
	 * switch, so we let login(1) to this for us.
	 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_OSF_SIA
	session_ਤਿਆਰੀ_sia(pw, s->ttyfd == -1 ? ਨਿਰਾ : s->tty);
	ਜੇ (!check_quietlogin(s, command))
		do_motd();
#ਨਹੀਂਤਾਂ /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	ਜੇ (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	ਜੇ (!check_quietlogin(s, command))
		display_loginmsg();
#ਜੇ_ਅੰਤ /* HAVE_OSF_SIA */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam && !is_pam_session_open()) {
		debug3("PAM session not opened, exiting");
		display_loginmsg();
		ਬਾਹਰ_ਨਿਕਲੋ(254);
	}
#ਜੇ_ਅੰਤ

	/*
	 * Get the shell from the password data.  An empty shell field is
	 * legal, and means /bin/sh.
	 */
	shell = (pw->pw_shell[0] == '\0') ? _PATH_BSHELL : pw->pw_shell;

	/*
	 * Make sure $SHELL points to the shell from the password file,
	 * even if shell is overridden from login.conf
	 */
	env = do_ਤਿਆਰੀ_env(ssh, s, shell);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
	shell = login_getcapstr(lc, "shell", (ਅੱਖਰ *)shell, (ਅੱਖਰ *)shell);
#ਜੇ_ਅੰਤ

	/*
	 * Close the connection descriptors; note that this is the child, and
	 * the server will still have the socket open, and it is important
	 * that we do not shutdown it.  Note that the descriptors cannot be
	 * closed before building the environment, as we call
	 * ssh_remote_ipaddr there.
	 */
	ਬੱਚਾ_close_fds(ssh);

	/*
	 * Must take new environment into use so that .ssh/rc,
	 * /etc/ssh/sshrc and xauth are run in the proper environment.
	 */
	environ = env;

#ਜੇ defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	ਜੇ (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != ਨਿਰਾ)) {
		ਅੱਖਰ cell[64];

		debug("Getting AFS token");

		k_setpag();

		ਜੇ (k_afs_cell_ਦਾ_file(pw->pw_dir, cell, ਆਕਾਰ(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, ਨਿਰਾ);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, ਨਿਰਾ, ਨਿਰਾ, pw->pw_dir);
	}
#ਜੇ_ਅੰਤ

	/* Change current directory to the user's home directory. */
	ਜੇ (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#ਜੇ_ਅੰਤ
		ਜੇ (r || !ਵਿੱਚ_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		ਜੇ (r)
			ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	ਜੇ (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		ਲਿਖੋ("This service allows sftp connections only.\n");
		fflush(ਨਿਰਾ);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	} ਨਹੀਂਤਾਂ ਜੇ (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		ਬਾਹਰੀ ਪੂਰਨ optind, optreset;
		ਪੂਰਨ sftp_argc;
		ਅੱਖਰ **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, ਅੰਦਰੂਨੀ_SFTP_NAME);
		ਜੇ (argv_ਵੰਡੋ(command == ਨਿਰਾ ? "sftp-server" : command,
		    &sftp_argc, &sftp_argv, 1) != 0) {
			error("internal error: can't split internal-sftp "
			    "arguments");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		optind = optreset = 1;
		__progname = sftp_argv[0];
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
		ssh_selinux_change_context("sftpd_t");
#ਜੇ_ਅੰਤ
		ਬਾਹਰ_ਨਿਕਲੋ(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}

	fflush(ਨਿਰਾ);

	/* Get the last component of the shell name. */
	ਜੇ ((shell0 = strrchr(shell, '/')) != ਨਿਰਾ)
		shell0++;
	ਨਹੀਂਤਾਂ
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	ਜੇ (!command) {
		ਅੱਖਰ argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		ਜੇ (strlcpy(argv0 + 1, shell0, ਆਕਾਰ(argv0) - 1)
		    >= ਆਕਾਰ(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = ਨਿਰਾ;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (ਅੱਖਰ *) shell0;
	argv[1] = "-c";
	argv[2] = (ਅੱਖਰ *) command;
	argv[3] = ਨਿਰਾ;
	execve(shell, argv, env);
	perror(shell);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਖਾਲੀ
session_ਅਣਵਰਤਿਆ(ਪੂਰਨ id)
{
	debug3_f("session id %d unused", id);
	ਜੇ (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, ਆਕਾਰ(*sessions));
	sessions[id].self = id;
	sessions[id].ਵਰਤਿਆ = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = ਨਿਰਾ;
	sessions[id].ਅਗਲਾ_ਅਣਵਰਤਿਆ = sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ;
	sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ = id;
}

Session *
session_new(ਖਾਲੀ)
{
	Session *s, *tmp;

	ਜੇ (sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ == -1) {
		ਜੇ (sessions_nalloc >= options.max_sessions)
			ਵਾਪਸ ਨਿਰਾ;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, ਆਕਾਰ(*sessions));
		ਜੇ (tmp == ਨਿਰਾ) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			ਵਾਪਸ ਨਿਰਾ;
		}
		sessions = tmp;
		session_ਅਣਵਰਤਿਆ(sessions_nalloc++);
	}

	ਜੇ (sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ >= sessions_nalloc ||
	    sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ];
	ਜੇ (s->ਵਰਤਿਆ)
		fatal_f("session %d already used", sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ);
	sessions_ਪਹਿਲਾ_ਅਣਵਰਤਿਆ = s->ਅਗਲਾ_ਅਣਵਰਤਿਆ;
	s->ਵਰਤਿਆ = 1;
	s->ਅਗਲਾ_ਅਣਵਰਤਿਆ = -1;
	debug("session_new: session %d", s->self);

	ਵਾਪਸ s;
}

ਸਥਿਰ ਖਾਲੀ
session_dump(ਖਾਲੀ)
{
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->ਵਰਤਿਆ,
		    s->ਅਗਲਾ_ਅਣਵਰਤਿਆ,
		    s->self,
		    s->chanid,
		    (ਲੰਮਾ)s->pid);
	}
}

ਪੂਰਨ
session_open(Authctxt *authctxt, ਪੂਰਨ chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	ਜੇ (s == ਨਿਰਾ) {
		error("no more sessions");
		ਵਾਪਸ 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	ਜੇ (s->pw == ਨਿਰਾ || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	ਵਾਪਸ 1;
}

Session *
session_by_tty(ਅੱਖਰ *tty)
{
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ਜੇ (s->ਵਰਤਿਆ && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			ਵਾਪਸ s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ Session *
session_by_channel(ਪੂਰਨ id)
{
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ਜੇ (s->ਵਰਤਿਆ && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			ਵਾਪਸ s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ Session *
session_by_x11_channel(ਪੂਰਨ id)
{
	ਪੂਰਨ i, j;

	ਲਈ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		ਜੇ (s->x11_chanids == ਨਿਰਾ || !s->ਵਰਤਿਆ)
			ਜਾਰੀ;
		ਲਈ (j = 0; s->x11_chanids[j] != -1; j++) {
			ਜੇ (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				ਵਾਪਸ s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ Session *
session_by_pid(pid_t pid)
{
	ਪੂਰਨ i;
	debug("session_by_pid: pid %ld", (ਲੰਮਾ)pid);
	ਲਈ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ਜੇ (s->ਵਰਤਿਆ && s->pid == pid)
			ਵਾਪਸ s;
	}
	error("session_by_pid: unknown pid %ld", (ਲੰਮਾ)pid);
	session_dump();
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
session_ਖਿੜਕੀ_change_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_get_u32(ssh, &s->ਖਾਨਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ਪੰਕਤੀ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_ਖਿੜਕੀ_ਮਾਪ(s->ptyfd, s->ਪੰਕਤੀ, s->ਖਾਨਾ, s->xpixel, s->ypixel);
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
session_pty_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਪੂਰਨ r;

	ਜੇ (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		ਵਾਪਸ 0;
	}
	ਜੇ (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		ਵਾਪਸ 0;
	}

	ਜੇ ((r = sshpkt_get_cstring(ssh, &s->ਪਦ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ਖਾਨਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ਪੰਕਤੀ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ਜੇ (strcmp(s->ਪਦ, "") == 0) {
		ਮੁਕਤ(s->ਪਦ);
		s->ਪਦ = ਨਿਰਾ;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	ਜੇ (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, ਆਕਾਰ(s->tty))) {
		ਮੁਕਤ(s->ਪਦ);
		s->ਪਦ = ਨਿਰਾ;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		ਵਾਪਸ 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_ਖਿੜਕੀ_ਮਾਪ(s->ptyfd, s->ਪੰਕਤੀ, s->ਖਾਨਾ, s->xpixel, s->ypixel);

	session_proctitle(s);
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
session_subsystem_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਬਣਤਰ stat st;
	ਪੂਰਨ r, success = 0, ਮਿਲਿਆ = 0;
	ਅੱਖਰ *prog, *cmd, *type;
	u_int i;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &s->subsys, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	ਲਈ (i = 0; i < options.ਅੰਕ_subsystems; i++) {
		ਜੇ (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			ਜਾਰੀ;
		ਮਿਲਿਆ = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_ਦਲੀਲਾਂ[i];
		ਜੇ (strcmp(ਅੰਦਰੂਨੀ_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} ਨਹੀਂਤਾਂ {
			ਜੇ (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_ਸੈੱਟ_xtype(ssh, s->chanid, type);
		ਮੁਕਤ(type);
		success = do_exec(ssh, s, cmd) == 0;
		ਰੋਕੋ;
	}

	ਜੇ (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    ਮਿਲਿਆ ? "execution failed" : "subsystem not found");
	}

	ਵਾਪਸ success;
}

ਸਥਿਰ ਪੂਰਨ
session_x11_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਪੂਰਨ r, success;
	u_char single_connection = 0;

	ਜੇ (s->auth_proto != ਨਿਰਾ || s->auth_ਅੰਕੜੇ != ਨਿਰਾ) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		ਵਾਪਸ 0;
	}
	ਜੇ ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_ਅੰਕੜੇ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	ਜੇ (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_ਅੰਕੜੇ))
		success = session_ਤਿਆਰੀ_x11fwd(ssh, s);
	ਨਹੀਂਤਾਂ {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	ਜੇ (!success) {
		ਮੁਕਤ(s->auth_proto);
		ਮੁਕਤ(s->auth_ਅੰਕੜੇ);
		s->auth_proto = ਨਿਰਾ;
		s->auth_ਅੰਕੜੇ = ਨਿਰਾ;
	}
	ਵਾਪਸ success;
}

ਸਥਿਰ ਪੂਰਨ
session_shell_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_ਸੈੱਟ_xtype(ssh, s->chanid, "session:shell");

	ਵਾਪਸ do_exec(ssh, s, ਨਿਰਾ) == 0;
}

ਸਥਿਰ ਪੂਰਨ
session_exec_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	u_int success;
	ਪੂਰਨ r;
	ਅੱਖਰ *command = ਨਿਰਾ;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &command, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_ਸੈੱਟ_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	ਮੁਕਤ(command);
	ਵਾਪਸ success;
}

ਸਥਿਰ ਪੂਰਨ
session_break_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_get_u32(ssh, ਨਿਰਾ)) != 0 || /* ignore */
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ਜੇ (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
session_env_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਅੱਖਰ *name, *val;
	u_int i;
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &name, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	ਜੇ (s->ਅੰਕ_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		ਜਾਓ fail;
	}

	ਲਈ (i = 0; i < options.ਅੰਕ_accept_env; i++) {
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->ਅੰਕ_env, name, val);
			s->env = xrecallocarray(s->env, s->ਅੰਕ_env,
			    s->ਅੰਕ_env + 1, ਆਕਾਰ(*s->env));
			s->env[s->ਅੰਕ_env].name = name;
			s->env[s->ਅੰਕ_env].val = val;
			s->ਅੰਕ_env++;
			ਵਾਪਸ (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	ਮੁਕਤ(name);
	ਮੁਕਤ(val);
	ਵਾਪਸ (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
ਸਥਿਰ ਪੂਰਨ
name2sig(ਅੱਖਰ *name)
{
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SIG(x) ਜੇ (strcmp(name, #x) == 0) ਵਾਪਸ SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(ਪਦ_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ	SSH_SIG
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
	ਜੇ (strcmp(name, "INFO@openssh.com") == 0)
		ਵਾਪਸ SIGINFO;
#ਜੇ_ਅੰਤ
	ਵਾਪਸ -1;
}

ਸਥਿਰ ਪੂਰਨ
session_signal_req(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਅੱਖਰ *signame = ਨਿਰਾ;
	ਪੂਰਨ r, sig, success = 0;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &signame, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		error_fr(r, "parse");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (ਲੰਮਾ)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	ਜੇ (r != 0) {
		error_f("killpg(%ld, %d): %s", (ਲੰਮਾ)s->pid,
		    sig, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* success */
	success = 1;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(signame);
	ਵਾਪਸ success;
}

ਸਥਿਰ ਪੂਰਨ
session_auth_agent_req(ਬਣਤਰ ssh *ssh, Session *s, ਪੂਰਨ agent_new)
{
	ਸਥਿਰ ਪੂਰਨ called = 0;
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ਜੇ (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		ਵਾਪਸ 0;
	}
	ਜੇ (called)
		ਵਾਪਸ 0;

	called = 1;
	ਵਾਪਸ auth_ਨਿਵੇਸ਼_request_forwarding(ssh, s->pw, agent_new);
}

ਪੂਰਨ
session_ਨਿਵੇਸ਼_channel_req(ਬਣਤਰ ssh *ssh, Channel *c, ਅਚਲ ਅੱਖਰ *rtype)
{
	ਪੂਰਨ success = 0;
	Session *s;

	ਜੇ ((s = session_by_channel(c->self)) == ਨਿਰਾ) {
		logit_f("no session %d req %.100s", c->self, rtype);
		ਵਾਪਸ 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	ਜੇ (c->type == SSH_CHANNEL_LARVAL) {
		ਜੇ (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	ਜੇ (strcmp(rtype, "window-change") == 0) {
		success = session_ਖਿੜਕੀ_change_req(ssh, s);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	ਵਾਪਸ success;
}

ਖਾਲੀ
session_ਸੈੱਟ_fds(ਬਣਤਰ ssh *ssh, Session *s,
    ਪੂਰਨ fdin, ਪੂਰਨ fdout, ਪੂਰਨ fderr, ਪੂਰਨ ignore_fderr, ਪੂਰਨ is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	ਜੇ (s->chanid == -1)
		fatal("no channel for session %d", s->self);
	channel_ਸੈੱਟ_fds(ssh, s->chanid,
	    fdout, fdin, fderr,
	    ignore_fderr ? CHAN_EXTENDED_IGNORE : CHAN_EXTENDED_READ,
	    1, is_tty, CHAN_SES_ਖਿੜਕੀ_DEFAULT);
}

/*
 * Function to perform pty cleanup. Also called if we get aborted abnormally
 * (e.g., due to a dropped connection).
 */
ਖਾਲੀ
session_pty_cleanup2(Session *s)
{
	ਜੇ (s == ਨਿਰਾ) {
		error_f("no session");
		ਵਾਪਸ;
	}
	ਜੇ (s->ttyfd == -1)
		ਵਾਪਸ;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	ਜੇ (s->pid != 0)
		ਰਿਕਾਰਡ_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	ਜੇ (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	ਜੇ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

ਖਾਲੀ
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

ਸਥਿਰ ਅੱਖਰ *
sig2name(ਪੂਰਨ sig)
{
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SIG(x) ਜੇ (sig == SIG ## x) ਵਾਪਸ #x
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
	SSH_SIG(ਪਦ_2);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ	SSH_SIG
	ਵਾਪਸ "SIG@openssh.com";
}

ਸਥਿਰ ਖਾਲੀ
session_close_x11(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id)
{
	Channel *c;

	ਜੇ ((c = channel_by_id(ssh, id)) == ਨਿਰਾ) {
		debug_f("x11 channel %d missing", id);
	} ਨਹੀਂਤਾਂ {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		ਜੇ (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

ਸਥਿਰ ਖਾਲੀ
session_close_single_x11(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ force, ਖਾਲੀ *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	ਜੇ ((s = session_by_x11_channel(id)) == ਨਿਰਾ)
		fatal_f("no x11 channel %d", id);
	ਲਈ (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		ਜੇ (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	ਮੁਕਤ(s->x11_chanids);
	s->x11_chanids = ਨਿਰਾ;
	ਮੁਕਤ(s->display);
	s->display = ਨਿਰਾ;
	ਮੁਕਤ(s->auth_proto);
	s->auth_proto = ਨਿਰਾ;
	ਮੁਕਤ(s->auth_ਅੰਕੜੇ);
	s->auth_ਅੰਕੜੇ = ਨਿਰਾ;
	ਮੁਕਤ(s->auth_display);
	s->auth_display = ਨਿਰਾ;
}

ਸਥਿਰ ਖਾਲੀ
session_exit_ਸੁਨੇਹਾ(ਬਣਤਰ ssh *ssh, Session *s, ਪੂਰਨ ਸਥਿਤੀ)
{
	Channel *c;
	ਪੂਰਨ r;
	ਅੱਖਰ *note = ਨਿਰਾ;

	ਜੇ ((c = channel_lookup(ssh, s->chanid)) == ਨਿਰਾ)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	ਜੇ (WIFEXITED(ਸਥਿਤੀ)) {
		channel_request_ਸ਼ੁਰੂ(ssh, s->chanid, "exit-status", 0);
		ਜੇ ((r = sshpkt_put_u32(ssh, WEXITSTATUS(ਸਥਿਤੀ))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(ਸਥਿਤੀ));
	} ਨਹੀਂਤਾਂ ਜੇ (WIFSIGNALED(ਸਥਿਤੀ)) {
		channel_request_ਸ਼ੁਰੂ(ssh, s->chanid, "exit-signal", 0);
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WCOREDUMP
# define WCOREDUMP(x) (0)
#ਜੇ_ਅੰਤ
		ਜੇ ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(ਸਥਿਤੀ)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(ਸਥਿਤੀ)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(ਸਥਿਤੀ),
		    WCOREDUMP(ਸਥਿਤੀ) ? " core dumped" : "");
	} ਨਹੀਂਤਾਂ {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    ਸਥਿਤੀ);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (ਲੰਮਾ)s->pid, note == ਨਿਰਾ ? "UNKNOWN" : note);
	ਮੁਕਤ(note);

	/* disconnect channel */
	debug_f("release channel %d", s->chanid);

	/*
	 * Adjust cleanup callback attachment to send close messages when
	 * the channel gets EOF. The session will be then be closed
	 * by session_close_by_channel when the child sessions close their fds.
	 */
	channel_ਰਜਿਸਟਰ_cleanup(ssh, c->self, session_close_by_channel, 1);

	/*
	 * emulate a write failure with 'chan_write_failed', nobody will be
	 * interested in data we write.
	 * Note that we must not call 'chan_read_failed', since there could
	 * be some more data waiting in the pipe.
	 */
	ਜੇ (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

ਖਾਲੀ
session_close(ਬਣਤਰ ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_ਪੋਰਟ(ssh),
	    s->self);

	ਜੇ (s->ttyfd != -1)
		session_pty_cleanup(s);
	ਮੁਕਤ(s->ਪਦ);
	ਮੁਕਤ(s->display);
	ਮੁਕਤ(s->x11_chanids);
	ਮੁਕਤ(s->auth_display);
	ਮੁਕਤ(s->auth_ਅੰਕੜੇ);
	ਮੁਕਤ(s->auth_proto);
	ਮੁਕਤ(s->subsys);
	ਜੇ (s->env != ਨਿਰਾ) {
		ਲਈ (i = 0; i < s->ਅੰਕ_env; i++) {
			ਮੁਕਤ(s->env[i].name);
			ਮੁਕਤ(s->env[i].val);
		}
		ਮੁਕਤ(s->env);
	}
	session_proctitle(s);
	session_ਅਣਵਰਤਿਆ(s->self);
}

ਖਾਲੀ
session_close_by_pid(ਬਣਤਰ ssh *ssh, pid_t pid, ਪੂਰਨ ਸਥਿਤੀ)
{
	Session *s = session_by_pid(pid);
	ਜੇ (s == ਨਿਰਾ) {
		debug_f("no session for pid %ld", (ਲੰਮਾ)pid);
		ਵਾਪਸ;
	}
	ਜੇ (s->chanid != -1)
		session_exit_ਸੁਨੇਹਾ(ssh, s, ਸਥਿਤੀ);
	ਜੇ (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
ਖਾਲੀ
session_close_by_channel(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ force, ਖਾਲੀ *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	ਜੇ (s == ਨਿਰਾ) {
		debug_f("no session for id %d", id);
		ਵਾਪਸ;
	}
	debug_f("channel %d child %ld", id, (ਲੰਮਾ)s->pid);
	ਜੇ (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		ਜੇ (s->ttyfd != -1)
			session_pty_cleanup(s);
		ਜੇ (!force)
			ਵਾਪਸ;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	ਜੇ (s->x11_chanids != ਨਿਰਾ) {
		ਲਈ (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

ਖਾਲੀ
session_destroy_all(ਬਣਤਰ ssh *ssh, ਖਾਲੀ (*closefunc)(Session *))
{
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ਜੇ (s->ਵਰਤਿਆ) {
			ਜੇ (closefunc != ਨਿਰਾ)
				closefunc(s);
			ਨਹੀਂਤਾਂ
				session_close(ssh, s);
		}
	}
}

ਸਥਿਰ ਅੱਖਰ *
session_tty_list(ਖਾਲੀ)
{
	ਸਥਿਰ ਅੱਖਰ buf[1024];
	ਪੂਰਨ i;
	ਅੱਖਰ *cp;

	buf[0] = '\0';
	ਲਈ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ਜੇ (s->ਵਰਤਿਆ && s->ttyfd != -1) {

			ਜੇ (ਲੜੀ_ਤੁਲਨਾ(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == ਨਿਰਾ) ? s->tty : cp + 1;
			} ਨਹੀਂਤਾਂ
				cp = s->tty + 5;

			ਜੇ (buf[0] != '\0')
				strlcat(buf, ",", ਆਕਾਰ buf);
			strlcat(buf, cp, ਆਕਾਰ buf);
		}
	}
	ਜੇ (buf[0] == '\0')
		strlcpy(buf, "notty", ਆਕਾਰ buf);
	ਵਾਪਸ buf;
}

ਖਾਲੀ
session_proctitle(Session *s)
{
	ਜੇ (s->pw == ਨਿਰਾ)
		error("no user for session %d", s->self);
	ਨਹੀਂਤਾਂ
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

ਪੂਰਨ
session_ਤਿਆਰੀ_x11fwd(ਬਣਤਰ ssh *ssh, Session *s)
{
	ਬਣਤਰ stat st;
	ਅੱਖਰ display[512], auth_display[512];
	ਅੱਖਰ hostname[NI_MAXHOST];
	u_int i;

	ਜੇ (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		ਵਾਪਸ 0;
	}
	ਜੇ (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		ਵਾਪਸ 0;
	}
	ਜੇ (options.xauth_location == ਨਿਰਾ ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		ਵਾਪਸ 0;
	}
	ਜੇ (s->display != ਨਿਰਾ) {
		debug("X11 display already set.");
		ਵਾਪਸ 0;
	}
	ਜੇ (x11_create_display_inet(ssh, options.x11_display_ਵਿੱਥ,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_ਸੰਖਿਆ, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		ਵਾਪਸ 0;
	}
	ਲਈ (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_ਰਜਿਸਟਰ_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	ਜੇ (gethostname(hostname, ਆਕਾਰ(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	ਜੇ (options.x11_use_localhost) {
		snprintf(display, ਆਕਾਰ display, "localhost:%u.%u",
		    s->display_ਸੰਖਿਆ, s->screen);
		snprintf(auth_display, ਆਕਾਰ auth_display, "unix:%u.%u",
		    s->display_ਸੰਖਿਆ, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} ਨਹੀਂਤਾਂ {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ IPADDR_ਵਿੱਚ_DISPLAY
		ਬਣਤਰ hostent *he;
		ਬਣਤਰ in_addr my_addr;

		he = gethostbyname(hostname);
		ਜੇ (he == ਨਿਰਾ) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			ਵਾਪਸ 0;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(&my_addr, he->h_addr_list[0], ਆਕਾਰ(ਬਣਤਰ in_addr));
		snprintf(display, ਆਕਾਰ display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_ਸੰਖਿਆ, s->screen);
#ਨਹੀਂਤਾਂ
		snprintf(display, ਆਕਾਰ display, "%.400s:%u.%u", hostname,
		    s->display_ਸੰਖਿਆ, s->screen);
#ਜੇ_ਅੰਤ
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
do_authenticated2(ਬਣਤਰ ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

ਖਾਲੀ
do_cleanup(ਬਣਤਰ ssh *ssh, Authctxt *authctxt)
{
	ਸਥਿਰ ਪੂਰਨ called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	ਜੇ (is_ਬੱਚਾ)
		ਵਾਪਸ;

	/* avoid double cleanup */
	ਜੇ (called)
		ਵਾਪਸ;
	called = 1;

	ਜੇ (authctxt == ਨਿਰਾ)
		ਵਾਪਸ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#ਜੇ_ਅੰਤ

	ਜੇ (!authctxt->authenticated)
		ਵਾਪਸ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
	ਜੇ (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	ਜੇ (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#ਜੇ_ਅੰਤ

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	ਜੇ (auth_info_file != ਨਿਰਾ) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		ਮੁਕਤ(auth_info_file);
		auth_info_file = ਨਿਰਾ;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	ਜੇ (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

ਅਚਲ ਅੱਖਰ *
session_get_remote_name_or_ip(ਬਣਤਰ ssh *ssh, u_int utmp_ਮਾਪ, ਪੂਰਨ use_dns)
{
	ਅਚਲ ਅੱਖਰ *remote = "";

	ਜੇ (utmp_ਮਾਪ > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	ਜੇ (utmp_ਮਾਪ == 0 || ਲੜੀ_ਲੰਬਾਈ(remote) > utmp_ਮਾਪ)
		remote = ssh_remote_ipaddr(ssh);
	ਵਾਪਸ remote;
}

