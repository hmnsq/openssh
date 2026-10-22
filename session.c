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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>

#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "sshpty.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "sshlogin.h"
#ଅନ୍ତର୍ଭାଵ "serverloop.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "session.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "sftp.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"

#ଯଦି defined(KRB5) && defined(USE_AFS)
#ଅନ୍ତର୍ଭାଵ <kafs.h>
#endif

#ifdef WITH_SELINUX
#ଅନ୍ତର୍ଭାଵ <selinux/selinux.h>
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
	(!strncmp(c, INTERNAL_SFTP_NAME, ଆକାର(INTERNAL_SFTP_NAME) - 1) && \
	 (c[ଆକାର(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[ଆକାର(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[ଆକାର(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(ଶୂନ୍ୟ);
ଶୂନ୍ୟ	session_set_fds(ସଂରଚନା ssh *, Session *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	session_pty_cleanup(Session *);
ଶୂନ୍ୟ	session_proctitle(Session *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	session_setup_x11fwd(ସଂରଚନା ssh *, Session *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	do_exec_pty(ସଂରଚନା ssh *, Session *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	do_exec_no_pty(ସଂରଚନା ssh *, Session *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	do_exec(ସଂରଚନା ssh *, Session *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	do_login(ସଂରଚନା ssh *, Session *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	do_child(ସଂରଚନା ssh *, Session *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	do_motd(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	check_quietlogin(Session *, ଅଚଳ ଅକ୍ଷର *);

ସ୍ଥିର ଶୂନ୍ୟ do_authenticated2(ସଂରଚନା ssh *, Authctxt *);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା session_pty_req(ସଂରଚନା ssh *, Session *);

/* import */
ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ ଅକ୍ଷର *__progname;
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_flag;
ବାହ୍ୟ ସଂରଚନା sshbuf *loginmsg;
ବାହ୍ୟ ସଂରଚନା sshauthopt *auth_opts;
ବାହ୍ୟ ଅକ୍ଷର *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
ଅଚଳ ଅକ୍ଷର *original_command = ଖାଲି;

/* data */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sessions_first_unused = -1;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sessions_nalloc = 0;
ସ୍ଥିର Session *sessions = ଖାଲି;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_child = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
ସ୍ଥିର ଅକ୍ଷର *auth_info_file = ଖାଲି;

/* Name and directory of socket for authentication agent forwarding. */
ସ୍ଥିର ଅକ୍ଷର *auth_sock_name = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *auth_sock_dir = ଖାଲି; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

ସ୍ଥିର ଶୂନ୍ୟ
auth_sock_cleanup_proc(ସଂରଚନା passwd *pw)
{
	ଯଦି (auth_sock_name != ଖାଲି) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		ମୁକ୍ତ(auth_sock_name);
		auth_sock_name = ଖାଲି;
		restore_uid();
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_ନିବେଶ_request_forwarding(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *pw, ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_new)
{
	Channel *nc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock = -1;

	ଯଦି (auth_sock_name != ଖାଲି) {
		error("authentication forwarding requested twice.");
		ଫେରନ୍ତୁ 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	ଯଦି (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		ଯାଅ authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	ଫେରନ୍ତୁ 1;

 authsock_err:
	ମୁକ୍ତ(auth_sock_name);
	ଯଦି (sock != -1)
		close(sock);
	auth_sock_name = ଖାଲି;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
display_loginmsg(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (sshbuf_len(loginmsg) == 0)
		ଫେରନ୍ତୁ;
	ଯଦି ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	printf("%s", (ଅକ୍ଷର *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

ସ୍ଥିର ଶୂନ୍ୟ
prepare_auth_info_file(ସଂରଚନା passwd *pw, ସଂରଚନା sshbuf *info)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd = -1, success = 0;

	ଯଦି (!options.expose_userauth_info || info == ଖାଲି)
		ଫେରନ୍ତୁ;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	ଯଦି ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		ଯାଅ out;
	}
	success = 1;
 out:
	ଯଦି (!success) {
		ଯଦି (fd != -1)
			close(fd);
		ମୁକ୍ତ(auth_info_file);
		auth_info_file = ଖାଲି;
	}
	restore_uid();
}

ସ୍ଥିର ଶୂନ୍ୟ
set_fwdpermit_from_authopts(ସଂରଚନା ssh *ssh, ଅଚଳ ସଂରଚନା sshauthopt *opts)
{
	ଅକ୍ଷର *tmp, *cp, *host;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port;
	size_t i;

	ଯଦି ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		ପାଇଁ (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			ଯଦି ((host = hpdelim2(&cp, ଖାଲି)) == ଖାଲି)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ଯଦି (cp == ଖାଲି || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			ମୁକ୍ତ(tmp);
		}
	}
	ଯଦି ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		ପାଇଁ (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			ଯଦି ((host = hpdelim(&cp)) == ଖାଲି)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ଯଦି (cp == ଖାଲି || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			ମୁକ୍ତ(tmp);
		}
	}
}

ଶୂନ୍ୟ
do_authenticated(ସଂରଚନା ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	ଯଦି (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} ଅନ୍ୟଥା {
		ଯଦି ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		ଅନ୍ୟଥା
			channel_permit_all(ssh, FORWARD_LOCAL);
		ଯଦି ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		ଅନ୍ୟଥା
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
xauth_valid_string(ଅଚଳ ଅକ୍ଷର *s)
{
	size_t i;

	ପାଇଁ (i = 0; s[i] != '\0'; i++) {
		ଯଦି (!isalnum((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_exec_no_pty(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	pid_t pid;
#ifdef USE_PIPES
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pin[2], pout[2], perr[2];

	ଯଦି (s == ଖାଲି)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	ଯଦି (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		ଫେରନ୍ତୁ -1;
	}
#ଅନ୍ୟଥା
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା inout[2], err[2];

	ଯଦି (s == ଖାଲି)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		ଫେରନ୍ତୁ -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	ବାଛ ((pid = fork())) {
	ସ୍ଥିତି -1:
		error_f("fork: %.100s", strerror(errno));
#ifdef USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#ଅନ୍ୟଥା
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#endif
		ଫେରନ୍ତୁ -1;
	ସ୍ଥିତି 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		ଯଦି (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		ଯଦି (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		ଯଦି (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		ଯଦି (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#ଅନ୍ୟଥା
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		ଯଦି (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		ଯଦି (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		ଯଦି (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଭାଙ୍ଗ;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_ମୂଲ୍ୟ);
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
#ଅନ୍ୟଥା
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
	ଫେରନ୍ତୁ 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_exec_pty(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	ଯଦି (s == ଖାଲି)
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
	ଯଦି ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		ଫେରନ୍ତୁ -1;
	}
	/* we keep a reference to the pty master */
	ଯଦି ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		ଫେରନ୍ତୁ -1;
	}

	/* Fork the child. */
	ବାଛ ((pid = fork())) {
	ସ୍ଥିତି -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		ଫେରନ୍ତୁ -1;
	ସ୍ଥିତି 0:
		is_child = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		ଯଦି (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		ଯଦି (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		ଯଦି (dup2(ttyfd, 2) == -1)
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
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଭାଙ୍ଗ;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_ମୂଲ୍ୟ);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	ଫେରନ୍ତୁ 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_exec(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;
	ଅଚଳ ଅକ୍ଷର *forced = ଖାଲି, *tty = ଖାଲି;
	ଅକ୍ଷର session_type[1024];

	ଯଦି (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} ଅନ୍ୟଥା ଯଦି (auth_opts->force_command != ଖାଲି) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	ଯଦି (forced != ଖାଲି) {
		s->forced = 1;
		ଯଦି (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} ଅନ୍ୟଥା ଯଦି (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, ଆକାର(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} ଅନ୍ୟଥା ଯଦି (s->is_subsystem) {
		snprintf(session_type, ଆକାର(session_type),
		    "subsystem '%.900s'", s->subsys);
	} ଅନ୍ୟଥା ଯଦି (command == ଖାଲି) {
		snprintf(session_type, ଆକାର(session_type), "shell");
	} ଅନ୍ୟଥା {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, ଆକାର(session_type), "command");
	}

	ଯଦି (s->ttyfd != -1) {
		tty = s->tty;
		ଯଦି (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == ଖାଲି ? "" : " on ",
	    tty == ଖାଲି ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	ଯଦି (command != ଖାଲି)
		mm_audit_run_command(command);
	ଅନ୍ୟଥା ଯଦି (s->ttyfd == -1) {
		ଅକ୍ଷର *shell = s->pw->pw_shell;

		ଯଦି (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	ଯଦି (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	ଅନ୍ୟଥା
		ret = do_exec_no_pty(ssh, s, command);

	original_command = ଖାଲି;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	ଫେରନ୍ତୁ ret;
}

/* administrative, login(1)-like work */
ଶୂନ୍ୟ
do_login(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	socklen_t fromlen;
	ସଂରଚନା sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, ଆକାର(from));
	fromlen = ଆକାର(from);
	ଯଦି (ssh_packet_connection_is_on_socket(ssh)) {
		ଯଦି (getpeername(ssh_packet_get_connection_in(ssh),
		    (ସଂରଚନା sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	ଯଦି (check_quietlogin(s, command))
		ଫେରନ୍ତୁ;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
ଶୂନ୍ୟ
do_motd(ଶୂନ୍ୟ)
{
	FILE *f;
	ଅକ୍ଷର buf[256];

	ଯଦି (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#ଅନ୍ୟଥା
		f = fopen("/etc/motd", "r");
#endif
		ଯଦି (f) {
			ଯେତେବେଳେ (fgets(buf, ଆକାର(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_quietlogin(Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	ଅକ୍ଷର buf[256];
	ସଂରଚନା passwd *pw = s->pw;
	ସଂରଚନା stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	ଯଦି (command != ଖାଲି)
		ଫେରନ୍ତୁ 1;
	snprintf(buf, ଆକାର(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	ଯଦି (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		ଫେରନ୍ତୁ 1;
#ଅନ୍ୟଥା
	ଯଦି (stat(buf, &st) >= 0)
		ଫେରନ୍ତୁ 1;
#endif
	ଫେରନ୍ତୁ 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
ସ୍ଥିର ଶୂନ୍ୟ
read_environment_file(ଅକ୍ଷର ***env, u_int *envsize,
	ଅଚଳ ଅକ୍ଷର *filename, ଅଚଳ ଅକ୍ଷର *allowlist)
{
	FILE *f;
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି, *cp, *ମୂଲ୍ୟ;
	size_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	ଯଦି (!f)
		ଫେରନ୍ତୁ;

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		ଯଦି (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		ପାଇଁ (cp = ଧାଡ଼ି; *cp == ' ' || *cp == '\t'; cp++)
			;
		ଯଦି (!*cp || *cp == '#' || *cp == '\n')
			ଜାରି;

		cp[strcspn(cp, "\n")] = '\0';

		ମୂଲ୍ୟ = strchr(cp, '=');
		ଯଦି (ମୂଲ୍ୟ == ଖାଲି) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			ଜାରି;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*ମୂଲ୍ୟ = '\0';
		ମୂଲ୍ୟ++;
		ଯଦି (allowlist != ଖାଲି &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			ଜାରି;
		child_set_env(env, envsize, cp, ମୂଲ୍ୟ);
	}
	ମୁକ୍ତ(ଧାଡ଼ି);
	fclose(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
ସ୍ଥିର ଅକ୍ଷର *
child_get_env(ଅକ୍ଷର **env, ଅଚଳ ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	size_t len;

	len = strlen(name);
	ପାଇଁ (i=0; env[i] != ଖାଲି; i++)
		ଯଦି (strncmp(name, env[i], len) == 0 && env[i][len] == '=')
			ଫେରନ୍ତୁ(env[i] + len + 1);
	ଫେରନ୍ତୁ ଖାଲି;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
ସ୍ଥିର ଶୂନ୍ୟ
read_etc_default_login(ଅକ୍ଷର ***env, u_int *envsize, uid_t uid)
{
	ଅକ୍ଷର **tmpenv = ଖାଲି, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	ଯଦି (tmpenv == ଖାଲି)
		ଫେରନ୍ତୁ;

	ଯଦି (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	ଅନ୍ୟଥା
		var = child_get_env(tmpenv, "PATH");
	ଯଦି (var != ଖାଲି)
		child_set_env(env, envsize, "PATH", var);

	ଯଦି ((var = child_get_env(tmpenv, "UMASK")) != ଖାଲି)
		ଯଦି (sscanf(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	ପାଇଁ (i = 0; tmpenv[i] != ଖାଲି; i++)
		ମୁକ୍ତ(tmpenv[i]);
	ମୁକ୍ତ(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#ଯଦି defined(USE_PAM) || defined(HAVE_CYGWIN)
ସ୍ଥିର ଶୂନ୍ୟ
copy_environment_denylist(ଅକ୍ଷର **source, ଅକ୍ଷର ***env, u_int *envsize,
    ଅଚଳ ଅକ୍ଷର *denylist)
{
	ଅକ୍ଷର *var_name, *var_val;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (source == ଖାଲି)
		ଫେରନ୍ତୁ;

	ପାଇଁ(i = 0; source[i] != ଖାଲି; i++) {
		var_name = xstrdup(source[i]);
		ଯଦି ((var_val = strstr(var_name, "=")) == ଖାଲି) {
			ମୁକ୍ତ(var_name);
			ଜାରି;
		}
		*var_val++ = '\0';

		ଯଦି (denylist == ଖାଲି ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		ମୁକ୍ତ(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
ସ୍ଥିର ଶୂନ୍ୟ
copy_environment(ଅକ୍ଷର **source, ଅକ୍ଷର ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, ଖାଲି);
}
#endif

ସ୍ଥିର ଅକ୍ଷର **
do_setup_env(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *shell)
{
	ଅକ୍ଷର buf[256];
	size_t n;
	u_int i, envsize;
	ଅକ୍ଷର *ocp, *cp, *ମୂଲ୍ୟ, **env, *laddr;
	ସଂରଚନା passwd *pw = s->pw;
#ଯଦି !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	ଅକ୍ଷର *path = ଖାଲି;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, ଆକାର(ଅକ୍ଷର *));
	env[0] = ଖାଲି;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		ଅକ୍ଷର **p;

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
	ପାଇଁ (i = 0; i < s->ଅଙ୍କ_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	ଯଦି (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	ଅନ୍ୟଥା
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#ଅନ୍ୟଥା /* HAVE_LOGIN_CAP */
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
	ଯଦି (path == ଖାଲି || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	ଯଦି (!options.use_pam) {
		snprintf(buf, ଆକାର buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	ଯଦି (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
#ifdef HAVE_LOGIN_CAP
	ଯଦି (getenv("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	ଯଦି (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	ଯଦି (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		ଅକ୍ଷର *cp;

		ଯଦି ((cp = getenv("KRB5CCNAME")) != ଖାଲି)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		ଅକ୍ଷର *cp;

		ଯଦି ((cp = getenv("AUTHSTATE")) != ଖାଲି)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	ଯଦି (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	ଯଦି (auth_sock_name != ଖାଲି)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	ଯଦି (options.permit_user_env) {
		ପାଇଁ (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			ଯଦି (cp != ଖାଲି) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				ଯଦି (options.permit_user_env_allowlist == ଖାଲି ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			ମୁକ୍ତ(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	ଯଦି (options.permit_user_env) {
		snprintf(buf, ଆକାର buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	ଯଦି (options.use_pam) {
		ଅକ୍ଷର **p;

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
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		ଯଦି ((ମୂଲ୍ୟ = strchr(cp, '=')) == ଖାଲି) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*ମୂଲ୍ୟ++ = '\0';
		child_set_env(&env, &envsize, cp, ମୂଲ୍ୟ);
		ମୁକ୍ତ(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, ଆକାର buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, ଆକାର buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	ମୁକ୍ତ(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	ଯଦି (tun_fwd_ifnames != ଖାଲି)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	ଯଦି (auth_info_file != ଖାଲି)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	ଯଦି (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	ଯଦି (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	ଯଦି (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		ପାଇଁ (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	ଫେରନ୍ତୁ env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
ସ୍ଥିର ଶୂନ୍ୟ
do_rc_files(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *shell)
{
	FILE *f = ଖାଲି;
	ଅକ୍ଷର *cmd = ଖାଲି, *user_rc = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_xauth;
	ସଂରଚନା stat st;

	do_xauth =
	    s->display != ଖାଲି && s->auth_proto != ଖାଲି && s->auth_data != ଖାଲି;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	ଯଦି (!s->is_subsystem && options.adm_forced_command == ଖାଲି &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		ଯଦି (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		ଯଦି (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		ଯଦି (f) {
			ଯଦି (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} ଅନ୍ୟଥା
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} ଅନ୍ୟଥା ଯଦି (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		ଯଦି (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		ଯଦି (f) {
			ଯଦି (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} ଅନ୍ୟଥା
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} ଅନ୍ୟଥା ଯଦି (do_xauth && options.xauth_location != ଖାଲି) {
		/* Add authority data to .Xauthority if appropriate. */
		ଯଦି (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		ଯଦି (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		ଯଦି (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} ଅନ୍ୟଥା {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	ମୁକ୍ତ(cmd);
	ମୁକ୍ତ(user_rc);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_nologin(ସଂରଚନା passwd *pw)
{
	FILE *f = ଖାଲି;
	ଅକ୍ଷର buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	ସଂରଚନା stat sb;

#ifdef HAVE_LOGIN_CAP
	ଯଦି (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		ଫେରନ୍ତୁ;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#ଅନ୍ୟଥା
	ଯଦି (pw->pw_uid == 0)
		ଫେରନ୍ତୁ;
	nl = def_nl;
#endif
	ଯଦି (stat(nl, &sb) == -1)
		ଫେରନ୍ତୁ;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	ଯଦି ((f = fopen(nl, "r")) != ଖାଲି) {
		ଯେତେବେଳେ (fgets(buf, ଆକାର(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
ସ୍ଥିର ଶୂନ୍ୟ
safely_chroot(ଅଚଳ ଅକ୍ଷର *path, uid_t uid)
{
	ଅଚଳ ଅକ୍ଷର *cp;
	ଅକ୍ଷର component[PATH_MAX];
	ସଂରଚନା stat st;

	ଯଦି (!path_absolute(path))
		fatal("chroot path does not begin at root");
	ଯଦି (strlen(path) >= ଆକାର(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ପାଇଁ (cp = path; cp != ଖାଲି;) {
		ଯଦି ((cp = strchr(cp, '/')) == ଖାଲି)
			strlcpy(component, path, ଆକାର(component));
		ଅନ୍ୟଥା {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		ଯଦି (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		ଯଦି (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ଖାଲି ? "" : "component ", component);
		ଯଦି (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ଖାଲି ? "" : "component ", component);

	}

	ଯଦି (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	ଯଦି (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	ଯଦି (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
ଶୂନ୍ୟ
do_setusercontext(ସଂରଚନା passwd *pw)
{
	ଅକ୍ଷର uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	ଯଦି (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		ଯଦି (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			exit(1);
		}
#ଅନ୍ୟଥା
		ଯଦି (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		ଯଦି (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			exit(1);
		}
		/* Initialize the group list. */
		ଯଦି (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			exit(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		ଯଦି (!in_chroot && options.chroot_directory != ଖାଲି &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, ଆକାର(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (ଅକ୍ଷର *)ଖାଲି);
			safely_chroot(chroot_path, pw->pw_uid);
			ମୁକ୍ତ(tmp);
			ମୁକ୍ତ(chroot_path);
			/* Make sure we don't attempt to chroot again */
			ମୁକ୍ତ(options.chroot_directory);
			options.chroot_directory = ଖାଲି;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		ଯଦି (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			exit(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(ଶୂନ୍ୟ) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#ଅନ୍ୟଥା
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		ଯଦି (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} ଅନ୍ୟଥା ଯଦି (options.chroot_directory != ଖାଲି &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	ଯଦି (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_pwchange(Session *s)
{
	fflush(ଖାଲି);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	ଯଦି (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(ଖାଲି);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (ଅକ୍ଷର *)ଖାଲି);
#ଅନ୍ୟଥା
		execl(_PATH_PASSWD_PROG, "passwd", (ଅକ୍ଷର *)ଖାଲି);
#endif
		perror("passwd");
	} ଅନ୍ୟଥା {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	exit(1);
}

ସ୍ଥିର ଶୂନ୍ୟ
child_close_fds(ସଂରଚନା ssh *ssh)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_sock;

	ଯଦି (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	ଯଦି (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	ଅନ୍ୟଥା {
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
	log_redirect_stderr_to(ଖାଲି);

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
ଶୂନ୍ୟ
do_child(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	ବାହ୍ୟ ଅକ୍ଷର **environ;
	ଅକ୍ଷର **env, *argv[ARGV_MAX], remote_id[512];
	ଅଚଳ ଅକ୍ଷର *shell, *shell0;
	ସଂରଚନା passwd *pw = s->pw;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, ଆକାର(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ssh);

	/* Force a password change */
	ଯଦି (s->authctxt->force_pwchange) {
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
	session_setup_sia(pw, s->ttyfd == -1 ? ଖାଲି : s->tty);
	ଯଦି (!check_quietlogin(s, command))
		do_motd();
#ଅନ୍ୟଥା /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	ଯଦି (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	ଯଦି (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	ଯଦି (options.use_pam && !is_pam_session_open()) {
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
	shell = login_getcapstr(lc, "shell", (ଅକ୍ଷର *)shell, (ଅକ୍ଷର *)shell);
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

#ଯଦି defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	ଯଦି (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != ଖାଲି)) {
		ଅକ୍ଷର cell[64];

		debug("Getting AFS token");

		k_setpag();

		ଯଦି (k_afs_cell_of_file(pw->pw_dir, cell, ଆକାର(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, ଖାଲି);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, ଖାଲି, ଖାଲି, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	ଯଦି (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		ଯଦି (r || !in_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		ଯଦି (r)
			exit(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	ଯଦି (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(ଖାଲି);
		exit(1);
	} ଅନ୍ୟଥା ଯଦି (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind, optreset;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_argc;
		ଅକ୍ଷର **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		ଯଦି (argv_split(command == ଖାଲି ? "sftp-server" : command,
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

	fflush(ଖାଲି);

	/* Get the last component of the shell name. */
	ଯଦି ((shell0 = strrchr(shell, '/')) != ଖାଲି)
		shell0++;
	ଅନ୍ୟଥା
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	ଯଦି (!command) {
		ଅକ୍ଷର argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		ଯଦି (strlcpy(argv0 + 1, shell0, ଆକାର(argv0) - 1)
		    >= ଆକାର(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = ଖାଲି;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (ଅକ୍ଷର *) shell0;
	argv[1] = "-c";
	argv[2] = (ଅକ୍ଷର *) command;
	argv[3] = ଖାଲି;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

ଶୂନ୍ୟ
session_unused(ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	debug3_f("session id %d unused", id);
	ଯଦି (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, ଆକାର(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = ଖାଲି;
	sessions[id].next_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(ଶୂନ୍ୟ)
{
	Session *s, *tmp;

	ଯଦି (sessions_first_unused == -1) {
		ଯଦି (sessions_nalloc >= options.max_sessions)
			ଫେରନ୍ତୁ ଖାଲି;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, ଆକାର(*sessions));
		ଯଦି (tmp == ଖାଲି) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			ଫେରନ୍ତୁ ଖାଲି;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	ଯଦି (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	ଯଦି (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->next_unused;
	s->used = 1;
	s->next_unused = -1;
	debug("session_new: session %d", s->self);

	ଫେରନ୍ତୁ s;
}

ସ୍ଥିର ଶୂନ୍ୟ
session_dump(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପାଇଁ (i = 0; i < sessions_nalloc; i++) {
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

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_open(Authctxt *authctxt, ପୂର୍ଣ୍ଣସଂଖ୍ୟା chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	ଯଦି (s == ଖାଲି) {
		error("no more sessions");
		ଫେରନ୍ତୁ 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	ଯଦି (s->pw == ଖାଲି || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	ଫେରନ୍ତୁ 1;
}

Session *
session_by_tty(ଅକ୍ଷର *tty)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପାଇଁ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ଯଦି (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			ଫେରନ୍ତୁ s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର Session *
session_by_channel(ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପାଇଁ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ଯଦି (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			ଫେରନ୍ତୁ s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର Session *
session_by_x11_channel(ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j;

	ପାଇଁ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		ଯଦି (s->x11_chanids == ଖାଲି || !s->used)
			ଜାରି;
		ପାଇଁ (j = 0; s->x11_chanids[j] != -1; j++) {
			ଯଦି (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				ଫେରନ୍ତୁ s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର Session *
session_by_pid(pid_t pid)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	debug("session_by_pid: pid %ld", (long)pid);
	ପାଇଁ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ଯଦି (s->used && s->pid == pid)
			ଫେରନ୍ତୁ s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_window_change_req(ସଂରଚନା ssh *ssh, Session *s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_pty_req(ସଂରଚନା ssh *ssh, Session *s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି ((r = sshpkt_get_cstring(ssh, &s->term, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ଯଦି (strcmp(s->term, "") == 0) {
		ମୁକ୍ତ(s->term);
		s->term = ଖାଲି;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	ଯଦି (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, ଆକାର(s->tty))) {
		ମୁକ୍ତ(s->term);
		s->term = ଖାଲି;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		ଫେରନ୍ତୁ 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_subsystem_req(ସଂରଚନା ssh *ssh, Session *s)
{
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0, found = 0;
	ଅକ୍ଷର *prog, *cmd, *type;
	u_int i;

	ଯଦି ((r = sshpkt_get_cstring(ssh, &s->subsys, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_subsystems; i++) {
		ଯଦି (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			ଜାରି;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		ଯଦି (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} ଅନ୍ୟଥା {
			ଯଦି (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		ମୁକ୍ତ(type);
		success = do_exec(ssh, s, cmd) == 0;
		ଭାଙ୍ଗ;
	}

	ଯଦି (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	ଫେରନ୍ତୁ success;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_x11_req(ସଂରଚନା ssh *ssh, Session *s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success;
	u_char single_connection = 0;

	ଯଦି (s->auth_proto != ଖାଲି || s->auth_data != ଖାଲି) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_data, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	ଯଦି (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_data))
		success = session_setup_x11fwd(ssh, s);
	ଅନ୍ୟଥା {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	ଯଦି (!success) {
		ମୁକ୍ତ(s->auth_proto);
		ମୁକ୍ତ(s->auth_data);
		s->auth_proto = ଖାଲି;
		s->auth_data = ଖାଲି;
	}
	ଫେରନ୍ତୁ success;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_shell_req(ସଂରଚନା ssh *ssh, Session *s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	ଫେରନ୍ତୁ do_exec(ssh, s, ଖାଲି) == 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_exec_req(ସଂରଚନା ssh *ssh, Session *s)
{
	u_int success;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *command = ଖାଲି;

	ଯଦି ((r = sshpkt_get_cstring(ssh, &command, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	ମୁକ୍ତ(command);
	ଫେରନ୍ତୁ success;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_break_req(ସଂରଚନା ssh *ssh, Session *s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_get_u32(ssh, ଖାଲି)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ଯଦି (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_env_req(ସଂରଚନା ssh *ssh, Session *s)
{
	ଅକ୍ଷର *name, *val;
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_get_cstring(ssh, &name, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	ଯଦି (s->ଅଙ୍କ_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		ଯାଅ fail;
	}

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_accept_env; i++) {
		ଯଦି (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->ଅଙ୍କ_env, name, val);
			s->env = xrecallocarray(s->env, s->ଅଙ୍କ_env,
			    s->ଅଙ୍କ_env + 1, ଆକାର(*s->env));
			s->env[s->ଅଙ୍କ_env].name = name;
			s->env[s->ଅଙ୍କ_env].val = val;
			s->ଅଙ୍କ_env++;
			ଫେରନ୍ତୁ (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	ମୁକ୍ତ(name);
	ମୁକ୍ତ(val);
	ଫେରନ୍ତୁ (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
name2sig(ଅକ୍ଷର *name)
{
#define SSH_SIG(x) ଯଦି (strcmp(name, #x) == 0) ଫେରନ୍ତୁ SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	ଯଦି (strcmp(name, "INFO@openssh.com") == 0)
		ଫେରନ୍ତୁ SIGINFO;
#endif
	ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_signal_req(ସଂରଚନା ssh *ssh, Session *s)
{
	ଅକ୍ଷର *signame = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, sig, success = 0;

	ଯଦି ((r = sshpkt_get_cstring(ssh, &signame, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		ଯାଅ out;
	}
	ଯଦି ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		ଯାଅ out;
	}
	ଯଦି (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		ଯାଅ out;
	}
	ଯଦି (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		ଯାଅ out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (long)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	ଯଦି (r != 0) {
		error_f("killpg(%ld, %d): %s", (long)s->pid,
		    sig, strerror(errno));
		ଯାଅ out;
	}

	/* success */
	success = 1;
 out:
	ମୁକ୍ତ(signame);
	ଫେରନ୍ତୁ success;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_auth_agent_req(ସଂରଚନା ssh *ssh, Session *s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_new)
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା called = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ଯଦି (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (called)
		ଫେରନ୍ତୁ 0;

	called = 1;
	ଫେରନ୍ତୁ auth_ନିବେଶ_request_forwarding(ssh, s->pw, agent_new);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_ନିବେଶ_channel_req(ସଂରଚନା ssh *ssh, Channel *c, ଅଚଳ ଅକ୍ଷର *rtype)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success = 0;
	Session *s;

	ଯଦି ((s = session_by_channel(c->self)) == ଖାଲି) {
		logit_f("no session %d req %.100s", c->self, rtype);
		ଫେରନ୍ତୁ 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	ଯଦି (c->type == SSH_CHANNEL_LARVAL) {
		ଯଦି (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	ଯଦି (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	ଫେରନ୍ତୁ success;
}

ଶୂନ୍ୟ
session_set_fds(ସଂରଚନା ssh *ssh, Session *s,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା fdin, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fdout, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fderr, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ignore_fderr, ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	ଯଦି (s->chanid == -1)
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
ଶୂନ୍ୟ
session_pty_cleanup2(Session *s)
{
	ଯଦି (s == ଖାଲି) {
		error_f("no session");
		ଫେରନ୍ତୁ;
	}
	ଯଦି (s->ttyfd == -1)
		ଫେରନ୍ତୁ;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	ଯଦି (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	ଯଦି (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	ଯଦି (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

ଶୂନ୍ୟ
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

ସ୍ଥିର ଅକ୍ଷର *
sig2name(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
#define SSH_SIG(x) ଯଦି (sig == SIG ## x) ଫେରନ୍ତୁ #x
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
	ଫେରନ୍ତୁ "SIG@openssh.com";
}

ସ୍ଥିର ଶୂନ୍ୟ
session_close_x11(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	Channel *c;

	ଯଦି ((c = channel_by_id(ssh, id)) == ଖାଲି) {
		debug_f("x11 channel %d missing", id);
	} ଅନ୍ୟଥା {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		ଯଦି (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
session_close_single_x11(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force, ଶୂନ୍ୟ *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	ଯଦି ((s = session_by_x11_channel(id)) == ଖାଲି)
		fatal_f("no x11 channel %d", id);
	ପାଇଁ (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		ଯଦି (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	ମୁକ୍ତ(s->x11_chanids);
	s->x11_chanids = ଖାଲି;
	ମୁକ୍ତ(s->display);
	s->display = ଖାଲି;
	ମୁକ୍ତ(s->auth_proto);
	s->auth_proto = ଖାଲି;
	ମୁକ୍ତ(s->auth_data);
	s->auth_data = ଖାଲି;
	ମୁକ୍ତ(s->auth_display);
	s->auth_display = ଖାଲି;
}

ସ୍ଥିର ଶୂନ୍ୟ
session_exit_message(ସଂରଚନା ssh *ssh, Session *s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା status)
{
	Channel *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *note = ଖାଲି;

	ଯଦି ((c = channel_lookup(ssh, s->chanid)) == ଖାଲି)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	ଯଦି (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		ଯଦି ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} ଅନ୍ୟଥା ଯଦି (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		ଯଦି ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} ଅନ୍ୟଥା {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (long)s->pid, note == ଖାଲି ? "UNKNOWN" : note);
	ମୁକ୍ତ(note);

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
	ଯଦି (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

ଶୂନ୍ୟ
session_close(ସଂରଚନା ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	ଯଦି (s->ttyfd != -1)
		session_pty_cleanup(s);
	ମୁକ୍ତ(s->term);
	ମୁକ୍ତ(s->display);
	ମୁକ୍ତ(s->x11_chanids);
	ମୁକ୍ତ(s->auth_display);
	ମୁକ୍ତ(s->auth_data);
	ମୁକ୍ତ(s->auth_proto);
	ମୁକ୍ତ(s->subsys);
	ଯଦି (s->env != ଖାଲି) {
		ପାଇଁ (i = 0; i < s->ଅଙ୍କ_env; i++) {
			ମୁକ୍ତ(s->env[i].name);
			ମୁକ୍ତ(s->env[i].val);
		}
		ମୁକ୍ତ(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

ଶୂନ୍ୟ
session_close_by_pid(ସଂରଚନା ssh *ssh, pid_t pid, ପୂର୍ଣ୍ଣସଂଖ୍ୟା status)
{
	Session *s = session_by_pid(pid);
	ଯଦି (s == ଖାଲି) {
		debug_f("no session for pid %ld", (long)pid);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (s->chanid != -1)
		session_exit_message(ssh, s, status);
	ଯଦି (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
ଶୂନ୍ୟ
session_close_by_channel(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force, ଶୂନ୍ୟ *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	ଯଦି (s == ଖାଲି) {
		debug_f("no session for id %d", id);
		ଫେରନ୍ତୁ;
	}
	debug_f("channel %d child %ld", id, (long)s->pid);
	ଯଦି (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		ଯଦି (s->ttyfd != -1)
			session_pty_cleanup(s);
		ଯଦି (!force)
			ଫେରନ୍ତୁ;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	ଯଦି (s->x11_chanids != ଖାଲି) {
		ପାଇଁ (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

ଶୂନ୍ୟ
session_destroy_all(ସଂରଚନା ssh *ssh, ଶୂନ୍ୟ (*closefunc)(Session *))
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପାଇଁ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ଯଦି (s->used) {
			ଯଦି (closefunc != ଖାଲି)
				closefunc(s);
			ଅନ୍ୟଥା
				session_close(ssh, s);
		}
	}
}

ସ୍ଥିର ଅକ୍ଷର *
session_tty_list(ଶୂନ୍ୟ)
{
	ସ୍ଥିର ଅକ୍ଷର buf[1024];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ଅକ୍ଷର *cp;

	buf[0] = '\0';
	ପାଇଁ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ଯଦି (s->used && s->ttyfd != -1) {

			ଯଦି (strncmp(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == ଖାଲି) ? s->tty : cp + 1;
			} ଅନ୍ୟଥା
				cp = s->tty + 5;

			ଯଦି (buf[0] != '\0')
				strlcat(buf, ",", ଆକାର buf);
			strlcat(buf, cp, ଆକାର buf);
		}
	}
	ଯଦି (buf[0] == '\0')
		strlcpy(buf, "notty", ଆକାର buf);
	ଫେରନ୍ତୁ buf;
}

ଶୂନ୍ୟ
session_proctitle(Session *s)
{
	ଯଦି (s->pw == ଖାଲି)
		error("no user for session %d", s->self);
	ଅନ୍ୟଥା
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
session_setup_x11fwd(ସଂରଚନା ssh *ssh, Session *s)
{
	ସଂରଚନା stat st;
	ଅକ୍ଷର display[512], auth_display[512];
	ଅକ୍ଷର hostname[NI_MAXHOST];
	u_int i;

	ଯଦି (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (options.xauth_location == ଖାଲି ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (s->display != ଖାଲି) {
		debug("X11 display already set.");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_ସଂଖ୍ୟା, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		ଫେରନ୍ତୁ 0;
	}
	ପାଇଁ (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	ଯଦି (gethostname(hostname, ଆକାର(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	ଯଦି (options.x11_use_localhost) {
		snprintf(display, ଆକାର display, "localhost:%u.%u",
		    s->display_ସଂଖ୍ୟା, s->screen);
		snprintf(auth_display, ଆକାର auth_display, "unix:%u.%u",
		    s->display_ସଂଖ୍ୟା, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} ଅନ୍ୟଥା {
#ifdef IPADDR_IN_DISPLAY
		ସଂରଚନା hostent *he;
		ସଂରଚନା in_addr my_addr;

		he = gethostbyname(hostname);
		ଯଦି (he == ଖାଲି) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			ଫେରନ୍ତୁ 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], ଆକାର(ସଂରଚନା in_addr));
		snprintf(display, ଆକାର display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_ସଂଖ୍ୟା, s->screen);
#ଅନ୍ୟଥା
		snprintf(display, ଆକାର display, "%.400s:%u.%u", hostname,
		    s->display_ସଂଖ୍ୟା, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
do_authenticated2(ସଂରଚନା ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

ଶୂନ୍ୟ
do_cleanup(ସଂରଚନା ssh *ssh, Authctxt *authctxt)
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	ଯଦି (is_child)
		ଫେରନ୍ତୁ;

	/* avoid double cleanup */
	ଯଦି (called)
		ଫେରନ୍ତୁ;
	called = 1;

	ଯଦି (authctxt == ଖାଲି)
		ଫେରନ୍ତୁ;

#ifdef USE_PAM
	ଯଦି (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	ଯଦି (!authctxt->authenticated)
		ଫେରନ୍ତୁ;

#ifdef KRB5
	ଯଦି (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	ଯଦି (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	ଯଦି (auth_info_file != ଖାଲି) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		ମୁକ୍ତ(auth_info_file);
		auth_info_file = ଖାଲି;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	ଯଦି (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

ଅଚଳ ଅକ୍ଷର *
session_get_remote_name_or_ip(ସଂରଚନା ssh *ssh, u_int utmp_size, ପୂର୍ଣ୍ଣସଂଖ୍ୟା use_dns)
{
	ଅଚଳ ଅକ୍ଷର *remote = "";

	ଯଦି (utmp_size > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	ଯଦି (utmp_size == 0 || strlen(remote) > utmp_size)
		remote = ssh_remote_ipaddr(ssh);
	ଫେରନ୍ତୁ remote;
}

