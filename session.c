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

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "sshpty.h"
#include "packet.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "match.h"
#include "uidswap.h"
#include "channels.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#include "authfd.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "sshlogin.h"
#include "serverloop.h"
#include "canohost.h"
#include "session.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "sftp.h"
#include "atomicio.h"

#ຖ້າ defined(KRB5) && defined(USE_AFS)
#include <kafs.h>
#endif

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
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
	(!strncmp(c, INTERNAL_SFTP_NAME, parimaa_na(INTERNAL_SFTP_NAME) - 1) && \
	 (c[parimaa_na(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[parimaa_na(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[parimaa_na(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(void);
void	session_set_fds(sa_nracanaa ssh *, Session *, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ);
void	session_pty_cleanup(Session *);
void	session_proctitle(Session *);
ຈຳນວນເຕັມ	session_setup_x11fwd(sa_nracanaa ssh *, Session *);
ຈຳນວນເຕັມ	do_exec_pty(sa_nracanaa ssh *, Session *, const var_na *);
ຈຳນວນເຕັມ	do_exec_no_pty(sa_nracanaa ssh *, Session *, const var_na *);
ຈຳນວນເຕັມ	do_exec(sa_nracanaa ssh *, Session *, const var_na *);
void	do_login(sa_nracanaa ssh *, Session *, const var_na *);
void	do_child(sa_nracanaa ssh *, Session *, const var_na *);
void	do_motd(void);
ຈຳນວນເຕັມ	check_quietlogin(Session *, const var_na *);

static void do_authenticated2(sa_nracanaa ssh *, Authctxt *);

static ຈຳນວນເຕັມ session_pty_req(sa_nracanaa ssh *, Session *);

/* import */
extern ServerOptions options;
extern var_na *__progname;
extern ຈຳນວນເຕັມ debug_flag;
extern sa_nracanaa sshbuf *loginmsg;
extern sa_nracanaa sshauthopt *auth_opts;
extern var_na *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
const var_na *original_command = NULL;

/* data */
static ຈຳນວນເຕັມ sessions_first_unused = -1;
static ຈຳນວນເຕັມ sessions_nalloc = 0;
static Session *sessions = NULL;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

static ຈຳນວນເຕັມ is_child = 0;
static ຈຳນວນເຕັມ in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
static var_na *auth_info_file = NULL;

/* Name and directory of socket for authentication agent forwarding. */
static var_na *auth_sock_name = NULL;
static var_na *auth_sock_dir = NULL; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

static void
auth_sock_cleanup_proc(sa_nracanaa passwd *pw)
{
	ຖ້າ (auth_sock_name != NULL) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		free(auth_sock_name);
		auth_sock_name = NULL;
		restore_uid();
	}
}

static ຈຳນວນເຕັມ
auth_input_request_forwarding(sa_nracanaa ssh *ssh, sa_nracanaa passwd *pw, ຈຳນວນເຕັມ agent_new)
{
	Channel *nc;
	ຈຳນວນເຕັມ sock = -1;

	ຖ້າ (auth_sock_name != NULL) {
		error("authentication forwarding requested twice.");
		ສົ່ງຄືນ 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	ຖ້າ (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		goto authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	ສົ່ງຄືນ 1;

 authsock_err:
	free(auth_sock_name);
	ຖ້າ (sock != -1)
		close(sock);
	auth_sock_name = NULL;
	ສົ່ງຄືນ 0;
}

static void
display_loginmsg(void)
{
	ຈຳນວນເຕັມ r;

	ຖ້າ (sshbuf_len(loginmsg) == 0)
		ສົ່ງຄືນ;
	ຖ້າ ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	printf("%s", (var_na *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

static void
prepare_auth_info_file(sa_nracanaa passwd *pw, sa_nracanaa sshbuf *info)
{
	ຈຳນວນເຕັມ fd = -1, success = 0;

	ຖ້າ (!options.expose_userauth_info || info == NULL)
		ສົ່ງຄືນ;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	ຖ້າ ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", strerror(errno));
		goto out;
	}
	ຖ້າ (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", strerror(errno));
		goto out;
	}
	ຖ້າ (close(fd) != 0) {
		error_f("close: %s", strerror(errno));
		goto out;
	}
	success = 1;
 out:
	ຖ້າ (!success) {
		ຖ້າ (fd != -1)
			close(fd);
		free(auth_info_file);
		auth_info_file = NULL;
	}
	restore_uid();
}

static void
set_fwdpermit_from_authopts(sa_nracanaa ssh *ssh, const sa_nracanaa sshauthopt *opts)
{
	var_na *tmp, *cp, *host;
	ຈຳນວນເຕັມ port;
	size_t i;

	ຖ້າ ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		ສຳລັບ (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			ຖ້າ ((host = hpdelim2(&cp, NULL)) == NULL)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ຖ້າ (cp == NULL || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			free(tmp);
		}
	}
	ຖ້າ ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		ສຳລັບ (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			ຖ້າ ((host = hpdelim(&cp)) == NULL)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			ຖ້າ (cp == NULL || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			free(tmp);
		}
	}
}

void
do_authenticated(sa_nracanaa ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	ຖ້າ (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} ບໍ່ດັ່ງນັ້ນ {
		ຖ້າ ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		ບໍ່ດັ່ງນັ້ນ
			channel_permit_all(ssh, FORWARD_LOCAL);
		ຖ້າ ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		ບໍ່ດັ່ງນັ້ນ
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
static ຈຳນວນເຕັມ
xauth_valid_string(const var_na *s)
{
	size_t i;

	ສຳລັບ (i = 0; s[i] != '\0'; i++) {
		ຖ້າ (!isalnum((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			ສົ່ງຄືນ 0;
	}
	ສົ່ງຄືນ 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
ຈຳນວນເຕັມ
do_exec_no_pty(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	pid_t pid;
#ifdef USE_PIPES
	ຈຳນວນເຕັມ pin[2], pout[2], perr[2];

	ຖ້າ (s == NULL)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	ຖ້າ (pipe(pin) == -1) {
		error_f("pipe in: %.100s", strerror(errno));
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (pipe(pout) == -1) {
		error_f("pipe out: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (pipe(perr) == -1) {
		error_f("pipe err: %.100s", strerror(errno));
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		ສົ່ງຄືນ -1;
	}
#ບໍ່ດັ່ງນັ້ນ
	ຈຳນວນເຕັມ inout[2], err[2];

	ຖ້າ (s == NULL)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	ຖ້າ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", strerror(errno));
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", strerror(errno));
		close(inout[0]);
		close(inout[1]);
		ສົ່ງຄືນ -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	switch ((pid = fork())) {
	pak_sa -1:
		error_f("fork: %.100s", strerror(errno));
#ifdef USE_PIPES
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
		close(perr[0]);
		close(perr[1]);
#ບໍ່ດັ່ງນັ້ນ
		close(inout[0]);
		close(inout[1]);
		close(err[0]);
		close(err[1]);
#endif
		ສົ່ງຄືນ -1;
	pak_sa 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		ຖ້າ (setsid() == -1)
			error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		close(pin[1]);
		ຖ້າ (dup2(pin[0], 0) == -1)
			perror("dup2 stdin");
		close(pin[0]);

		/* Redirect stdout. */
		close(pout[0]);
		ຖ້າ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		close(pout[1]);

		/* Redirect stderr. */
		close(perr[0]);
		ຖ້າ (dup2(perr[1], 2) == -1)
			perror("dup2 stderr");
		close(perr[1]);
#ບໍ່ດັ່ງນັ້ນ
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		ຖ້າ (dup2(inout[0], 0) == -1)	/* stdin */
			perror("dup2 stdin");
		ຖ້າ (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			perror("dup2 stdout");
		close(inout[0]);
		ຖ້າ (dup2(err[0], 2) == -1)	/* stderr */
			perror("dup2 stderr");
		close(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	default:
		bha_nga;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_VALUE);
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
#ບໍ່ດັ່ງນັ້ນ
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
	ສົ່ງຄືນ 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
ຈຳນວນເຕັມ
do_exec_pty(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	ຈຳນວນເຕັມ fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	ຖ້າ (s == NULL)
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
	ຖ້າ ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		ສົ່ງຄືນ -1;
	}
	/* we keep a reference to the pty master */
	ຖ້າ ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", strerror(errno));
		close(ttyfd);
		close(ptyfd);
		close(fdout);
		ສົ່ງຄືນ -1;
	}

	/* Fork the child. */
	switch ((pid = fork())) {
	pak_sa -1:
		error_f("fork: %.100s", strerror(errno));
		close(fdout);
		close(ptymaster);
		close(ttyfd);
		close(ptyfd);
		ສົ່ງຄືນ -1;
	pak_sa 0:
		is_child = 1;

		close(fdout);
		close(ptymaster);

		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		ຖ້າ (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", strerror(errno));
		ຖ້າ (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", strerror(errno));
		ຖ້າ (dup2(ttyfd, 2) == -1)
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
	default:
		bha_nga;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_VALUE);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	ສົ່ງຄືນ 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
ຈຳນວນເຕັມ
do_exec(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	ຈຳນວນເຕັມ ret;
	const var_na *forced = NULL, *tty = NULL;
	var_na session_type[1024];

	ຖ້າ (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (auth_opts->force_command != NULL) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	ຖ້າ (forced != NULL) {
		s->forced = 1;
		ຖ້າ (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, parimaa_na(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (s->is_subsystem) {
		snprintf(session_type, parimaa_na(session_type),
		    "subsystem '%.900s'", s->subsys);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (command == NULL) {
		snprintf(session_type, parimaa_na(session_type), "shell");
	} ບໍ່ດັ່ງນັ້ນ {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, parimaa_na(session_type), "command");
	}

	ຖ້າ (s->ttyfd != -1) {
		tty = s->tty;
		ຖ້າ (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == NULL ? "" : " on ",
	    tty == NULL ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	ຖ້າ (command != NULL)
		mm_audit_run_command(command);
	ບໍ່ດັ່ງນັ້ນ ຖ້າ (s->ttyfd == -1) {
		var_na *shell = s->pw->pw_shell;

		ຖ້າ (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	ຖ້າ (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	ບໍ່ດັ່ງນັ້ນ
		ret = do_exec_no_pty(ssh, s, command);

	original_command = NULL;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	ສົ່ງຄືນ ret;
}

/* administrative, login(1)-like work */
void
do_login(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	socklen_t fromlen;
	sa_nracanaa sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, parimaa_na(from));
	fromlen = parimaa_na(from);
	ຖ້າ (ssh_packet_connection_is_on_socket(ssh)) {
		ຖ້າ (getpeername(ssh_packet_get_connection_in(ssh),
		    (sa_nracanaa sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}

	ຖ້າ (check_quietlogin(s, command))
		ສົ່ງຄືນ;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
void
do_motd(void)
{
	FILE *f;
	var_na buf[256];

	ຖ້າ (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#ບໍ່ດັ່ງນັ້ນ
		f = fopen("/etc/motd", "r");
#endif
		ຖ້າ (f) {
			ໃນຂະນະທີ່ (fgets(buf, parimaa_na(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
ຈຳນວນເຕັມ
check_quietlogin(Session *s, const var_na *command)
{
	var_na buf[256];
	sa_nracanaa passwd *pw = s->pw;
	sa_nracanaa stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	ຖ້າ (command != NULL)
		ສົ່ງຄືນ 1;
	snprintf(buf, parimaa_na(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	ຖ້າ (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		ສົ່ງຄືນ 1;
#ບໍ່ດັ່ງນັ້ນ
	ຖ້າ (stat(buf, &st) >= 0)
		ສົ່ງຄືນ 1;
#endif
	ສົ່ງຄືນ 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
static void
read_environment_file(var_na ***env, u_int *envsize,
	const var_na *filename, const var_na *allowlist)
{
	FILE *f;
	var_na *line = NULL, *cp, *value;
	size_t linesize = 0;
	u_int lineno = 0;

	f = fopen(filename, "r");
	ຖ້າ (!f)
		ສົ່ງຄືນ;

	ໃນຂະນະທີ່ (getline(&line, &linesize, f) != -1) {
		ຖ້າ (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		ສຳລັບ (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		ຖ້າ (!*cp || *cp == '#' || *cp == '\n')
			continue;

		cp[strcspn(cp, "\n")] = '\0';

		value = strchr(cp, '=');
		ຖ້າ (value == NULL) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno,
			    filename);
			continue;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*value = '\0';
		value++;
		ຖ້າ (allowlist != NULL &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			continue;
		child_set_env(env, envsize, cp, value);
	}
	free(line);
	fclose(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
static var_na *
child_get_env(var_na **env, const var_na *name)
{
	ຈຳນວນເຕັມ i;
	size_t len;

	len = strlen(name);
	ສຳລັບ (i=0; env[i] != NULL; i++)
		ຖ້າ (strncmp(name, env[i], len) == 0 && env[i][len] == '=')
			ສົ່ງຄືນ(env[i] + len + 1);
	ສົ່ງຄືນ NULL;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
static void
read_etc_default_login(var_na ***env, u_int *envsize, uid_t uid)
{
	var_na **tmpenv = NULL, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	ຖ້າ (tmpenv == NULL)
		ສົ່ງຄືນ;

	ຖ້າ (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	ບໍ່ດັ່ງນັ້ນ
		var = child_get_env(tmpenv, "PATH");
	ຖ້າ (var != NULL)
		child_set_env(env, envsize, "PATH", var);

	ຖ້າ ((var = child_get_env(tmpenv, "UMASK")) != NULL)
		ຖ້າ (sscanf(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	ສຳລັບ (i = 0; tmpenv[i] != NULL; i++)
		free(tmpenv[i]);
	free(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#ຖ້າ defined(USE_PAM) || defined(HAVE_CYGWIN)
static void
copy_environment_denylist(var_na **source, var_na ***env, u_int *envsize,
    const var_na *denylist)
{
	var_na *var_name, *var_val;
	ຈຳນວນເຕັມ i;

	ຖ້າ (source == NULL)
		ສົ່ງຄືນ;

	ສຳລັບ(i = 0; source[i] != NULL; i++) {
		var_name = xstrdup(source[i]);
		ຖ້າ ((var_val = strstr(var_name, "=")) == NULL) {
			free(var_name);
			continue;
		}
		*var_val++ = '\0';

		ຖ້າ (denylist == NULL ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		free(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
static void
copy_environment(var_na **source, var_na ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, NULL);
}
#endif

static var_na **
do_setup_env(sa_nracanaa ssh *ssh, Session *s, const var_na *shell)
{
	var_na buf[256];
	size_t n;
	u_int i, envsize;
	var_na *ocp, *cp, *value, **env, *laddr;
	sa_nracanaa passwd *pw = s->pw;
#ຖ້າ !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	var_na *path = NULL;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, parimaa_na(var_na *));
	env[0] = NULL;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		var_na **p;

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
	ສຳລັບ (i = 0; i < s->num_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	ຖ້າ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	ບໍ່ດັ່ງນັ້ນ
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#ບໍ່ດັ່ງນັ້ນ /* HAVE_LOGIN_CAP */
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
	ຖ້າ (path == NULL || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	ຖ້າ (!options.use_pam) {
		snprintf(buf, parimaa_na buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	ຖ້າ (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
#ifdef HAVE_LOGIN_CAP
	ຖ້າ (getenv("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    getenv("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	ຖ້າ (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	ຖ້າ (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		var_na *cp;

		ຖ້າ ((cp = getenv("KRB5CCNAME")) != NULL)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		var_na *cp;

		ຖ້າ ((cp = getenv("AUTHSTATE")) != NULL)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	ຖ້າ (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	ຖ້າ (auth_sock_name != NULL)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	ຖ້າ (options.permit_user_env) {
		ສຳລັບ (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = strchr(ocp, '=');
			ຖ້າ (cp != NULL) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				ຖ້າ (options.permit_user_env_allowlist == NULL ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			free(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	ຖ້າ (options.permit_user_env) {
		snprintf(buf, parimaa_na buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	ຖ້າ (options.use_pam) {
		var_na **p;

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
	ສຳລັບ (i = 0; i < options.num_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		ຖ້າ ((value = strchr(cp, '=')) == NULL) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*value++ = '\0';
		child_set_env(&env, &envsize, cp, value);
		free(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, parimaa_na buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, parimaa_na buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	free(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	ຖ້າ (tun_fwd_ifnames != NULL)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	ຖ້າ (auth_info_file != NULL)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	ຖ້າ (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	ຖ້າ (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	ຖ້າ (debug_flag) {
		/* dump the environment */
		fprintf(stderr, "Environment:\n");
		ສຳລັບ (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	ສົ່ງຄືນ env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
static void
do_rc_files(sa_nracanaa ssh *ssh, Session *s, const var_na *shell)
{
	FILE *f = NULL;
	var_na *cmd = NULL, *user_rc = NULL;
	ຈຳນວນເຕັມ do_xauth;
	sa_nracanaa stat st;

	do_xauth =
	    s->display != NULL && s->auth_proto != NULL && s->auth_data != NULL;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	ຖ້າ (!s->is_subsystem && options.adm_forced_command == NULL &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		ຖ້າ (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		ຖ້າ (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		ຖ້າ (f) {
			ຖ້າ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} ບໍ່ດັ່ງນັ້ນ
			fprintf(stderr, "Could not run %s\n",
			    user_rc);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		ຖ້າ (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		ຖ້າ (f) {
			ຖ້າ (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} ບໍ່ດັ່ງນັ້ນ
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (do_xauth && options.xauth_location != NULL) {
		/* Add authority data to .Xauthority if appropriate. */
		ຖ້າ (debug_flag) {
			fprintf(stderr,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			fprintf(stderr,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		ຖ້າ (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", strerror(errno));
		f = popen(cmd, "w");
		ຖ້າ (f) {
			fprintf(f, "remove %s\n",
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} ບໍ່ດັ່ງນັ້ນ {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
	free(cmd);
	free(user_rc);
}

static void
do_nologin(sa_nracanaa passwd *pw)
{
	FILE *f = NULL;
	var_na buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	sa_nracanaa stat sb;

#ifdef HAVE_LOGIN_CAP
	ຖ້າ (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		ສົ່ງຄືນ;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#ບໍ່ດັ່ງນັ້ນ
	ຖ້າ (pw->pw_uid == 0)
		ສົ່ງຄືນ;
	nl = def_nl;
#endif
	ຖ້າ (stat(nl, &sb) == -1)
		ສົ່ງຄືນ;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	ຖ້າ ((f = fopen(nl, "r")) != NULL) {
		ໃນຂະນະທີ່ (fgets(buf, parimaa_na(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
static void
safely_chroot(const var_na *path, uid_t uid)
{
	const var_na *cp;
	var_na component[PATH_MAX];
	sa_nracanaa stat st;

	ຖ້າ (!path_absolute(path))
		fatal("chroot path does not begin at root");
	ຖ້າ (strlen(path) >= parimaa_na(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ສຳລັບ (cp = path; cp != NULL;) {
		ຖ້າ ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, parimaa_na(component));
		ບໍ່ດັ່ງນັ້ນ {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		ຖ້າ (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, strerror(errno));
		ຖ້າ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		ຖ້າ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	ຖ້າ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	ຖ້າ (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	ຖ້າ (chdir("/") == -1)
		fatal_f("chdir(/) after chroot: %s", strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
void
do_setusercontext(sa_nracanaa passwd *pw)
{
	var_na uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	ຖ້າ (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		ຖ້າ (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			perror("unable to set user context");
			exit(1);
		}
#ບໍ່ດັ່ງນັ້ນ
		ຖ້າ (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", strerror(errno));
		ຖ້າ (setgid(pw->pw_gid) < 0) {
			perror("setgid");
			exit(1);
		}
		/* Initialize the group list. */
		ຖ້າ (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			perror("initgroups");
			exit(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		ຖ້າ (!in_chroot && options.chroot_directory != NULL &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, parimaa_na(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (var_na *)NULL);
			safely_chroot(chroot_path, pw->pw_uid);
			free(tmp);
			free(chroot_path);
			/* Make sure we don't attempt to chroot again */
			free(options.chroot_directory);
			options.chroot_directory = NULL;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		ຖ້າ (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			perror("unable to set user context (setuser)");
			exit(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(void) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#ບໍ່ດັ່ງນັ້ນ
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		ຖ້າ (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (options.chroot_directory != NULL &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	ຖ້າ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

static void
do_pwchange(Session *s)
{
	fflush(NULL);
	fprintf(stderr, "WARNING: Your password has expired.\n");
	ຖ້າ (s->ttyfd != -1) {
		fprintf(stderr,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(NULL);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (var_na *)NULL);
#ບໍ່ດັ່ງນັ້ນ
		execl(_PATH_PASSWD_PROG, "passwd", (var_na *)NULL);
#endif
		perror("passwd");
	} ບໍ່ດັ່ງນັ້ນ {
		fprintf(stderr,
		    "Password change required but no TTY available.\n");
	}
	exit(1);
}

static void
child_close_fds(sa_nracanaa ssh *ssh)
{
	extern ຈຳນວນເຕັມ auth_sock;

	ຖ້າ (auth_sock != -1) {
		close(auth_sock);
		auth_sock = -1;
	}

	ຖ້າ (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	ບໍ່ດັ່ງນັ້ນ {
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
	log_redirect_stderr_to(NULL);

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
void
do_child(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	extern var_na **environ;
	var_na **env, *argv[ARGV_MAX], remote_id[512];
	const var_na *shell, *shell0;
	sa_nracanaa passwd *pw = s->pw;
	ຈຳນວນເຕັມ r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, parimaa_na(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_keys(ssh);

	/* Force a password change */
	ຖ້າ (s->authctxt->force_pwchange) {
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
	session_setup_sia(pw, s->ttyfd == -1 ? NULL : s->tty);
	ຖ້າ (!check_quietlogin(s, command))
		do_motd();
#ບໍ່ດັ່ງນັ້ນ /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	ຖ້າ (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	ຖ້າ (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	ຖ້າ (options.use_pam && !is_pam_session_open()) {
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
	shell = login_getcapstr(lc, "shell", (var_na *)shell, (var_na *)shell);
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

#ຖ້າ defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	ຖ້າ (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != NULL)) {
		var_na cell[64];

		debug("Getting AFS token");

		k_setpag();

		ຖ້າ (k_afs_cell_of_file(pw->pw_dir, cell, parimaa_na(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, NULL);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, NULL, NULL, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	ຖ້າ (chdir(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		ຖ້າ (r || !in_chroot) {
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
		}
		ຖ້າ (r)
			exit(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, SIG_DFL);

	ຖ້າ (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(NULL);
		exit(1);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		extern ຈຳນວນເຕັມ optind, optreset;
		ຈຳນວນເຕັມ sftp_argc;
		var_na **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		ຖ້າ (argv_split(command == NULL ? "sftp-server" : command,
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

	fflush(NULL);

	/* Get the last component of the shell name. */
	ຖ້າ ((shell0 = strrchr(shell, '/')) != NULL)
		shell0++;
	ບໍ່ດັ່ງນັ້ນ
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	ຖ້າ (!command) {
		var_na argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		ຖ້າ (strlcpy(argv0 + 1, shell0, parimaa_na(argv0) - 1)
		    >= parimaa_na(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = NULL;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (var_na *) shell0;
	argv[1] = "-c";
	argv[2] = (var_na *) command;
	argv[3] = NULL;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

void
session_unused(ຈຳນວນເຕັມ id)
{
	debug3_f("session id %d unused", id);
	ຖ້າ (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	memset(&sessions[id], 0, parimaa_na(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = NULL;
	sessions[id].next_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(void)
{
	Session *s, *tmp;

	ຖ້າ (sessions_first_unused == -1) {
		ຖ້າ (sessions_nalloc >= options.max_sessions)
			ສົ່ງຄືນ NULL;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, parimaa_na(*sessions));
		ຖ້າ (tmp == NULL) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			ສົ່ງຄືນ NULL;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	ຖ້າ (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	ຖ້າ (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->next_unused;
	s->used = 1;
	s->next_unused = -1;
	debug("session_new: session %d", s->self);

	ສົ່ງຄືນ s;
}

static void
session_dump(void)
{
	ຈຳນວນເຕັມ i;
	ສຳລັບ (i = 0; i < sessions_nalloc; i++) {
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

ຈຳນວນເຕັມ
session_open(Authctxt *authctxt, ຈຳນວນເຕັມ chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	ຖ້າ (s == NULL) {
		error("no more sessions");
		ສົ່ງຄືນ 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	ຖ້າ (s->pw == NULL || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	ສົ່ງຄືນ 1;
}

Session *
session_by_tty(var_na *tty)
{
	ຈຳນວນເຕັມ i;
	ສຳລັບ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ຖ້າ (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			ສົ່ງຄືນ s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	ສົ່ງຄືນ NULL;
}

static Session *
session_by_channel(ຈຳນວນເຕັມ id)
{
	ຈຳນວນເຕັມ i;
	ສຳລັບ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ຖ້າ (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			ສົ່ງຄືນ s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	ສົ່ງຄືນ NULL;
}

static Session *
session_by_x11_channel(ຈຳນວນເຕັມ id)
{
	ຈຳນວນເຕັມ i, j;

	ສຳລັບ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		ຖ້າ (s->x11_chanids == NULL || !s->used)
			continue;
		ສຳລັບ (j = 0; s->x11_chanids[j] != -1; j++) {
			ຖ້າ (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				ສົ່ງຄືນ s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	ສົ່ງຄືນ NULL;
}

static Session *
session_by_pid(pid_t pid)
{
	ຈຳນວນເຕັມ i;
	debug("session_by_pid: pid %ld", (long)pid);
	ສຳລັບ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ຖ້າ (s->used && s->pid == pid)
			ສົ່ງຄືນ s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	ສົ່ງຄືນ NULL;
}

static ຈຳນວນເຕັມ
session_window_change_req(sa_nracanaa ssh *ssh, Session *s)
{
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	ສົ່ງຄືນ 1;
}

static ຈຳນວນເຕັມ
session_pty_req(sa_nracanaa ssh *ssh, Session *s)
{
	ຈຳນວນເຕັມ r;

	ຖ້າ (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		ສົ່ງຄືນ 0;
	}
	ຖ້າ (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		ສົ່ງຄືນ 0;
	}

	ຖ້າ ((r = sshpkt_get_cstring(ssh, &s->term, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ຖ້າ (strcmp(s->term, "") == 0) {
		free(s->term);
		s->term = NULL;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	ຖ້າ (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, parimaa_na(s->tty))) {
		free(s->term);
		s->term = NULL;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		ສົ່ງຄືນ 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	ຖ້າ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	ສົ່ງຄືນ 1;
}

static ຈຳນວນເຕັມ
session_subsystem_req(sa_nracanaa ssh *ssh, Session *s)
{
	sa_nracanaa stat st;
	ຈຳນວນເຕັມ r, success = 0, found = 0;
	var_na *prog, *cmd, *type;
	u_int i;

	ຖ້າ ((r = sshpkt_get_cstring(ssh, &s->subsys, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	ສຳລັບ (i = 0; i < options.num_subsystems; i++) {
		ຖ້າ (strcmp(s->subsys, options.subsystem_name[i]) != 0)
			continue;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		ຖ້າ (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} ບໍ່ດັ່ງນັ້ນ {
			ຖ້າ (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, strerror(errno));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		free(type);
		success = do_exec(ssh, s, cmd) == 0;
		bha_nga;
	}

	ຖ້າ (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	ສົ່ງຄືນ success;
}

static ຈຳນວນເຕັມ
session_x11_req(sa_nracanaa ssh *ssh, Session *s)
{
	ຈຳນວນເຕັມ r, success;
	u_char single_connection = 0;

	ຖ້າ (s->auth_proto != NULL || s->auth_data != NULL) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		ສົ່ງຄືນ 0;
	}
	ຖ້າ ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_data, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	ຖ້າ (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_data))
		success = session_setup_x11fwd(ssh, s);
	ບໍ່ດັ່ງນັ້ນ {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	ຖ້າ (!success) {
		free(s->auth_proto);
		free(s->auth_data);
		s->auth_proto = NULL;
		s->auth_data = NULL;
	}
	ສົ່ງຄືນ success;
}

static ຈຳນວນເຕັມ
session_shell_req(sa_nracanaa ssh *ssh, Session *s)
{
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	ສົ່ງຄືນ do_exec(ssh, s, NULL) == 0;
}

static ຈຳນວນເຕັມ
session_exec_req(sa_nracanaa ssh *ssh, Session *s)
{
	u_int success;
	ຈຳນວນເຕັມ r;
	var_na *command = NULL;

	ຖ້າ ((r = sshpkt_get_cstring(ssh, &command, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	free(command);
	ສົ່ງຄືນ success;
}

static ຈຳນວນເຕັມ
session_break_req(sa_nracanaa ssh *ssh, Session *s)
{
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = sshpkt_get_u32(ssh, NULL)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	ຖ້າ (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		ສົ່ງຄືນ 0;
	ສົ່ງຄືນ 1;
}

static ຈຳນວນເຕັມ
session_env_req(sa_nracanaa ssh *ssh, Session *s)
{
	var_na *name, *val;
	u_int i;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = sshpkt_get_cstring(ssh, &name, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	ຖ້າ (s->num_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		goto fail;
	}

	ສຳລັບ (i = 0; i < options.num_accept_env; i++) {
		ຖ້າ (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->num_env, name, val);
			s->env = xrecallocarray(s->env, s->num_env,
			    s->num_env + 1, parimaa_na(*s->env));
			s->env[s->num_env].name = name;
			s->env[s->num_env].val = val;
			s->num_env++;
			ສົ່ງຄືນ (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	free(name);
	free(val);
	ສົ່ງຄືນ (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
static ຈຳນວນເຕັມ
name2sig(var_na *name)
{
#define SSH_SIG(x) ຖ້າ (strcmp(name, #x) == 0) ສົ່ງຄືນ SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	ຖ້າ (strcmp(name, "INFO@openssh.com") == 0)
		ສົ່ງຄືນ SIGINFO;
#endif
	ສົ່ງຄືນ -1;
}

static ຈຳນວນເຕັມ
session_signal_req(sa_nracanaa ssh *ssh, Session *s)
{
	var_na *signame = NULL;
	ຈຳນວນເຕັມ r, sig, success = 0;

	ຖ້າ ((r = sshpkt_get_cstring(ssh, &signame, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	ຖ້າ ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		goto out;
	}
	ຖ້າ (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		goto out;
	}
	ຖ້າ (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		goto out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (long)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	ຖ້າ (r != 0) {
		error_f("killpg(%ld, %d): %s", (long)s->pid,
		    sig, strerror(errno));
		goto out;
	}

	/* success */
	success = 1;
 out:
	free(signame);
	ສົ່ງຄືນ success;
}

static ຈຳນວນເຕັມ
session_auth_agent_req(sa_nracanaa ssh *ssh, Session *s, ຈຳນວນເຕັມ agent_new)
{
	static ຈຳນວນເຕັມ called = 0;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	ຖ້າ (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		ສົ່ງຄືນ 0;
	}
	ຖ້າ (called)
		ສົ່ງຄືນ 0;

	called = 1;
	ສົ່ງຄືນ auth_input_request_forwarding(ssh, s->pw, agent_new);
}

ຈຳນວນເຕັມ
session_input_channel_req(sa_nracanaa ssh *ssh, Channel *c, const var_na *rtype)
{
	ຈຳນວນເຕັມ success = 0;
	Session *s;

	ຖ້າ ((s = session_by_channel(c->self)) == NULL) {
		logit_f("no session %d req %.100s", c->self, rtype);
		ສົ່ງຄືນ 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	ຖ້າ (c->type == SSH_CHANNEL_LARVAL) {
		ຖ້າ (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	ຖ້າ (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	ສົ່ງຄືນ success;
}

void
session_set_fds(sa_nracanaa ssh *ssh, Session *s,
    ຈຳນວນເຕັມ fdin, ຈຳນວນເຕັມ fdout, ຈຳນວນເຕັມ fderr, ຈຳນວນເຕັມ ignore_fderr, ຈຳນວນເຕັມ is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	ຖ້າ (s->chanid == -1)
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
void
session_pty_cleanup2(Session *s)
{
	ຖ້າ (s == NULL) {
		error_f("no session");
		ສົ່ງຄືນ;
	}
	ຖ້າ (s->ttyfd == -1)
		ສົ່ງຄືນ;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	ຖ້າ (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	ຖ້າ (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	ຖ້າ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

void
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

static var_na *
sig2name(ຈຳນວນເຕັມ sig)
{
#define SSH_SIG(x) ຖ້າ (sig == SIG ## x) ສົ່ງຄືນ #x
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
	ສົ່ງຄືນ "SIG@openssh.com";
}

static void
session_close_x11(sa_nracanaa ssh *ssh, ຈຳນວນເຕັມ id)
{
	Channel *c;

	ຖ້າ ((c = channel_by_id(ssh, id)) == NULL) {
		debug_f("x11 channel %d missing", id);
	} ບໍ່ດັ່ງນັ້ນ {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		ຖ້າ (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

static void
session_close_single_x11(sa_nracanaa ssh *ssh, ຈຳນວນເຕັມ id, ຈຳນວນເຕັມ force, void *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	ຖ້າ ((s = session_by_x11_channel(id)) == NULL)
		fatal_f("no x11 channel %d", id);
	ສຳລັບ (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		ຖ້າ (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	free(s->x11_chanids);
	s->x11_chanids = NULL;
	free(s->display);
	s->display = NULL;
	free(s->auth_proto);
	s->auth_proto = NULL;
	free(s->auth_data);
	s->auth_data = NULL;
	free(s->auth_display);
	s->auth_display = NULL;
}

static void
session_exit_message(sa_nracanaa ssh *ssh, Session *s, ຈຳນວນເຕັມ status)
{
	Channel *c;
	ຈຳນວນເຕັມ r;
	var_na *note = NULL;

	ຖ້າ ((c = channel_lookup(ssh, s->chanid)) == NULL)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	ຖ້າ (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		ຖ້າ ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		ຖ້າ ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} ບໍ່ດັ່ງນັ້ນ {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (long)s->pid, note == NULL ? "UNKNOWN" : note);
	free(note);

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
	ຖ້າ (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

void
session_close(sa_nracanaa ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	ຖ້າ (s->ttyfd != -1)
		session_pty_cleanup(s);
	free(s->term);
	free(s->display);
	free(s->x11_chanids);
	free(s->auth_display);
	free(s->auth_data);
	free(s->auth_proto);
	free(s->subsys);
	ຖ້າ (s->env != NULL) {
		ສຳລັບ (i = 0; i < s->num_env; i++) {
			free(s->env[i].name);
			free(s->env[i].val);
		}
		free(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

void
session_close_by_pid(sa_nracanaa ssh *ssh, pid_t pid, ຈຳນວນເຕັມ status)
{
	Session *s = session_by_pid(pid);
	ຖ້າ (s == NULL) {
		debug_f("no session for pid %ld", (long)pid);
		ສົ່ງຄືນ;
	}
	ຖ້າ (s->chanid != -1)
		session_exit_message(ssh, s, status);
	ຖ້າ (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
void
session_close_by_channel(sa_nracanaa ssh *ssh, ຈຳນວນເຕັມ id, ຈຳນວນເຕັມ force, void *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	ຖ້າ (s == NULL) {
		debug_f("no session for id %d", id);
		ສົ່ງຄືນ;
	}
	debug_f("channel %d child %ld", id, (long)s->pid);
	ຖ້າ (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		ຖ້າ (s->ttyfd != -1)
			session_pty_cleanup(s);
		ຖ້າ (!force)
			ສົ່ງຄືນ;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	ຖ້າ (s->x11_chanids != NULL) {
		ສຳລັບ (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

void
session_destroy_all(sa_nracanaa ssh *ssh, void (*closefunc)(Session *))
{
	ຈຳນວນເຕັມ i;
	ສຳລັບ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ຖ້າ (s->used) {
			ຖ້າ (closefunc != NULL)
				closefunc(s);
			ບໍ່ດັ່ງນັ້ນ
				session_close(ssh, s);
		}
	}
}

static var_na *
session_tty_list(void)
{
	static var_na buf[1024];
	ຈຳນວນເຕັມ i;
	var_na *cp;

	buf[0] = '\0';
	ສຳລັບ (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		ຖ້າ (s->used && s->ttyfd != -1) {

			ຖ້າ (strncmp(s->tty, "/dev/", 5) != 0) {
				cp = strrchr(s->tty, '/');
				cp = (cp == NULL) ? s->tty : cp + 1;
			} ບໍ່ດັ່ງນັ້ນ
				cp = s->tty + 5;

			ຖ້າ (buf[0] != '\0')
				strlcat(buf, ",", parimaa_na buf);
			strlcat(buf, cp, parimaa_na buf);
		}
	}
	ຖ້າ (buf[0] == '\0')
		strlcpy(buf, "notty", parimaa_na buf);
	ສົ່ງຄືນ buf;
}

void
session_proctitle(Session *s)
{
	ຖ້າ (s->pw == NULL)
		error("no user for session %d", s->self);
	ບໍ່ດັ່ງນັ້ນ
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

ຈຳນວນເຕັມ
session_setup_x11fwd(sa_nracanaa ssh *ssh, Session *s)
{
	sa_nracanaa stat st;
	var_na display[512], auth_display[512];
	var_na hostname[NI_MAXHOST];
	u_int i;

	ຖ້າ (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		ສົ່ງຄືນ 0;
	}
	ຖ້າ (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		ສົ່ງຄືນ 0;
	}
	ຖ້າ (options.xauth_location == NULL ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		ສົ່ງຄືນ 0;
	}
	ຖ້າ (s->display != NULL) {
		debug("X11 display already set.");
		ສົ່ງຄືນ 0;
	}
	ຖ້າ (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_number, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		ສົ່ງຄືນ 0;
	}
	ສຳລັບ (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	ຖ້າ (gethostname(hostname, parimaa_na(hostname)) == -1)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	ຖ້າ (options.x11_use_localhost) {
		snprintf(display, parimaa_na display, "localhost:%u.%u",
		    s->display_number, s->screen);
		snprintf(auth_display, parimaa_na auth_display, "unix:%u.%u",
		    s->display_number, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} ບໍ່ດັ່ງນັ້ນ {
#ifdef IPADDR_IN_DISPLAY
		sa_nracanaa hostent *he;
		sa_nracanaa in_addr my_addr;

		he = gethostbyname(hostname);
		ຖ້າ (he == NULL) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			ສົ່ງຄືນ 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], parimaa_na(sa_nracanaa in_addr));
		snprintf(display, parimaa_na display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_number, s->screen);
#ບໍ່ດັ່ງນັ້ນ
		snprintf(display, parimaa_na display, "%.400s:%u.%u", hostname,
		    s->display_number, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	ສົ່ງຄືນ 1;
}

static void
do_authenticated2(sa_nracanaa ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

void
do_cleanup(sa_nracanaa ssh *ssh, Authctxt *authctxt)
{
	static ຈຳນວນເຕັມ called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	ຖ້າ (is_child)
		ສົ່ງຄືນ;

	/* avoid double cleanup */
	ຖ້າ (called)
		ສົ່ງຄືນ;
	called = 1;

	ຖ້າ (authctxt == NULL)
		ສົ່ງຄືນ;

#ifdef USE_PAM
	ຖ້າ (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	ຖ້າ (!authctxt->authenticated)
		ສົ່ງຄືນ;

#ifdef KRB5
	ຖ້າ (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	ຖ້າ (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	ຖ້າ (auth_info_file != NULL) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		free(auth_info_file);
		auth_info_file = NULL;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	ຖ້າ (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

const var_na *
session_get_remote_name_or_ip(sa_nracanaa ssh *ssh, u_int utmp_size, ຈຳນວນເຕັມ use_dns)
{
	const var_na *remote = "";

	ຖ້າ (utmp_size > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	ຖ້າ (utmp_size == 0 || strlen(remote) > utmp_size)
		remote = ssh_remote_ipaddr(ssh);
	ສົ່ງຄືນ remote;
}

