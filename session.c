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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/un.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <grp.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "sshlogin.h"
#अन्तर्भाव "serverloop.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "session.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "sftp.h"
#अन्तर्भाव "atomicio.h"

#यदि defined(KRB5) && defined(USE_AFS)
#अन्तर्भाव <kafs.h>
#endif

#ifdef WITH_SELINUX
#अन्तर्भाव <selinux/selinux.h>
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
	(!म_भेदन(c, INTERNAL_SFTP_NAME, परिमाण(INTERNAL_SFTP_NAME) - 1) && \
	 (c[परिमाण(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[परिमाण(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[परिमाण(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(शून्य);
शून्य	session_set_fds(संरचना ssh *, Session *, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
शून्य	session_pty_cleanup(Session *);
शून्य	session_proctitle(Session *);
पूर्णाङ्क	session_setup_x11fwd(संरचना ssh *, Session *);
पूर्णाङ्क	do_exec_pty(संरचना ssh *, Session *, अचर वर्ण *);
पूर्णाङ्क	do_exec_no_pty(संरचना ssh *, Session *, अचर वर्ण *);
पूर्णाङ्क	do_exec(संरचना ssh *, Session *, अचर वर्ण *);
शून्य	do_login(संरचना ssh *, Session *, अचर वर्ण *);
शून्य	do_child(संरचना ssh *, Session *, अचर वर्ण *);
शून्य	do_motd(शून्य);
पूर्णाङ्क	check_quietlogin(Session *, अचर वर्ण *);

स्थिर शून्य do_authenticated2(संरचना ssh *, Authctxt *);

स्थिर पूर्णाङ्क session_pty_req(संरचना ssh *, Session *);

/* import */
बाह्य ServerOptions options;
बाह्य वर्ण *__progname;
बाह्य पूर्णाङ्क debug_flag;
बाह्य संरचना sshbuf *loginmsg;
बाह्य संरचना sshauthopt *auth_opts;
बाह्य वर्ण *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
अचर वर्ण *original_command = रिक्त;

/* data */
स्थिर पूर्णाङ्क sessions_first_unused = -1;
स्थिर पूर्णाङ्क sessions_nalloc = 0;
स्थिर Session *sessions = रिक्त;

#define SUBSYSTEM_NONE			0
#define SUBSYSTEM_EXT			1
#define SUBSYSTEM_INT_SFTP		2
#define SUBSYSTEM_INT_SFTP_ERROR	3

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

स्थिर पूर्णाङ्क is_child = 0;
स्थिर पूर्णाङ्क in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
स्थिर वर्ण *auth_info_file = रिक्त;

/* Name and directory of socket for authentication agent forwarding. */
स्थिर वर्ण *auth_sock_name = रिक्त;
स्थिर वर्ण *auth_sock_dir = रिक्त; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

स्थिर शून्य
auth_sock_cleanup_proc(संरचना passwd *pw)
{
	यदि (auth_sock_name != रिक्त) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		मुक्त(auth_sock_name);
		auth_sock_name = रिक्त;
		restore_uid();
	}
}

स्थिर पूर्णाङ्क
auth_आगत_request_forwarding(संरचना ssh *ssh, संरचना passwd *pw, पूर्णाङ्क agent_new)
{
	Channel *nc;
	पूर्णाङ्क sock = -1;

	यदि (auth_sock_name != रिक्त) {
		error("authentication forwarding requested twice.");
		फर्काऊ 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	यदि (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		गच्छ authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	फर्काऊ 1;

 authsock_err:
	मुक्त(auth_sock_name);
	यदि (sock != -1)
		बंद(sock);
	auth_sock_name = रिक्त;
	फर्काऊ 0;
}

स्थिर शून्य
display_loginmsg(शून्य)
{
	पूर्णाङ्क r;

	यदि (sshbuf_len(loginmsg) == 0)
		फर्काऊ;
	यदि ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	म_लिखो("%s", (वर्ण *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

स्थिर शून्य
prepare_auth_info_file(संरचना passwd *pw, संरचना sshbuf *info)
{
	पूर्णाङ्क fd = -1, success = 0;

	यदि (!options.expose_userauth_info || info == रिक्त)
		फर्काऊ;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	यदि ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	यदि (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	यदि (बंद(fd) != 0) {
		error_f("close: %s", म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	success = 1;
 out:
	यदि (!success) {
		यदि (fd != -1)
			बंद(fd);
		मुक्त(auth_info_file);
		auth_info_file = रिक्त;
	}
	restore_uid();
}

स्थिर शून्य
set_fwdpermit_from_authopts(संरचना ssh *ssh, अचर संरचना sshauthopt *opts)
{
	वर्ण *tmp, *cp, *host;
	पूर्णाङ्क port;
	माप_प्रकार i;

	यदि ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		लागि (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			यदि ((host = hpdelim2(&cp, रिक्त)) == रिक्त)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			यदि (cp == रिक्त || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			मुक्त(tmp);
		}
	}
	यदि ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		लागि (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			यदि ((host = hpdelim(&cp)) == रिक्त)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			यदि (cp == रिक्त || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			मुक्त(tmp);
		}
	}
}

शून्य
do_authenticated(संरचना ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	यदि (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} अन्यथा {
		यदि ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		अन्यथा
			channel_permit_all(ssh, FORWARD_LOCAL);
		यदि ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
			channel_disable_admin(ssh, FORWARD_REMOTE);
		अन्यथा
			channel_permit_all(ssh, FORWARD_REMOTE);
	}
	auth_debug_send(ssh);

	prepare_auth_info_file(authctxt->pw, authctxt->session_info);

	do_authenticated2(ssh, authctxt);

	do_cleanup(ssh, authctxt);
}

/* Check untrusted xauth strings for metacharacters */
स्थिर पूर्णाङ्क
xauth_valid_string(अचर वर्ण *s)
{
	माप_प्रकार i;

	लागि (i = 0; s[i] != '\0'; i++) {
		यदि (!है_अक्षर_अंक((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			फर्काऊ 0;
	}
	फर्काऊ 1;
}

#define USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
पूर्णाङ्क
do_exec_no_pty(संरचना ssh *ssh, Session *s, अचर वर्ण *command)
{
	pid_t pid;
#ifdef USE_PIPES
	पूर्णाङ्क pin[2], pout[2], perr[2];

	यदि (s == रिक्त)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	यदि (pipe(pin) == -1) {
		error_f("pipe in: %.100s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ -1;
	}
	यदि (pipe(pout) == -1) {
		error_f("pipe out: %.100s", म_त्रुटि(त्रुटि_सं));
		बंद(pin[0]);
		बंद(pin[1]);
		फर्काऊ -1;
	}
	यदि (pipe(perr) == -1) {
		error_f("pipe err: %.100s", म_त्रुटि(त्रुटि_सं));
		बंद(pin[0]);
		बंद(pin[1]);
		बंद(pout[0]);
		बंद(pout[1]);
		फर्काऊ -1;
	}
#अन्यथा
	पूर्णाङ्क inout[2], err[2];

	यदि (s == रिक्त)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ -1;
	}
	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", म_त्रुटि(त्रुटि_सं));
		बंद(inout[0]);
		बंद(inout[1]);
		फर्काऊ -1;
	}
#endif

	session_proctitle(s);

	/* Fork the child. */
	विकल्प ((pid = विभाजन())) {
	पक्ष -1:
		error_f("fork: %.100s", म_त्रुटि(त्रुटि_सं));
#ifdef USE_PIPES
		बंद(pin[0]);
		बंद(pin[1]);
		बंद(pout[0]);
		बंद(pout[1]);
		बंद(perr[0]);
		बंद(perr[1]);
#अन्यथा
		बंद(inout[0]);
		बंद(inout[1]);
		बंद(err[0]);
		बंद(err[1]);
#endif
		फर्काऊ -1;
	पक्ष 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		यदि (setsid() == -1)
			error("setsid failed: %.100s", म_त्रुटि(त्रुटि_सं));

#ifdef USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		बंद(pin[1]);
		यदि (dup2(pin[0], 0) == -1)
			लिखो_त्रुटि("dup2 stdin");
		बंद(pin[0]);

		/* Redirect stdout. */
		बंद(pout[0]);
		यदि (dup2(pout[1], 1) == -1)
			लिखो_त्रुटि("dup2 stdout");
		बंद(pout[1]);

		/* Redirect stderr. */
		बंद(perr[0]);
		यदि (dup2(perr[1], 2) == -1)
			लिखो_त्रुटि("dup2 stderr");
		बंद(perr[1]);
#अन्यथा
		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		बंद(inout[1]);
		बंद(err[1]);
		यदि (dup2(inout[0], 0) == -1)	/* stdin */
			लिखो_त्रुटि("dup2 stdin");
		यदि (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			लिखो_त्रुटि("dup2 stdout");
		बंद(inout[0]);
		यदि (dup2(err[0], 2) == -1)	/* stderr */
			लिखो_त्रुटि("dup2 stderr");
		बंद(err[0]);
#endif

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	स्वभाव:
		रोक;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_मान);
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
	बंद(pin[0]);
	बंद(pout[1]);
	बंद(perr[1]);

	session_set_fds(ssh, s, pin[1], pout[0], perr[0],
	    s->is_subsystem, 0);
#अन्यथा
	/* We are the parent.  Close the child sides of the socket pairs. */
	बंद(inout[0]);
	बंद(err[0]);

	/*
	 * Enter the interactive session.  Note: server_loop must be able to
	 * handle the case that fdin and fdout are the same.
	 */
	session_set_fds(ssh, s, inout[1], inout[1], err[1],
	    s->is_subsystem, 0);
#endif
	फर्काऊ 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
पूर्णाङ्क
do_exec_pty(संरचना ssh *ssh, Session *s, अचर वर्ण *command)
{
	पूर्णाङ्क fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	यदि (s == रिक्त)
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
	यदि ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", म_त्रुटि(त्रुटि_सं));
		बंद(ttyfd);
		बंद(ptyfd);
		फर्काऊ -1;
	}
	/* we keep a reference to the pty master */
	यदि ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", म_त्रुटि(त्रुटि_सं));
		बंद(ttyfd);
		बंद(ptyfd);
		बंद(fdout);
		फर्काऊ -1;
	}

	/* Fork the child. */
	विकल्प ((pid = विभाजन())) {
	पक्ष -1:
		error_f("fork: %.100s", म_त्रुटि(त्रुटि_सं));
		बंद(fdout);
		बंद(ptymaster);
		बंद(ttyfd);
		बंद(ptyfd);
		फर्काऊ -1;
	पक्ष 0:
		is_child = 1;

		बंद(fdout);
		बंद(ptymaster);

		/* Close the master side of the pseudo tty. */
		बंद(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		यदि (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", म_त्रुटि(त्रुटि_सं));
		यदि (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", म_त्रुटि(त्रुटि_सं));
		यदि (dup2(ttyfd, 2) == -1)
			error("dup2 stderr: %s", म_त्रुटि(त्रुटि_सं));

		/* Close the extra descriptor for the pseudo tty. */
		बंद(ttyfd);

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
	स्वभाव:
		रोक;
	}

#ifdef HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_मान);
#endif

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	बंद(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	फर्काऊ 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
पूर्णाङ्क
do_exec(संरचना ssh *ssh, Session *s, अचर वर्ण *command)
{
	पूर्णाङ्क ret;
	अचर वर्ण *forced = रिक्त, *tty = रिक्त;
	वर्ण session_type[1024];

	यदि (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} अन्यथा यदि (auth_opts->force_command != रिक्त) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	यदि (forced != रिक्त) {
		s->forced = 1;
		यदि (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} अन्यथा यदि (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, परिमाण(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} अन्यथा यदि (s->is_subsystem) {
		snprintf(session_type, परिमाण(session_type),
		    "subsystem '%.900s'", s->subsys);
	} अन्यथा यदि (command == रिक्त) {
		snprintf(session_type, परिमाण(session_type), "shell");
	} अन्यथा {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, परिमाण(session_type), "command");
	}

	यदि (s->ttyfd != -1) {
		tty = s->tty;
		यदि (म_भेदन(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == रिक्त ? "" : " on ",
	    tty == रिक्त ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#ifdef SSH_AUDIT_EVENTS
	यदि (command != रिक्त)
		mm_audit_run_command(command);
	अन्यथा यदि (s->ttyfd == -1) {
		वर्ण *shell = s->pw->pw_shell;

		यदि (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#endif
	यदि (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	अन्यथा
		ret = do_exec_no_pty(ssh, s, command);

	original_command = रिक्त;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	फर्काऊ ret;
}

/* administrative, login(1)-like work */
शून्य
do_login(संरचना ssh *ssh, Session *s, अचर वर्ण *command)
{
	socklen_t fromlen;
	संरचना sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	स_रखो(&from, 0, परिमाण(from));
	fromlen = परिमाण(from);
	यदि (ssh_packet_connection_is_on_socket(ssh)) {
		यदि (getpeername(ssh_packet_get_connection_in(ssh),
		    (संरचना sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", म_त्रुटि(त्रुटि_सं));
			cleanup_exit(255);
		}
	}

	यदि (check_quietlogin(s, command))
		फर्काऊ;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
शून्य
do_motd(शून्य)
{
	खाता *f;
	वर्ण buf[256];

	यदि (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = ख_खोलो(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#अन्यथा
		f = ख_खोलो("/etc/motd", "r");
#endif
		यदि (f) {
			जबसम्म (ख_माला_लो(buf, परिमाण(buf), f))
				ख_माला_दो(buf, मानक_निकास);
			ख_बंद(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
पूर्णाङ्क
check_quietlogin(Session *s, अचर वर्ण *command)
{
	वर्ण buf[256];
	संरचना passwd *pw = s->pw;
	संरचना stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	यदि (command != रिक्त)
		फर्काऊ 1;
	snprintf(buf, परिमाण(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	यदि (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		फर्काऊ 1;
#अन्यथा
	यदि (stat(buf, &st) >= 0)
		फर्काऊ 1;
#endif
	फर्काऊ 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
स्थिर शून्य
read_environment_file(वर्ण ***env, u_int *envsize,
	अचर वर्ण *filename, अचर वर्ण *allowlist)
{
	खाता *f;
	वर्ण *पङ्क्ति = रिक्त, *cp, *मान;
	माप_प्रकार linesize = 0;
	u_int lineno = 0;

	f = ख_खोलो(filename, "r");
	यदि (!f)
		फर्काऊ;

	जबसम्म (getline(&पङ्क्ति, &linesize, f) != -1) {
		यदि (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		लागि (cp = पङ्क्ति; *cp == ' ' || *cp == '\t'; cp++)
			;
		यदि (!*cp || *cp == '#' || *cp == '\n')
			जारी;

		cp[म_खोज(cp, "\n")] = '\0';

		मान = म_अक्षर(cp, '=');
		यदि (मान == रिक्त) {
			ख_लिखो(मानक_त्रुटि, "Bad line %u in %.100s\n", lineno,
			    filename);
			जारी;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*मान = '\0';
		मान++;
		यदि (allowlist != रिक्त &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			जारी;
		child_set_env(env, envsize, cp, मान);
	}
	मुक्त(पङ्क्ति);
	ख_बंद(f);
}

#ifdef HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
स्थिर वर्ण *
child_get_env(वर्ण **env, अचर वर्ण *name)
{
	पूर्णाङ्क i;
	माप_प्रकार len;

	len = म_माप(name);
	लागि (i=0; env[i] != रिक्त; i++)
		यदि (म_भेदन(name, env[i], len) == 0 && env[i][len] == '=')
			फर्काऊ(env[i] + len + 1);
	फर्काऊ रिक्त;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
स्थिर शून्य
read_etc_default_login(वर्ण ***env, u_int *envsize, uid_t uid)
{
	वर्ण **tmpenv = रिक्त, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	यदि (tmpenv == रिक्त)
		फर्काऊ;

	यदि (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	अन्यथा
		var = child_get_env(tmpenv, "PATH");
	यदि (var != रिक्त)
		child_set_env(env, envsize, "PATH", var);

	यदि ((var = child_get_env(tmpenv, "UMASK")) != रिक्त)
		यदि (माला_पूछो(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	लागि (i = 0; tmpenv[i] != रिक्त; i++)
		मुक्त(tmpenv[i]);
	मुक्त(tmpenv);
}
#endif /* HAVE_ETC_DEFAULT_LOGIN */

#यदि defined(USE_PAM) || defined(HAVE_CYGWIN)
स्थिर शून्य
copy_environment_denylist(वर्ण **source, वर्ण ***env, u_int *envsize,
    अचर वर्ण *denylist)
{
	वर्ण *var_name, *var_val;
	पूर्णाङ्क i;

	यदि (source == रिक्त)
		फर्काऊ;

	लागि(i = 0; source[i] != रिक्त; i++) {
		var_name = xstrdup(source[i]);
		यदि ((var_val = म_माला(var_name, "=")) == रिक्त) {
			मुक्त(var_name);
			जारी;
		}
		*var_val++ = '\0';

		यदि (denylist == रिक्त ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		मुक्त(var_name);
	}
}
#endif /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#ifdef HAVE_CYGWIN
स्थिर शून्य
copy_environment(वर्ण **source, वर्ण ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, रिक्त);
}
#endif

स्थिर वर्ण **
do_setup_env(संरचना ssh *ssh, Session *s, अचर वर्ण *shell)
{
	वर्ण buf[256];
	माप_प्रकार n;
	u_int i, envsize;
	वर्ण *ocp, *cp, *मान, **env, *laddr;
	संरचना passwd *pw = s->pw;
#यदि !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	वर्ण *path = रिक्त;
#endif

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, परिमाण(वर्ण *));
	env[0] = रिक्त;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		वर्ण **p;

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
	लागि (i = 0; i < s->अङ्क_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#ifdef _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#endif
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	यदि (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	अन्यथा
		child_set_env(&env, &envsize, "PATH", दो_पर्या("PATH"));
#अन्यथा /* HAVE_LOGIN_CAP */
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
	यदि (path == रिक्त || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	यदि (!options.use_pam) {
		snprintf(buf, परिमाण buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	यदि (दो_पर्या("TZ"))
		child_set_env(&env, &envsize, "TZ", दो_पर्या("TZ"));
#ifdef HAVE_LOGIN_CAP
	यदि (दो_पर्या("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    दो_पर्या("XDG_RUNTIME_DIR"));
	}
#endif /* HAVE_LOGIN_CAP */
	यदि (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	यदि (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		वर्ण *cp;

		यदि ((cp = दो_पर्या("KRB5CCNAME")) != रिक्त)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#ifdef _AIX
	{
		वर्ण *cp;

		यदि ((cp = दो_पर्या("AUTHSTATE")) != रिक्त)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#endif
#ifdef KRB5
	यदि (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#endif
	यदि (auth_sock_name != रिक्त)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	यदि (options.permit_user_env) {
		लागि (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = म_अक्षर(ocp, '=');
			यदि (cp != रिक्त) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				यदि (options.permit_user_env_allowlist == रिक्त ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			मुक्त(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	यदि (options.permit_user_env) {
		snprintf(buf, परिमाण buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	यदि (options.use_pam) {
		वर्ण **p;

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
	लागि (i = 0; i < options.अङ्क_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		यदि ((मान = म_अक्षर(cp, '=')) == रिक्त) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*मान++ = '\0';
		child_set_env(&env, &envsize, cp, मान);
		मुक्त(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, परिमाण buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, परिमाण buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	मुक्त(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	यदि (tun_fwd_ifnames != रिक्त)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	यदि (auth_info_file != रिक्त)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	यदि (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	यदि (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	यदि (debug_flag) {
		/* dump the environment */
		ख_लिखो(मानक_त्रुटि, "Environment:\n");
		लागि (i = 0; env[i]; i++)
			ख_लिखो(मानक_त्रुटि, "  %.200s\n", env[i]);
	}
	फर्काऊ env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
स्थिर शून्य
do_rc_files(संरचना ssh *ssh, Session *s, अचर वर्ण *shell)
{
	खाता *f = रिक्त;
	वर्ण *cmd = रिक्त, *user_rc = रिक्त;
	पूर्णाङ्क do_xauth;
	संरचना stat st;

	do_xauth =
	    s->display != रिक्त && s->auth_proto != रिक्त && s->auth_data != रिक्त;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	यदि (!s->is_subsystem && options.adm_forced_command == रिक्त &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		यदि (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", म_त्रुटि(त्रुटि_सं));
		यदि (debug_flag)
			ख_लिखो(मानक_त्रुटि, "Running %s\n", cmd);
		f = popen(cmd, "w");
		यदि (f) {
			यदि (do_xauth)
				ख_लिखो(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} अन्यथा
			ख_लिखो(मानक_त्रुटि, "Could not run %s\n",
			    user_rc);
	} अन्यथा यदि (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		यदि (debug_flag)
			ख_लिखो(मानक_त्रुटि, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		यदि (f) {
			यदि (do_xauth)
				ख_लिखो(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} अन्यथा
			ख_लिखो(मानक_त्रुटि, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} अन्यथा यदि (do_xauth && options.xauth_location != रिक्त) {
		/* Add authority data to .Xauthority if appropriate. */
		यदि (debug_flag) {
			ख_लिखो(मानक_त्रुटि,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			ख_लिखो(मानक_त्रुटि,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		यदि (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", म_त्रुटि(त्रुटि_सं));
		f = popen(cmd, "w");
		यदि (f) {
			ख_लिखो(f, "remove %s\n",
			    s->auth_display);
			ख_लिखो(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} अन्यथा {
			ख_लिखो(मानक_त्रुटि, "Could not run %s\n",
			    cmd);
		}
	}
	मुक्त(cmd);
	मुक्त(user_rc);
}

स्थिर शून्य
do_nologin(संरचना passwd *pw)
{
	खाता *f = रिक्त;
	वर्ण buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	संरचना stat sb;

#ifdef HAVE_LOGIN_CAP
	यदि (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		फर्काऊ;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#अन्यथा
	यदि (pw->pw_uid == 0)
		फर्काऊ;
	nl = def_nl;
#endif
	यदि (stat(nl, &sb) == -1)
		फर्काऊ;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	यदि ((f = ख_खोलो(nl, "r")) != रिक्त) {
		जबसम्म (ख_माला_लो(buf, परिमाण(buf), f))
			ख_माला_दो(buf, मानक_त्रुटि);
		ख_बंद(f);
	}
	निकास(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
स्थिर शून्य
safely_chroot(अचर वर्ण *path, uid_t uid)
{
	अचर वर्ण *cp;
	वर्ण component[PATH_MAX];
	संरचना stat st;

	यदि (!path_absolute(path))
		fatal("chroot path does not begin at root");
	यदि (म_माप(path) >= परिमाण(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	लागि (cp = path; cp != रिक्त;) {
		यदि ((cp = म_अक्षर(cp, '/')) == रिक्त)
			strlcpy(component, path, परिमाण(component));
		अन्यथा {
			cp++;
			स_नकल(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		यदि (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, म_त्रुटि(त्रुटि_सं));
		यदि (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == रिक्त ? "" : "component ", component);
		यदि (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == रिक्त ? "" : "component ", component);

	}

	यदि (स_बदलो(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, म_त्रुटि(त्रुटि_सं));
	यदि (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, म_त्रुटि(त्रुटि_सं));
	यदि (स_बदलो("/") == -1)
		fatal_f("chdir(/) after chroot: %s", म_त्रुटि(त्रुटि_सं));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
शून्य
do_setusercontext(संरचना passwd *pw)
{
	वर्ण uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	यदि (platform_privileged_uidswap()) {
#ifdef HAVE_LOGIN_CAP
		यदि (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			लिखो_त्रुटि("unable to set user context");
			निकास(1);
		}
#अन्यथा
		यदि (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", म_त्रुटि(त्रुटि_सं));
		यदि (setgid(pw->pw_gid) < 0) {
			लिखो_त्रुटि("setgid");
			निकास(1);
		}
		/* Initialize the group list. */
		यदि (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			लिखो_त्रुटि("initgroups");
			निकास(1);
		}
		endgrent();
#endif

		platform_setusercontext_post_groups(pw);

		यदि (!in_chroot && options.chroot_directory != रिक्त &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, परिमाण(uidstr), "%llu",
			    (अचिन्हित दीर्घ दीर्घ)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (वर्ण *)रिक्त);
			safely_chroot(chroot_path, pw->pw_uid);
			मुक्त(tmp);
			मुक्त(chroot_path);
			/* Make sure we don't attempt to chroot again */
			मुक्त(options.chroot_directory);
			options.chroot_directory = रिक्त;
			in_chroot = 1;
		}

#ifdef HAVE_LOGIN_CAP
		यदि (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			लिखो_त्रुटि("unable to set user context (setuser)");
			निकास(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(शून्य) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
#अन्यथा
# ifdef USE_LIBIAF
		/*
		 * In a chroot environment, the set_id() will always fail;
		 * typically because of the lack of necessary authentication
		 * services and runtime such as ./usr/lib/libiaf.so,
		 * ./usr/lib/libpam.so.1, and ./etc/passwd We skip it in the
		 * internal sftp chroot case.  We'll lose auditing and ACLs but
		 * permanently_set_uid will take care of the rest.
		 */
		यदि (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#endif
	} अन्यथा यदि (options.chroot_directory != रिक्त &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	यदि (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

स्थिर शून्य
do_pwchange(Session *s)
{
	ख_साफ(रिक्त);
	ख_लिखो(मानक_त्रुटि, "WARNING: Your password has expired.\n");
	यदि (s->ttyfd != -1) {
		ख_लिखो(मानक_त्रुटि,
		    "You must change your password now and log in again!\n");
#ifdef WITH_SELINUX
		setexeccon(रिक्त);
#endif
#ifdef PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (वर्ण *)रिक्त);
#अन्यथा
		execl(_PATH_PASSWD_PROG, "passwd", (वर्ण *)रिक्त);
#endif
		लिखो_त्रुटि("passwd");
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि,
		    "Password change required but no TTY available.\n");
	}
	निकास(1);
}

स्थिर शून्य
child_close_fds(संरचना ssh *ssh)
{
	बाह्य पूर्णाङ्क auth_sock;

	यदि (auth_sock != -1) {
		बंद(auth_sock);
		auth_sock = -1;
	}

	यदि (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		बंद(ssh_packet_get_connection_in(ssh));
	अन्यथा {
		बंद(ssh_packet_get_connection_in(ssh));
		बंद(ssh_packet_get_connection_out(ssh));
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
	log_redirect_stderr_to(रिक्त);

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
शून्य
do_child(संरचना ssh *ssh, Session *s, अचर वर्ण *command)
{
	बाह्य वर्ण **environ;
	वर्ण **env, *argv[ARGV_MAX], remote_id[512];
	अचर वर्ण *shell, *shell0;
	संरचना passwd *pw = s->pw;
	पूर्णाङ्क r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, परिमाण(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_साँचोहरू(ssh);

	/* Force a password change */
	यदि (s->authctxt->force_pwchange) {
		do_setusercontext(pw);
		child_close_fds(ssh);
		do_pwchange(s);
		निकास(1);
	}

	/*
	 * Login(1) does this as well, and it needs uid 0 for the "-h"
	 * switch, so we let login(1) to this for us.
	 */
#ifdef HAVE_OSF_SIA
	session_setup_sia(pw, s->ttyfd == -1 ? रिक्त : s->tty);
	यदि (!check_quietlogin(s, command))
		do_motd();
#अन्यथा /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	यदि (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	यदि (!check_quietlogin(s, command))
		display_loginmsg();
#endif /* HAVE_OSF_SIA */

#ifdef USE_PAM
	यदि (options.use_pam && !is_pam_session_open()) {
		debug3("PAM session not opened, exiting");
		display_loginmsg();
		निकास(254);
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
	shell = login_getcapstr(lc, "shell", (वर्ण *)shell, (वर्ण *)shell);
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

#यदि defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	यदि (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != रिक्त)) {
		वर्ण cell[64];

		debug("Getting AFS token");

		k_setpag();

		यदि (k_afs_cell_of_file(pw->pw_dir, cell, परिमाण(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, रिक्त);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, रिक्त, रिक्त, pw->pw_dir);
	}
#endif

	/* Change current directory to the user's home directory. */
	यदि (स_बदलो(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#ifdef HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#endif
		यदि (r || !in_chroot) {
			ख_लिखो(मानक_त्रुटि, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    म_त्रुटि(त्रुटि_सं));
		}
		यदि (r)
			निकास(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, संक_पूर्व);

	यदि (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		म_लिखो("This service allows sftp connections only.\n");
		ख_साफ(रिक्त);
		निकास(1);
	} अन्यथा यदि (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		बाह्य पूर्णाङ्क optind, optreset;
		पूर्णाङ्क sftp_argc;
		वर्ण **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		यदि (argv_split(command == रिक्त ? "sftp-server" : command,
		    &sftp_argc, &sftp_argv, 1) != 0) {
			error("internal error: can't split internal-sftp "
			    "arguments");
			निकास(1);
		}
		optind = optreset = 1;
		__progname = sftp_argv[0];
#ifdef WITH_SELINUX
		ssh_selinux_change_context("sftpd_t");
#endif
		निकास(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}

	ख_साफ(रिक्त);

	/* Get the last component of the shell name. */
	यदि ((shell0 = म_खोजप(shell, '/')) != रिक्त)
		shell0++;
	अन्यथा
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	यदि (!command) {
		वर्ण argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		यदि (strlcpy(argv0 + 1, shell0, परिमाण(argv0) - 1)
		    >= परिमाण(argv0) - 1) {
			त्रुटि_सं = EINVAL;
			लिखो_त्रुटि(shell);
			निकास(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = रिक्त;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		लिखो_त्रुटि(shell);
		निकास(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (वर्ण *) shell0;
	argv[1] = "-c";
	argv[2] = (वर्ण *) command;
	argv[3] = रिक्त;
	execve(shell, argv, env);
	लिखो_त्रुटि(shell);
	निकास(1);
}

शून्य
session_unused(पूर्णाङ्क id)
{
	debug3_f("session id %d unused", id);
	यदि (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	स_रखो(&sessions[id], 0, परिमाण(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = रिक्त;
	sessions[id].next_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(शून्य)
{
	Session *s, *tmp;

	यदि (sessions_first_unused == -1) {
		यदि (sessions_nalloc >= options.max_sessions)
			फर्काऊ रिक्त;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, परिमाण(*sessions));
		यदि (tmp == रिक्त) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			फर्काऊ रिक्त;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	यदि (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	यदि (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->next_unused;
	s->used = 1;
	s->next_unused = -1;
	debug("session_new: session %d", s->self);

	फर्काऊ s;
}

स्थिर शून्य
session_dump(शून्य)
{
	पूर्णाङ्क i;
	लागि (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->used,
		    s->next_unused,
		    s->self,
		    s->chanid,
		    (दीर्घ)s->pid);
	}
}

पूर्णाङ्क
session_open(Authctxt *authctxt, पूर्णाङ्क chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	यदि (s == रिक्त) {
		error("no more sessions");
		फर्काऊ 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	यदि (s->pw == रिक्त || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	फर्काऊ 1;
}

Session *
session_by_tty(वर्ण *tty)
{
	पूर्णाङ्क i;
	लागि (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		यदि (s->used && s->ttyfd != -1 && म_भेद(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			फर्काऊ s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	फर्काऊ रिक्त;
}

स्थिर Session *
session_by_channel(पूर्णाङ्क id)
{
	पूर्णाङ्क i;
	लागि (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		यदि (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			फर्काऊ s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	फर्काऊ रिक्त;
}

स्थिर Session *
session_by_x11_channel(पूर्णाङ्क id)
{
	पूर्णाङ्क i, j;

	लागि (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		यदि (s->x11_chanids == रिक्त || !s->used)
			जारी;
		लागि (j = 0; s->x11_chanids[j] != -1; j++) {
			यदि (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				फर्काऊ s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	फर्काऊ रिक्त;
}

स्थिर Session *
session_by_pid(pid_t pid)
{
	पूर्णाङ्क i;
	debug("session_by_pid: pid %ld", (दीर्घ)pid);
	लागि (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		यदि (s->used && s->pid == pid)
			फर्काऊ s;
	}
	error("session_by_pid: unknown pid %ld", (दीर्घ)pid);
	session_dump();
	फर्काऊ रिक्त;
}

स्थिर पूर्णाङ्क
session_window_change_req(संरचना ssh *ssh, Session *s)
{
	पूर्णाङ्क r;

	यदि ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
session_pty_req(संरचना ssh *ssh, Session *s)
{
	पूर्णाङ्क r;

	यदि (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		फर्काऊ 0;
	}
	यदि (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		फर्काऊ 0;
	}

	यदि ((r = sshpkt_get_cstring(ssh, &s->term, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	यदि (म_भेद(s->term, "") == 0) {
		मुक्त(s->term);
		s->term = रिक्त;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	यदि (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, परिमाण(s->tty))) {
		मुक्त(s->term);
		s->term = रिक्त;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		फर्काऊ 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	यदि ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
session_subsystem_req(संरचना ssh *ssh, Session *s)
{
	संरचना stat st;
	पूर्णाङ्क r, success = 0, found = 0;
	वर्ण *prog, *cmd, *type;
	u_int i;

	यदि ((r = sshpkt_get_cstring(ssh, &s->subsys, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	लागि (i = 0; i < options.अङ्क_subsystems; i++) {
		यदि (म_भेद(s->subsys, options.subsystem_name[i]) != 0)
			जारी;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		यदि (म_भेद(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} अन्यथा {
			यदि (stat(prog, &st) == -1)
				debug("subsystem: cannot stat %s: %s",
				    prog, म_त्रुटि(त्रुटि_सं));
			s->is_subsystem = SUBSYSTEM_EXT;
			debug("subsystem: exec() %s", cmd);
		}
		xasprintf(&type, "session:subsystem:%s",
		    options.subsystem_name[i]);
		channel_set_xtype(ssh, s->chanid, type);
		मुक्त(type);
		success = do_exec(ssh, s, cmd) == 0;
		रोक;
	}

	यदि (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	फर्काऊ success;
}

स्थिर पूर्णाङ्क
session_x11_req(संरचना ssh *ssh, Session *s)
{
	पूर्णाङ्क r, success;
	u_char single_connection = 0;

	यदि (s->auth_proto != रिक्त || s->auth_data != रिक्त) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		फर्काऊ 0;
	}
	यदि ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_data, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	यदि (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_data))
		success = session_setup_x11fwd(ssh, s);
	अन्यथा {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	यदि (!success) {
		मुक्त(s->auth_proto);
		मुक्त(s->auth_data);
		s->auth_proto = रिक्त;
		s->auth_data = रिक्त;
	}
	फर्काऊ success;
}

स्थिर पूर्णाङ्क
session_shell_req(संरचना ssh *ssh, Session *s)
{
	पूर्णाङ्क r;

	यदि ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	फर्काऊ do_exec(ssh, s, रिक्त) == 0;
}

स्थिर पूर्णाङ्क
session_exec_req(संरचना ssh *ssh, Session *s)
{
	u_int success;
	पूर्णाङ्क r;
	वर्ण *command = रिक्त;

	यदि ((r = sshpkt_get_cstring(ssh, &command, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	मुक्त(command);
	फर्काऊ success;
}

स्थिर पूर्णाङ्क
session_break_req(संरचना ssh *ssh, Session *s)
{
	पूर्णाङ्क r;

	यदि ((r = sshpkt_get_u32(ssh, रिक्त)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	यदि (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		फर्काऊ 0;
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
session_env_req(संरचना ssh *ssh, Session *s)
{
	वर्ण *name, *val;
	u_int i;
	पूर्णाङ्क r;

	यदि ((r = sshpkt_get_cstring(ssh, &name, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	यदि (s->अङ्क_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		गच्छ fail;
	}

	लागि (i = 0; i < options.अङ्क_accept_env; i++) {
		यदि (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->अङ्क_env, name, val);
			s->env = xrecallocarray(s->env, s->अङ्क_env,
			    s->अङ्क_env + 1, परिमाण(*s->env));
			s->env[s->अङ्क_env].name = name;
			s->env[s->अङ्क_env].val = val;
			s->अङ्क_env++;
			फर्काऊ (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	मुक्त(name);
	मुक्त(val);
	फर्काऊ (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
स्थिर पूर्णाङ्क
name2sig(वर्ण *name)
{
#define SSH_SIG(x) यदि (म_भेद(name, #x) == 0) फर्काऊ SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
#ifdef SIGINFO
	यदि (म_भेद(name, "INFO@openssh.com") == 0)
		फर्काऊ SIGINFO;
#endif
	फर्काऊ -1;
}

स्थिर पूर्णाङ्क
session_signal_req(संरचना ssh *ssh, Session *s)
{
	वर्ण *signame = रिक्त;
	पूर्णाङ्क r, sig, success = 0;

	यदि ((r = sshpkt_get_cstring(ssh, &signame, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		गच्छ out;
	}
	यदि ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		गच्छ out;
	}
	यदि (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		गच्छ out;
	}
	यदि (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		गच्छ out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (दीर्घ)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	यदि (r != 0) {
		error_f("killpg(%ld, %d): %s", (दीर्घ)s->pid,
		    sig, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}

	/* success */
	success = 1;
 out:
	मुक्त(signame);
	फर्काऊ success;
}

स्थिर पूर्णाङ्क
session_auth_agent_req(संरचना ssh *ssh, Session *s, पूर्णाङ्क agent_new)
{
	स्थिर पूर्णाङ्क called = 0;
	पूर्णाङ्क r;

	यदि ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	यदि (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		फर्काऊ 0;
	}
	यदि (called)
		फर्काऊ 0;

	called = 1;
	फर्काऊ auth_आगत_request_forwarding(ssh, s->pw, agent_new);
}

पूर्णाङ्क
session_आगत_channel_req(संरचना ssh *ssh, Channel *c, अचर वर्ण *rtype)
{
	पूर्णाङ्क success = 0;
	Session *s;

	यदि ((s = session_by_channel(c->self)) == रिक्त) {
		logit_f("no session %d req %.100s", c->self, rtype);
		फर्काऊ 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	यदि (c->type == SSH_CHANNEL_LARVAL) {
		यदि (म_भेद(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} अन्यथा यदि (म_भेद(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} अन्यथा यदि (म_भेद(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} अन्यथा यदि (म_भेद(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} अन्यथा यदि (म_भेद(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} अन्यथा यदि (म_भेद(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} अन्यथा यदि (म_भेद(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} अन्यथा यदि (म_भेद(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	यदि (म_भेद(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} अन्यथा यदि (म_भेद(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} अन्यथा यदि (म_भेद(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	फर्काऊ success;
}

शून्य
session_set_fds(संरचना ssh *ssh, Session *s,
    पूर्णाङ्क fdin, पूर्णाङ्क fdout, पूर्णाङ्क fderr, पूर्णाङ्क ignore_fderr, पूर्णाङ्क is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	यदि (s->chanid == -1)
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
शून्य
session_pty_cleanup2(Session *s)
{
	यदि (s == रिक्त) {
		error_f("no session");
		फर्काऊ;
	}
	यदि (s->ttyfd == -1)
		फर्काऊ;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	यदि (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	यदि (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	यदि (s->ptymaster != -1 && बंद(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, म_त्रुटि(त्रुटि_सं));

	/* unlink pty from session */
	s->ttyfd = -1;
}

शून्य
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

स्थिर वर्ण *
sig2name(पूर्णाङ्क sig)
{
#define SSH_SIG(x) यदि (sig == SIG ## x) फर्काऊ #x
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
	फर्काऊ "SIG@openssh.com";
}

स्थिर शून्य
session_close_x11(संरचना ssh *ssh, पूर्णाङ्क id)
{
	Channel *c;

	यदि ((c = channel_by_id(ssh, id)) == रिक्त) {
		debug_f("x11 channel %d missing", id);
	} अन्यथा {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		यदि (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

स्थिर शून्य
session_close_single_x11(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क force, शून्य *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	यदि ((s = session_by_x11_channel(id)) == रिक्त)
		fatal_f("no x11 channel %d", id);
	लागि (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		यदि (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	मुक्त(s->x11_chanids);
	s->x11_chanids = रिक्त;
	मुक्त(s->display);
	s->display = रिक्त;
	मुक्त(s->auth_proto);
	s->auth_proto = रिक्त;
	मुक्त(s->auth_data);
	s->auth_data = रिक्त;
	मुक्त(s->auth_display);
	s->auth_display = रिक्त;
}

स्थिर शून्य
session_exit_message(संरचना ssh *ssh, Session *s, पूर्णाङ्क status)
{
	Channel *c;
	पूर्णाङ्क r;
	वर्ण *note = रिक्त;

	यदि ((c = channel_lookup(ssh, s->chanid)) == रिक्त)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	यदि (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		यदि ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} अन्यथा यदि (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#ifndef WCOREDUMP
# define WCOREDUMP(x) (0)
#endif
		यदि ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
		    (r = sshpkt_put_u8(ssh, WCOREDUMP(status)? 1 : 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " core dumped" : "");
	} अन्यथा {
		/* Some weird exit cause.  Just exit. */
		ssh_packet_disconnect(ssh, "wait returned status %04x.",
		    status);
	}

	debug_f("session %d channel %d pid %ld %s", s->self, s->chanid,
	    (दीर्घ)s->pid, note == रिक्त ? "UNKNOWN" : note);
	मुक्त(note);

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
	यदि (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

शून्य
session_close(संरचना ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	यदि (s->ttyfd != -1)
		session_pty_cleanup(s);
	मुक्त(s->term);
	मुक्त(s->display);
	मुक्त(s->x11_chanids);
	मुक्त(s->auth_display);
	मुक्त(s->auth_data);
	मुक्त(s->auth_proto);
	मुक्त(s->subsys);
	यदि (s->env != रिक्त) {
		लागि (i = 0; i < s->अङ्क_env; i++) {
			मुक्त(s->env[i].name);
			मुक्त(s->env[i].val);
		}
		मुक्त(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

शून्य
session_close_by_pid(संरचना ssh *ssh, pid_t pid, पूर्णाङ्क status)
{
	Session *s = session_by_pid(pid);
	यदि (s == रिक्त) {
		debug_f("no session for pid %ld", (दीर्घ)pid);
		फर्काऊ;
	}
	यदि (s->chanid != -1)
		session_exit_message(ssh, s, status);
	यदि (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
शून्य
session_close_by_channel(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क force, शून्य *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	यदि (s == रिक्त) {
		debug_f("no session for id %d", id);
		फर्काऊ;
	}
	debug_f("channel %d child %ld", id, (दीर्घ)s->pid);
	यदि (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		यदि (s->ttyfd != -1)
			session_pty_cleanup(s);
		यदि (!force)
			फर्काऊ;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	यदि (s->x11_chanids != रिक्त) {
		लागि (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

शून्य
session_destroy_all(संरचना ssh *ssh, शून्य (*closefunc)(Session *))
{
	पूर्णाङ्क i;
	लागि (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		यदि (s->used) {
			यदि (closefunc != रिक्त)
				closefunc(s);
			अन्यथा
				session_close(ssh, s);
		}
	}
}

स्थिर वर्ण *
session_tty_list(शून्य)
{
	स्थिर वर्ण buf[1024];
	पूर्णाङ्क i;
	वर्ण *cp;

	buf[0] = '\0';
	लागि (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		यदि (s->used && s->ttyfd != -1) {

			यदि (म_भेदन(s->tty, "/dev/", 5) != 0) {
				cp = म_खोजप(s->tty, '/');
				cp = (cp == रिक्त) ? s->tty : cp + 1;
			} अन्यथा
				cp = s->tty + 5;

			यदि (buf[0] != '\0')
				strlcat(buf, ",", परिमाण buf);
			strlcat(buf, cp, परिमाण buf);
		}
	}
	यदि (buf[0] == '\0')
		strlcpy(buf, "notty", परिमाण buf);
	फर्काऊ buf;
}

शून्य
session_proctitle(Session *s)
{
	यदि (s->pw == रिक्त)
		error("no user for session %d", s->self);
	अन्यथा
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

पूर्णाङ्क
session_setup_x11fwd(संरचना ssh *ssh, Session *s)
{
	संरचना stat st;
	वर्ण display[512], auth_display[512];
	वर्ण hostname[NI_MAXHOST];
	u_int i;

	यदि (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		फर्काऊ 0;
	}
	यदि (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		फर्काऊ 0;
	}
	यदि (options.xauth_location == रिक्त ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		फर्काऊ 0;
	}
	यदि (s->display != रिक्त) {
		debug("X11 display already set.");
		फर्काऊ 0;
	}
	यदि (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_सङ्ख्या, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		फर्काऊ 0;
	}
	लागि (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	यदि (gethostname(hostname, परिमाण(hostname)) == -1)
		fatal("gethostname: %.100s", म_त्रुटि(त्रुटि_सं));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	यदि (options.x11_use_localhost) {
		snprintf(display, परिमाण display, "localhost:%u.%u",
		    s->display_सङ्ख्या, s->screen);
		snprintf(auth_display, परिमाण auth_display, "unix:%u.%u",
		    s->display_सङ्ख्या, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} अन्यथा {
#ifdef IPADDR_IN_DISPLAY
		संरचना hostent *he;
		संरचना in_addr my_addr;

		he = gethostbyname(hostname);
		यदि (he == रिक्त) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			फर्काऊ 0;
		}
		स_नकल(&my_addr, he->h_addr_list[0], परिमाण(संरचना in_addr));
		snprintf(display, परिमाण display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_सङ्ख्या, s->screen);
#अन्यथा
		snprintf(display, परिमाण display, "%.400s:%u.%u", hostname,
		    s->display_सङ्ख्या, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	फर्काऊ 1;
}

स्थिर शून्य
do_authenticated2(संरचना ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

शून्य
do_cleanup(संरचना ssh *ssh, Authctxt *authctxt)
{
	स्थिर पूर्णाङ्क called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	यदि (is_child)
		फर्काऊ;

	/* avoid double cleanup */
	यदि (called)
		फर्काऊ;
	called = 1;

	यदि (authctxt == रिक्त)
		फर्काऊ;

#ifdef USE_PAM
	यदि (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	यदि (!authctxt->authenticated)
		फर्काऊ;

#ifdef KRB5
	यदि (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	यदि (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	यदि (auth_info_file != रिक्त) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		मुक्त(auth_info_file);
		auth_info_file = रिक्त;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	यदि (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

अचर वर्ण *
session_get_remote_name_or_ip(संरचना ssh *ssh, u_int utmp_size, पूर्णाङ्क use_dns)
{
	अचर वर्ण *remote = "";

	यदि (utmp_size > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	यदि (utmp_size == 0 || म_माप(remote) > utmp_size)
		remote = ssh_remote_ipaddr(ssh);
	फर्काऊ remote;
}

