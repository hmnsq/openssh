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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/wait.h>
#समावेश <sys/un.h>
#समावेश <sys/stat.h>
#समावेश <sys/socket.h>
#समावेश <sys/queue.h>

#समावेश <arpa/inet.h>

#समावेश <ctype.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <grp.h>
#समावेश <netdb.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <unistd.h>
#समावेश <limits.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "sshpty.h"
#समावेश "packet.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "match.h"
#समावेश "uidswap.h"
#समावेश "channels.h"
#समावेश "sshkey.h"
#समावेश "cipher.h"
#समावेश "kex.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-options.h"
#समावेश "authfd.h"
#समावेश "pathnames.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "sshlogin.h"
#समावेश "serverloop.h"
#समावेश "canohost.h"
#समावेश "session.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "sftp.h"
#समावेश "atomicio.h"

#अगर defined(KRB5) && defined(USE_AFS)
#समावेश <kafs.h>
#पूर्ण_अगर

#अगर_घोषित WITH_SELINUX
#समावेश <selinux/selinux.h>
#पूर्ण_अगर

/*
 * Hack for systems that do not support FD passing: allocate PTYs directly
 * without calling into the monitor. This requires either the post-auth
 * privsep process retain root privileges (see the comment in
 * sshd-session.c:privsep_postauth) or that PTY allocation doesn't require
 * privileges to begin with (e.g. Cygwin).
 */
#अगर_घोषित DISABLE_FD_PASSING
#घोषणा mm_pty_allocate pty_allocate
#पूर्ण_अगर

#घोषणा IS_INTERNAL_SFTP(c) \
	(!म_भेदन(c, INTERNAL_SFTP_NAME, माप(INTERNAL_SFTP_NAME) - 1) && \
	 (c[माप(INTERNAL_SFTP_NAME) - 1] == '\0' || \
	  c[माप(INTERNAL_SFTP_NAME) - 1] == ' ' || \
	  c[माप(INTERNAL_SFTP_NAME) - 1] == '\t'))

/* func */

Session *session_new(व्योम);
व्योम	session_set_fds(काष्ठा ssh *, Session *, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक);
व्योम	session_pty_cleanup(Session *);
व्योम	session_proctitle(Session *);
पूर्णांक	session_setup_x11fwd(काष्ठा ssh *, Session *);
पूर्णांक	do_exec_pty(काष्ठा ssh *, Session *, स्थिर अक्षर *);
पूर्णांक	do_exec_no_pty(काष्ठा ssh *, Session *, स्थिर अक्षर *);
पूर्णांक	do_exec(काष्ठा ssh *, Session *, स्थिर अक्षर *);
व्योम	do_login(काष्ठा ssh *, Session *, स्थिर अक्षर *);
व्योम	do_child(काष्ठा ssh *, Session *, स्थिर अक्षर *);
व्योम	do_motd(व्योम);
पूर्णांक	check_quietlogin(Session *, स्थिर अक्षर *);

अटल व्योम do_authenticated2(काष्ठा ssh *, Authctxt *);

अटल पूर्णांक session_pty_req(काष्ठा ssh *, Session *);

/* import */
बाह्य ServerOptions options;
बाह्य अक्षर *__progname;
बाह्य पूर्णांक debug_flag;
बाह्य काष्ठा sshbuf *loginmsg;
बाह्य काष्ठा sshauthopt *auth_opts;
बाह्य अक्षर *tun_fwd_ifnames; /* serverloop.c */

/* original command from peer. */
स्थिर अक्षर *original_command = शून्य;

/*तथ्य*/
अटल पूर्णांक sessions_first_unused = -1;
अटल पूर्णांक sessions_nalloc = 0;
अटल Session *sessions = शून्य;

#घोषणा SUBSYSTEM_NONE			0
#घोषणा SUBSYSTEM_EXT			1
#घोषणा SUBSYSTEM_INT_SFTP		2
#घोषणा SUBSYSTEM_INT_SFTP_ERROR	3

#अगर_घोषित HAVE_LOGIN_CAP
login_cap_t *lc;
#पूर्ण_अगर

अटल पूर्णांक is_child = 0;
अटल पूर्णांक in_chroot = 0;

/* File containing userauth info, if ExposeAuthInfo set */
अटल अक्षर *auth_info_file = शून्य;

/* Name and directory of socket for authentication agent forwarding. */
अटल अक्षर *auth_sock_name = शून्य;
अटल अक्षर *auth_sock_dir = शून्य; /* only set if directory needs cleanup */

/* removes the agent forwarding socket */

अटल व्योम
auth_sock_cleanup_proc(काष्ठा passwd *pw)
{
	अगर (auth_sock_name != शून्य) {
		temporarily_use_uid(pw);
		agent_listener_cleanup(options.agent_socket_path,
		    auth_sock_name, auth_sock_dir);
		मुक्त(auth_sock_name);
		auth_sock_name = शून्य;
		restore_uid();
	}
}

अटल पूर्णांक
auth_निवेश_request_forwarding(काष्ठा ssh *ssh, काष्ठा passwd *pw, पूर्णांक agent_new)
{
	Channel *nc;
	पूर्णांक sock = -1;

	अगर (auth_sock_name != शून्य) {
		error("authentication forwarding requested twice.");
		वापस 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	अगर (agent_listener(options.agent_socket_path, pw->pw_name, pw->pw_uid,
	    pw->pw_dir, getpid(), "sshd", &sock, &auth_sock_name,
	    &auth_sock_dir) != 0) {
		/* a more detailed error is already logged */
		ssh_packet_send_debug(ssh, "Agent forwarding disabled: "
		    "couldn't create listener socket");
		restore_uid();
		जाओ authsock_err;
	}
	restore_uid();

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new(ssh, "auth-listener",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, "auth socket", 1);
	nc->path = xstrdup(auth_sock_name);
	nc->agent_new = agent_new;
	वापस 1;

 authsock_err:
	मुक्त(auth_sock_name);
	अगर (sock != -1)
		बंद(sock);
	auth_sock_name = शून्य;
	वापस 0;
}

अटल व्योम
display_loginmsg(व्योम)
{
	पूर्णांक r;

	अगर (sshbuf_len(loginmsg) == 0)
		वापस;
	अगर ((r = sshbuf_put_u8(loginmsg, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	म_लिखो("%s", (अक्षर *)sshbuf_ptr(loginmsg));
	sshbuf_reset(loginmsg);
}

अटल व्योम
prepare_auth_info_file(काष्ठा passwd *pw, काष्ठा sshbuf *info)
{
	पूर्णांक fd = -1, success = 0;

	अगर (!options.expose_userauth_info || info == शून्य)
		वापस;

	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	अगर ((fd = mkstemp(auth_info_file)) == -1) {
		error_f("mkstemp: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (atomicio(vwrite, fd, sshbuf_mutable_ptr(info),
	    sshbuf_len(info)) != sshbuf_len(info)) {
		error_f("write: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (बंद(fd) != 0) {
		error_f("close: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	success = 1;
 out:
	अगर (!success) {
		अगर (fd != -1)
			बंद(fd);
		मुक्त(auth_info_file);
		auth_info_file = शून्य;
	}
	restore_uid();
}

अटल व्योम
set_fwdpermit_from_authopts(काष्ठा ssh *ssh, स्थिर काष्ठा sshauthopt *opts)
{
	अक्षर *tmp, *cp, *host;
	पूर्णांक port;
	माप_प्रकार i;

	अगर ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
		क्रम (i = 0; i < auth_opts->npermitopen; i++) {
			tmp = cp = xstrdup(auth_opts->permitopen[i]);
			/* This shouldn't fail as it has already been checked */
			अगर ((host = hpdelim2(&cp, शून्य)) == शून्य)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			अगर (cp == शून्य || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitopen port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_LOCAL, host, port);
			मुक्त(tmp);
		}
	}
	अगर ((options.allow_tcp_forwarding & FORWARD_REMOTE) != 0) {
		channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
		क्रम (i = 0; i < auth_opts->npermitlisten; i++) {
			tmp = cp = xstrdup(auth_opts->permitlisten[i]);
			/* This shouldn't fail as it has already been checked */
			अगर ((host = hpdelim(&cp)) == शून्य)
				fatal_f("internal error: hpdelim");
			host = cleanhostname(host);
			अगर (cp == शून्य || (port = permitopen_port(cp)) < 0)
				fatal_f("internal error: permitlisten port");
			channel_add_permission(ssh,
			    FORWARD_USER, FORWARD_REMOTE, host, port);
			मुक्त(tmp);
		}
	}
}

व्योम
do_authenticated(काष्ठा ssh *ssh, Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	auth_log_authopts("active", auth_opts, 0);

	/* set up the channel layer */
	/* XXX - streamlocal? */
	set_fwdpermit_from_authopts(ssh, auth_opts);

	अगर (!auth_opts->permit_port_forwarding_flag ||
	    options.disable_forwarding) {
		channel_disable_admin(ssh, FORWARD_LOCAL);
		channel_disable_admin(ssh, FORWARD_REMOTE);
	} अन्यथा {
		अगर ((options.allow_tcp_forwarding & FORWARD_LOCAL) == 0)
			channel_disable_admin(ssh, FORWARD_LOCAL);
		अन्यथा
			channel_permit_all(ssh, FORWARD_LOCAL);
		अगर ((options.allow_tcp_forwarding & FORWARD_REMOTE) == 0)
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
अटल पूर्णांक
xauth_valid_string(स्थिर अक्षर *s)
{
	माप_प्रकार i;

	क्रम (i = 0; s[i] != '\0'; i++) {
		अगर (!है_अक्षर_अंक((u_char)s[i]) &&
		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
		    s[i] != '-' && s[i] != '_')
			वापस 0;
	}
	वापस 1;
}

#घोषणा USE_PIPES 1
/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
पूर्णांक
do_exec_no_pty(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *command)
{
	pid_t pid;
#अगर_घोषित USE_PIPES
	पूर्णांक pin[2], pout[2], perr[2];

	अगर (s == शून्य)
		fatal("do_exec_no_pty: no session");

	/* Allocate pipes for communicating with the program. */
	अगर (pipe(pin) == -1) {
		error_f("pipe in: %.100s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (pipe(pout) == -1) {
		error_f("pipe out: %.100s", म_त्रुटि(त्रुटि_सं));
		बंद(pin[0]);
		बंद(pin[1]);
		वापस -1;
	}
	अगर (pipe(perr) == -1) {
		error_f("pipe err: %.100s", म_त्रुटि(त्रुटि_सं));
		बंद(pin[0]);
		बंद(pin[1]);
		बंद(pout[0]);
		बंद(pout[1]);
		वापस -1;
	}
#अन्यथा
	पूर्णांक inout[2], err[2];

	अगर (s == शून्य)
		fatal("do_exec_no_pty: no session");

	/* Uses socket pairs to communicate with the program. */
	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1) {
		error_f("socketpair #1: %.100s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		error_f("socketpair #2: %.100s", म_त्रुटि(त्रुटि_सं));
		बंद(inout[0]);
		बंद(inout[1]);
		वापस -1;
	}
#पूर्ण_अगर

	session_proctitle(s);

	/* Fork the child. */
	चयन ((pid = विभाजन())) {
	हाल -1:
		error_f("fork: %.100s", म_त्रुटि(त्रुटि_सं));
#अगर_घोषित USE_PIPES
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
#पूर्ण_अगर
		वापस -1;
	हाल 0:
		is_child = 1;

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		अगर (setsid() == -1)
			error("setsid failed: %.100s", म_त्रुटि(त्रुटि_सं));

#अगर_घोषित USE_PIPES
		/*
		 * Redirect stdin.  We close the parent side of the socket
		 * pair, and make the child side the standard input.
		 */
		बंद(pin[1]);
		अगर (dup2(pin[0], 0) == -1)
			लिखो_त्रुटि("dup2 stdin");
		बंद(pin[0]);

		/* Redirect stdout. */
		बंद(pout[0]);
		अगर (dup2(pout[1], 1) == -1)
			लिखो_त्रुटि("dup2 stdout");
		बंद(pout[1]);

		/* Redirect stderr. */
		बंद(perr[0]);
		अगर (dup2(perr[1], 2) == -1)
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
		अगर (dup2(inout[0], 0) == -1)	/* stdin */
			लिखो_त्रुटि("dup2 stdin");
		अगर (dup2(inout[0], 1) == -1)	/* stdout (same as stdin) */
			लिखो_त्रुटि("dup2 stdout");
		बंद(inout[0]);
		अगर (dup2(err[0], 2) == -1)	/* stderr */
			लिखो_त्रुटि("dup2 stderr");
		बंद(err[0]);
#पूर्ण_अगर

		/* Do processing for the child (exec command etc). */
		do_child(ssh, s, command);
		/* NOTREACHED */
	शेष:
		अवरोध;
	}

#अगर_घोषित HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_मूल्य);
#पूर्ण_अगर

	s->pid = pid;

	/*
	 * Clear loginmsg, since it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

#अगर_घोषित USE_PIPES
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
#पूर्ण_अगर
	वापस 0;
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
पूर्णांक
do_exec_pty(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *command)
{
	पूर्णांक fdout, ptyfd, ttyfd, ptymaster;
	pid_t pid;

	अगर (s == शून्य)
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
	अगर ((fdout = dup(ptyfd)) == -1) {
		error_f("dup #1: %s", म_त्रुटि(त्रुटि_सं));
		बंद(ttyfd);
		बंद(ptyfd);
		वापस -1;
	}
	/* we keep a reference to the pty master */
	अगर ((ptymaster = dup(ptyfd)) == -1) {
		error_f("dup #2: %s", म_त्रुटि(त्रुटि_सं));
		बंद(ttyfd);
		बंद(ptyfd);
		बंद(fdout);
		वापस -1;
	}

	/* Fork the child. */
	चयन ((pid = विभाजन())) {
	हाल -1:
		error_f("fork: %.100s", म_त्रुटि(त्रुटि_सं));
		बंद(fdout);
		बंद(ptymaster);
		बंद(ttyfd);
		बंद(ptyfd);
		वापस -1;
	हाल 0:
		is_child = 1;

		बंद(fdout);
		बंद(ptymaster);

		/* Close the master side of the pseudo tty. */
		बंद(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		अगर (dup2(ttyfd, 0) == -1)
			error("dup2 stdin: %s", म_त्रुटि(त्रुटि_सं));
		अगर (dup2(ttyfd, 1) == -1)
			error("dup2 stdout: %s", म_त्रुटि(त्रुटि_सं));
		अगर (dup2(ttyfd, 2) == -1)
			error("dup2 stderr: %s", म_त्रुटि(त्रुटि_सं));

		/* Close the extra descriptor for the pseudo tty. */
		बंद(ttyfd);

		/* record login, etc. similar to login(1) */
#अगर_अघोषित HAVE_OSF_SIA
		do_login(ssh, s, command);
#पूर्ण_अगर
		/*
		 * Do common processing for the child, such as execing
		 * the command.
		 */
		do_child(ssh, s, command);
		/* NOTREACHED */
	शेष:
		अवरोध;
	}

#अगर_घोषित HAVE_CYGWIN
	cygwin_set_impersonation_token(INVALID_HANDLE_मूल्य);
#पूर्ण_अगर

	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	बंद(ttyfd);

	/* Enter interactive session. */
	s->ptymaster = ptymaster;
	session_set_fds(ssh, s, ptyfd, fdout, -1, 1, 1);
	वापस 0;
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
पूर्णांक
do_exec(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *command)
{
	पूर्णांक ret;
	स्थिर अक्षर *forced = शून्य, *tty = शून्य;
	अक्षर session_type[1024];

	अगर (options.adm_forced_command) {
		original_command = command;
		command = options.adm_forced_command;
		forced = "(config)";
	} अन्यथा अगर (auth_opts->force_command != शून्य) {
		original_command = command;
		command = auth_opts->force_command;
		forced = "(key-option)";
	}
	s->forced = 0;
	अगर (forced != शून्य) {
		s->forced = 1;
		अगर (IS_INTERNAL_SFTP(command)) {
			s->is_subsystem = s->is_subsystem ?
			    SUBSYSTEM_INT_SFTP : SUBSYSTEM_INT_SFTP_ERROR;
		} अन्यथा अगर (s->is_subsystem)
			s->is_subsystem = SUBSYSTEM_EXT;
		snprintf(session_type, माप(session_type),
		    "forced-command %s '%.900s'", forced, command);
	} अन्यथा अगर (s->is_subsystem) {
		snprintf(session_type, माप(session_type),
		    "subsystem '%.900s'", s->subsys);
	} अन्यथा अगर (command == शून्य) {
		snprintf(session_type, माप(session_type), "shell");
	} अन्यथा {
		/* NB. we don't log unforced commands to preserve privacy */
		snprintf(session_type, माप(session_type), "command");
	}

	अगर (s->ttyfd != -1) {
		tty = s->tty;
		अगर (म_भेदन(tty, "/dev/", 5) == 0)
			tty += 5;
	}

	verbose("Starting session: %s%s%s for %s from %.200s port %d id %d",
	    session_type,
	    tty == शून्य ? "" : " on ",
	    tty == शून्य ? "" : tty,
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

#अगर_घोषित SSH_AUDIT_EVENTS
	अगर (command != शून्य)
		mm_audit_run_command(command);
	अन्यथा अगर (s->ttyfd == -1) {
		अक्षर *shell = s->pw->pw_shell;

		अगर (shell[0] == '\0')	/* empty shell means /bin/sh */
			shell =_PATH_BSHELL;
		mm_audit_run_command(shell);
	}
#पूर्ण_अगर
	अगर (s->ttyfd != -1)
		ret = do_exec_pty(ssh, s, command);
	अन्यथा
		ret = do_exec_no_pty(ssh, s, command);

	original_command = शून्य;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	sshbuf_reset(loginmsg);

	वापस ret;
}

/* administrative, login(1)-like work */
व्योम
do_login(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *command)
{
	socklen_t fromlen;
	काष्ठा sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	स_रखो(&from, 0, माप(from));
	fromlen = माप(from);
	अगर (ssh_packet_connection_is_on_socket(ssh)) {
		अगर (getpeername(ssh_packet_get_connection_in(ssh),
		    (काष्ठा sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", म_त्रुटि(त्रुटि_सं));
			cleanup_exit(255);
		}
	}

	अगर (check_quietlogin(s, command))
		वापस;

	display_loginmsg();

	do_motd();
}

/*
 * Display the message of the day.
 */
व्योम
do_motd(व्योम)
{
	खाता *f;
	अक्षर buf[256];

	अगर (options.print_motd) {
#अगर_घोषित HAVE_LOGIN_CAP
		f = ख_खोलो(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#अन्यथा
		f = ख_खोलो("/etc/motd", "r");
#पूर्ण_अगर
		अगर (f) {
			जबतक (ख_माला_लो(buf, माप(buf), f))
				ख_माला_दो(buf, मानक_निकास);
			ख_बंद(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
पूर्णांक
check_quietlogin(Session *s, स्थिर अक्षर *command)
{
	अक्षर buf[256];
	काष्ठा passwd *pw = s->pw;
	काष्ठा stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	अगर (command != शून्य)
		वापस 1;
	snprintf(buf, माप(buf), "%.200s/.hushlogin", pw->pw_dir);
#अगर_घोषित HAVE_LOGIN_CAP
	अगर (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		वापस 1;
#अन्यथा
	अगर (stat(buf, &st) >= 0)
		वापस 1;
#पूर्ण_अगर
	वापस 0;
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 * If allowlist is not NULL, then it is interpreted as a pattern list and
 * only variable names that match it will be accepted.
 */
अटल व्योम
read_environment_file(अक्षर ***env, u_int *envsize,
	स्थिर अक्षर *filename, स्थिर अक्षर *allowlist)
{
	खाता *f;
	अक्षर *पंक्ति = शून्य, *cp, *मूल्य;
	माप_प्रकार linesize = 0;
	u_int lineno = 0;

	f = ख_खोलो(filename, "r");
	अगर (!f)
		वापस;

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		अगर (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		क्रम (cp = पंक्ति; *cp == ' ' || *cp == '\t'; cp++)
			;
		अगर (!*cp || *cp == '#' || *cp == '\n')
			जारी;

		cp[म_खोज(cp, "\n")] = '\0';

		मूल्य = म_अक्षर(cp, '=');
		अगर (मूल्य == शून्य) {
			ख_लिखो(मानक_त्रुटि, "Bad line %u in %.100s\n", lineno,
			    filename);
			जारी;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*मूल्य = '\0';
		मूल्य++;
		अगर (allowlist != शून्य &&
		    match_pattern_list(cp, allowlist, 0) != 1)
			जारी;
		child_set_env(env, envsize, cp, मूल्य);
	}
	मुक्त(पंक्ति);
	ख_बंद(f);
}

#अगर_घोषित HAVE_ETC_DEFAULT_LOGIN
/*
 * Return named variable from specified environment, or NULL if not present.
 */
अटल अक्षर *
child_get_env(अक्षर **env, स्थिर अक्षर *name)
{
	पूर्णांक i;
	माप_प्रकार len;

	len = म_माप(name);
	क्रम (i=0; env[i] != शून्य; i++)
		अगर (म_भेदन(name, env[i], len) == 0 && env[i][len] == '=')
			वापस(env[i] + len + 1);
	वापस शून्य;
}

/*
 * Read /etc/default/login.
 * We pick up the PATH (or SUPATH for root) and UMASK.
 */
अटल व्योम
read_etc_default_login(अक्षर ***env, u_int *envsize, uid_t uid)
{
	अक्षर **tmpenv = शून्य, *var;
	u_int i, tmpenvsize = 0;
	u_long mask;

	/*
	 * We don't want to copy the whole file to the child's environment,
	 * so we use a temporary environment and copy the variables we're
	 * interested in.
	 */
	read_environment_file(&tmpenv, &tmpenvsize, "/etc/default/login",
	    options.permit_user_env_allowlist);

	अगर (tmpenv == शून्य)
		वापस;

	अगर (uid == 0)
		var = child_get_env(tmpenv, "SUPATH");
	अन्यथा
		var = child_get_env(tmpenv, "PATH");
	अगर (var != शून्य)
		child_set_env(env, envsize, "PATH", var);

	अगर ((var = child_get_env(tmpenv, "UMASK")) != शून्य)
		अगर (माला_पूछो(var, "%5lo", &mask) == 1)
			umask((mode_t)mask);

	क्रम (i = 0; tmpenv[i] != शून्य; i++)
		मुक्त(tmpenv[i]);
	मुक्त(tmpenv);
}
#पूर्ण_अगर /* HAVE_ETC_DEFAULT_LOGIN */

#अगर defined(USE_PAM) || defined(HAVE_CYGWIN)
अटल व्योम
copy_environment_denylist(अक्षर **source, अक्षर ***env, u_int *envsize,
    स्थिर अक्षर *denylist)
{
	अक्षर *var_name, *var_val;
	पूर्णांक i;

	अगर (source == शून्य)
		वापस;

	क्रम(i = 0; source[i] != शून्य; i++) {
		var_name = xstrdup(source[i]);
		अगर ((var_val = म_माला(var_name, "=")) == शून्य) {
			मुक्त(var_name);
			जारी;
		}
		*var_val++ = '\0';

		अगर (denylist == शून्य ||
		    match_pattern_list(var_name, denylist, 0) != 1) {
			debug3("Copy environment: %s=%s", var_name, var_val);
			child_set_env(env, envsize, var_name, var_val);
		}

		मुक्त(var_name);
	}
}
#पूर्ण_अगर /* defined(USE_PAM) || defined(HAVE_CYGWIN) */

#अगर_घोषित HAVE_CYGWIN
अटल व्योम
copy_environment(अक्षर **source, अक्षर ***env, u_int *envsize)
{
	copy_environment_denylist(source, env, envsize, शून्य);
}
#पूर्ण_अगर

अटल अक्षर **
do_setup_env(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *shell)
{
	अक्षर buf[256];
	माप_प्रकार n;
	u_int i, envsize;
	अक्षर *ocp, *cp, *मूल्य, **env, *laddr;
	काष्ठा passwd *pw = s->pw;
#अगर !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
	अक्षर *path = शून्य;
#पूर्ण_अगर

	/* Initialize the environment. */
	envsize = 100;
	env = xcalloc(envsize, माप(अक्षर *));
	env[0] = शून्य;

#अगर_घोषित HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	{
		अक्षर **p;

		p = fetch_windows_environment();
		copy_environment(p, &env, &envsize);
		free_windows_environment(p);
	}
#पूर्ण_अगर

#अगर_घोषित GSSAPI
	/* Allow any GSSAPI methods that we've used to alter
	 * the child's environment as they see fit
	 */
	ssh_gssapi_do_child(&env, &envsize);
#पूर्ण_अगर

	/* Set basic environment. */
	क्रम (i = 0; i < s->अंक_env; i++)
		child_set_env(&env, &envsize, s->env[i].name, s->env[i].val);

	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
#अगर_घोषित _AIX
	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
#पूर्ण_अगर
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#अगर_घोषित HAVE_LOGIN_CAP
	अगर (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
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
	अगर (path == शून्य || *path == '\0') {
		child_set_env(&env, &envsize, "PATH",
		    s->pw->pw_uid == 0 ?  SUPERUSER_PATH : _PATH_STDPATH);
	}
# endif /* HAVE_CYGWIN */
#पूर्ण_अगर /* HAVE_LOGIN_CAP */

	अगर (!options.use_pam) {
		snprintf(buf, माप buf, "%.200s/%.50s",
		    _PATH_MAILDIR, pw->pw_name);
		child_set_env(&env, &envsize, "MAIL", buf);
	}

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

	अगर (दो_पर्या("TZ"))
		child_set_env(&env, &envsize, "TZ", दो_पर्या("TZ"));
#अगर_घोषित HAVE_LOGIN_CAP
	अगर (दो_पर्या("XDG_RUNTIME_DIR")) {
		child_set_env(&env, &envsize, "XDG_RUNTIME_DIR",
		    दो_पर्या("XDG_RUNTIME_DIR"));
	}
#पूर्ण_अगर /* HAVE_LOGIN_CAP */
	अगर (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	अगर (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);

	/*
	 * Since we clear KRB5CCNAME at startup, if it's set now then it
	 * must have been set by a native authentication method (eg AIX or
	 * SIA), so copy it to the child.
	 */
	{
		अक्षर *cp;

		अगर ((cp = दो_पर्या("KRB5CCNAME")) != शून्य)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
	}

#अगर_घोषित _AIX
	{
		अक्षर *cp;

		अगर ((cp = दो_पर्या("AUTHSTATE")) != शून्य)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		read_environment_file(&env, &envsize, "/etc/environment",
		    options.permit_user_env_allowlist);
	}
#पूर्ण_अगर
#अगर_घोषित KRB5
	अगर (s->authctxt->krb5_ccname)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ccname);
#पूर्ण_अगर
	अगर (auth_sock_name != शून्य)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);


	/* Set custom environment options from pubkey authentication. */
	अगर (options.permit_user_env) {
		क्रम (n = 0 ; n < auth_opts->nenv; n++) {
			ocp = xstrdup(auth_opts->env[n]);
			cp = म_अक्षर(ocp, '=');
			अगर (cp != शून्य) {
				*cp = '\0';
				/* Apply PermitUserEnvironment allowlist */
				अगर (options.permit_user_env_allowlist == शून्य ||
				    match_pattern_list(ocp,
				    options.permit_user_env_allowlist, 0) == 1)
					child_set_env(&env, &envsize,
					    ocp, cp + 1);
			}
			मुक्त(ocp);
		}
	}

	/* read $HOME/.ssh/environment. */
	अगर (options.permit_user_env) {
		snprintf(buf, माप buf, "%.200s/%s/environment",
		    pw->pw_dir, _PATH_SSH_USER_DIR);
		read_environment_file(&env, &envsize, buf,
		    options.permit_user_env_allowlist);
	}

#अगर_घोषित USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	अगर (options.use_pam) {
		अक्षर **p;

		/*
		 * Don't allow PAM-internal env vars to leak
		 * back into the session environment.
		 */
#घोषणा PAM_ENV_DENYLIST  "SSH_AUTH_INFO*,SSH_CONNECTION*"
		p = fetch_pam_child_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);

		p = fetch_pam_environment();
		copy_environment_denylist(p, &env, &envsize,
		    PAM_ENV_DENYLIST);
		free_pam_environment(p);
	}
#पूर्ण_अगर /* USE_PAM */

	/* Environment specified by admin */
	क्रम (i = 0; i < options.अंक_setenv; i++) {
		cp = xstrdup(options.setenv[i]);
		अगर ((मूल्य = म_अक्षर(cp, '=')) == शून्य) {
			/* shouldn't happen; vars are checked in servconf.c */
			fatal("Invalid config SetEnv: %s", options.setenv[i]);
		}
		*मूल्य++ = '\0';
		child_set_env(&env, &envsize, cp, मूल्य);
		मुक्त(cp);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, माप buf, "%.50s %d %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    ssh_local_port(ssh));
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
	snprintf(buf, माप buf, "%.50s %d %.50s %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
	    laddr, ssh_local_port(ssh));
	मुक्त(laddr);
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	अगर (tun_fwd_ifnames != शून्य)
		child_set_env(&env, &envsize, "SSH_TUNNEL", tun_fwd_ifnames);
	अगर (auth_info_file != शून्य)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
	अगर (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	अगर (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

	अगर (debug_flag) {
		/* dump the environment */
		ख_लिखो(मानक_त्रुटि, "Environment:\n");
		क्रम (i = 0; env[i]; i++)
			ख_लिखो(मानक_त्रुटि, "  %.200s\n", env[i]);
	}
	वापस env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
अटल व्योम
do_rc_files(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *shell)
{
	खाता *f = शून्य;
	अक्षर *cmd = शून्य, *user_rc = शून्य;
	पूर्णांक do_xauth;
	काष्ठा stat st;

	do_xauth =
	    s->display != शून्य && s->auth_proto != शून्य && s->auth_तथ्य != शून्य;
	xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);

	/* ignore _PATH_SSH_USER_RC for subsystems and admin forced commands */
	अगर (!s->is_subsystem && options.adm_forced_command == शून्य &&
	    auth_opts->permit_user_rc && options.permit_user_rc &&
	    stat(user_rc, &st) >= 0) {
		अगर (xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL,
		    user_rc) == -1)
			fatal_f("xasprintf: %s", म_त्रुटि(त्रुटि_सं));
		अगर (debug_flag)
			ख_लिखो(मानक_त्रुटि, "Running %s\n", cmd);
		f = popen(cmd, "w");
		अगर (f) {
			अगर (do_xauth)
				ख_लिखो(f, "%s %s\n", s->auth_proto,
				    s->auth_तथ्य);
			pclose(f);
		} अन्यथा
			ख_लिखो(मानक_त्रुटि, "Could not run %s\n",
			    user_rc);
	} अन्यथा अगर (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		अगर (debug_flag)
			ख_लिखो(मानक_त्रुटि, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		अगर (f) {
			अगर (do_xauth)
				ख_लिखो(f, "%s %s\n", s->auth_proto,
				    s->auth_तथ्य);
			pclose(f);
		} अन्यथा
			ख_लिखो(मानक_त्रुटि, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} अन्यथा अगर (do_xauth && options.xauth_location != शून्य) {
		/* Add authority data to .Xauthority if appropriate. */
		अगर (debug_flag) {
			ख_लिखो(मानक_त्रुटि,
			    "Running %.500s remove %.100s\n",
			    options.xauth_location, s->auth_display);
			ख_लिखो(मानक_त्रुटि,
			    "%.500s add %.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_तथ्य);
		}
		अगर (xasprintf(&cmd, "%s -q -", options.xauth_location) == -1)
			fatal_f("xasprintf: %s", म_त्रुटि(त्रुटि_सं));
		f = popen(cmd, "w");
		अगर (f) {
			ख_लिखो(f, "remove %s\n",
			    s->auth_display);
			ख_लिखो(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_तथ्य);
			pclose(f);
		} अन्यथा {
			ख_लिखो(मानक_त्रुटि, "Could not run %s\n",
			    cmd);
		}
	}
	मुक्त(cmd);
	मुक्त(user_rc);
}

अटल व्योम
do_nologin(काष्ठा passwd *pw)
{
	खाता *f = शून्य;
	अक्षर buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
	काष्ठा stat sb;

#अगर_घोषित HAVE_LOGIN_CAP
	अगर (login_getcapbool(lc, "ignorenologin", 0) || pw->pw_uid == 0)
		वापस;
	nl = login_getcapstr(lc, "nologin", def_nl, def_nl);
#अन्यथा
	अगर (pw->pw_uid == 0)
		वापस;
	nl = def_nl;
#पूर्ण_अगर
	अगर (stat(nl, &sb) == -1)
		वापस;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	logit("User %.100s not allowed because %s exists", pw->pw_name, nl);
	अगर ((f = ख_खोलो(nl, "r")) != शून्य) {
		जबतक (ख_माला_लो(buf, माप(buf), f))
			ख_माला_दो(buf, मानक_त्रुटि);
		ख_बंद(f);
	}
	निकास(254);
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
अटल व्योम
safely_chroot(स्थिर अक्षर *path, uid_t uid)
{
	स्थिर अक्षर *cp;
	अक्षर component[PATH_MAX];
	काष्ठा stat st;

	अगर (!path_absolute(path))
		fatal("chroot path does not begin at root");
	अगर (म_माप(path) >= माप(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	क्रम (cp = path; cp != शून्य;) {
		अगर ((cp = म_अक्षर(cp, '/')) == शून्य)
			strlcpy(component, path, माप(component));
		अन्यथा {
			cp++;
			स_नकल(component, path, cp - path);
			component[cp - path] = '\0';
		}

		debug3_f("checking '%s'", component);

		अगर (stat(component, &st) != 0)
			fatal_f("stat(\"%s\"): %s",
			    component, म_त्रुटि(त्रुटि_सं));
		अगर (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == शून्य ? "" : "component ", component);
		अगर (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == शून्य ? "" : "component ", component);

	}

	अगर (स_बदलो(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, म_त्रुटि(त्रुटि_सं));
	अगर (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, म_त्रुटि(त्रुटि_सं));
	अगर (स_बदलो("/") == -1)
		fatal_f("chdir(/) after chroot: %s", म_त्रुटि(त्रुटि_सं));
	verbose("Changed root directory to \"%s\"", path);
}

/* Set login name, uid, gid, and groups. */
व्योम
do_setusercontext(काष्ठा passwd *pw)
{
	अक्षर uidstr[32], *chroot_path, *tmp;

	platform_setusercontext(pw);

	अगर (platform_privileged_uidswap()) {
#अगर_घोषित HAVE_LOGIN_CAP
		अगर (setusercontext(lc, pw, pw->pw_uid,
		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
			लिखो_त्रुटि("unable to set user context");
			निकास(1);
		}
#अन्यथा
		अगर (setlogin(pw->pw_name) < 0)
			error("setlogin failed: %s", म_त्रुटि(त्रुटि_सं));
		अगर (setgid(pw->pw_gid) < 0) {
			लिखो_त्रुटि("setgid");
			निकास(1);
		}
		/* Initialize the group list. */
		अगर (initgroups(pw->pw_name, pw->pw_gid) < 0) {
			लिखो_त्रुटि("initgroups");
			निकास(1);
		}
		endgrent();
#पूर्ण_अगर

		platform_setusercontext_post_groups(pw);

		अगर (!in_chroot && options.chroot_directory != शून्य &&
		    strcasecmp(options.chroot_directory, "none") != 0) {
			tmp = tilde_expand_filename(options.chroot_directory,
			    pw->pw_uid);
			snprintf(uidstr, माप(uidstr), "%llu",
			    (अचिन्हित दीर्घ दीर्घ)pw->pw_uid);
			chroot_path = percent_expand(tmp, "h", pw->pw_dir,
			    "u", pw->pw_name, "U", uidstr, (अक्षर *)शून्य);
			safely_chroot(chroot_path, pw->pw_uid);
			मुक्त(tmp);
			मुक्त(chroot_path);
			/* Make sure we don't attempt to chroot again */
			मुक्त(options.chroot_directory);
			options.chroot_directory = शून्य;
			in_chroot = 1;
		}

#अगर_घोषित HAVE_LOGIN_CAP
		अगर (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUSER) < 0) {
			लिखो_त्रुटि("unable to set user context (setuser)");
			निकास(1);
		}
		/* 
		 * FreeBSD's setusercontext() will not apply the user's
		 * own umask setting unless running with the user's UID.
		 */
		(व्योम) setusercontext(lc, pw, pw->pw_uid, LOGIN_SETUMASK);
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
		अगर (!in_chroot && set_id(pw->pw_name) != 0)
			fatal("set_id(%s) Failed", pw->pw_name);
# endif /* USE_LIBIAF */
		/* Permanently switch to the desired uid. */
		permanently_set_uid(pw);
#पूर्ण_अगर
	} अन्यथा अगर (options.chroot_directory != शून्य &&
	    strcasecmp(options.chroot_directory, "none") != 0) {
		fatal("server lacks privileges to chroot to ChrootDirectory");
	}

	अगर (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("Failed to set uids to %u.", (u_int) pw->pw_uid);
}

अटल व्योम
do_pwchange(Session *s)
{
	ख_साफ(शून्य);
	ख_लिखो(मानक_त्रुटि, "WARNING: Your password has expired.\n");
	अगर (s->ttyfd != -1) {
		ख_लिखो(मानक_त्रुटि,
		    "You must change your password now and log in again!\n");
#अगर_घोषित WITH_SELINUX
		setexeccon(शून्य);
#पूर्ण_अगर
#अगर_घोषित PASSWD_NEEDS_USERNAME
		execl(_PATH_PASSWD_PROG, "passwd", s->pw->pw_name,
		    (अक्षर *)शून्य);
#अन्यथा
		execl(_PATH_PASSWD_PROG, "passwd", (अक्षर *)शून्य);
#पूर्ण_अगर
		लिखो_त्रुटि("passwd");
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि,
		    "Password change required but no TTY available.\n");
	}
	निकास(1);
}

अटल व्योम
child_close_fds(काष्ठा ssh *ssh)
{
	बाह्य पूर्णांक auth_sock;

	अगर (auth_sock != -1) {
		बंद(auth_sock);
		auth_sock = -1;
	}

	अगर (ssh_packet_get_connection_in(ssh) ==
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
	log_redirect_stderr_to(शून्य);

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
#घोषणा ARGV_MAX 10
व्योम
do_child(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *command)
{
	बाह्य अक्षर **environ;
	अक्षर **env, *argv[ARGV_MAX], remote_id[512];
	स्थिर अक्षर *shell, *shell0;
	काष्ठा passwd *pw = s->pw;
	पूर्णांक r = 0;

	sshpkt_fmt_connection_id(ssh, remote_id, माप(remote_id));

	/* remove keys from memory */
	ssh_packet_clear_कुंजियाँ(ssh);

	/* Force a password change */
	अगर (s->authctxt->force_pwchange) {
		do_setusercontext(pw);
		child_close_fds(ssh);
		do_pwchange(s);
		निकास(1);
	}

	/*
	 * Login(1) does this as well, and it needs uid 0 for the "-h"
	 * switch, so we let login(1) to this for us.
	 */
#अगर_घोषित HAVE_OSF_SIA
	session_setup_sia(pw, s->ttyfd == -1 ? शून्य : s->tty);
	अगर (!check_quietlogin(s, command))
		do_motd();
#अन्यथा /* HAVE_OSF_SIA */
	/* When PAM is enabled we rely on it to do the nologin check */
	अगर (!options.use_pam)
		do_nologin(pw);
	do_setusercontext(pw);
	/*
	 * PAM session modules in do_setusercontext may have
	 * generated messages, so if this in an interactive
	 * login then display them too.
	 */
	अगर (!check_quietlogin(s, command))
		display_loginmsg();
#पूर्ण_अगर /* HAVE_OSF_SIA */

#अगर_घोषित USE_PAM
	अगर (options.use_pam && !is_pam_session_open()) {
		debug3("PAM session not opened, exiting");
		display_loginmsg();
		निकास(254);
	}
#पूर्ण_अगर

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

#अगर_घोषित HAVE_LOGIN_CAP
	shell = login_getcapstr(lc, "shell", (अक्षर *)shell, (अक्षर *)shell);
#पूर्ण_अगर

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

#अगर defined(KRB5) && defined(USE_AFS)
	/*
	 * At this point, we check to see if AFS is active and if we have
	 * a valid Kerberos 5 TGT. If so, it seems like a good idea to see
	 * if we can (and need to) extend the ticket into an AFS token. If
	 * we don't do this, we run into potential problems if the user's
	 * home directory is in AFS and it's not world-readable.
	 */

	अगर (options.kerberos_get_afs_token && k_hasafs() &&
	    (s->authctxt->krb5_ctx != शून्य)) {
		अक्षर cell[64];

		debug("Getting AFS token");

		k_setpag();

		अगर (k_afs_cell_of_file(pw->pw_dir, cell, माप(cell)) == 0)
			krb5_afslog(s->authctxt->krb5_ctx,
			    s->authctxt->krb5_fwd_ccache, cell, शून्य);

		krb5_afslog_home(s->authctxt->krb5_ctx,
		    s->authctxt->krb5_fwd_ccache, शून्य, शून्य, pw->pw_dir);
	}
#पूर्ण_अगर

	/* Change current directory to the user's home directory. */
	अगर (स_बदलो(pw->pw_dir) == -1) {
		/* Suppress missing homedir warning for chroot case */
#अगर_घोषित HAVE_LOGIN_CAP
		r = login_getcapbool(lc, "requirehome", 0);
#पूर्ण_अगर
		अगर (r || !in_chroot) {
			ख_लिखो(मानक_त्रुटि, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    म_त्रुटि(त्रुटि_सं));
		}
		अगर (r)
			निकास(1);
	}

	closefrom(STDERR_FILENO + 1);

	do_rc_files(ssh, s, shell);

	/* restore SIGPIPE for child */
	ssh_signal(SIGPIPE, संक_पूर्व);

	अगर (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		म_लिखो("This service allows sftp connections only.\n");
		ख_साफ(शून्य);
		निकास(1);
	} अन्यथा अगर (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		बाह्य पूर्णांक optind, optreset;
		पूर्णांक sftp_argc;
		अक्षर **sftp_argv;

		setproctitle("%s@%s", s->pw->pw_name, INTERNAL_SFTP_NAME);
		अगर (argv_split(command == शून्य ? "sftp-server" : command,
		    &sftp_argc, &sftp_argv, 1) != 0) {
			error("internal error: can't split internal-sftp "
			    "arguments");
			निकास(1);
		}
		optind = optreset = 1;
		__progname = sftp_argv[0];
#अगर_घोषित WITH_SELINUX
		ssh_selinux_change_context("sftpd_t");
#पूर्ण_अगर
		निकास(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}

	ख_साफ(शून्य);

	/* Get the last component of the shell name. */
	अगर ((shell0 = म_खोजप(shell, '/')) != शून्य)
		shell0++;
	अन्यथा
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	अगर (!command) {
		अक्षर argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		अगर (strlcpy(argv0 + 1, shell0, माप(argv0) - 1)
		    >= माप(argv0) - 1) {
			त्रुटि_सं = EINVAL;
			लिखो_त्रुटि(shell);
			निकास(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = शून्य;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		लिखो_त्रुटि(shell);
		निकास(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (अक्षर *) shell0;
	argv[1] = "-c";
	argv[2] = (अक्षर *) command;
	argv[3] = शून्य;
	execve(shell, argv, env);
	लिखो_त्रुटि(shell);
	निकास(1);
}

व्योम
session_unused(पूर्णांक id)
{
	debug3_f("session id %d unused", id);
	अगर (id >= options.max_sessions ||
	    id >= sessions_nalloc) {
		fatal_f("insane session id %d (max %d nalloc %d)",
		    id, options.max_sessions, sessions_nalloc);
	}
	स_रखो(&sessions[id], 0, माप(*sessions));
	sessions[id].self = id;
	sessions[id].used = 0;
	sessions[id].chanid = -1;
	sessions[id].ptyfd = -1;
	sessions[id].ttyfd = -1;
	sessions[id].ptymaster = -1;
	sessions[id].x11_chanids = शून्य;
	sessions[id].अग्र_unused = sessions_first_unused;
	sessions_first_unused = id;
}

Session *
session_new(व्योम)
{
	Session *s, *tmp;

	अगर (sessions_first_unused == -1) {
		अगर (sessions_nalloc >= options.max_sessions)
			वापस शून्य;
		debug2_f("allocate (allocated %d max %d)",
		    sessions_nalloc, options.max_sessions);
		tmp = xrecallocarray(sessions, sessions_nalloc,
		    sessions_nalloc + 1, माप(*sessions));
		अगर (tmp == शून्य) {
			error_f("cannot allocate %d sessions",
			    sessions_nalloc + 1);
			वापस शून्य;
		}
		sessions = tmp;
		session_unused(sessions_nalloc++);
	}

	अगर (sessions_first_unused >= sessions_nalloc ||
	    sessions_first_unused < 0) {
		fatal_f("insane first_unused %d max %d nalloc %d",
		    sessions_first_unused, options.max_sessions,
		    sessions_nalloc);
	}

	s = &sessions[sessions_first_unused];
	अगर (s->used)
		fatal_f("session %d already used", sessions_first_unused);
	sessions_first_unused = s->अग्र_unused;
	s->used = 1;
	s->अग्र_unused = -1;
	debug("session_new: session %d", s->self);

	वापस s;
}

अटल व्योम
session_dump(व्योम)
{
	पूर्णांक i;
	क्रम (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		debug("dump: used %d next_unused %d session %d "
		    "channel %d pid %ld",
		    s->used,
		    s->अग्र_unused,
		    s->self,
		    s->chanid,
		    (दीर्घ)s->pid);
	}
}

पूर्णांक
session_open(Authctxt *authctxt, पूर्णांक chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	अगर (s == शून्य) {
		error("no more sessions");
		वापस 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	अगर (s->pw == शून्य || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	वापस 1;
}

Session *
session_by_tty(अक्षर *tty)
{
	पूर्णांक i;
	क्रम (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		अगर (s->used && s->ttyfd != -1 && म_भेद(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			वापस s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	वापस शून्य;
}

अटल Session *
session_by_channel(पूर्णांक id)
{
	पूर्णांक i;
	क्रम (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		अगर (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d",
			    i, id);
			वापस s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	वापस शून्य;
}

अटल Session *
session_by_x11_channel(पूर्णांक id)
{
	पूर्णांक i, j;

	क्रम (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];

		अगर (s->x11_chanids == शून्य || !s->used)
			जारी;
		क्रम (j = 0; s->x11_chanids[j] != -1; j++) {
			अगर (s->x11_chanids[j] == id) {
				debug("session_by_x11_channel: session %d "
				    "channel %d", s->self, id);
				वापस s;
			}
		}
	}
	debug("session_by_x11_channel: unknown channel %d", id);
	session_dump();
	वापस शून्य;
}

अटल Session *
session_by_pid(pid_t pid)
{
	पूर्णांक i;
	debug("session_by_pid: pid %ld", (दीर्घ)pid);
	क्रम (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		अगर (s->used && s->pid == pid)
			वापस s;
	}
	error("session_by_pid: unknown pid %ld", (दीर्घ)pid);
	session_dump();
	वापस शून्य;
}

अटल पूर्णांक
session_window_change_req(काष्ठा ssh *ssh, Session *s)
{
	पूर्णांक r;

	अगर ((r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	pty_change_window_आकार(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	वापस 1;
}

अटल पूर्णांक
session_pty_req(काष्ठा ssh *ssh, Session *s)
{
	पूर्णांक r;

	अगर (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		वापस 0;
	}
	अगर (s->ttyfd != -1) {
		ssh_packet_disconnect(ssh, "Protocol error: you already have a pty.");
		वापस 0;
	}

	अगर ((r = sshpkt_get_cstring(ssh, &s->term, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->xpixel)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->ypixel)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	अगर (म_भेद(s->term, "") == 0) {
		मुक्त(s->term);
		s->term = शून्य;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	अगर (!mm_pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, माप(s->tty))) {
		मुक्त(s->term);
		s->term = शून्य;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		वापस 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	ssh_tty_parse_modes(ssh, s->ttyfd);

	अगर ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Set window size from the packet. */
	pty_change_window_आकार(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	session_proctitle(s);
	वापस 1;
}

अटल पूर्णांक
session_subsystem_req(काष्ठा ssh *ssh, Session *s)
{
	काष्ठा stat st;
	पूर्णांक r, success = 0, found = 0;
	अक्षर *prog, *cmd, *type;
	u_int i;

	अगर ((r = sshpkt_get_cstring(ssh, &s->subsys, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug2("subsystem request for %.100s by user %s", s->subsys,
	    s->pw->pw_name);

	क्रम (i = 0; i < options.अंक_subsystems; i++) {
		अगर (म_भेद(s->subsys, options.subsystem_name[i]) != 0)
			जारी;
		found = 1;
		prog = options.subsystem_command[i];
		cmd = options.subsystem_args[i];
		अगर (म_भेद(INTERNAL_SFTP_NAME, prog) == 0) {
			s->is_subsystem = SUBSYSTEM_INT_SFTP;
			debug("subsystem: %s", prog);
		} अन्यथा {
			अगर (stat(prog, &st) == -1)
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
		अवरोध;
	}

	अगर (!success) {
		logit("subsystem request for %.100s by user %s failed, %s",
		    s->subsys, s->pw->pw_name,
		    found ? "execution failed" : "subsystem not found");
	}

	वापस success;
}

अटल पूर्णांक
session_x11_req(काष्ठा ssh *ssh, Session *s)
{
	पूर्णांक r, success;
	u_char single_connection = 0;

	अगर (s->auth_proto != शून्य || s->auth_तथ्य != शून्य) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		वापस 0;
	}
	अगर ((r = sshpkt_get_u8(ssh, &single_connection)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_proto, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &s->auth_तथ्य, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->screen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	s->single_connection = single_connection;

	अगर (xauth_valid_string(s->auth_proto) &&
	    xauth_valid_string(s->auth_तथ्य))
		success = session_setup_x11fwd(ssh, s);
	अन्यथा {
		success = 0;
		error("Invalid X11 forwarding data");
	}
	अगर (!success) {
		मुक्त(s->auth_proto);
		मुक्त(s->auth_तथ्य);
		s->auth_proto = शून्य;
		s->auth_तथ्य = शून्य;
	}
	वापस success;
}

अटल पूर्णांक
session_shell_req(काष्ठा ssh *ssh, Session *s)
{
	पूर्णांक r;

	अगर ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:shell");

	वापस do_exec(ssh, s, शून्य) == 0;
}

अटल पूर्णांक
session_exec_req(काष्ठा ssh *ssh, Session *s)
{
	u_int success;
	पूर्णांक r;
	अक्षर *command = शून्य;

	अगर ((r = sshpkt_get_cstring(ssh, &command, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	channel_set_xtype(ssh, s->chanid, "session:command");

	success = do_exec(ssh, s, command) == 0;
	मुक्त(command);
	वापस success;
}

अटल पूर्णांक
session_break_req(काष्ठा ssh *ssh, Session *s)
{
	पूर्णांक r;

	अगर ((r = sshpkt_get_u32(ssh, शून्य)) != 0 || /* ignore */
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	अगर (s->ptymaster == -1 || tcsendbreak(s->ptymaster, 0) == -1)
		वापस 0;
	वापस 1;
}

अटल पूर्णांक
session_env_req(काष्ठा ssh *ssh, Session *s)
{
	अक्षर *name, *val;
	u_int i;
	पूर्णांक r;

	अगर ((r = sshpkt_get_cstring(ssh, &name, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &val, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	/* Don't set too many environment variables */
	अगर (s->अंक_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		जाओ fail;
	}

	क्रम (i = 0; i < options.अंक_accept_env; i++) {
		अगर (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->अंक_env, name, val);
			s->env = xrecallocarray(s->env, s->अंक_env,
			    s->अंक_env + 1, माप(*s->env));
			s->env[s->अंक_env].name = name;
			s->env[s->अंक_env].val = val;
			s->अंक_env++;
			वापस (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	मुक्त(name);
	मुक्त(val);
	वापस (0);
}

/*
 * Conversion of signals from ssh channel request names.
 * Subset of signals from RFC 4254 section 6.10C, with SIGINFO as
 * local extension.
 */
अटल पूर्णांक
name2sig(अक्षर *name)
{
#घोषणा SSH_SIG(x) अगर (म_भेद(name, #x) == 0) वापस SIG ## x
	SSH_SIG(HUP);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(QUIT);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#अघोषित	SSH_SIG
#अगर_घोषित SIGINFO
	अगर (म_भेद(name, "INFO@openssh.com") == 0)
		वापस SIGINFO;
#पूर्ण_अगर
	वापस -1;
}

अटल पूर्णांक
session_signal_req(काष्ठा ssh *ssh, Session *s)
{
	अक्षर *signame = शून्य;
	पूर्णांक r, sig, success = 0;

	अगर ((r = sshpkt_get_cstring(ssh, &signame, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse");
		जाओ out;
	}
	अगर ((sig = name2sig(signame)) == -1) {
		error_f("unsupported signal \"%s\"", signame);
		जाओ out;
	}
	अगर (s->pid <= 0) {
		error_f("no pid for session %d", s->self);
		जाओ out;
	}
	अगर (s->forced || s->is_subsystem) {
		error_f("refusing to send signal %s to %s session",
		    signame, s->forced ? "forced-command" : "subsystem");
		जाओ out;
	}

	debug_f("signal %s, killpg(%ld, %d)", signame, (दीर्घ)s->pid, sig);
	temporarily_use_uid(s->pw);
	r = killpg(s->pid, sig);
	restore_uid();
	अगर (r != 0) {
		error_f("killpg(%ld, %d): %s", (दीर्घ)s->pid,
		    sig, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}

	/* success */
	success = 1;
 out:
	मुक्त(signame);
	वापस success;
}

अटल पूर्णांक
session_auth_agent_req(काष्ठा ssh *ssh, Session *s, पूर्णांक agent_new)
{
	अटल पूर्णांक called = 0;
	पूर्णांक r;

	अगर ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	अगर (!auth_opts->permit_agent_forwarding_flag ||
	    !options.allow_agent_forwarding ||
	    options.disable_forwarding) {
		debug_f("agent forwarding disabled");
		वापस 0;
	}
	अगर (called)
		वापस 0;

	called = 1;
	वापस auth_निवेश_request_forwarding(ssh, s->pw, agent_new);
}

पूर्णांक
session_निवेश_channel_req(काष्ठा ssh *ssh, Channel *c, स्थिर अक्षर *rtype)
{
	पूर्णांक success = 0;
	Session *s;

	अगर ((s = session_by_channel(c->self)) == शून्य) {
		logit_f("no session %d req %.100s", c->self, rtype);
		वापस 0;
	}
	debug_f("session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	अगर (c->type == SSH_CHANNEL_LARVAL) {
		अगर (म_भेद(rtype, "shell") == 0) {
			success = session_shell_req(ssh, s);
		} अन्यथा अगर (म_भेद(rtype, "exec") == 0) {
			success = session_exec_req(ssh, s);
		} अन्यथा अगर (म_भेद(rtype, "pty-req") == 0) {
			success = session_pty_req(ssh, s);
		} अन्यथा अगर (म_भेद(rtype, "x11-req") == 0) {
			success = session_x11_req(ssh, s);
		} अन्यथा अगर (म_भेद(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(ssh, s, 0);
		} अन्यथा अगर (म_भेद(rtype, "agent-req") == 0) {
			success = session_auth_agent_req(ssh, s, 1);
		} अन्यथा अगर (म_भेद(rtype, "subsystem") == 0) {
			success = session_subsystem_req(ssh, s);
		} अन्यथा अगर (म_भेद(rtype, "env") == 0) {
			success = session_env_req(ssh, s);
		}
	}
	अगर (म_भेद(rtype, "window-change") == 0) {
		success = session_window_change_req(ssh, s);
	} अन्यथा अगर (म_भेद(rtype, "break") == 0) {
		success = session_break_req(ssh, s);
	} अन्यथा अगर (म_भेद(rtype, "signal") == 0) {
		success = session_signal_req(ssh, s);
	}

	वापस success;
}

व्योम
session_set_fds(काष्ठा ssh *ssh, Session *s,
    पूर्णांक fdin, पूर्णांक fdout, पूर्णांक fderr, पूर्णांक ignore_fderr, पूर्णांक is_tty)
{
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	अगर (s->chanid == -1)
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
व्योम
session_pty_cleanup2(Session *s)
{
	अगर (s == शून्य) {
		error_f("no session");
		वापस;
	}
	अगर (s->ttyfd == -1)
		वापस;

	debug_f("session %d release %s", s->self, s->tty);

	/* Record that the user has logged out. */
	अगर (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);

	/* Release the pseudo-tty. */
	अगर (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	अगर (s->ptymaster != -1 && बंद(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, म_त्रुटि(त्रुटि_सं));

	/* unlink pty from session */
	s->ttyfd = -1;
}

व्योम
session_pty_cleanup(Session *s)
{
	mm_session_pty_cleanup2(s);
}

अटल अक्षर *
sig2name(पूर्णांक sig)
{
#घोषणा SSH_SIG(x) अगर (sig == SIG ## x) वापस #x
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
#अघोषित	SSH_SIG
	वापस "SIG@openssh.com";
}

अटल व्योम
session_close_x11(काष्ठा ssh *ssh, पूर्णांक id)
{
	Channel *c;

	अगर ((c = channel_by_id(ssh, id)) == शून्य) {
		debug_f("x11 channel %d missing", id);
	} अन्यथा {
		/* Detach X11 listener */
		debug_f("detach x11 channel %d", id);
		channel_cancel_cleanup(ssh, id);
		अगर (c->ostate != CHAN_OUTPUT_CLOSED)
			chan_mark_dead(ssh, c);
	}
}

अटल व्योम
session_close_single_x11(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक force, व्योम *arg)
{
	Session *s;
	u_int i;

	debug3_f("channel %d", id);
	channel_cancel_cleanup(ssh, id);
	अगर ((s = session_by_x11_channel(id)) == शून्य)
		fatal_f("no x11 channel %d", id);
	क्रम (i = 0; s->x11_chanids[i] != -1; i++) {
		debug_f("session %d: closing channel %d",
		    s->self, s->x11_chanids[i]);
		/*
		 * The channel "id" is already closing, but make sure we
		 * close all of its siblings.
		 */
		अगर (s->x11_chanids[i] != id)
			session_close_x11(ssh, s->x11_chanids[i]);
	}
	मुक्त(s->x11_chanids);
	s->x11_chanids = शून्य;
	मुक्त(s->display);
	s->display = शून्य;
	मुक्त(s->auth_proto);
	s->auth_proto = शून्य;
	मुक्त(s->auth_तथ्य);
	s->auth_तथ्य = शून्य;
	मुक्त(s->auth_display);
	s->auth_display = शून्य;
}

अटल व्योम
session_exit_message(काष्ठा ssh *ssh, Session *s, पूर्णांक status)
{
	Channel *c;
	पूर्णांक r;
	अक्षर *note = शून्य;

	अगर ((c = channel_lookup(ssh, s->chanid)) == शून्य)
		fatal_f("session %d: no channel %d", s->self, s->chanid);

	अगर (WIFEXITED(status)) {
		channel_request_start(ssh, s->chanid, "exit-status", 0);
		अगर ((r = sshpkt_put_u32(ssh, WEXITSTATUS(status))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: exit reply", __func__);
		xasprintf(&note, "exit %d", WEXITSTATUS(status));
	} अन्यथा अगर (WIFSIGNALED(status)) {
		channel_request_start(ssh, s->chanid, "exit-signal", 0);
#अगर_अघोषित WCOREDUMP
# define WCOREDUMP(x) (0)
#पूर्ण_अगर
		अगर ((r = sshpkt_put_cstring(ssh, sig2name(WTERMSIG(status)))) != 0 ||
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
	    (दीर्घ)s->pid, note == शून्य ? "UNKNOWN" : note);
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
	अगर (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(ssh, c);
}

व्योम
session_close(काष्ठा ssh *ssh, Session *s)
{
	u_int i;

	verbose("Close session: user %s from %.200s port %d id %d",
	    s->pw->pw_name,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    s->self);

	अगर (s->ttyfd != -1)
		session_pty_cleanup(s);
	मुक्त(s->term);
	मुक्त(s->display);
	मुक्त(s->x11_chanids);
	मुक्त(s->auth_display);
	मुक्त(s->auth_तथ्य);
	मुक्त(s->auth_proto);
	मुक्त(s->subsys);
	अगर (s->env != शून्य) {
		क्रम (i = 0; i < s->अंक_env; i++) {
			मुक्त(s->env[i].name);
			मुक्त(s->env[i].val);
		}
		मुक्त(s->env);
	}
	session_proctitle(s);
	session_unused(s->self);
}

व्योम
session_close_by_pid(काष्ठा ssh *ssh, pid_t pid, पूर्णांक status)
{
	Session *s = session_by_pid(pid);
	अगर (s == शून्य) {
		debug_f("no session for pid %ld", (दीर्घ)pid);
		वापस;
	}
	अगर (s->chanid != -1)
		session_exit_message(ssh, s, status);
	अगर (s->ttyfd != -1)
		session_pty_cleanup(s);
	s->pid = 0;
}

/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
व्योम
session_close_by_channel(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक force, व्योम *arg)
{
	Session *s = session_by_channel(id);
	u_int i;

	अगर (s == शून्य) {
		debug_f("no session for id %d", id);
		वापस;
	}
	debug_f("channel %d child %ld", id, (दीर्घ)s->pid);
	अगर (s->pid != 0) {
		debug_f("channel %d: has child, ttyfd %d", id, s->ttyfd);
		/*
		 * delay detach of session (unless this is a forced close),
		 * but release pty, since the fd's to the child are already
		 * closed
		 */
		अगर (s->ttyfd != -1)
			session_pty_cleanup(s);
		अगर (!force)
			वापस;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(ssh, s->chanid);

	/* Close any X11 listeners associated with this session */
	अगर (s->x11_chanids != शून्य) {
		क्रम (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(ssh, s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}

	s->chanid = -1;
	session_close(ssh, s);
}

व्योम
session_destroy_all(काष्ठा ssh *ssh, व्योम (*closefunc)(Session *))
{
	पूर्णांक i;
	क्रम (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		अगर (s->used) {
			अगर (closefunc != शून्य)
				closefunc(s);
			अन्यथा
				session_close(ssh, s);
		}
	}
}

अटल अक्षर *
session_tty_list(व्योम)
{
	अटल अक्षर buf[1024];
	पूर्णांक i;
	अक्षर *cp;

	buf[0] = '\0';
	क्रम (i = 0; i < sessions_nalloc; i++) {
		Session *s = &sessions[i];
		अगर (s->used && s->ttyfd != -1) {

			अगर (म_भेदन(s->tty, "/dev/", 5) != 0) {
				cp = म_खोजप(s->tty, '/');
				cp = (cp == शून्य) ? s->tty : cp + 1;
			} अन्यथा
				cp = s->tty + 5;

			अगर (buf[0] != '\0')
				strlcat(buf, ",", माप buf);
			strlcat(buf, cp, माप buf);
		}
	}
	अगर (buf[0] == '\0')
		strlcpy(buf, "notty", माप buf);
	वापस buf;
}

व्योम
session_proctitle(Session *s)
{
	अगर (s->pw == शून्य)
		error("no user for session %d", s->self);
	अन्यथा
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

पूर्णांक
session_setup_x11fwd(काष्ठा ssh *ssh, Session *s)
{
	काष्ठा stat st;
	अक्षर display[512], auth_display[512];
	अक्षर hostname[NI_MAXHOST];
	u_int i;

	अगर (!auth_opts->permit_x11_forwarding_flag) {
		ssh_packet_send_debug(ssh, "X11 forwarding disabled by key options.");
		वापस 0;
	}
	अगर (!options.x11_forwarding || options.disable_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		वापस 0;
	}
	अगर (options.xauth_location == शून्य ||
	    (stat(options.xauth_location, &st) == -1)) {
		ssh_packet_send_debug(ssh, "No xauth program; cannot forward X11.");
		वापस 0;
	}
	अगर (s->display != शून्य) {
		debug("X11 display already set.");
		वापस 0;
	}
	अगर (x11_create_display_inet(ssh, options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_संख्या, &s->x11_chanids) == -1) {
		debug("x11_create_display_inet failed.");
		वापस 0;
	}
	क्रम (i = 0; s->x11_chanids[i] != -1; i++) {
		channel_register_cleanup(ssh, s->x11_chanids[i],
		    session_close_single_x11, 0);
	}

	/* Set up a suitable value for the DISPLAY variable. */
	अगर (gethostname(hostname, माप(hostname)) == -1)
		fatal("gethostname: %.100s", म_त्रुटि(त्रुटि_सं));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	अगर (options.x11_use_localhost) {
		snprintf(display, माप display, "localhost:%u.%u",
		    s->display_संख्या, s->screen);
		snprintf(auth_display, माप auth_display, "unix:%u.%u",
		    s->display_संख्या, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} अन्यथा {
#अगर_घोषित IPADDR_IN_DISPLAY
		काष्ठा hostent *he;
		काष्ठा in_addr my_addr;

		he = gethostbyname(hostname);
		अगर (he == शून्य) {
			error("Can't get IP address for X11 DISPLAY.");
			ssh_packet_send_debug(ssh, "Can't get IP address for X11 DISPLAY.");
			वापस 0;
		}
		स_नकल(&my_addr, he->h_addr_list[0], माप(काष्ठा in_addr));
		snprintf(display, माप display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_संख्या, s->screen);
#अन्यथा
		snprintf(display, माप display, "%.400s:%u.%u", hostname,
		    s->display_संख्या, s->screen);
#पूर्ण_अगर
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	वापस 1;
}

अटल व्योम
do_authenticated2(काष्ठा ssh *ssh, Authctxt *authctxt)
{
	server_loop2(ssh, authctxt);
}

व्योम
do_cleanup(काष्ठा ssh *ssh, Authctxt *authctxt)
{
	अटल पूर्णांक called = 0;

	debug("do_cleanup");

	/* no cleanup if we're in the child for login shell */
	अगर (is_child)
		वापस;

	/* avoid double cleanup */
	अगर (called)
		वापस;
	called = 1;

	अगर (authctxt == शून्य)
		वापस;

#अगर_घोषित USE_PAM
	अगर (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#पूर्ण_अगर

	अगर (!authctxt->authenticated)
		वापस;

#अगर_घोषित KRB5
	अगर (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#पूर्ण_अगर

#अगर_घोषित GSSAPI
	अगर (options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#पूर्ण_अगर

	/* remove agent socket */
	auth_sock_cleanup_proc(authctxt->pw);

	/* remove userauth info */
	अगर (auth_info_file != शून्य) {
		temporarily_use_uid(authctxt->pw);
		unlink(auth_info_file);
		restore_uid();
		मुक्त(auth_info_file);
		auth_info_file = शून्य;
	}

	/*
	 * Cleanup ptys/utmp only if privsep is disabled,
	 * or if running in monitor.
	 */
	अगर (mm_is_monitor())
		session_destroy_all(ssh, session_pty_cleanup2);
}

/* Return a name for the remote host that fits inside utmp_size */

स्थिर अक्षर *
session_get_remote_name_or_ip(काष्ठा ssh *ssh, u_int utmp_आकार, पूर्णांक use_dns)
{
	स्थिर अक्षर *remote = "";

	अगर (utmp_आकार > 0)
		remote = auth_get_canonical_hostname(ssh, use_dns);
	अगर (utmp_आकार == 0 || म_माप(remote) > utmp_आकार)
		remote = ssh_remote_ipaddr(ssh);
	वापस remote;
}

