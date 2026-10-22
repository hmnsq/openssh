/* $OpenBSD: sshd.c,v 1.635 2026/09/16 07:47:29 jsg Exp $ */
/*
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
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
#समावेश <sys/ioctl.h>
#समावेश <sys/socket.h>
#समावेश <sys/stat.h>
#समावेश <sys/time.h>
#समावेश <sys/queue.h>
#समावेश <sys/wait.h>
#समावेश <sys/utsname.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <netdb.h>
#समावेश <paths.h>
#समावेश <grp.h>
#समावेश <poll.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <time.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>

#अगर_घोषित HAVE_SECUREWARE
#समावेश <sys/security.h>
#समावेश <prot.h>
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "sshpty.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "compat.h"
#समावेश "digest.h"
#समावेश "sshkey.h"
#समावेश "authfile.h"
#समावेश "pathnames.h"
#समावेश "canohost.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "authfd.h"
#समावेश "msg.h"
#समावेश "version.h"
#समावेश "ssherr.h"
#समावेश "sk-api.h"
#समावेश "addr.h"
#समावेश "srclimit.h"
#समावेश "atomicio.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"

/* Re-exec fds */
#घोषणा REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#घोषणा REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#घोषणा REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

बाह्य अक्षर *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
पूर्णांक debug_flag = 0;

/* Saved arguments to main(). */
अटल अक्षर execpath[PATH_MAX];
अटल अक्षर **saved_argv;
अटल पूर्णांक saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#घोषणा	MAX_LISTEN_SOCKS	16
अटल पूर्णांक listen_socks[MAX_LISTEN_SOCKS];
अटल पूर्णांक अंक_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
काष्ठा {
	काष्ठा sshkey	**host_कुंजियाँ;		/* all private host keys */
	काष्ठा sshkey	**host_pubkeys;		/* all public host keys */
	काष्ठा sshkey	**host_certificates;	/* all public host certificates */
	पूर्णांक		have_ssh2_कुंजी;
} sensitive_तथ्य;

/* This is set to true when a signal is received. */
अटल अस्थिर संक_पूर्ण_प्रकार received_siginfo = 0;
अटल अस्थिर संक_पूर्ण_प्रकार received_sigchld = 0;
अटल अस्थिर संक_पूर्ण_प्रकार received_sighup = 0;
अटल अस्थिर संक_पूर्ण_प्रकार received_sigterm = 0;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/*
 * The early_child/children array below is used for tracking children of the
 * listening sshd process early in their lifespans, before they have
 * completed authentication. This tracking is needed for four things:
 *
 * 1) Implementing the MaxStartups limit of concurrent unauthenticated
 *    connections.
 * 2) Avoiding a race condition for SIGHUP processing, where child processes
 *    may have listen_socks open that could collide with main listener process
 *    after it restarts.
 * 3) Ensuring that rexec'd sshd processes have received their initial state
 *    from the parent listen process before handling SIGHUP.
 * 4) Tracking and logging unsuccessful exits from the preauth sshd monitor,
 *    including and especially those for LoginGraceTime timeouts.
 *
 * Child processes signal that they have completed closure of the listen_socks
 * and (if applicable) received their rexec state by sending a char over their
 * sock.
 *
 * Child processes signal that authentication has completed by sending a
 * second char over the socket before closing it, otherwise the listener will
 * continue tracking the child (and using up a MaxStartups slot) until the
 * preauth subprocess exits, whereupon the listener will log its exit status.
 * preauth processes will exit with a status of EXIT_LOGIN_GRACE to indicate
 * they did not authenticate before the LoginGraceTime alarm fired.
 */
काष्ठा early_child {
	पूर्णांक pipefd;
	पूर्णांक early;		/* Indicates child closed listener */
	अक्षर *id;		/* human readable connection identifier */
	pid_t pid;
	काष्ठा xaddr addr;
	पूर्णांक have_addr;
	पूर्णांक status, have_status;
	काष्ठा sshbuf *config;
	काष्ठा sshbuf *कुंजियाँ;
};
अटल काष्ठा early_child *children;
अटल पूर्णांक children_active;

/* sshd_config buffer */
काष्ठा sshbuf *cfg;
काष्ठा sshbuf *config;	/* packed */

/* Included files from the configuration file */
काष्ठा include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
काष्ठा sshbuf *loginmsg;

/* Unprivileged user */
काष्ठा passwd *privsep_pw = शून्य;

अटल अक्षर *listener_proctitle;

/*
 * Close all listening sockets
 */
अटल व्योम
close_listen_socks(व्योम)
{
	पूर्णांक i;

	क्रम (i = 0; i < अंक_listen_socks; i++)
		बंद(listen_socks[i]);
	अंक_listen_socks = 0;
}

/* Allocate and initialise the children array */
अटल व्योम
child_alloc(व्योम)
{
	पूर्णांक i;

	children = xcalloc(options.max_startups, माप(*children));
	क्रम (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
अटल काष्ठा early_child *
child_register(पूर्णांक pipefd, पूर्णांक sockfd)
{
	पूर्णांक i, lport, rport;
	अक्षर *laddr = शून्य, *raddr = शून्य;
	काष्ठा early_child *child = शून्य;
	काष्ठा sockaddr_storage addr;
	socklen_t addrlen = माप(addr);
	काष्ठा sockaddr *sa = (काष्ठा sockaddr *)&addr;

	क्रम (i = 0; i < options.max_startups; i++) {
		अगर (children[i].pipefd != -1 ||
		    children[i].config != शून्य ||
		    children[i].कुंजियाँ != शून्य ||
		    children[i].pid > 0)
			जारी;
		child = &(children[i]);
		अवरोध;
	}
	अगर (child == शून्य) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	अगर ((child->config = sshbuf_fromb(config)) == शून्य)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	अगर (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	अगर ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} अन्यथा {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	मुक्त(laddr);
	मुक्त(raddr);
	अगर (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	वापस child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
अटल व्योम
child_finish(काष्ठा early_child *child)
{
	अगर (children_active == 0)
		fatal_f("internal error: children_active underflow");
	अगर (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		बंद(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->कुंजियाँ);
	मुक्त(child->id);
	स_रखो(child, '\0', माप(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
अटल व्योम
child_close(काष्ठा early_child *child, पूर्णांक force_final, पूर्णांक quiet)
{
	अगर (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	अगर (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		बंद(child->pipefd);
		child->pipefd = -1;
	}
	अगर (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
अटल व्योम
child_exit(pid_t pid, पूर्णांक status)
{
	पूर्णांक i;

	अगर (children == शून्य || pid <= 0)
		वापस;
	क्रम (i = 0; i < options.max_startups; i++) {
		अगर (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			अवरोध;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
अटल व्योम
child_reap(काष्ठा early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	पूर्णांक was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	स्थिर अक्षर *child_status;

	अगर (child->config)
		child_status = " (sending config)";
	अन्यथा अगर (child->कुंजियाँ)
		child_status = " (sending keys)";
	अन्यथा अगर (child->early)
		child_status = " (early)";
	अन्यथा
		child_status = "";

	/* Log exit information */
	अगर (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		अगर ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (दीर्घ)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		अगर (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} अन्यथा अगर (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (दीर्घ)child->pid, child->id, child->status,
		    child_status);
	} अन्यथा {
		/* Normal exit. We care about the status */
		चयन (WEXITSTATUS(child->status)) {
		हाल 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (दीर्घ)child->pid, child->id,
			    child_status);
			अवरोध;
		हाल EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (दीर्घ)child->pid,
			    child_status);
			अवरोध;
		हाल EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (दीर्घ)child->pid, child->id, child_status);
			अवरोध;
		हाल EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (दीर्घ)child->pid, child->id, child_status);
			अवरोध;
		हाल EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (दीर्घ)child->pid, child->id, child_status);
			अवरोध;
		हाल EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (दीर्घ)child->pid, child->id, child_status);
			अवरोध;
		शेष:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (दीर्घ)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			अवरोध;
		}
	}

	अगर (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	अगर (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
अटल व्योम
child_reap_all_exited(व्योम)
{
	पूर्णांक i;
	pid_t pid;
	पूर्णांक status;

	अगर (children == शून्य)
		वापस;

	क्रम (;;) {
		अगर ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			अवरोध;
		अन्यथा अगर (pid == -1) {
			अगर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
				जारी;
			अगर (त्रुटि_सं != ECHILD)
				error_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
			अवरोध;
		}
		child_exit(pid, status);
	}

	क्रम (i = 0; i < options.max_startups; i++) {
		अगर (!children[i].have_status)
			जारी;
		child_reap(&(children[i]));
	}
}

अटल व्योम
close_startup_pipes(व्योम)
{
	पूर्णांक i;

	अगर (children == शून्य)
		वापस;
	क्रम (i = 0; i < options.max_startups; i++) {
		अगर (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
अटल व्योम
show_info(व्योम)
{
	पूर्णांक i;
	स्थिर अक्षर *child_status;

	/* XXX print listening sockets here too */
	अगर (children == शून्य)
		वापस;
	logit("%d active startups", children_active);
	क्रम (i = 0; i < options.max_startups; i++) {
		अगर (children[i].pipefd == -1 && children[i].pid <= 0)
			जारी;
		अगर (children[i].config)
			child_status = " (sending config)";
		अन्यथा अगर (children[i].कुंजियाँ)
			child_status = " (sending keys)";
		अन्यथा अगर (children[i].early)
			child_status = " (early)";
		अन्यथा
			child_status = "";
		logit("child %d: fd=%d pid=%ld %s%s", i, children[i].pipefd,
		    (दीर्घ)children[i].pid, children[i].id, child_status);
	}
	srclimit_penalty_info();
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

अटल व्योम
sighup_handler(पूर्णांक sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
अटल व्योम
sighup_restart(व्योम)
{
	logit("Received SIGHUP; restarting.");
	अगर (options.pid_file != शून्य)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, संक_छोड़ो); /* will be restored after exec */
	execv(execpath, saved_argv);
	logit("RESTART FAILED: execpath='%.100s', error: %.100s.", execpath,
	    म_त्रुटि(त्रुटि_सं));
	निकास(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
अटल व्योम
sigterm_handler(पूर्णांक sig)
{
	received_sigterm = sig;
}

#अगर_घोषित SIGINFO
अटल व्योम
siginfo_handler(पूर्णांक sig)
{
	received_siginfo = 1;
}
#पूर्ण_अगर

अटल व्योम
main_sigchld_handler(पूर्णांक sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
अटल पूर्णांक
should_drop_connection(पूर्णांक startups)
{
	पूर्णांक p, r;

	अगर (startups < options.max_startups_begin)
		वापस 0;
	अगर (startups >= options.max_startups)
		वापस 1;
	अगर (options.max_startups_rate == 100)
		वापस 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	वापस (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
अटल पूर्णांक
drop_connection(पूर्णांक sock, पूर्णांक startups, पूर्णांक notify_pipe)
{
	अटल काष्ठा log_ratelimit_ctx ratelimit_maxstartups;
	अटल काष्ठा log_ratelimit_ctx ratelimit_penalty;
	अटल पूर्णांक init_done;
	अक्षर *laddr, *raddr;
	स्थिर अक्षर *reason = शून्य, *subreason = शून्य;
	स्थिर अक्षर संदेश[] = "Not allowed at this time\r\n";
	काष्ठा log_ratelimit_ctx *rl = शून्य;
	पूर्णांक ratelimited;
	u_int ndropped;

	अगर (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	अगर (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} अन्यथा {
		/* MaxStartups */
		अगर (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			वापस 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, समय(शून्य), शून्य, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != शून्य ? subreason : reason);
	मुक्त(laddr);
	मुक्त(raddr);
	अगर (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(व्योम)ग_लिखो(sock, संदेश, माप(संदेश) - 1);
	वापस 1;
}

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	ख_लिखो(मानक_त्रुटि,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	निकास(1);
}

अटल काष्ठा sshbuf *
pack_hostkeys(व्योम)
{
	काष्ठा sshbuf *m = शून्य, *keybuf = शून्य, *hostkeys = शून्य;
	पूर्णांक r;
	u_int i;
	माप_प्रकार len;

	अगर ((m = sshbuf_new()) == शून्य ||
	    (keybuf = sshbuf_new()) == शून्य ||
	    (hostkeys = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		अगर (sensitive_तथ्य.host_कुंजियाँ[i] != शून्य &&
		    (r = sshkey_private_serialize(sensitive_तथ्य.host_कुंजियाँ[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		अगर ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		अगर (sensitive_तथ्य.host_pubkeys[i] != शून्य) {
			अगर ((r = sshkey_puts(sensitive_तथ्य.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} अन्यथा {
			अगर ((r = sshbuf_put_string(hostkeys, शून्य, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		अगर (sensitive_तथ्य.host_certificates[i] != शून्य) {
			अगर ((r = sshkey_puts(
			    sensitive_तथ्य.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} अन्यथा {
			अगर ((r = sshbuf_put_string(hostkeys, शून्य, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	अगर ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	अगर ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	वापस m;
}

अटल काष्ठा sshbuf *
pack_config(काष्ठा sshbuf *conf)
{
	काष्ठा sshbuf *m = शून्य, *inc = शून्य;
	काष्ठा include_item *item = शून्य;
	माप_प्रकार len;
	पूर्णांक r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	अगर ((m = sshbuf_new()) == शून्य ||
	    (inc = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		अगर ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	अगर ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	अगर ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	वापस m;
}

/*
 * Protocol from reexec master to child:
 *	uint32  size
 *	uint8   type (ignored)
 *	string	configuration
 *	uint64	timing_secret
 *	string	included_files[] {
 *		string	selector
 *		string	filename
 *		string	contents
 *	}
 * Second message
 *	uint32  size
 *	uint8   type (ignored)
 *	string	host_keys[] {
 *		string private_key
 *		string public_key
 *		string certificate
 *	}
 */
/*
 * This function is used only if inet_flag or debug_flag is set,
 * otherwise the data is sent from the main poll loop.
 * It sends the config from a child process back to the parent.
 * The parent will read the config after exec.
 */
अटल व्योम
send_rexec_state(पूर्णांक fd)
{
	काष्ठा sshbuf *कुंजियाँ;
	u_int mlen;
	pid_t pid;

	अगर ((pid = विभाजन()) == -1)
		fatal_f("fork failed: %s", म_त्रुटि(त्रुटि_सं));
	अगर (pid != 0)
		वापस;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	अगर (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", म_त्रुटि(त्रुटि_सं));

	कुंजियाँ = pack_hostkeys();
	mlen = sshbuf_len(कुंजियाँ);
	अगर (atomicio(vwrite, fd, sshbuf_mutable_ptr(कुंजियाँ), mlen) != mlen)
		error_f("write: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_free(कुंजियाँ);
	debug3_f("done");
	निकास(0);
}

/*
 * Listen for TCP connections
 */
अटल व्योम
listen_on_addrs(काष्ठा listenaddr *la)
{
	पूर्णांक ret, listen_sock;
	काष्ठा addrinfo *ai;
	अक्षर ntop[NI_MAXHOST], strport[NI_MAXSERV];

	क्रम (ai = la->addrs; ai; ai = ai->ai_next) {
		अगर (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			जारी;
		अगर (अंक_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		अगर ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, माप(ntop), strport, माप(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			जारी;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		अगर (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		अगर (set_nonblock(listen_sock) == -1) {
			बंद(listen_sock);
			जारी;
		}
		अगर (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", म_त्रुटि(त्रुटि_सं));
			बंद(listen_sock);
			जारी;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		अगर (la->rdomain != शून्य &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			बंद(listen_sock);
			जारी;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		अगर (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		अगर (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, म_त्रुटि(त्रुटि_सं));
			बंद(listen_sock);
			जारी;
		}
		listen_socks[अंक_listen_socks] = listen_sock;
		अंक_listen_socks++;

		/* Start listening on the port. */
		अगर (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, म_त्रुटि(त्रुटि_सं));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == शून्य ? "" : " rdomain ",
		    la->rdomain == शून्य ? "" : la->rdomain);
	}
}

अटल व्योम
server_listen(व्योम)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	क्रम (i = 0; i < options.अंक_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		मुक्त(options.listen_addrs[i].rdomain);
		स_रखो(&options.listen_addrs[i], 0,
		    माप(options.listen_addrs[i]));
	}
	मुक्त(options.listen_addrs);
	options.listen_addrs = शून्य;
	options.अंक_listen_addrs = 0;

	अगर (!अंक_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
अटल व्योम
server_accept_loop(पूर्णांक *sock_in, पूर्णांक *sock_out, पूर्णांक *newsock, पूर्णांक *config_s,
    पूर्णांक log_stderr)
{
	काष्ठा pollfd *pfd = शून्य;
	पूर्णांक i, ret, npfd, r;
	पूर्णांक oactive = -1, listening = 0, lameduck = 0;
	पूर्णांक *startup_pollfd;
	ssize_t len;
	स्थिर u_char *ptr;
	अक्षर c = 0;
	काष्ठा sockaddr_storage from;
	काष्ठा early_child *child;
	काष्ठा sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, माप(पूर्णांक));

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm/hup/chld/info, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
#अगर_घोषित SIGINFO
	sigaddset(&nsigset, SIGINFO);
#पूर्ण_अगर
	sigaddset(&nsigset, संक_इति);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(अंक_listen_socks + options.max_startups,
	    माप(काष्ठा pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	क्रम (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		अगर (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (पूर्णांक) received_sigterm);
			close_listen_socks();
			अगर (options.pid_file != शून्य)
				unlink(options.pid_file);
			निकास(received_sigterm == संक_इति ? 0 : 255);
		}
		अगर (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		अगर (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		अगर (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		अगर (received_sighup) {
			अगर (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			अगर (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, संक_इति);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, शून्य);
				sighup_restart();
			}
		}

		क्रम (i = 0; i < अंक_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = अंक_listen_socks;
		क्रम (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			अगर (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				अगर (children[i].config != शून्य ||
				    children[i].कुंजियाँ != शून्य)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, शून्य, &osigset);
		अगर (ret == -1 && त्रुटि_सं != EINTR) {
			error("ppoll: %.100s", म_त्रुटि(त्रुटि_सं));
			अगर (त्रुटि_सं == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, शून्य);
		अगर (ret == -1)
			जारी;

		क्रम (i = 0; i < options.max_startups; i++) {
			अगर (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				जारी;
			अगर (children[i].config)
				buf = children[i].config;
			अन्यथा अगर (children[i].कुंजियाँ)
				buf = children[i].कुंजियाँ;
			अन्यथा {
				error_f("no buffer to send");
				जारी;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = ग_लिखो(children[i].pipefd, ptr, len);
			अगर (ret == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN))
				जारी;
			अगर (ret <= 0) {
				अगर (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				जारी;
			}
			अगर (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				अगर (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = शून्य;
					children[i].कुंजियाँ = pack_hostkeys();
				} अन्यथा अगर (children[i].कुंजियाँ == buf) {
					/* sent both config and keys */
					children[i].कुंजियाँ = शून्य;
				} अन्यथा {
					fatal("config buf not set");
				}

			} अन्यथा {
				अगर ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		क्रम (i = 0; i < options.max_startups; i++) {
			अगर (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				जारी;
			चयन (पढ़ो(children[i].pipefd, &c, माप(c))) {
			हाल -1:
				अगर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
					जारी;
				अगर (त्रुटि_सं != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    म_त्रुटि(त्रुटि_सं));
				}
				/* FALLTHROUGH */
			हाल 0:
				/* child closed pipe */
				अगर (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (दीर्घ)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				अवरोध;
			हाल 1:
				अगर (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					जाओ problem_child;
				}
				अगर (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (दीर्घ)children[i].pid,
					    children[i].id);
				} अन्यथा अगर (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (दीर्घ)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} अन्यथा {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (पूर्णांक)c, (दीर्घ)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					अगर (children[i].early)
						listening--;
					अगर (children[i].pid > 0)
						समाप्त(children[i].pid, संक_इति);
					child_close(&(children[i]), 0, 0);
				}
				अवरोध;
			}
		}
		क्रम (i = 0; i < अंक_listen_socks; i++) {
			अगर (!(pfd[i].revents & POLLIN))
				जारी;
			fromlen = माप(from);
			*newsock = accept(listen_socks[i],
			    (काष्ठा sockaddr *)&from, &fromlen);
			अगर (*newsock == -1) {
				अगर (त्रुटि_सं != EINTR && त्रुटि_सं != EWOULDBLOCK &&
				    त्रुटि_सं != ECONNABORTED && त्रुटि_सं != EAGAIN)
					error("accept: %.100s",
					    म_त्रुटि(त्रुटि_सं));
				अगर (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
					usleep(100 * 1000);
				जारी;
			}
			अगर (unset_nonblock(*newsock) == -1) {
				बंद(*newsock);
				जारी;
			}
			अगर (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    म_त्रुटि(त्रुटि_सं));
				बंद(*newsock);
				जारी;
			}
			अगर (drop_connection(*newsock,
			    children_active, config_s[0])) {
				बंद(*newsock);
				बंद(config_s[0]);
				बंद(config_s[1]);
				जारी;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			अगर (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_in = *newsock;
				*sock_out = *newsock;
				send_rexec_state(config_s[0]);
				बंद(config_s[0]);
				मुक्त(pfd);
				मुक्त(startup_pollfd);
				वापस;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			platform_pre_fork();
			set_nonblock(config_s[0]);
			listening++;
			child = child_register(config_s[0], *newsock);
			अगर ((child->pid = विभाजन()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				platform_post_fork_child();
				close_startup_pipes();
				close_listen_socks();
				*sock_in = *newsock;
				*sock_out = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				बंद(config_s[0]);
				मुक्त(pfd);
				मुक्त(startup_pollfd);
				वापस;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			अगर (child->pid == -1)
				error("fork: %.100s", म_त्रुटि(त्रुटि_सं));
			अन्यथा
				debug("Forked child %ld.", (दीर्घ)child->pid);

			बंद(config_s[1]);
			बंद(*newsock);

			/*
			 * Ensure that our random state differs
			 * from that of the child
			 */
			reseed_prngs();
		}
	}
}

अटल व्योम
accumulate_host_timing_secret(काष्ठा sshbuf *server_cfg,
    काष्ठा sshkey *कुंजी)
{
	अटल काष्ठा ssh_digest_ctx *ctx;
	u_char *hash;
	माप_प्रकार len;
	काष्ठा sshbuf *buf;
	पूर्णांक r;

	अगर (ctx == शून्य && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == शून्य)
		fatal_f("ssh_digest_start");
	अगर (कुंजी == शून्य) { /* finalize */
		/* add server config in case we are using agent for host keys */
		अगर (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		अगर (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = शून्य;
		वापस;
	}
	अगर ((buf = sshbuf_new()) == शून्य)
		fatal_f("could not allocate buffer");
	अगर ((r = sshkey_private_serialize(कुंजी, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(कुंजी));
	अगर (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

अटल अक्षर *
prepare_proctitle(पूर्णांक ac, अक्षर **av)
{
	अक्षर *ret = शून्य;
	पूर्णांक i;

	क्रम (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	वापस ret;
}

/* Disconnect from the controlling tty. */
अटल व्योम
disconnect_controlling_tty(व्योम)
{
#अगर_घोषित TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	पूर्णांक fd;

	अगर ((fd = खोलो(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(व्योम) ioctl(fd, TIOCNOTTY, शून्य);
		बंद(fd);
	}
#पूर्ण_अगर /* TIOCNOTTY */
}

अटल व्योम
print_config(काष्ठा connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	निकास(0);
}

/*
 * Main program for the daemon.
 */
पूर्णांक
मुख्य(पूर्णांक ac, अक्षर **av)
{
	बाह्य अक्षर *optarg;
	बाह्य पूर्णांक optind;
	पूर्णांक log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	अक्षर *config_file_name = _PATH_SERVER_CONFIG_FILE;
	पूर्णांक r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	पूर्णांक sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	पूर्णांक devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	पूर्णांक need_chroot = 1;
	अक्षर *args, *fp, *पंक्ति, *logfile = शून्य, **rexec_argv = शून्य;
	काष्ठा stat sb;
	u_int i, j;
	mode_t new_umask;
	काष्ठा sshkey *कुंजी;
	काष्ठा sshkey *pubkey;
	काष्ठा connection_info connection_info;
	काष्ठा utsname utsname;
	sigset_t sigmask;

	स_रखो(&connection_info, 0, माप(connection_info));
#अगर_घोषित HAVE_SECUREWARE
	(व्योम)set_auth_parameters(ac, av);
#पूर्ण_अगर
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, शून्य);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, माप(*saved_argv));
	क्रम (i = 0; (पूर्णांक)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = शून्य;

#अगर_अघोषित HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#पूर्ण_अगर

	अगर (geteuid() == 0 && setgroups(0, शून्य) == -1)
		debug("setgroups(): %.200s", म_त्रुटि(त्रुटि_सं));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	जबतक ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		चयन (opt) {
		हाल '4':
			options.address_family = AF_INET;
			अवरोध;
		हाल '6':
			options.address_family = AF_INET6;
			अवरोध;
		हाल 'f':
			config_file_name = optarg;
			अवरोध;
		हाल 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			अवरोध;
		हाल 'd':
			अगर (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} अन्यथा अगर (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			अवरोध;
		हाल 'D':
			no_daemon_flag = 1;
			अवरोध;
		हाल 'G':
			do_dump_cfg = 1;
			अवरोध;
		हाल 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		हाल 'e':
			log_stderr = 1;
			अवरोध;
		हाल 'i':
			inetd_flag = 1;
			अवरोध;
		हाल 'r':
			logit("-r option is deprecated");
			अवरोध;
		हाल 'R':
			fatal("-R not supported here");
			अवरोध;
		हाल 'Q':
			/* ignored */
			अवरोध;
		हाल 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			अवरोध;
		हाल 'b':
			/* protocol 1, ignored */
			अवरोध;
		हाल 'p':
			options.ports_from_cmdline = 1;
			अगर (options.अंक_ports >= MAX_PORTS) {
				ख_लिखो(मानक_त्रुटि, "too many ports.\n");
				निकास(1);
			}
			options.ports[options.अंक_ports++] = a2port(optarg);
			अगर (options.ports[options.अंक_ports-1] <= 0) {
				ख_लिखो(मानक_त्रुटि, "Bad port number.\n");
				निकास(1);
			}
			अवरोध;
		हाल 'g':
			अगर ((options.login_grace_time = convtime(optarg)) == -1) {
				ख_लिखो(मानक_त्रुटि, "Invalid login grace time.\n");
				निकास(1);
			}
			अवरोध;
		हाल 'k':
			/* protocol 1, ignored */
			अवरोध;
		हाल 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			अवरोध;
		हाल 't':
			test_flag = 1;
			अवरोध;
		हाल 'T':
			test_flag = 2;
			अवरोध;
		हाल 'C':
			अगर (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				निकास(1);
			have_connection_info = 1;
			अवरोध;
		हाल 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, शून्य);
			अगर (utmp_len > HOST_NAME_MAX+1) {
				ख_लिखो(मानक_त्रुटि, "Invalid utmp length.\n");
				निकास(1);
			}
			अवरोध;
		हाल 'o':
			पंक्ति = xstrdup(optarg);
			अगर (process_server_config_पंक्ति(&options, पंक्ति,
			    "command-line", 0, शून्य, शून्य, &includes) != 0)
				निकास(1);
			मुक्त(पंक्ति);
			अवरोध;
		हाल 'V':
			ख_लिखो(मानक_त्रुटि, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			निकास(0);
		शेष:
			usage();
			अवरोध;
		}
	}

	अगर (getexecpath(execpath, माप execpath) != 0) {
		अगर (strlcpy(execpath, av[0], माप execpath) >=
		    माप execpath) {
			ख_लिखो(मानक_त्रुटि, "execution path is too long\n");
			निकास(1);
		}
	}
	अगर (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	अगर ((devnull = खोलो(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, म_त्रुटि(त्रुटि_सं));
	जबतक (devnull < REEXEC_MIN_FREE_FD) {
		अगर ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, म_त्रुटि(त्रुटि_सं));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	अगर (logfile != शून्य) {
		अक्षर *cp, pid_s[32];

		snprintf(pid_s, माप(pid_s), "%ld", (अचिन्हित दीर्घ)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (अक्षर *)शून्य);
		log_redirect_stderr_to(cp);
		मुक्त(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/*
	 * Unset KRB5CCNAME, otherwise the user's session may inherit it from
	 * root's environment
	 */
	अगर (दो_पर्या("KRB5CCNAME") != शून्य)
		(व्योम) unsetenv("KRB5CCNAME");

	sensitive_तथ्य.have_ssh2_कुंजी = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	अगर (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	अगर (uname(&utsname) != 0) {
		स_रखो(&utsname, 0, माप(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", माप(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	मुक्त(args);

	/* Fetch our configuration */
	अगर ((cfg = sshbuf_new()) == शून्य)
		fatal("sshbuf_new config failed");
	अगर (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, शून्य, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	अगर (options.authorized_कुंजियाँ_command_user == शून्य &&
	    (options.authorized_कुंजियाँ_command != शून्य &&
	    strcasecmp(options.authorized_कुंजियाँ_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	अगर (options.authorized_principals_command_user == शून्य &&
	    (options.authorized_principals_command != शून्य &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	अगर (options.अंक_auth_methods != 0) {
		क्रम (i = 0; i < options.अंक_auth_methods; i++) {
			अगर (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				अवरोध;
		}
		अगर (i >= options.अंक_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	अगर (optind < ac) {
		ख_लिखो(मानक_त्रुटि, "Extra argument %s.\n", av[optind]);
		निकास(1);
	}

	अगर (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_तथ्य.host_कुंजियाँ = xcalloc(options.अंक_host_कुंजी_files,
	    माप(काष्ठा sshkey *));
	sensitive_तथ्य.host_pubkeys = xcalloc(options.अंक_host_कुंजी_files,
	    माप(काष्ठा sshkey *));

	अगर (options.host_कुंजी_agent) {
		अगर (म_भेद(options.host_कुंजी_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_कुंजी_agent, 1);
		अगर ((r = ssh_get_authentication_socket(शून्य)) == 0)
			have_agent = 1;
		अन्यथा
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_कुंजी_agent);
	}

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		पूर्णांक ll = options.host_कुंजी_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		अगर (options.host_कुंजी_files[i] == शून्य)
			जारी;
		अगर ((r = sshkey_load_private(options.host_कुंजी_files[i], "",
		    &कुंजी, शून्य)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_कुंजी_files[i]);
		अगर (sshkey_is_sk(कुंजी) &&
		    कुंजी->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_कुंजी_files[i]);
			कुंजी->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		अगर (r == 0 && कुंजी != शून्य &&
		    (r = sshkey_shield_private(कुंजी)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_कुंजी_files[i]);
			sshkey_free(कुंजी);
			कुंजी = शून्य;
		}
		अगर ((r = sshkey_load_public(options.host_कुंजी_files[i],
		    &pubkey, शून्य)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_कुंजी_files[i]);
		अगर (pubkey != शून्य && कुंजी != शून्य) {
			अगर (!sshkey_equal(pubkey, कुंजी)) {
				error("Public key for %s does not match "
				    "private key", options.host_कुंजी_files[i]);
				sshkey_free(pubkey);
				pubkey = शून्य;
			}
		}
		अगर (pubkey == शून्य && कुंजी != शून्य) {
			अगर ((r = sshkey_from_private(कुंजी, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_कुंजी_files[i]);
		}
		अगर (pubkey != शून्य && (r = sshkey_check_rsa_लंबाई(pubkey,
		    options.required_rsa_आकार)) != 0) {
			error_fr(r, "Host key %s", options.host_कुंजी_files[i]);
			sshkey_free(pubkey);
			sshkey_free(कुंजी);
			जारी;
		}
		sensitive_तथ्य.host_कुंजियाँ[i] = कुंजी;
		sensitive_तथ्य.host_pubkeys[i] = pubkey;

		अगर (कुंजी == शून्य && pubkey != शून्य && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_कुंजी_files[i]);
			keytype = pubkey->type;
		} अन्यथा अगर (कुंजी != शून्य) {
			keytype = कुंजी->type;
			accumulate_host_timing_secret(cfg, कुंजी);
		} अन्यथा {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_कुंजी_files[i]);
			sensitive_तथ्य.host_कुंजियाँ[i] = शून्य;
			sensitive_तथ्य.host_pubkeys[i] = शून्य;
			जारी;
		}

		चयन (keytype) {
		हाल कुंजी_RSA:
		हाल कुंजी_ECDSA:
		हाल कुंजी_ED25519:
		हाल कुंजी_MLDSA44_ED25519:
		हाल कुंजी_ECDSA_SK:
		हाल कुंजी_ED25519_SK:
			अगर (have_agent || कुंजी != शून्य)
				sensitive_तथ्य.have_ssh2_कुंजी = 1;
			अवरोध;
		}
		अगर ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == शून्य)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    कुंजी ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		मुक्त(fp);
	}
	accumulate_host_timing_secret(cfg, शून्य);
	अगर (!sensitive_तथ्य.have_ssh2_कुंजी) {
		logit("sshd: no hostkeys available -- exiting.");
		निकास(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_तथ्य.host_certificates = xcalloc(options.अंक_host_कुंजी_files,
	    माप(काष्ठा sshkey *));
	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++)
		sensitive_तथ्य.host_certificates[i] = शून्य;

	क्रम (i = 0; i < options.अंक_host_cert_files; i++) {
		अगर (options.host_cert_files[i] == शून्य)
			जारी;
		अगर ((r = sshkey_load_public(options.host_cert_files[i],
		    &कुंजी, शून्य)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			जारी;
		}
		अगर (!sshkey_is_cert(कुंजी)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(कुंजी);
			जारी;
		}
		/* Find matching private key */
		क्रम (j = 0; j < options.अंक_host_कुंजी_files; j++) {
			अगर (sshkey_equal_public(कुंजी,
			    sensitive_तथ्य.host_pubkeys[j])) {
				sensitive_तथ्य.host_certificates[j] = कुंजी;
				अवरोध;
			}
		}
		अगर (j >= options.अंक_host_कुंजी_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(कुंजी);
			जारी;
		}
		sensitive_तथ्य.host_certificates[j] = कुंजी;
		debug("host certificate: #%u type %d %s", j, कुंजी->type,
		    sshkey_type(कुंजी));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	अगर ((getpwnam(SSH_PRIVSEP_USER)) == शून्य && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	अगर (need_chroot) {
		अगर ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#अगर_घोषित HAVE_CYGWIN
		अगर (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#अन्यथा
		अगर (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#पूर्ण_अगर
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	अगर (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	अगर (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	अगर (test_flag)
		निकास(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	अगर (setgroups(0, शून्य) < 0)
		debug("setgroups() failed: %.200s", म_त्रुटि(त्रुटि_सं));

	/* Prepare arguments for sshd-session */
	अगर (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, माप(अक्षर *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	क्रम (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = शून्य;
	अगर (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	अगर (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(व्योम) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	अगर (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	क्रम (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	अगर (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		अगर (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", म_त्रुटि(त्रुटि_सं));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	अगर (स_बदलो("/") == -1)
		error("chdir(\"/\"): %s", म_त्रुटि(त्रुटि_सं));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, संक_छोड़ो);

	/* Get a connection, either from inetd or a listening TCP socket */
	अगर (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", म_त्रुटि(त्रुटि_सं));
		send_rexec_state(config_s[0]);
		बंद(config_s[0]);
	} अन्यथा {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(संक_इति, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
#अगर_घोषित SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#पूर्ण_अगर

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		अगर (options.pid_file != शून्य && !debug_flag) {
			खाता *f = ख_खोलो(options.pid_file, "w");

			अगर (f == शून्य) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, म_त्रुटि(त्रुटि_सं));
			} अन्यथा {
				ख_लिखो(f, "%ld\n", (दीर्घ) getpid());
				ख_बंद(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_in, &sock_out,
		    &newsock, config_s, log_stderr);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	अगर (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", म_त्रुटि(त्रुटि_सं));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	अगर (!inetd_flag) {
		अगर (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", म_त्रुटि(त्रुटि_सं));
		अगर (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", म_त्रुटि(त्रुटि_सं));
		अगर (newsock > STDOUT_FILENO)
			बंद(newsock);
	}
	अगर (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		अगर (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", म_त्रुटि(त्रुटि_सं));
		बंद(config_s[1]);
	}
	log_redirect_stderr_to(शून्य);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, संक_छोड़ो); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], म_त्रुटि(त्रुटि_सं));
}

/* server specific fatal cleanup */
व्योम
cleanup_exit(पूर्णांक i)
{
	_निकास(i);
}
