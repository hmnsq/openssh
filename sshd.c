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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/utsname.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <grp.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#ifdef HAVE_SECUREWARE
#अन्तर्भाव <sys/security.h>
#अन्तर्भाव <prot.h>
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "version.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "addr.h"
#अन्तर्भाव "srclimit.h"
#अन्तर्भाव "atomicio.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

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
स्थिर अक्षर execpath[PATH_MAX];
स्थिर अक्षर **saved_argv;
स्थिर पूर्णांक saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
स्थिर पूर्णांक listen_socks[MAX_LISTEN_SOCKS];
स्थिर पूर्णांक अंक_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
संरचना {
	संरचना sshkey	**host_किल्ल्या;		/* all private host keys */
	संरचना sshkey	**host_pubkeys;		/* all public host keys */
	संरचना sshkey	**host_certificates;	/* all public host certificates */
	पूर्णांक		have_ssh2_किल्ली;
} sensitive_data;

/* This is set to true when a signal is received. */
स्थिर अस्थिर संक_पूर्ण_प्रकार received_siginfo = 0;
स्थिर अस्थिर संक_पूर्ण_प्रकार received_sigchld = 0;
स्थिर अस्थिर संक_पूर्ण_प्रकार received_sighup = 0;
स्थिर अस्थिर संक_पूर्ण_प्रकार received_sigterm = 0;

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
संरचना early_child {
	पूर्णांक pipefd;
	पूर्णांक early;		/* Indicates child closed listener */
	अक्षर *id;		/* human readable connection identifier */
	pid_t pid;
	संरचना xaddr addr;
	पूर्णांक have_addr;
	पूर्णांक status, have_status;
	संरचना sshbuf *config;
	संरचना sshbuf *किल्ल्या;
};
स्थिर संरचना early_child *children;
स्थिर पूर्णांक children_active;

/* sshd_config buffer */
संरचना sshbuf *cfg;
संरचना sshbuf *config;	/* packed */

/* Included files from the configuration file */
संरचना include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
संरचना sshbuf *loginmsg;

/* Unprivileged user */
संरचना passwd *privsep_pw = रिक्त;

स्थिर अक्षर *listener_proctitle;

/*
 * Close all listening sockets
 */
स्थिर शून्य
close_listen_socks(शून्य)
{
	पूर्णांक i;

	साठी (i = 0; i < अंक_listen_socks; i++)
		बंद(listen_socks[i]);
	अंक_listen_socks = 0;
}

/* Allocate and initialise the children array */
स्थिर शून्य
child_alloc(शून्य)
{
	पूर्णांक i;

	children = xcalloc(options.max_startups, आकार(*children));
	साठी (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
स्थिर संरचना early_child *
child_register(पूर्णांक pipefd, पूर्णांक sockfd)
{
	पूर्णांक i, lport, rport;
	अक्षर *laddr = रिक्त, *raddr = रिक्त;
	संरचना early_child *child = रिक्त;
	संरचना sockaddr_storage addr;
	socklen_t addrlen = आकार(addr);
	संरचना sockaddr *sa = (संरचना sockaddr *)&addr;

	साठी (i = 0; i < options.max_startups; i++) {
		जर (children[i].pipefd != -1 ||
		    children[i].config != रिक्त ||
		    children[i].किल्ल्या != रिक्त ||
		    children[i].pid > 0)
			सुरूठेवा;
		child = &(children[i]);
		थांबा;
	}
	जर (child == रिक्त) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	जर ((child->config = sshbuf_fromb(config)) == रिक्त)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	जर (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	जर ((lport = get_local_port(sockfd)) == 0 ||
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
	जर (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	परत child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
स्थिर शून्य
child_finish(संरचना early_child *child)
{
	जर (children_active == 0)
		fatal_f("internal error: children_active underflow");
	जर (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		बंद(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->किल्ल्या);
	मुक्त(child->id);
	स_रखो(child, '\0', आकार(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
स्थिर शून्य
child_close(संरचना early_child *child, पूर्णांक force_final, पूर्णांक quiet)
{
	जर (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	जर (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		बंद(child->pipefd);
		child->pipefd = -1;
	}
	जर (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
स्थिर शून्य
child_exit(pid_t pid, पूर्णांक status)
{
	पूर्णांक i;

	जर (children == रिक्त || pid <= 0)
		परत;
	साठी (i = 0; i < options.max_startups; i++) {
		जर (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			थांबा;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
स्थिर शून्य
child_reap(संरचना early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	पूर्णांक was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	स्थिरांक अक्षर *child_status;

	जर (child->config)
		child_status = " (sending config)";
	अन्यथा जर (child->किल्ल्या)
		child_status = " (sending keys)";
	अन्यथा जर (child->early)
		child_status = " (early)";
	अन्यथा
		child_status = "";

	/* Log exit information */
	जर (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		जर ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (दीर्घ)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		जर (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} अन्यथा जर (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (दीर्घ)child->pid, child->id, child->status,
		    child_status);
	} अन्यथा {
		/* Normal exit. We care about the status */
		निवड (WEXITSTATUS(child->status)) {
		स्थिती 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (दीर्घ)child->pid, child->id,
			    child_status);
			थांबा;
		स्थिती EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (दीर्घ)child->pid,
			    child_status);
			थांबा;
		स्थिती EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (दीर्घ)child->pid, child->id, child_status);
			थांबा;
		स्थिती EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (दीर्घ)child->pid, child->id, child_status);
			थांबा;
		स्थिती EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (दीर्घ)child->pid, child->id, child_status);
			थांबा;
		स्थिती EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (दीर्घ)child->pid, child->id, child_status);
			थांबा;
		पूर्वनिर्धारित:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (दीर्घ)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			थांबा;
		}
	}

	जर (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	जर (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
स्थिर शून्य
child_reap_all_exited(शून्य)
{
	पूर्णांक i;
	pid_t pid;
	पूर्णांक status;

	जर (children == रिक्त)
		परत;

	साठी (;;) {
		जर ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			थांबा;
		अन्यथा जर (pid == -1) {
			जर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
				सुरूठेवा;
			जर (त्रुटि_सं != ECHILD)
				error_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
			थांबा;
		}
		child_exit(pid, status);
	}

	साठी (i = 0; i < options.max_startups; i++) {
		जर (!children[i].have_status)
			सुरूठेवा;
		child_reap(&(children[i]));
	}
}

स्थिर शून्य
close_startup_pipes(शून्य)
{
	पूर्णांक i;

	जर (children == रिक्त)
		परत;
	साठी (i = 0; i < options.max_startups; i++) {
		जर (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
स्थिर शून्य
show_info(शून्य)
{
	पूर्णांक i;
	स्थिरांक अक्षर *child_status;

	/* XXX print listening sockets here too */
	जर (children == रिक्त)
		परत;
	logit("%d active startups", children_active);
	साठी (i = 0; i < options.max_startups; i++) {
		जर (children[i].pipefd == -1 && children[i].pid <= 0)
			सुरूठेवा;
		जर (children[i].config)
			child_status = " (sending config)";
		अन्यथा जर (children[i].किल्ल्या)
			child_status = " (sending keys)";
		अन्यथा जर (children[i].early)
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

स्थिर शून्य
sighup_handler(पूर्णांक sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
स्थिर शून्य
sighup_restart(शून्य)
{
	logit("Received SIGHUP; restarting.");
	जर (options.pid_file != रिक्त)
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
स्थिर शून्य
sigterm_handler(पूर्णांक sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
स्थिर शून्य
siginfo_handler(पूर्णांक sig)
{
	received_siginfo = 1;
}
#endif

स्थिर शून्य
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
स्थिर पूर्णांक
should_drop_connection(पूर्णांक startups)
{
	पूर्णांक p, r;

	जर (startups < options.max_startups_begin)
		परत 0;
	जर (startups >= options.max_startups)
		परत 1;
	जर (options.max_startups_rate == 100)
		परत 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	परत (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
स्थिर पूर्णांक
drop_connection(पूर्णांक sock, पूर्णांक startups, पूर्णांक notify_pipe)
{
	स्थिर संरचना log_ratelimit_ctx ratelimit_maxstartups;
	स्थिर संरचना log_ratelimit_ctx ratelimit_penalty;
	स्थिर पूर्णांक init_done;
	अक्षर *laddr, *raddr;
	स्थिरांक अक्षर *reason = रिक्त, *subreason = रिक्त;
	स्थिरांक अक्षर संदेश[] = "Not allowed at this time\r\n";
	संरचना log_ratelimit_ctx *rl = रिक्त;
	पूर्णांक ratelimited;
	u_int ndropped;

	जर (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	जर (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} अन्यथा {
		/* MaxStartups */
		जर (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			परत 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, समय(रिक्त), रिक्त, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != रिक्त ? subreason : reason);
	मुक्त(laddr);
	मुक्त(raddr);
	जर (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(शून्य)लिख(sock, संदेश, आकार(संदेश) - 1);
	परत 1;
}

स्थिर शून्य
usage(शून्य)
{
	ख_लिखो(मानक_त्रुटि, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	ख_लिखो(मानक_त्रुटि,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	निकास(1);
}

स्थिर संरचना sshbuf *
pack_hostkeys(शून्य)
{
	संरचना sshbuf *m = रिक्त, *keybuf = रिक्त, *hostkeys = रिक्त;
	पूर्णांक r;
	u_int i;
	माप_प्रकार len;

	जर ((m = sshbuf_new()) == रिक्त ||
	    (keybuf = sshbuf_new()) == रिक्त ||
	    (hostkeys = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	साठी (i = 0; i < options.अंक_host_किल्ली_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		जर (sensitive_data.host_किल्ल्या[i] != रिक्त &&
		    (r = sshkey_private_serialize(sensitive_data.host_किल्ल्या[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		जर ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		जर (sensitive_data.host_pubkeys[i] != रिक्त) {
			जर ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} अन्यथा {
			जर ((r = sshbuf_put_string(hostkeys, रिक्त, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		जर (sensitive_data.host_certificates[i] != रिक्त) {
			जर ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} अन्यथा {
			जर ((r = sshbuf_put_string(hostkeys, रिक्त, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	जर ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	जर ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	परत m;
}

स्थिर संरचना sshbuf *
pack_config(संरचना sshbuf *conf)
{
	संरचना sshbuf *m = रिक्त, *inc = रिक्त;
	संरचना include_item *item = रिक्त;
	माप_प्रकार len;
	पूर्णांक r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	जर ((m = sshbuf_new()) == रिक्त ||
	    (inc = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		जर ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	जर ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	जर ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	परत m;
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
स्थिर शून्य
send_rexec_state(पूर्णांक fd)
{
	संरचना sshbuf *किल्ल्या;
	u_int mlen;
	pid_t pid;

	जर ((pid = विभाजन()) == -1)
		fatal_f("fork failed: %s", म_त्रुटि(त्रुटि_सं));
	जर (pid != 0)
		परत;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	जर (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", म_त्रुटि(त्रुटि_सं));

	किल्ल्या = pack_hostkeys();
	mlen = sshbuf_len(किल्ल्या);
	जर (atomicio(vwrite, fd, sshbuf_mutable_ptr(किल्ल्या), mlen) != mlen)
		error_f("write: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_free(किल्ल्या);
	debug3_f("done");
	निकास(0);
}

/*
 * Listen for TCP connections
 */
स्थिर शून्य
listen_on_addrs(संरचना listenaddr *la)
{
	पूर्णांक ret, listen_sock;
	संरचना addrinfo *ai;
	अक्षर ntop[NI_MAXHOST], strport[NI_MAXSERV];

	साठी (ai = la->addrs; ai; ai = ai->ai_next) {
		जर (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			सुरूठेवा;
		जर (अंक_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		जर ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, आकार(ntop), strport, आकार(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			सुरूठेवा;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		जर (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			सुरूठेवा;
		}
		जर (set_nonblock(listen_sock) == -1) {
			बंद(listen_sock);
			सुरूठेवा;
		}
		जर (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", म_त्रुटि(त्रुटि_सं));
			बंद(listen_sock);
			सुरूठेवा;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		जर (la->rdomain != रिक्त &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			बंद(listen_sock);
			सुरूठेवा;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		जर (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		जर (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, म_त्रुटि(त्रुटि_सं));
			बंद(listen_sock);
			सुरूठेवा;
		}
		listen_socks[अंक_listen_socks] = listen_sock;
		अंक_listen_socks++;

		/* Start listening on the port. */
		जर (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, म_त्रुटि(त्रुटि_सं));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == रिक्त ? "" : " rdomain ",
		    la->rdomain == रिक्त ? "" : la->rdomain);
	}
}

स्थिर शून्य
server_listen(शून्य)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	साठी (i = 0; i < options.अंक_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		मुक्त(options.listen_addrs[i].rdomain);
		स_रखो(&options.listen_addrs[i], 0,
		    आकार(options.listen_addrs[i]));
	}
	मुक्त(options.listen_addrs);
	options.listen_addrs = रिक्त;
	options.अंक_listen_addrs = 0;

	जर (!अंक_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
स्थिर शून्य
server_accept_loop(पूर्णांक *sock_in, पूर्णांक *sock_out, पूर्णांक *newsock, पूर्णांक *config_s,
    पूर्णांक log_stderr)
{
	संरचना pollfd *pfd = रिक्त;
	पूर्णांक i, ret, npfd, r;
	पूर्णांक oactive = -1, listening = 0, lameduck = 0;
	पूर्णांक *startup_pollfd;
	ssize_t len;
	स्थिरांक u_char *ptr;
	अक्षर c = 0;
	संरचना sockaddr_storage from;
	संरचना early_child *child;
	संरचना sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, आकार(पूर्णांक));

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm/hup/chld/info, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
#ifdef SIGINFO
	sigaddset(&nsigset, SIGINFO);
#endif
	sigaddset(&nsigset, संक_इति);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(अंक_listen_socks + options.max_startups,
	    आकार(संरचना pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	साठी (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		जर (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (पूर्णांक) received_sigterm);
			close_listen_socks();
			जर (options.pid_file != रिक्त)
				unlink(options.pid_file);
			निकास(received_sigterm == संक_इति ? 0 : 255);
		}
		जर (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		जर (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		जर (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		जर (received_sighup) {
			जर (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			जर (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, संक_इति);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, रिक्त);
				sighup_restart();
			}
		}

		साठी (i = 0; i < अंक_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = अंक_listen_socks;
		साठी (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			जर (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				जर (children[i].config != रिक्त ||
				    children[i].किल्ल्या != रिक्त)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, रिक्त, &osigset);
		जर (ret == -1 && त्रुटि_सं != EINTR) {
			error("ppoll: %.100s", म_त्रुटि(त्रुटि_सं));
			जर (त्रुटि_सं == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, रिक्त);
		जर (ret == -1)
			सुरूठेवा;

		साठी (i = 0; i < options.max_startups; i++) {
			जर (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				सुरूठेवा;
			जर (children[i].config)
				buf = children[i].config;
			अन्यथा जर (children[i].किल्ल्या)
				buf = children[i].किल्ल्या;
			अन्यथा {
				error_f("no buffer to send");
				सुरूठेवा;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = लिख(children[i].pipefd, ptr, len);
			जर (ret == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN))
				सुरूठेवा;
			जर (ret <= 0) {
				जर (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				सुरूठेवा;
			}
			जर (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				जर (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = रिक्त;
					children[i].किल्ल्या = pack_hostkeys();
				} अन्यथा जर (children[i].किल्ल्या == buf) {
					/* sent both config and keys */
					children[i].किल्ल्या = रिक्त;
				} अन्यथा {
					fatal("config buf not set");
				}

			} अन्यथा {
				जर ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		साठी (i = 0; i < options.max_startups; i++) {
			जर (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				सुरूठेवा;
			निवड (पठ(children[i].pipefd, &c, आकार(c))) {
			स्थिती -1:
				जर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
					सुरूठेवा;
				जर (त्रुटि_सं != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    म_त्रुटि(त्रुटि_सं));
				}
				/* FALLTHROUGH */
			स्थिती 0:
				/* child closed pipe */
				जर (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (दीर्घ)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				थांबा;
			स्थिती 1:
				जर (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					जा problem_child;
				}
				जर (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (दीर्घ)children[i].pid,
					    children[i].id);
				} अन्यथा जर (!children[i].early && c == '\001') {
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
					जर (children[i].early)
						listening--;
					जर (children[i].pid > 0)
						समाप्त(children[i].pid, संक_इति);
					child_close(&(children[i]), 0, 0);
				}
				थांबा;
			}
		}
		साठी (i = 0; i < अंक_listen_socks; i++) {
			जर (!(pfd[i].revents & POLLIN))
				सुरूठेवा;
			fromlen = आकार(from);
			*newsock = accept(listen_socks[i],
			    (संरचना sockaddr *)&from, &fromlen);
			जर (*newsock == -1) {
				जर (त्रुटि_सं != EINTR && त्रुटि_सं != EWOULDBLOCK &&
				    त्रुटि_सं != ECONNABORTED && त्रुटि_सं != EAGAIN)
					error("accept: %.100s",
					    म_त्रुटि(त्रुटि_सं));
				जर (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
					usleep(100 * 1000);
				सुरूठेवा;
			}
			जर (unset_nonblock(*newsock) == -1) {
				बंद(*newsock);
				सुरूठेवा;
			}
			जर (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    म_त्रुटि(त्रुटि_सं));
				बंद(*newsock);
				सुरूठेवा;
			}
			जर (drop_connection(*newsock,
			    children_active, config_s[0])) {
				बंद(*newsock);
				बंद(config_s[0]);
				बंद(config_s[1]);
				सुरूठेवा;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			जर (debug_flag) {
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
				परत;
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
			जर ((child->pid = विभाजन()) == 0) {
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
				परत;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			जर (child->pid == -1)
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

स्थिर शून्य
accumulate_host_timing_secret(संरचना sshbuf *server_cfg,
    संरचना sshkey *किल्ली)
{
	स्थिर संरचना ssh_digest_ctx *ctx;
	u_char *hash;
	माप_प्रकार len;
	संरचना sshbuf *buf;
	पूर्णांक r;

	जर (ctx == रिक्त && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == रिक्त)
		fatal_f("ssh_digest_start");
	जर (किल्ली == रिक्त) { /* finalize */
		/* add server config in case we are using agent for host keys */
		जर (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		जर (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = रिक्त;
		परत;
	}
	जर ((buf = sshbuf_new()) == रिक्त)
		fatal_f("could not allocate buffer");
	जर ((r = sshkey_private_serialize(किल्ली, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(किल्ली));
	जर (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

स्थिर अक्षर *
prepare_proctitle(पूर्णांक ac, अक्षर **av)
{
	अक्षर *ret = रिक्त;
	पूर्णांक i;

	साठी (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	परत ret;
}

/* Disconnect from the controlling tty. */
स्थिर शून्य
disconnect_controlling_tty(शून्य)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	पूर्णांक fd;

	जर ((fd = खोलो(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(शून्य) ioctl(fd, TIOCNOTTY, रिक्त);
		बंद(fd);
	}
#endif /* TIOCNOTTY */
}

स्थिर शून्य
print_config(संरचना connection_info *connection_info)
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
main(पूर्णांक ac, अक्षर **av)
{
	बाह्य अक्षर *optarg;
	बाह्य पूर्णांक optind;
	पूर्णांक log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	अक्षर *config_file_name = _PATH_SERVER_CONFIG_FILE;
	पूर्णांक r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	पूर्णांक sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	पूर्णांक devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	पूर्णांक need_chroot = 1;
	अक्षर *args, *fp, *ओळ, *logfile = रिक्त, **rexec_argv = रिक्त;
	संरचना stat sb;
	u_int i, j;
	mode_t new_umask;
	संरचना sshkey *किल्ली;
	संरचना sshkey *pubkey;
	संरचना connection_info connection_info;
	संरचना utsname utsname;
	sigset_t sigmask;

	स_रखो(&connection_info, 0, आकार(connection_info));
#ifdef HAVE_SECUREWARE
	(शून्य)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, रिक्त);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, आकार(*saved_argv));
	साठी (i = 0; (पूर्णांक)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = रिक्त;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	जर (geteuid() == 0 && setgroups(0, रिक्त) == -1)
		debug("setgroups(): %.200s", म_त्रुटि(त्रुटि_सं));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	पर्यंत ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		निवड (opt) {
		स्थिती '4':
			options.address_family = AF_INET;
			थांबा;
		स्थिती '6':
			options.address_family = AF_INET6;
			थांबा;
		स्थिती 'f':
			config_file_name = optarg;
			थांबा;
		स्थिती 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			थांबा;
		स्थिती 'd':
			जर (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} अन्यथा जर (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			थांबा;
		स्थिती 'D':
			no_daemon_flag = 1;
			थांबा;
		स्थिती 'G':
			do_dump_cfg = 1;
			थांबा;
		स्थिती 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		स्थिती 'e':
			log_stderr = 1;
			थांबा;
		स्थिती 'i':
			inetd_flag = 1;
			थांबा;
		स्थिती 'r':
			logit("-r option is deprecated");
			थांबा;
		स्थिती 'R':
			fatal("-R not supported here");
			थांबा;
		स्थिती 'Q':
			/* ignored */
			थांबा;
		स्थिती 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			थांबा;
		स्थिती 'b':
			/* protocol 1, ignored */
			थांबा;
		स्थिती 'p':
			options.ports_from_cmdline = 1;
			जर (options.अंक_ports >= MAX_PORTS) {
				ख_लिखो(मानक_त्रुटि, "too many ports.\n");
				निकास(1);
			}
			options.ports[options.अंक_ports++] = a2port(optarg);
			जर (options.ports[options.अंक_ports-1] <= 0) {
				ख_लिखो(मानक_त्रुटि, "Bad port number.\n");
				निकास(1);
			}
			थांबा;
		स्थिती 'g':
			जर ((options.login_grace_time = convtime(optarg)) == -1) {
				ख_लिखो(मानक_त्रुटि, "Invalid login grace time.\n");
				निकास(1);
			}
			थांबा;
		स्थिती 'k':
			/* protocol 1, ignored */
			थांबा;
		स्थिती 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			थांबा;
		स्थिती 't':
			test_flag = 1;
			थांबा;
		स्थिती 'T':
			test_flag = 2;
			थांबा;
		स्थिती 'C':
			जर (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				निकास(1);
			have_connection_info = 1;
			थांबा;
		स्थिती 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, रिक्त);
			जर (utmp_len > HOST_NAME_MAX+1) {
				ख_लिखो(मानक_त्रुटि, "Invalid utmp length.\n");
				निकास(1);
			}
			थांबा;
		स्थिती 'o':
			ओळ = xstrdup(optarg);
			जर (process_server_config_ओळ(&options, ओळ,
			    "command-line", 0, रिक्त, रिक्त, &includes) != 0)
				निकास(1);
			मुक्त(ओळ);
			थांबा;
		स्थिती 'V':
			ख_लिखो(मानक_त्रुटि, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			निकास(0);
		पूर्वनिर्धारित:
			usage();
			थांबा;
		}
	}

	जर (getexecpath(execpath, आकार execpath) != 0) {
		जर (strlcpy(execpath, av[0], आकार execpath) >=
		    आकार execpath) {
			ख_लिखो(मानक_त्रुटि, "execution path is too long\n");
			निकास(1);
		}
	}
	जर (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	जर ((devnull = खोलो(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, म_त्रुटि(त्रुटि_सं));
	पर्यंत (devnull < REEXEC_MIN_FREE_FD) {
		जर ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, म_त्रुटि(त्रुटि_सं));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	जर (logfile != रिक्त) {
		अक्षर *cp, pid_s[32];

		snprintf(pid_s, आकार(pid_s), "%ld", (अचिन्हित दीर्घ)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (अक्षर *)रिक्त);
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
	जर (दो_पर्या("KRB5CCNAME") != रिक्त)
		(शून्य) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_किल्ली = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	जर (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	जर (uname(&utsname) != 0) {
		स_रखो(&utsname, 0, आकार(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", आकार(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	मुक्त(args);

	/* Fetch our configuration */
	जर ((cfg = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new config failed");
	जर (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, रिक्त, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	जर (options.authorized_किल्ल्या_command_user == रिक्त &&
	    (options.authorized_किल्ल्या_command != रिक्त &&
	    strcasecmp(options.authorized_किल्ल्या_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	जर (options.authorized_principals_command_user == रिक्त &&
	    (options.authorized_principals_command != रिक्त &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	जर (options.अंक_auth_methods != 0) {
		साठी (i = 0; i < options.अंक_auth_methods; i++) {
			जर (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				थांबा;
		}
		जर (i >= options.अंक_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	जर (optind < ac) {
		ख_लिखो(मानक_त्रुटि, "Extra argument %s.\n", av[optind]);
		निकास(1);
	}

	जर (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_किल्ल्या = xcalloc(options.अंक_host_किल्ली_files,
	    आकार(संरचना sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.अंक_host_किल्ली_files,
	    आकार(संरचना sshkey *));

	जर (options.host_किल्ली_agent) {
		जर (म_भेद(options.host_किल्ली_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_किल्ली_agent, 1);
		जर ((r = ssh_get_authentication_socket(रिक्त)) == 0)
			have_agent = 1;
		अन्यथा
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_किल्ली_agent);
	}

	साठी (i = 0; i < options.अंक_host_किल्ली_files; i++) {
		पूर्णांक ll = options.host_किल्ली_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		जर (options.host_किल्ली_files[i] == रिक्त)
			सुरूठेवा;
		जर ((r = sshkey_load_private(options.host_किल्ली_files[i], "",
		    &किल्ली, रिक्त)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_किल्ली_files[i]);
		जर (sshkey_is_sk(किल्ली) &&
		    किल्ली->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_किल्ली_files[i]);
			किल्ली->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		जर (r == 0 && किल्ली != रिक्त &&
		    (r = sshkey_shield_private(किल्ली)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_किल्ली_files[i]);
			sshkey_free(किल्ली);
			किल्ली = रिक्त;
		}
		जर ((r = sshkey_load_public(options.host_किल्ली_files[i],
		    &pubkey, रिक्त)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_किल्ली_files[i]);
		जर (pubkey != रिक्त && किल्ली != रिक्त) {
			जर (!sshkey_equal(pubkey, किल्ली)) {
				error("Public key for %s does not match "
				    "private key", options.host_किल्ली_files[i]);
				sshkey_free(pubkey);
				pubkey = रिक्त;
			}
		}
		जर (pubkey == रिक्त && किल्ली != रिक्त) {
			जर ((r = sshkey_from_private(किल्ली, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_किल्ली_files[i]);
		}
		जर (pubkey != रिक्त && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_किल्ली_files[i]);
			sshkey_free(pubkey);
			sshkey_free(किल्ली);
			सुरूठेवा;
		}
		sensitive_data.host_किल्ल्या[i] = किल्ली;
		sensitive_data.host_pubkeys[i] = pubkey;

		जर (किल्ली == रिक्त && pubkey != रिक्त && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_किल्ली_files[i]);
			keytype = pubkey->type;
		} अन्यथा जर (किल्ली != रिक्त) {
			keytype = किल्ली->type;
			accumulate_host_timing_secret(cfg, किल्ली);
		} अन्यथा {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_किल्ली_files[i]);
			sensitive_data.host_किल्ल्या[i] = रिक्त;
			sensitive_data.host_pubkeys[i] = रिक्त;
			सुरूठेवा;
		}

		निवड (keytype) {
		स्थिती किल्ली_RSA:
		स्थिती किल्ली_ECDSA:
		स्थिती किल्ली_ED25519:
		स्थिती किल्ली_MLDSA44_ED25519:
		स्थिती किल्ली_ECDSA_SK:
		स्थिती किल्ली_ED25519_SK:
			जर (have_agent || किल्ली != रिक्त)
				sensitive_data.have_ssh2_किल्ली = 1;
			थांबा;
		}
		जर ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    किल्ली ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		मुक्त(fp);
	}
	accumulate_host_timing_secret(cfg, रिक्त);
	जर (!sensitive_data.have_ssh2_किल्ली) {
		logit("sshd: no hostkeys available -- exiting.");
		निकास(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.अंक_host_किल्ली_files,
	    आकार(संरचना sshkey *));
	साठी (i = 0; i < options.अंक_host_किल्ली_files; i++)
		sensitive_data.host_certificates[i] = रिक्त;

	साठी (i = 0; i < options.अंक_host_cert_files; i++) {
		जर (options.host_cert_files[i] == रिक्त)
			सुरूठेवा;
		जर ((r = sshkey_load_public(options.host_cert_files[i],
		    &किल्ली, रिक्त)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			सुरूठेवा;
		}
		जर (!sshkey_is_cert(किल्ली)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(किल्ली);
			सुरूठेवा;
		}
		/* Find matching private key */
		साठी (j = 0; j < options.अंक_host_किल्ली_files; j++) {
			जर (sshkey_equal_public(किल्ली,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = किल्ली;
				थांबा;
			}
		}
		जर (j >= options.अंक_host_किल्ली_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(किल्ली);
			सुरूठेवा;
		}
		sensitive_data.host_certificates[j] = किल्ली;
		debug("host certificate: #%u type %d %s", j, किल्ली->type,
		    sshkey_type(किल्ली));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	जर ((getpwnam(SSH_PRIVSEP_USER)) == रिक्त && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	जर (need_chroot) {
		जर ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		जर (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#अन्यथा
		जर (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	जर (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	जर (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	जर (test_flag)
		निकास(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	जर (setgroups(0, रिक्त) < 0)
		debug("setgroups() failed: %.200s", म_त्रुटि(त्रुटि_सं));

	/* Prepare arguments for sshd-session */
	जर (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, आकार(अक्षर *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	साठी (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = रिक्त;
	जर (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	जर (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(शून्य) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	जर (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	साठी (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	जर (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		जर (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", म_त्रुटि(त्रुटि_सं));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	जर (स_बदलो("/") == -1)
		error("chdir(\"/\"): %s", म_त्रुटि(त्रुटि_सं));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, संक_छोड़ो);

	/* Get a connection, either from inetd or a listening TCP socket */
	जर (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		जर (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
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
#ifdef SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#endif

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		जर (options.pid_file != रिक्त && !debug_flag) {
			खाता *f = ख_खोलो(options.pid_file, "w");

			जर (f == रिक्त) {
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
	जर (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", म_त्रुटि(त्रुटि_सं));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	जर (!inetd_flag) {
		जर (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", म_त्रुटि(त्रुटि_सं));
		जर (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", म_त्रुटि(त्रुटि_सं));
		जर (newsock > STDOUT_FILENO)
			बंद(newsock);
	}
	जर (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		जर (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", म_त्रुटि(त्रुटि_सं));
		बंद(config_s[1]);
	}
	log_redirect_stderr_to(रिक्त);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, संक_छोड़ो); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], म_त्रुटि(त्रुटि_सं));
}

/* server specific fatal cleanup */
शून्य
cleanup_exit(पूर्णांक i)
{
	_exit(i);
}
