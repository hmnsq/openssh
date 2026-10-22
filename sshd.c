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

बाह्य वर्ण *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
पूर्णाङ्क debug_flag = 0;

/* Saved arguments to main(). */
स्थिर वर्ण execpath[PATH_MAX];
स्थिर वर्ण **saved_argv;
स्थिर पूर्णाङ्क saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
स्थिर पूर्णाङ्क listen_socks[MAX_LISTEN_SOCKS];
स्थिर पूर्णाङ्क अंक_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
संरचना {
	संरचना sshkey	**host_कुंजियाँ;		/* all private host keys */
	संरचना sshkey	**host_pubkeys;		/* all public host keys */
	संरचना sshkey	**host_certificates;	/* all public host certificates */
	पूर्णाङ्क		have_ssh2_कुंजी;
} sensitive_data;

/* This is set to true when a signal is received. */
स्थिर चञ्चल sig_atomic_t received_siginfo = 0;
स्थिर चञ्चल sig_atomic_t received_sigchld = 0;
स्थिर चञ्चल sig_atomic_t received_sighup = 0;
स्थिर चञ्चल sig_atomic_t received_sigterm = 0;

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
	पूर्णाङ्क pipefd;
	पूर्णाङ्क early;		/* Indicates child closed listener */
	वर्ण *id;		/* human readable connection identifier */
	pid_t pid;
	संरचना xaddr addr;
	पूर्णाङ्क have_addr;
	पूर्णाङ्क status, have_status;
	संरचना sshbuf *config;
	संरचना sshbuf *कुंजियाँ;
};
स्थिर संरचना early_child *children;
स्थिर पूर्णाङ्क children_active;

/* sshd_config buffer */
संरचना sshbuf *cfg;
संरचना sshbuf *config;	/* packed */

/* Included files from the configuration file */
संरचना include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
संरचना sshbuf *loginmsg;

/* Unprivileged user */
संरचना passwd *privsep_pw = रिक्त;

स्थिर वर्ण *listener_proctitle;

/*
 * Close all listening sockets
 */
स्थिर शून्य
close_listen_socks(शून्य)
{
	पूर्णाङ्क i;

	प्रति (i = 0; i < अंक_listen_socks; i++)
		close(listen_socks[i]);
	अंक_listen_socks = 0;
}

/* Allocate and initialise the children array */
स्थिर शून्य
child_alloc(शून्य)
{
	पूर्णाङ्क i;

	children = xcalloc(options.max_startups, परिमाण(*children));
	प्रति (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
स्थिर संरचना early_child *
child_register(पूर्णाङ्क pipefd, पूर्णाङ्क sockfd)
{
	पूर्णाङ्क i, lport, rport;
	वर्ण *laddr = रिक्त, *raddr = रिक्त;
	संरचना early_child *child = रिक्त;
	संरचना sockaddr_storage addr;
	socklen_t addrlen = परिमाण(addr);
	संरचना sockaddr *sa = (संरचना sockaddr *)&addr;

	प्रति (i = 0; i < options.max_startups; i++) {
		यदि (children[i].pipefd != -1 ||
		    children[i].config != रिक्त ||
		    children[i].कुंजियाँ != रिक्त ||
		    children[i].pid > 0)
			अनुवर्त;
		child = &(children[i]);
		भङ्ग;
	}
	यदि (child == रिक्त) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	यदि ((child->config = sshbuf_fromb(config)) == रिक्त)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	यदि (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	यदि ((lport = get_local_port(sockfd)) == 0 ||
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
	यदि (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	प्रत्यागम child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
स्थिर शून्य
child_finish(संरचना early_child *child)
{
	यदि (children_active == 0)
		fatal_f("internal error: children_active underflow");
	यदि (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->कुंजियाँ);
	मुक्त(child->id);
	memset(child, '\0', परिमाण(*child));
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
child_close(संरचना early_child *child, पूर्णाङ्क force_final, पूर्णाङ्क quiet)
{
	यदि (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	यदि (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	यदि (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
स्थिर शून्य
child_exit(pid_t pid, पूर्णाङ्क status)
{
	पूर्णाङ्क i;

	यदि (children == रिक्त || pid <= 0)
		प्रत्यागम;
	प्रति (i = 0; i < options.max_startups; i++) {
		यदि (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			भङ्ग;
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
	पूर्णाङ्क was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ध्रुव वर्ण *child_status;

	यदि (child->config)
		child_status = " (sending config)";
	अन्यथा यदि (child->कुंजियाँ)
		child_status = " (sending keys)";
	अन्यथा यदि (child->early)
		child_status = " (early)";
	अन्यथा
		child_status = "";

	/* Log exit information */
	यदि (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		यदि ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		यदि (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} अन्यथा यदि (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} अन्यथा {
		/* Normal exit. We care about the status */
		विकल्प (WEXITSTATUS(child->status)) {
		पक्ष 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			भङ्ग;
		पक्ष EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			भङ्ग;
		पक्ष EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			भङ्ग;
		पक्ष EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			भङ्ग;
		पक्ष EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			भङ्ग;
		पक्ष EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			भङ्ग;
		स्वभाव:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			भङ्ग;
		}
	}

	यदि (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	यदि (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
स्थिर शून्य
child_reap_all_exited(शून्य)
{
	पूर्णाङ्क i;
	pid_t pid;
	पूर्णाङ्क status;

	यदि (children == रिक्त)
		प्रत्यागम;

	प्रति (;;) {
		यदि ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			भङ्ग;
		अन्यथा यदि (pid == -1) {
			यदि (errno == EINTR || errno == EAGAIN)
				अनुवर्त;
			यदि (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			भङ्ग;
		}
		child_exit(pid, status);
	}

	प्रति (i = 0; i < options.max_startups; i++) {
		यदि (!children[i].have_status)
			अनुवर्त;
		child_reap(&(children[i]));
	}
}

स्थिर शून्य
close_startup_pipes(शून्य)
{
	पूर्णाङ्क i;

	यदि (children == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < options.max_startups; i++) {
		यदि (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
स्थिर शून्य
show_info(शून्य)
{
	पूर्णाङ्क i;
	ध्रुव वर्ण *child_status;

	/* XXX print listening sockets here too */
	यदि (children == रिक्त)
		प्रत्यागम;
	logit("%d active startups", children_active);
	प्रति (i = 0; i < options.max_startups; i++) {
		यदि (children[i].pipefd == -1 && children[i].pid <= 0)
			अनुवर्त;
		यदि (children[i].config)
			child_status = " (sending config)";
		अन्यथा यदि (children[i].कुंजियाँ)
			child_status = " (sending keys)";
		अन्यथा यदि (children[i].early)
			child_status = " (early)";
		अन्यथा
			child_status = "";
		logit("child %d: fd=%d pid=%ld %s%s", i, children[i].pipefd,
		    (long)children[i].pid, children[i].id, child_status);
	}
	srclimit_penalty_info();
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

स्थिर शून्य
sighup_handler(पूर्णाङ्क sig)
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
	यदि (options.pid_file != रिक्त)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(execpath, saved_argv);
	logit("RESTART FAILED: execpath='%.100s', error: %.100s.", execpath,
	    strerror(errno));
	exit(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
स्थिर शून्य
sigterm_handler(पूर्णाङ्क sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
स्थिर शून्य
siginfo_handler(पूर्णाङ्क sig)
{
	received_siginfo = 1;
}
#endif

स्थिर शून्य
main_sigchld_handler(पूर्णाङ्क sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
स्थिर पूर्णाङ्क
should_drop_connection(पूर्णाङ्क startups)
{
	पूर्णाङ्क p, r;

	यदि (startups < options.max_startups_begin)
		प्रत्यागम 0;
	यदि (startups >= options.max_startups)
		प्रत्यागम 1;
	यदि (options.max_startups_rate == 100)
		प्रत्यागम 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	प्रत्यागम (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
स्थिर पूर्णाङ्क
drop_connection(पूर्णाङ्क sock, पूर्णाङ्क startups, पूर्णाङ्क notify_pipe)
{
	स्थिर संरचना log_ratelimit_ctx ratelimit_maxstartups;
	स्थिर संरचना log_ratelimit_ctx ratelimit_penalty;
	स्थिर पूर्णाङ्क init_done;
	वर्ण *laddr, *raddr;
	ध्रुव वर्ण *reason = रिक्त, *subreason = रिक्त;
	ध्रुव वर्ण संदेश[] = "Not allowed at this time\r\n";
	संरचना log_ratelimit_ctx *rl = रिक्त;
	पूर्णाङ्क ratelimited;
	u_int ndropped;

	यदि (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	यदि (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} अन्यथा {
		/* MaxStartups */
		यदि (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			प्रत्यागम 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(रिक्त), रिक्त, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != रिक्त ? subreason : reason);
	मुक्त(laddr);
	मुक्त(raddr);
	यदि (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(शून्य)लिख(sock, संदेश, परिमाण(संदेश) - 1);
	प्रत्यागम 1;
}

स्थिर शून्य
usage(शून्य)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

स्थिर संरचना sshbuf *
pack_hostkeys(शून्य)
{
	संरचना sshbuf *m = रिक्त, *keybuf = रिक्त, *hostkeys = रिक्त;
	पूर्णाङ्क r;
	u_int i;
	size_t len;

	यदि ((m = sshbuf_new()) == रिक्त ||
	    (keybuf = sshbuf_new()) == रिक्त ||
	    (hostkeys = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	प्रति (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		यदि (sensitive_data.host_कुंजियाँ[i] != रिक्त &&
		    (r = sshkey_private_serialize(sensitive_data.host_कुंजियाँ[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		यदि ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		यदि (sensitive_data.host_pubkeys[i] != रिक्त) {
			यदि ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} अन्यथा {
			यदि ((r = sshbuf_put_string(hostkeys, रिक्त, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		यदि (sensitive_data.host_certificates[i] != रिक्त) {
			यदि ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} अन्यथा {
			यदि ((r = sshbuf_put_string(hostkeys, रिक्त, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	यदि ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	यदि ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	प्रत्यागम m;
}

स्थिर संरचना sshbuf *
pack_config(संरचना sshbuf *conf)
{
	संरचना sshbuf *m = रिक्त, *inc = रिक्त;
	संरचना include_item *item = रिक्त;
	size_t len;
	पूर्णाङ्क r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	यदि ((m = sshbuf_new()) == रिक्त ||
	    (inc = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		यदि ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	यदि ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	यदि ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	प्रत्यागम m;
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
send_rexec_state(पूर्णाङ्क fd)
{
	संरचना sshbuf *कुंजियाँ;
	u_int mlen;
	pid_t pid;

	यदि ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	यदि (pid != 0)
		प्रत्यागम;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	यदि (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	कुंजियाँ = pack_hostkeys();
	mlen = sshbuf_len(कुंजियाँ);
	यदि (atomicio(vwrite, fd, sshbuf_mutable_ptr(कुंजियाँ), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(कुंजियाँ);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
स्थिर शून्य
listen_on_addrs(संरचना listenaddr *la)
{
	पूर्णाङ्क ret, listen_sock;
	संरचना addrinfo *ai;
	वर्ण ntop[NI_MAXHOST], strport[NI_MAXSERV];

	प्रति (ai = la->addrs; ai; ai = ai->ai_next) {
		यदि (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			अनुवर्त;
		यदि (अंक_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		यदि ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, परिमाण(ntop), strport, परिमाण(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			अनुवर्त;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		यदि (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			अनुवर्त;
		}
		यदि (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			अनुवर्त;
		}
		यदि (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			अनुवर्त;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		यदि (la->rdomain != रिक्त &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			अनुवर्त;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		यदि (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		यदि (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			अनुवर्त;
		}
		listen_socks[अंक_listen_socks] = listen_sock;
		अंक_listen_socks++;

		/* Start listening on the port. */
		यदि (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
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

	प्रति (i = 0; i < options.अंक_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		मुक्त(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    परिमाण(options.listen_addrs[i]));
	}
	मुक्त(options.listen_addrs);
	options.listen_addrs = रिक्त;
	options.अंक_listen_addrs = 0;

	यदि (!अंक_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
स्थिर शून्य
server_accept_loop(पूर्णाङ्क *sock_in, पूर्णाङ्क *sock_out, पूर्णाङ्क *newsock, पूर्णाङ्क *config_s,
    पूर्णाङ्क log_stderr)
{
	संरचना pollfd *pfd = रिक्त;
	पूर्णाङ्क i, ret, npfd, r;
	पूर्णाङ्क oactive = -1, listening = 0, lameduck = 0;
	पूर्णाङ्क *startup_pollfd;
	ssize_t len;
	ध्रुव u_char *ptr;
	वर्ण c = 0;
	संरचना sockaddr_storage from;
	संरचना early_child *child;
	संरचना sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, परिमाण(पूर्णाङ्क));

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
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(अंक_listen_socks + options.max_startups,
	    परिमाण(संरचना pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	प्रति (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		यदि (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (पूर्णाङ्क) received_sigterm);
			close_listen_socks();
			यदि (options.pid_file != रिक्त)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		यदि (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		यदि (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		यदि (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		यदि (received_sighup) {
			यदि (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			यदि (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, रिक्त);
				sighup_restart();
			}
		}

		प्रति (i = 0; i < अंक_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = अंक_listen_socks;
		प्रति (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			यदि (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				यदि (children[i].config != रिक्त ||
				    children[i].कुंजियाँ != रिक्त)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, रिक्त, &osigset);
		यदि (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			यदि (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, रिक्त);
		यदि (ret == -1)
			अनुवर्त;

		प्रति (i = 0; i < options.max_startups; i++) {
			यदि (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				अनुवर्त;
			यदि (children[i].config)
				buf = children[i].config;
			अन्यथा यदि (children[i].कुंजियाँ)
				buf = children[i].कुंजियाँ;
			अन्यथा {
				error_f("no buffer to send");
				अनुवर्त;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = लिख(children[i].pipefd, ptr, len);
			यदि (ret == -1 && (errno == EINTR || errno == EAGAIN))
				अनुवर्त;
			यदि (ret <= 0) {
				यदि (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				अनुवर्त;
			}
			यदि (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				यदि (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = रिक्त;
					children[i].कुंजियाँ = pack_hostkeys();
				} अन्यथा यदि (children[i].कुंजियाँ == buf) {
					/* sent both config and keys */
					children[i].कुंजियाँ = रिक्त;
				} अन्यथा {
					fatal("config buf not set");
				}

			} अन्यथा {
				यदि ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		प्रति (i = 0; i < options.max_startups; i++) {
			यदि (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				अनुवर्त;
			विकल्प (पठ(children[i].pipefd, &c, परिमाण(c))) {
			पक्ष -1:
				यदि (errno == EINTR || errno == EAGAIN)
					अनुवर्त;
				यदि (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			पक्ष 0:
				/* child closed pipe */
				यदि (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				भङ्ग;
			पक्ष 1:
				यदि (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					गच्छ problem_child;
				}
				यदि (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} अन्यथा यदि (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} अन्यथा {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (पूर्णाङ्क)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					यदि (children[i].early)
						listening--;
					यदि (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				भङ्ग;
			}
		}
		प्रति (i = 0; i < अंक_listen_socks; i++) {
			यदि (!(pfd[i].revents & POLLIN))
				अनुवर्त;
			fromlen = परिमाण(from);
			*newsock = accept(listen_socks[i],
			    (संरचना sockaddr *)&from, &fromlen);
			यदि (*newsock == -1) {
				यदि (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				यदि (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				अनुवर्त;
			}
			यदि (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				अनुवर्त;
			}
			यदि (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				अनुवर्त;
			}
			यदि (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				अनुवर्त;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			यदि (debug_flag) {
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
				close(config_s[0]);
				मुक्त(pfd);
				मुक्त(startup_pollfd);
				प्रत्यागम;
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
			यदि ((child->pid = fork()) == 0) {
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
				close(config_s[0]);
				मुक्त(pfd);
				मुक्त(startup_pollfd);
				प्रत्यागम;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			यदि (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			अन्यथा
				debug("Forked child %ld.", (long)child->pid);

			close(config_s[1]);
			close(*newsock);

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
    संरचना sshkey *कुंजी)
{
	स्थिर संरचना ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	संरचना sshbuf *buf;
	पूर्णाङ्क r;

	यदि (ctx == रिक्त && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == रिक्त)
		fatal_f("ssh_digest_start");
	यदि (कुंजी == रिक्त) { /* finalize */
		/* add server config in case we are using agent for host keys */
		यदि (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		यदि (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = रिक्त;
		प्रत्यागम;
	}
	यदि ((buf = sshbuf_new()) == रिक्त)
		fatal_f("could not allocate buffer");
	यदि ((r = sshkey_private_serialize(कुंजी, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(कुंजी));
	यदि (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

स्थिर वर्ण *
prepare_proctitle(पूर्णाङ्क ac, वर्ण **av)
{
	वर्ण *ret = रिक्त;
	पूर्णाङ्क i;

	प्रति (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	प्रत्यागम ret;
}

/* Disconnect from the controlling tty. */
स्थिर शून्य
disconnect_controlling_tty(शून्य)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	पूर्णाङ्क fd;

	यदि ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(शून्य) ioctl(fd, TIOCNOTTY, रिक्त);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

स्थिर शून्य
print_config(संरचना connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
पूर्णाङ्क
main(पूर्णाङ्क ac, वर्ण **av)
{
	बाह्य वर्ण *optarg;
	बाह्य पूर्णाङ्क optind;
	पूर्णाङ्क log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	वर्ण *config_file_name = _PATH_SERVER_CONFIG_FILE;
	पूर्णाङ्क r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	पूर्णाङ्क sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	पूर्णाङ्क devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	पूर्णाङ्क need_chroot = 1;
	वर्ण *args, *fp, *पंक्ति, *logfile = रिक्त, **rexec_argv = रिक्त;
	संरचना stat sb;
	u_int i, j;
	mode_t new_umask;
	संरचना sshkey *कुंजी;
	संरचना sshkey *pubkey;
	संरचना connection_info connection_info;
	संरचना utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, परिमाण(connection_info));
#ifdef HAVE_SECUREWARE
	(शून्य)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, रिक्त);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, परिमाण(*saved_argv));
	प्रति (i = 0; (पूर्णाङ्क)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = रिक्त;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	यदि (geteuid() == 0 && setgroups(0, रिक्त) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	यावत् ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		विकल्प (opt) {
		पक्ष '4':
			options.address_family = AF_INET;
			भङ्ग;
		पक्ष '6':
			options.address_family = AF_INET6;
			भङ्ग;
		पक्ष 'f':
			config_file_name = optarg;
			भङ्ग;
		पक्ष 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			भङ्ग;
		पक्ष 'd':
			यदि (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} अन्यथा यदि (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			भङ्ग;
		पक्ष 'D':
			no_daemon_flag = 1;
			भङ्ग;
		पक्ष 'G':
			do_dump_cfg = 1;
			भङ्ग;
		पक्ष 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		पक्ष 'e':
			log_stderr = 1;
			भङ्ग;
		पक्ष 'i':
			inetd_flag = 1;
			भङ्ग;
		पक्ष 'r':
			logit("-r option is deprecated");
			भङ्ग;
		पक्ष 'R':
			fatal("-R not supported here");
			भङ्ग;
		पक्ष 'Q':
			/* ignored */
			भङ्ग;
		पक्ष 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			भङ्ग;
		पक्ष 'b':
			/* protocol 1, ignored */
			भङ्ग;
		पक्ष 'p':
			options.ports_from_cmdline = 1;
			यदि (options.अंक_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.अंक_ports++] = a2port(optarg);
			यदि (options.ports[options.अंक_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			भङ्ग;
		पक्ष 'g':
			यदि ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			भङ्ग;
		पक्ष 'k':
			/* protocol 1, ignored */
			भङ्ग;
		पक्ष 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			भङ्ग;
		पक्ष 't':
			test_flag = 1;
			भङ्ग;
		पक्ष 'T':
			test_flag = 2;
			भङ्ग;
		पक्ष 'C':
			यदि (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			भङ्ग;
		पक्ष 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, रिक्त);
			यदि (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			भङ्ग;
		पक्ष 'o':
			पंक्ति = xstrdup(optarg);
			यदि (process_server_config_पंक्ति(&options, पंक्ति,
			    "command-line", 0, रिक्त, रिक्त, &includes) != 0)
				exit(1);
			मुक्त(पंक्ति);
			भङ्ग;
		पक्ष 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		स्वभाव:
			usage();
			भङ्ग;
		}
	}

	यदि (getexecpath(execpath, परिमाण execpath) != 0) {
		यदि (strlcpy(execpath, av[0], परिमाण execpath) >=
		    परिमाण execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	यदि (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	यदि ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	यावत् (devnull < REEXEC_MIN_FREE_FD) {
		यदि ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	यदि (logfile != रिक्त) {
		वर्ण *cp, pid_s[32];

		snprintf(pid_s, परिमाण(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (वर्ण *)रिक्त);
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
	यदि (getenv("KRB5CCNAME") != रिक्त)
		(शून्य) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_कुंजी = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	यदि (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	यदि (uname(&utsname) != 0) {
		memset(&utsname, 0, परिमाण(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", परिमाण(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	मुक्त(args);

	/* Fetch our configuration */
	यदि ((cfg = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new config failed");
	यदि (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, रिक्त, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	यदि (options.authorized_कुंजियाँ_command_user == रिक्त &&
	    (options.authorized_कुंजियाँ_command != रिक्त &&
	    strcasecmp(options.authorized_कुंजियाँ_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	यदि (options.authorized_principals_command_user == रिक्त &&
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
	यदि (options.अंक_auth_methods != 0) {
		प्रति (i = 0; i < options.अंक_auth_methods; i++) {
			यदि (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				भङ्ग;
		}
		यदि (i >= options.अंक_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	यदि (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	यदि (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_कुंजियाँ = xcalloc(options.अंक_host_कुंजी_files,
	    परिमाण(संरचना sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.अंक_host_कुंजी_files,
	    परिमाण(संरचना sshkey *));

	यदि (options.host_कुंजी_agent) {
		यदि (strcmp(options.host_कुंजी_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_कुंजी_agent, 1);
		यदि ((r = ssh_get_authentication_socket(रिक्त)) == 0)
			have_agent = 1;
		अन्यथा
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_कुंजी_agent);
	}

	प्रति (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		पूर्णाङ्क ll = options.host_कुंजी_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		यदि (options.host_कुंजी_files[i] == रिक्त)
			अनुवर्त;
		यदि ((r = sshkey_load_private(options.host_कुंजी_files[i], "",
		    &कुंजी, रिक्त)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_कुंजी_files[i]);
		यदि (sshkey_is_sk(कुंजी) &&
		    कुंजी->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_कुंजी_files[i]);
			कुंजी->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		यदि (r == 0 && कुंजी != रिक्त &&
		    (r = sshkey_shield_private(कुंजी)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_कुंजी_files[i]);
			sshkey_free(कुंजी);
			कुंजी = रिक्त;
		}
		यदि ((r = sshkey_load_public(options.host_कुंजी_files[i],
		    &pubkey, रिक्त)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_कुंजी_files[i]);
		यदि (pubkey != रिक्त && कुंजी != रिक्त) {
			यदि (!sshkey_equal(pubkey, कुंजी)) {
				error("Public key for %s does not match "
				    "private key", options.host_कुंजी_files[i]);
				sshkey_free(pubkey);
				pubkey = रिक्त;
			}
		}
		यदि (pubkey == रिक्त && कुंजी != रिक्त) {
			यदि ((r = sshkey_from_private(कुंजी, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_कुंजी_files[i]);
		}
		यदि (pubkey != रिक्त && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_कुंजी_files[i]);
			sshkey_free(pubkey);
			sshkey_free(कुंजी);
			अनुवर्त;
		}
		sensitive_data.host_कुंजियाँ[i] = कुंजी;
		sensitive_data.host_pubkeys[i] = pubkey;

		यदि (कुंजी == रिक्त && pubkey != रिक्त && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_कुंजी_files[i]);
			keytype = pubkey->type;
		} अन्यथा यदि (कुंजी != रिक्त) {
			keytype = कुंजी->type;
			accumulate_host_timing_secret(cfg, कुंजी);
		} अन्यथा {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_कुंजी_files[i]);
			sensitive_data.host_कुंजियाँ[i] = रिक्त;
			sensitive_data.host_pubkeys[i] = रिक्त;
			अनुवर्त;
		}

		विकल्प (keytype) {
		पक्ष कुंजी_RSA:
		पक्ष कुंजी_ECDSA:
		पक्ष कुंजी_ED25519:
		पक्ष कुंजी_MLDSA44_ED25519:
		पक्ष कुंजी_ECDSA_SK:
		पक्ष कुंजी_ED25519_SK:
			यदि (have_agent || कुंजी != रिक्त)
				sensitive_data.have_ssh2_कुंजी = 1;
			भङ्ग;
		}
		यदि ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    कुंजी ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		मुक्त(fp);
	}
	accumulate_host_timing_secret(cfg, रिक्त);
	यदि (!sensitive_data.have_ssh2_कुंजी) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.अंक_host_कुंजी_files,
	    परिमाण(संरचना sshkey *));
	प्रति (i = 0; i < options.अंक_host_कुंजी_files; i++)
		sensitive_data.host_certificates[i] = रिक्त;

	प्रति (i = 0; i < options.अंक_host_cert_files; i++) {
		यदि (options.host_cert_files[i] == रिक्त)
			अनुवर्त;
		यदि ((r = sshkey_load_public(options.host_cert_files[i],
		    &कुंजी, रिक्त)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			अनुवर्त;
		}
		यदि (!sshkey_is_cert(कुंजी)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(कुंजी);
			अनुवर्त;
		}
		/* Find matching private key */
		प्रति (j = 0; j < options.अंक_host_कुंजी_files; j++) {
			यदि (sshkey_equal_public(कुंजी,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = कुंजी;
				भङ्ग;
			}
		}
		यदि (j >= options.अंक_host_कुंजी_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(कुंजी);
			अनुवर्त;
		}
		sensitive_data.host_certificates[j] = कुंजी;
		debug("host certificate: #%u type %d %s", j, कुंजी->type,
		    sshkey_type(कुंजी));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	यदि ((getpwnam(SSH_PRIVSEP_USER)) == रिक्त && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	यदि (need_chroot) {
		यदि ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		यदि (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#अन्यथा
		यदि (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	यदि (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	यदि (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	यदि (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	यदि (setgroups(0, रिक्त) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	यदि (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, परिमाण(वर्ण *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	प्रति (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = रिक्त;
	यदि (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	यदि (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(शून्य) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	यदि (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	प्रति (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	यदि (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		यदि (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	यदि (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	यदि (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} अन्यथा {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
#ifdef SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#endif

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		यदि (options.pid_file != रिक्त && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			यदि (f == रिक्त) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} अन्यथा {
				fprintf(f, "%ld\n", (long) getpid());
				fclose(f);
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
	यदि (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	यदि (!inetd_flag) {
		यदि (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		यदि (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		यदि (newsock > STDOUT_FILENO)
			close(newsock);
	}
	यदि (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		यदि (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_to(रिक्त);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
शून्य
cleanup_exit(पूर्णाङ्क i)
{
	_exit(i);
}
