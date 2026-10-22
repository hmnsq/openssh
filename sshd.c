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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/ioctl.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/utsname.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <grp.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>

#ifdef HAVE_SECUREWARE
#অন্তর্ভাব <sys/security.h>
#অন্তর্ভাব <prot.h>
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "sshpty.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "version.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sk-api.h"
#অন্তর্ভাব "addr.h"
#অন্তর্ভাব "srclimit.h"
#অন্তর্ভাব "atomicio.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

বাহ্যিক অক্ষর *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
পূর্ণসংখ্যা debug_flag = 0;

/* Saved arguments to main(). */
স্থির অক্ষর execpath[PATH_MAX];
স্থির অক্ষর **saved_argv;
স্থির পূর্ণসংখ্যা saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
স্থির পূর্ণসংখ্যা listen_socks[MAX_LISTEN_SOCKS];
স্থির পূর্ণসংখ্যা অঙ্ক_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
কাঠামো {
	কাঠামো sshkey	**host_চাবিগুলি;		/* all private host keys */
	কাঠামো sshkey	**host_pubkeys;		/* all public host keys */
	কাঠামো sshkey	**host_certificates;	/* all public host certificates */
	পূর্ণসংখ্যা		have_ssh2_চাবি;
} sensitive_তথ্য;

/* This is set to true when a signal is received. */
স্থির অস্থির sig_atomic_t received_siginfo = 0;
স্থির অস্থির sig_atomic_t received_sigchld = 0;
স্থির অস্থির sig_atomic_t received_sighup = 0;
স্থির অস্থির sig_atomic_t received_sigterm = 0;

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
কাঠামো early_child {
	পূর্ণসংখ্যা pipefd;
	পূর্ণসংখ্যা early;		/* Indicates child closed listener */
	অক্ষর *id;		/* human readable connection identifier */
	pid_t pid;
	কাঠামো xaddr addr;
	পূর্ণসংখ্যা have_addr;
	পূর্ণসংখ্যা status, have_status;
	কাঠামো sshbuf *config;
	কাঠামো sshbuf *চাবিগুলি;
};
স্থির কাঠামো early_child *children;
স্থির পূর্ণসংখ্যা children_active;

/* sshd_config buffer */
কাঠামো sshbuf *cfg;
কাঠামো sshbuf *config;	/* packed */

/* Included files from the configuration file */
কাঠামো include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
কাঠামো sshbuf *loginmsg;

/* Unprivileged user */
কাঠামো passwd *privsep_pw = ফাঁকা;

স্থির অক্ষর *listener_proctitle;

/*
 * Close all listening sockets
 */
স্থির শূন্য
close_listen_socks(শূন্য)
{
	পূর্ণসংখ্যা i;

	জন্য (i = 0; i < অঙ্ক_listen_socks; i++)
		close(listen_socks[i]);
	অঙ্ক_listen_socks = 0;
}

/* Allocate and initialise the children array */
স্থির শূন্য
child_alloc(শূন্য)
{
	পূর্ণসংখ্যা i;

	children = xcalloc(options.max_startups, আকার(*children));
	জন্য (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
স্থির কাঠামো early_child *
child_register(পূর্ণসংখ্যা pipefd, পূর্ণসংখ্যা sockfd)
{
	পূর্ণসংখ্যা i, lport, rport;
	অক্ষর *laddr = ফাঁকা, *raddr = ফাঁকা;
	কাঠামো early_child *child = ফাঁকা;
	কাঠামো sockaddr_storage addr;
	socklen_t addrlen = আকার(addr);
	কাঠামো sockaddr *sa = (কাঠামো sockaddr *)&addr;

	জন্য (i = 0; i < options.max_startups; i++) {
		যদি (children[i].pipefd != -1 ||
		    children[i].config != ফাঁকা ||
		    children[i].চাবিগুলি != ফাঁকা ||
		    children[i].pid > 0)
			চালু;
		child = &(children[i]);
		বিরতি;
	}
	যদি (child == ফাঁকা) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	যদি ((child->config = sshbuf_fromb(config)) == ফাঁকা)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	যদি (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	যদি ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} অন্যথা {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	মুক্ত(laddr);
	মুক্ত(raddr);
	যদি (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	ফেরত child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
স্থির শূন্য
child_finish(কাঠামো early_child *child)
{
	যদি (children_active == 0)
		fatal_f("internal error: children_active underflow");
	যদি (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->চাবিগুলি);
	মুক্ত(child->id);
	memset(child, '\0', আকার(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
স্থির শূন্য
child_close(কাঠামো early_child *child, পূর্ণসংখ্যা force_final, পূর্ণসংখ্যা quiet)
{
	যদি (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	যদি (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	যদি (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
স্থির শূন্য
child_exit(pid_t pid, পূর্ণসংখ্যা status)
{
	পূর্ণসংখ্যা i;

	যদি (children == ফাঁকা || pid <= 0)
		ফেরত;
	জন্য (i = 0; i < options.max_startups; i++) {
		যদি (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			বিরতি;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
স্থির শূন্য
child_reap(কাঠামো early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	পূর্ণসংখ্যা was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ধ্রুবক অক্ষর *child_status;

	যদি (child->config)
		child_status = " (sending config)";
	অন্যথা যদি (child->চাবিগুলি)
		child_status = " (sending keys)";
	অন্যথা যদি (child->early)
		child_status = " (early)";
	অন্যথা
		child_status = "";

	/* Log exit information */
	যদি (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		যদি ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		যদি (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} অন্যথা যদি (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} অন্যথা {
		/* Normal exit. We care about the status */
		নির্বাচন (WEXITSTATUS(child->status)) {
		ক্ষেত্র 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			বিরতি;
		ক্ষেত্র EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			বিরতি;
		ক্ষেত্র EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			বিরতি;
		ক্ষেত্র EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			বিরতি;
		ক্ষেত্র EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			বিরতি;
		ক্ষেত্র EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			বিরতি;
		পূর্বনির্ধারিত:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			বিরতি;
		}
	}

	যদি (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	যদি (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
স্থির শূন্য
child_reap_all_exited(শূন্য)
{
	পূর্ণসংখ্যা i;
	pid_t pid;
	পূর্ণসংখ্যা status;

	যদি (children == ফাঁকা)
		ফেরত;

	জন্য (;;) {
		যদি ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			বিরতি;
		অন্যথা যদি (pid == -1) {
			যদি (errno == EINTR || errno == EAGAIN)
				চালু;
			যদি (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			বিরতি;
		}
		child_exit(pid, status);
	}

	জন্য (i = 0; i < options.max_startups; i++) {
		যদি (!children[i].have_status)
			চালু;
		child_reap(&(children[i]));
	}
}

স্থির শূন্য
close_startup_pipes(শূন্য)
{
	পূর্ণসংখ্যা i;

	যদি (children == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < options.max_startups; i++) {
		যদি (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
স্থির শূন্য
show_info(শূন্য)
{
	পূর্ণসংখ্যা i;
	ধ্রুবক অক্ষর *child_status;

	/* XXX print listening sockets here too */
	যদি (children == ফাঁকা)
		ফেরত;
	logit("%d active startups", children_active);
	জন্য (i = 0; i < options.max_startups; i++) {
		যদি (children[i].pipefd == -1 && children[i].pid <= 0)
			চালু;
		যদি (children[i].config)
			child_status = " (sending config)";
		অন্যথা যদি (children[i].চাবিগুলি)
			child_status = " (sending keys)";
		অন্যথা যদি (children[i].early)
			child_status = " (early)";
		অন্যথা
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

স্থির শূন্য
sighup_handler(পূর্ণসংখ্যা sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
স্থির শূন্য
sighup_restart(শূন্য)
{
	logit("Received SIGHUP; restarting.");
	যদি (options.pid_file != ফাঁকা)
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
স্থির শূন্য
sigterm_handler(পূর্ণসংখ্যা sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
স্থির শূন্য
siginfo_handler(পূর্ণসংখ্যা sig)
{
	received_siginfo = 1;
}
#endif

স্থির শূন্য
main_sigchld_handler(পূর্ণসংখ্যা sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
স্থির পূর্ণসংখ্যা
should_drop_connection(পূর্ণসংখ্যা startups)
{
	পূর্ণসংখ্যা p, r;

	যদি (startups < options.max_startups_begin)
		ফেরত 0;
	যদি (startups >= options.max_startups)
		ফেরত 1;
	যদি (options.max_startups_rate == 100)
		ফেরত 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	ফেরত (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
স্থির পূর্ণসংখ্যা
drop_connection(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা startups, পূর্ণসংখ্যা notify_pipe)
{
	স্থির কাঠামো log_ratelimit_ctx ratelimit_maxstartups;
	স্থির কাঠামো log_ratelimit_ctx ratelimit_penalty;
	স্থির পূর্ণসংখ্যা init_done;
	অক্ষর *laddr, *raddr;
	ধ্রুবক অক্ষর *reason = ফাঁকা, *subreason = ফাঁকা;
	ধ্রুবক অক্ষর বার্তা[] = "Not allowed at this time\r\n";
	কাঠামো log_ratelimit_ctx *rl = ফাঁকা;
	পূর্ণসংখ্যা ratelimited;
	u_int ndropped;

	যদি (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	যদি (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} অন্যথা {
		/* MaxStartups */
		যদি (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			ফেরত 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(ফাঁকা), ফাঁকা, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != ফাঁকা ? subreason : reason);
	মুক্ত(laddr);
	মুক্ত(raddr);
	যদি (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(শূন্য)লিখ(sock, বার্তা, আকার(বার্তা) - 1);
	ফেরত 1;
}

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

স্থির কাঠামো sshbuf *
pack_hostkeys(শূন্য)
{
	কাঠামো sshbuf *m = ফাঁকা, *keybuf = ফাঁকা, *hostkeys = ফাঁকা;
	পূর্ণসংখ্যা r;
	u_int i;
	আকার_t len;

	যদি ((m = sshbuf_new()) == ফাঁকা ||
	    (keybuf = sshbuf_new()) == ফাঁকা ||
	    (hostkeys = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	জন্য (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		যদি (sensitive_তথ্য.host_চাবিগুলি[i] != ফাঁকা &&
		    (r = sshkey_private_serialize(sensitive_তথ্য.host_চাবিগুলি[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		যদি ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		যদি (sensitive_তথ্য.host_pubkeys[i] != ফাঁকা) {
			যদি ((r = sshkey_puts(sensitive_তথ্য.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} অন্যথা {
			যদি ((r = sshbuf_put_string(hostkeys, ফাঁকা, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		যদি (sensitive_তথ্য.host_certificates[i] != ফাঁকা) {
			যদি ((r = sshkey_puts(
			    sensitive_তথ্য.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} অন্যথা {
			যদি ((r = sshbuf_put_string(hostkeys, ফাঁকা, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	যদি ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	যদি ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	ফেরত m;
}

স্থির কাঠামো sshbuf *
pack_config(কাঠামো sshbuf *conf)
{
	কাঠামো sshbuf *m = ফাঁকা, *inc = ফাঁকা;
	কাঠামো include_item *item = ফাঁকা;
	আকার_t len;
	পূর্ণসংখ্যা r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	যদি ((m = sshbuf_new()) == ফাঁকা ||
	    (inc = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		যদি ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	যদি ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	যদি ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	ফেরত m;
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
স্থির শূন্য
send_rexec_state(পূর্ণসংখ্যা fd)
{
	কাঠামো sshbuf *চাবিগুলি;
	u_int mlen;
	pid_t pid;

	যদি ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	যদি (pid != 0)
		ফেরত;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	যদি (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	চাবিগুলি = pack_hostkeys();
	mlen = sshbuf_len(চাবিগুলি);
	যদি (atomicio(vwrite, fd, sshbuf_mutable_ptr(চাবিগুলি), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(চাবিগুলি);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
স্থির শূন্য
listen_on_addrs(কাঠামো listenaddr *la)
{
	পূর্ণসংখ্যা ret, listen_sock;
	কাঠামো addrinfo *ai;
	অক্ষর ntop[NI_MAXHOST], strport[NI_MAXSERV];

	জন্য (ai = la->addrs; ai; ai = ai->ai_next) {
		যদি (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			চালু;
		যদি (অঙ্ক_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		যদি ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, আকার(ntop), strport, আকার(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			চালু;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		যদি (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			চালু;
		}
		যদি (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			চালু;
		}
		যদি (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			চালু;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		যদি (la->rdomain != ফাঁকা &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			চালু;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		যদি (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		যদি (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			চালু;
		}
		listen_socks[অঙ্ক_listen_socks] = listen_sock;
		অঙ্ক_listen_socks++;

		/* Start listening on the port. */
		যদি (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == ফাঁকা ? "" : " rdomain ",
		    la->rdomain == ফাঁকা ? "" : la->rdomain);
	}
}

স্থির শূন্য
server_listen(শূন্য)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	জন্য (i = 0; i < options.অঙ্ক_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		মুক্ত(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    আকার(options.listen_addrs[i]));
	}
	মুক্ত(options.listen_addrs);
	options.listen_addrs = ফাঁকা;
	options.অঙ্ক_listen_addrs = 0;

	যদি (!অঙ্ক_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
স্থির শূন্য
server_accept_loop(পূর্ণসংখ্যা *sock_in, পূর্ণসংখ্যা *sock_out, পূর্ণসংখ্যা *newsock, পূর্ণসংখ্যা *config_s,
    পূর্ণসংখ্যা log_stderr)
{
	কাঠামো pollfd *pfd = ফাঁকা;
	পূর্ণসংখ্যা i, ret, npfd, r;
	পূর্ণসংখ্যা oactive = -1, listening = 0, lameduck = 0;
	পূর্ণসংখ্যা *startup_pollfd;
	ssize_t len;
	ধ্রুবক u_char *ptr;
	অক্ষর c = 0;
	কাঠামো sockaddr_storage from;
	কাঠামো early_child *child;
	কাঠামো sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, আকার(পূর্ণসংখ্যা));

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
	pfd = xcalloc(অঙ্ক_listen_socks + options.max_startups,
	    আকার(কাঠামো pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	জন্য (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		যদি (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (পূর্ণসংখ্যা) received_sigterm);
			close_listen_socks();
			যদি (options.pid_file != ফাঁকা)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		যদি (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		যদি (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		যদি (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		যদি (received_sighup) {
			যদি (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			যদি (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, ফাঁকা);
				sighup_restart();
			}
		}

		জন্য (i = 0; i < অঙ্ক_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = অঙ্ক_listen_socks;
		জন্য (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			যদি (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				যদি (children[i].config != ফাঁকা ||
				    children[i].চাবিগুলি != ফাঁকা)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, ফাঁকা, &osigset);
		যদি (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			যদি (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, ফাঁকা);
		যদি (ret == -1)
			চালু;

		জন্য (i = 0; i < options.max_startups; i++) {
			যদি (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				চালু;
			যদি (children[i].config)
				buf = children[i].config;
			অন্যথা যদি (children[i].চাবিগুলি)
				buf = children[i].চাবিগুলি;
			অন্যথা {
				error_f("no buffer to send");
				চালু;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = লিখ(children[i].pipefd, ptr, len);
			যদি (ret == -1 && (errno == EINTR || errno == EAGAIN))
				চালু;
			যদি (ret <= 0) {
				যদি (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				চালু;
			}
			যদি (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				যদি (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = ফাঁকা;
					children[i].চাবিগুলি = pack_hostkeys();
				} অন্যথা যদি (children[i].চাবিগুলি == buf) {
					/* sent both config and keys */
					children[i].চাবিগুলি = ফাঁকা;
				} অন্যথা {
					fatal("config buf not set");
				}

			} অন্যথা {
				যদি ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		জন্য (i = 0; i < options.max_startups; i++) {
			যদি (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				চালু;
			নির্বাচন (পঠ(children[i].pipefd, &c, আকার(c))) {
			ক্ষেত্র -1:
				যদি (errno == EINTR || errno == EAGAIN)
					চালু;
				যদি (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			ক্ষেত্র 0:
				/* child closed pipe */
				যদি (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				বিরতি;
			ক্ষেত্র 1:
				যদি (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					যাও problem_child;
				}
				যদি (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} অন্যথা যদি (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} অন্যথা {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (পূর্ণসংখ্যা)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					যদি (children[i].early)
						listening--;
					যদি (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				বিরতি;
			}
		}
		জন্য (i = 0; i < অঙ্ক_listen_socks; i++) {
			যদি (!(pfd[i].revents & POLLIN))
				চালু;
			fromlen = আকার(from);
			*newsock = accept(listen_socks[i],
			    (কাঠামো sockaddr *)&from, &fromlen);
			যদি (*newsock == -1) {
				যদি (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				যদি (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				চালু;
			}
			যদি (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				চালু;
			}
			যদি (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				চালু;
			}
			যদি (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				চালু;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			যদি (debug_flag) {
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
				মুক্ত(pfd);
				মুক্ত(startup_pollfd);
				ফেরত;
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
			যদি ((child->pid = fork()) == 0) {
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
				মুক্ত(pfd);
				মুক্ত(startup_pollfd);
				ফেরত;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			যদি (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			অন্যথা
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

স্থির শূন্য
accumulate_host_timing_secret(কাঠামো sshbuf *server_cfg,
    কাঠামো sshkey *চাবি)
{
	স্থির কাঠামো ssh_digest_ctx *ctx;
	u_char *hash;
	আকার_t len;
	কাঠামো sshbuf *buf;
	পূর্ণসংখ্যা r;

	যদি (ctx == ফাঁকা && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == ফাঁকা)
		fatal_f("ssh_digest_start");
	যদি (চাবি == ফাঁকা) { /* finalize */
		/* add server config in case we are using agent for host keys */
		যদি (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		যদি (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = ফাঁকা;
		ফেরত;
	}
	যদি ((buf = sshbuf_new()) == ফাঁকা)
		fatal_f("could not allocate buffer");
	যদি ((r = sshkey_private_serialize(চাবি, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(চাবি));
	যদি (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

স্থির অক্ষর *
prepare_proctitle(পূর্ণসংখ্যা ac, অক্ষর **av)
{
	অক্ষর *ret = ফাঁকা;
	পূর্ণসংখ্যা i;

	জন্য (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	ফেরত ret;
}

/* Disconnect from the controlling tty. */
স্থির শূন্য
disconnect_controlling_tty(শূন্য)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	পূর্ণসংখ্যা fd;

	যদি ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(শূন্য) ioctl(fd, TIOCNOTTY, ফাঁকা);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

স্থির শূন্য
print_config(কাঠামো connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা ac, অক্ষর **av)
{
	বাহ্যিক অক্ষর *optarg;
	বাহ্যিক পূর্ণসংখ্যা optind;
	পূর্ণসংখ্যা log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	অক্ষর *config_file_name = _PATH_SERVER_CONFIG_FILE;
	পূর্ণসংখ্যা r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	পূর্ণসংখ্যা sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	পূর্ণসংখ্যা devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	পূর্ণসংখ্যা need_chroot = 1;
	অক্ষর *args, *fp, *সারি, *logfile = ফাঁকা, **rexec_argv = ফাঁকা;
	কাঠামো stat sb;
	u_int i, j;
	mode_t new_umask;
	কাঠামো sshkey *চাবি;
	কাঠামো sshkey *pubkey;
	কাঠামো connection_info connection_info;
	কাঠামো utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, আকার(connection_info));
#ifdef HAVE_SECUREWARE
	(শূন্য)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ফাঁকা);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, আকার(*saved_argv));
	জন্য (i = 0; (পূর্ণসংখ্যা)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ফাঁকা;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	যদি (geteuid() == 0 && setgroups(0, ফাঁকা) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	যখন ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		নির্বাচন (opt) {
		ক্ষেত্র '4':
			options.address_family = AF_INET;
			বিরতি;
		ক্ষেত্র '6':
			options.address_family = AF_INET6;
			বিরতি;
		ক্ষেত্র 'f':
			config_file_name = optarg;
			বিরতি;
		ক্ষেত্র 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			বিরতি;
		ক্ষেত্র 'd':
			যদি (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} অন্যথা যদি (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			বিরতি;
		ক্ষেত্র 'D':
			no_daemon_flag = 1;
			বিরতি;
		ক্ষেত্র 'G':
			do_dump_cfg = 1;
			বিরতি;
		ক্ষেত্র 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		ক্ষেত্র 'e':
			log_stderr = 1;
			বিরতি;
		ক্ষেত্র 'i':
			inetd_flag = 1;
			বিরতি;
		ক্ষেত্র 'r':
			logit("-r option is deprecated");
			বিরতি;
		ক্ষেত্র 'R':
			fatal("-R not supported here");
			বিরতি;
		ক্ষেত্র 'Q':
			/* ignored */
			বিরতি;
		ক্ষেত্র 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			বিরতি;
		ক্ষেত্র 'b':
			/* protocol 1, ignored */
			বিরতি;
		ক্ষেত্র 'p':
			options.ports_from_cmdline = 1;
			যদি (options.অঙ্ক_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.অঙ্ক_ports++] = a2port(optarg);
			যদি (options.ports[options.অঙ্ক_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			বিরতি;
		ক্ষেত্র 'g':
			যদি ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			বিরতি;
		ক্ষেত্র 'k':
			/* protocol 1, ignored */
			বিরতি;
		ক্ষেত্র 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			বিরতি;
		ক্ষেত্র 't':
			test_flag = 1;
			বিরতি;
		ক্ষেত্র 'T':
			test_flag = 2;
			বিরতি;
		ক্ষেত্র 'C':
			যদি (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			বিরতি;
		ক্ষেত্র 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, ফাঁকা);
			যদি (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			বিরতি;
		ক্ষেত্র 'o':
			সারি = xstrdup(optarg);
			যদি (process_server_config_সারি(&options, সারি,
			    "command-line", 0, ফাঁকা, ফাঁকা, &includes) != 0)
				exit(1);
			মুক্ত(সারি);
			বিরতি;
		ক্ষেত্র 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		পূর্বনির্ধারিত:
			usage();
			বিরতি;
		}
	}

	যদি (getexecpath(execpath, আকার execpath) != 0) {
		যদি (strlcpy(execpath, av[0], আকার execpath) >=
		    আকার execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	যদি (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	যদি ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	যখন (devnull < REEXEC_MIN_FREE_FD) {
		যদি ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	যদি (logfile != ফাঁকা) {
		অক্ষর *cp, pid_s[32];

		snprintf(pid_s, আকার(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (অক্ষর *)ফাঁকা);
		log_redirect_stderr_to(cp);
		মুক্ত(cp);
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
	যদি (getenv("KRB5CCNAME") != ফাঁকা)
		(শূন্য) unsetenv("KRB5CCNAME");

	sensitive_তথ্য.have_ssh2_চাবি = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	যদি (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	যদি (uname(&utsname) != 0) {
		memset(&utsname, 0, আকার(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", আকার(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	মুক্ত(args);

	/* Fetch our configuration */
	যদি ((cfg = sshbuf_new()) == ফাঁকা)
		fatal("sshbuf_new config failed");
	যদি (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, ফাঁকা, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	যদি (options.authorized_চাবিগুলি_command_user == ফাঁকা &&
	    (options.authorized_চাবিগুলি_command != ফাঁকা &&
	    strcasecmp(options.authorized_চাবিগুলি_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	যদি (options.authorized_principals_command_user == ফাঁকা &&
	    (options.authorized_principals_command != ফাঁকা &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	যদি (options.অঙ্ক_auth_methods != 0) {
		জন্য (i = 0; i < options.অঙ্ক_auth_methods; i++) {
			যদি (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				বিরতি;
		}
		যদি (i >= options.অঙ্ক_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	যদি (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	যদি (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_তথ্য.host_চাবিগুলি = xcalloc(options.অঙ্ক_host_চাবি_files,
	    আকার(কাঠামো sshkey *));
	sensitive_তথ্য.host_pubkeys = xcalloc(options.অঙ্ক_host_চাবি_files,
	    আকার(কাঠামো sshkey *));

	যদি (options.host_চাবি_agent) {
		যদি (strcmp(options.host_চাবি_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_চাবি_agent, 1);
		যদি ((r = ssh_get_authentication_socket(ফাঁকা)) == 0)
			have_agent = 1;
		অন্যথা
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_চাবি_agent);
	}

	জন্য (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		পূর্ণসংখ্যা ll = options.host_চাবি_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		যদি (options.host_চাবি_files[i] == ফাঁকা)
			চালু;
		যদি ((r = sshkey_load_private(options.host_চাবি_files[i], "",
		    &চাবি, ফাঁকা)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_চাবি_files[i]);
		যদি (sshkey_is_sk(চাবি) &&
		    চাবি->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_চাবি_files[i]);
			চাবি->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		যদি (r == 0 && চাবি != ফাঁকা &&
		    (r = sshkey_shield_private(চাবি)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_চাবি_files[i]);
			sshkey_free(চাবি);
			চাবি = ফাঁকা;
		}
		যদি ((r = sshkey_load_public(options.host_চাবি_files[i],
		    &pubkey, ফাঁকা)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_চাবি_files[i]);
		যদি (pubkey != ফাঁকা && চাবি != ফাঁকা) {
			যদি (!sshkey_equal(pubkey, চাবি)) {
				error("Public key for %s does not match "
				    "private key", options.host_চাবি_files[i]);
				sshkey_free(pubkey);
				pubkey = ফাঁকা;
			}
		}
		যদি (pubkey == ফাঁকা && চাবি != ফাঁকা) {
			যদি ((r = sshkey_from_private(চাবি, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_চাবি_files[i]);
		}
		যদি (pubkey != ফাঁকা && (r = sshkey_check_rsa_দৈর্ঘ্য(pubkey,
		    options.required_rsa_আকার)) != 0) {
			error_fr(r, "Host key %s", options.host_চাবি_files[i]);
			sshkey_free(pubkey);
			sshkey_free(চাবি);
			চালু;
		}
		sensitive_তথ্য.host_চাবিগুলি[i] = চাবি;
		sensitive_তথ্য.host_pubkeys[i] = pubkey;

		যদি (চাবি == ফাঁকা && pubkey != ফাঁকা && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_চাবি_files[i]);
			keytype = pubkey->type;
		} অন্যথা যদি (চাবি != ফাঁকা) {
			keytype = চাবি->type;
			accumulate_host_timing_secret(cfg, চাবি);
		} অন্যথা {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_চাবি_files[i]);
			sensitive_তথ্য.host_চাবিগুলি[i] = ফাঁকা;
			sensitive_তথ্য.host_pubkeys[i] = ফাঁকা;
			চালু;
		}

		নির্বাচন (keytype) {
		ক্ষেত্র চাবি_RSA:
		ক্ষেত্র চাবি_ECDSA:
		ক্ষেত্র চাবি_ED25519:
		ক্ষেত্র চাবি_MLDSA44_ED25519:
		ক্ষেত্র চাবি_ECDSA_SK:
		ক্ষেত্র চাবি_ED25519_SK:
			যদি (have_agent || চাবি != ফাঁকা)
				sensitive_তথ্য.have_ssh2_চাবি = 1;
			বিরতি;
		}
		যদি ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ফাঁকা)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    চাবি ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		মুক্ত(fp);
	}
	accumulate_host_timing_secret(cfg, ফাঁকা);
	যদি (!sensitive_তথ্য.have_ssh2_চাবি) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_তথ্য.host_certificates = xcalloc(options.অঙ্ক_host_চাবি_files,
	    আকার(কাঠামো sshkey *));
	জন্য (i = 0; i < options.অঙ্ক_host_চাবি_files; i++)
		sensitive_তথ্য.host_certificates[i] = ফাঁকা;

	জন্য (i = 0; i < options.অঙ্ক_host_cert_files; i++) {
		যদি (options.host_cert_files[i] == ফাঁকা)
			চালু;
		যদি ((r = sshkey_load_public(options.host_cert_files[i],
		    &চাবি, ফাঁকা)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			চালু;
		}
		যদি (!sshkey_is_cert(চাবি)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(চাবি);
			চালু;
		}
		/* Find matching private key */
		জন্য (j = 0; j < options.অঙ্ক_host_চাবি_files; j++) {
			যদি (sshkey_equal_public(চাবি,
			    sensitive_তথ্য.host_pubkeys[j])) {
				sensitive_তথ্য.host_certificates[j] = চাবি;
				বিরতি;
			}
		}
		যদি (j >= options.অঙ্ক_host_চাবি_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(চাবি);
			চালু;
		}
		sensitive_তথ্য.host_certificates[j] = চাবি;
		debug("host certificate: #%u type %d %s", j, চাবি->type,
		    sshkey_type(চাবি));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	যদি ((getpwnam(SSH_PRIVSEP_USER)) == ফাঁকা && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	যদি (need_chroot) {
		যদি ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		যদি (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#অন্যথা
		যদি (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	যদি (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	যদি (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	যদি (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	যদি (setgroups(0, ফাঁকা) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	যদি (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, আকার(অক্ষর *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	জন্য (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = ফাঁকা;
	যদি (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	যদি (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(শূন্য) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	যদি (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	জন্য (i = 0; i < options.অঙ্ক_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	যদি (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		যদি (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	যদি (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	যদি (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} অন্যথা {
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
		যদি (options.pid_file != ফাঁকা && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			যদি (f == ফাঁকা) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} অন্যথা {
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
	যদি (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	যদি (!inetd_flag) {
		যদি (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		যদি (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		যদি (newsock > STDOUT_FILENO)
			close(newsock);
	}
	যদি (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		যদি (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_to(ফাঁকা);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
শূন্য
cleanup_exit(পূর্ণসংখ্যা i)
{
	_exit(i);
}
