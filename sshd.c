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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>
#ضمن <sys/socket.h>
#ضمن <sys/stat.h>
#ضمن <sys/time.h>
#ضمن <sys/queue.h>
#ضمن <sys/wait.h>
#ضمن <sys/utsname.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <grp.h>
#ضمن <poll.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <time.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <limits.h>

#اگر_تعریف_شده HAVE_SECUREWARE
#ضمن <sys/security.h>
#ضمن <prot.h>
#پایان_اگر

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "sshpty.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "compat.h"
#ضمن "digest.h"
#ضمن "sshkey.h"
#ضمن "authfile.h"
#ضمن "pathnames.h"
#ضمن "canohost.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "authfd.h"
#ضمن "msg.h"
#ضمن "version.h"
#ضمن "ssherr.h"
#ضمن "sk-api.h"
#ضمن "addr.h"
#ضمن "srclimit.h"
#ضمن "atomicio.h"
#اگر_تعریف_شده GSSAPI
#ضمن "ssh-gss.h"
#پایان_اگر
#ضمن "monitor_wrap.h"

/* Re-exec fds */
#تعریف_کن REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#تعریف_کن REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#تعریف_کن REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

خارجي حرف *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
صحيح debug_flag = 0;

/* Saved arguments to main(). */
ساكن حرف execpath[PATH_MAX];
ساكن حرف **saved_argv;
ساكن صحيح saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#تعریف_کن	MAX_LISTEN_SOCKS	16
ساكن صحيح listen_socks[MAX_LISTEN_SOCKS];
ساكن صحيح رقم_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
بنية {
	بنية sshkey	**host_کلیدها;		/* all private host keys */
	بنية sshkey	**host_pubkeys;		/* all public host keys */
	بنية sshkey	**host_certificates;	/* all public host certificates */
	صحيح		have_ssh2_کلید;
} sensitive_داده;

/* This is set to true when a signal is received. */
ساكن متطاير sig_atomic_t received_siginfo = 0;
ساكن متطاير sig_atomic_t received_sigchld = 0;
ساكن متطاير sig_atomic_t received_sighup = 0;
ساكن متطاير sig_atomic_t received_sigterm = 0;

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
بنية early_فرزند {
	صحيح pipefd;
	صحيح early;		/* Indicates child closed listener */
	حرف *id;		/* human readable connection identifier */
	pid_t pid;
	بنية xaddr addr;
	صحيح have_addr;
	صحيح وضعیت, have_وضعیت;
	بنية sshbuf *config;
	بنية sshbuf *کلیدها;
};
ساكن بنية early_فرزند *children;
ساكن صحيح children_فعال;

/* sshd_config buffer */
بنية sshbuf *cfg;
بنية sshbuf *config;	/* packed */

/* Included files from the configuration file */
بنية include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
بنية sshbuf *loginmsg;

/* Unprivileged user */
بنية passwd *privsep_pw = عدم;

ساكن حرف *listener_proctitle;

/*
 * Close all listening sockets
 */
ساكن فراغ
close_listen_socks(فراغ)
{
	صحيح i;

	لكل (i = 0; i < رقم_listen_socks; i++)
		close(listen_socks[i]);
	رقم_listen_socks = 0;
}

/* Allocate and initialise the children array */
ساكن فراغ
فرزند_alloc(فراغ)
{
	صحيح i;

	children = xcalloc(options.max_startups, حجم(*children));
	لكل (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
ساكن بنية early_فرزند *
فرزند_ثبات(صحيح pipefd, صحيح sockfd)
{
	صحيح i, lport, rport;
	حرف *laddr = عدم, *raddr = عدم;
	بنية early_فرزند *فرزند = عدم;
	بنية sockaddr_storage addr;
	socklen_t addrlen = حجم(addr);
	بنية sockaddr *sa = (بنية sockaddr *)&addr;

	لكل (i = 0; i < options.max_startups; i++) {
		إذا (children[i].pipefd != -1 ||
		    children[i].config != عدم ||
		    children[i].کلیدها != عدم ||
		    children[i].pid > 0)
			استمر;
		فرزند = &(children[i]);
		اكسر;
	}
	إذا (فرزند == عدم) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	فرزند->pipefd = pipefd;
	فرزند->early = 1;
	إذا ((فرزند->config = sshbuf_fromb(config)) == عدم)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	إذا (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_مقصد_xaddr(sa, addrlen, &فرزند->addr) == 0)
		فرزند->have_addr = 1;
	/* format peer address string for logs */
	إذا ((lport = get_local_پورت(sockfd)) == 0 ||
	    (rport = get_peer_پورت(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&فرزند->id, "connection from %s", raddr);
	} وإلا {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&فرزند->id, "connection from %s to %s", raddr, laddr);
	}
	حرر(laddr);
	حرر(raddr);
	إذا (++children_فعال > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	أرجع فرزند;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
ساكن فراغ
فرزند_پایان(بنية early_فرزند *فرزند)
{
	إذا (children_فعال == 0)
		fatal_f("internal error: children_active underflow");
	إذا (فرزند->pipefd != -1) {
		srclimit_انجامشده(فرزند->pipefd);
		close(فرزند->pipefd);
	}
	sshbuf_free(فرزند->config);
	sshbuf_free(فرزند->کلیدها);
	حرر(فرزند->id);
	memset(فرزند, '\0', حجم(*فرزند));
	فرزند->pipefd = -1;
	فرزند->pid = -1;
	children_فعال--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
ساكن فراغ
فرزند_close(بنية early_فرزند *فرزند, صحيح force_final, صحيح quiet)
{
	إذا (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	إذا (فرزند->pipefd != -1) {
		srclimit_انجامشده(فرزند->pipefd);
		close(فرزند->pipefd);
		فرزند->pipefd = -1;
	}
	إذا (فرزند->pid == -1 || force_final)
		فرزند_پایان(فرزند);
}

/* Record a child exit. Safe to call from signal handlers */
ساكن فراغ
فرزند_exit(pid_t pid, صحيح وضعیت)
{
	صحيح i;

	إذا (children == عدم || pid <= 0)
		أرجع;
	لكل (i = 0; i < options.max_startups; i++) {
		إذا (children[i].pid == pid) {
			children[i].have_وضعیت = 1;
			children[i].وضعیت = وضعیت;
			اكسر;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
ساكن فراغ
فرزند_reap(بنية early_فرزند *فرزند)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	صحيح was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ثابت حرف *فرزند_وضعیت;

	إذا (فرزند->config)
		فرزند_وضعیت = " (sending config)";
	وإلا إذا (فرزند->کلیدها)
		فرزند_وضعیت = " (sending keys)";
	وإلا إذا (فرزند->early)
		فرزند_وضعیت = " (early)";
	وإلا
		فرزند_وضعیت = "";

	/* Log exit information */
	إذا (WIFSIGNALED(فرزند->وضعیت)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		إذا ((was_crash = signal_is_crash(WTERMSIG(فرزند->وضعیت))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (دراز)فرزند->pid, فرزند->id,
		    WTERMSIG(فرزند->وضعیت), فرزند_وضعیت);
		إذا (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} وإلا إذا (!WIFEXITED(فرزند->وضعیت)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (دراز)فرزند->pid, فرزند->id, فرزند->وضعیت,
		    فرزند_وضعیت);
	} وإلا {
		/* Normal exit. We care about the status */
		بدل (WEXITSTATUS(فرزند->وضعیت)) {
		حالة 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (دراز)فرزند->pid, فرزند->id,
			    فرزند_وضعیت);
			اكسر;
		حالة EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", فرزند->id, (دراز)فرزند->pid,
			    فرزند_وضعیت);
			اكسر;
		حالة EXIT_فرزند_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (دراز)فرزند->pid, فرزند->id, فرزند_وضعیت);
			اكسر;
		حالة EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (دراز)فرزند->pid, فرزند->id, فرزند_وضعیت);
			اكسر;
		حالة EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (دراز)فرزند->pid, فرزند->id, فرزند_وضعیت);
			اكسر;
		حالة EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (دراز)فرزند->pid, فرزند->id, فرزند_وضعیت);
			اكسر;
		افتراضي:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (دراز)فرزند->pid, فرزند->id,
			    WEXITSTATUS(فرزند->وضعیت), فرزند_وضعیت);
			اكسر;
		}
	}

	إذا (فرزند->have_addr)
		srclimit_penalise(&فرزند->addr, penalty_type);

	فرزند->pid = -1;
	فرزند->have_وضعیت = 0;
	إذا (فرزند->pipefd == -1)
		فرزند_پایان(فرزند);
}

/* Reap all children that have exited; called after SIGCHLD */
ساكن فراغ
فرزند_reap_all_exited(فراغ)
{
	صحيح i;
	pid_t pid;
	صحيح وضعیت;

	إذا (children == عدم)
		أرجع;

	لكل (;;) {
		إذا ((pid = waitpid(-1, &وضعیت, WNOHANG)) == 0)
			اكسر;
		وإلا إذا (pid == -1) {
			إذا (errno == EINTR || errno == EAGAIN)
				استمر;
			إذا (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			اكسر;
		}
		فرزند_exit(pid, وضعیت);
	}

	لكل (i = 0; i < options.max_startups; i++) {
		إذا (!children[i].have_وضعیت)
			استمر;
		فرزند_reap(&(children[i]));
	}
}

ساكن فراغ
close_startup_pipes(فراغ)
{
	صحيح i;

	إذا (children == عدم)
		أرجع;
	لكل (i = 0; i < options.max_startups; i++) {
		إذا (children[i].pipefd != -1)
			فرزند_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
ساكن فراغ
show_info(فراغ)
{
	صحيح i;
	ثابت حرف *فرزند_وضعیت;

	/* XXX print listening sockets here too */
	إذا (children == عدم)
		أرجع;
	logit("%d active startups", children_فعال);
	لكل (i = 0; i < options.max_startups; i++) {
		إذا (children[i].pipefd == -1 && children[i].pid <= 0)
			استمر;
		إذا (children[i].config)
			فرزند_وضعیت = " (sending config)";
		وإلا إذا (children[i].کلیدها)
			فرزند_وضعیت = " (sending keys)";
		وإلا إذا (children[i].early)
			فرزند_وضعیت = " (early)";
		وإلا
			فرزند_وضعیت = "";
		logit("child %d: fd=%d pid=%ld %s%s", i, children[i].pipefd,
		    (دراز)children[i].pid, children[i].id, فرزند_وضعیت);
	}
	srclimit_penalty_info();
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

ساكن فراغ
sighup_handler(صحيح sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
ساكن فراغ
sighup_restart(فراغ)
{
	logit("Received SIGHUP; restarting.");
	إذا (options.pid_file != عدم)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(execpath, saved_argv);
	logit("RESTART FAILED: execpath='%.100s', error: %.100s.", execpath,
	    strerror(errno));
	خروج(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
ساكن فراغ
sigterm_handler(صحيح sig)
{
	received_sigterm = sig;
}

#اگر_تعریف_شده SIGINFO
ساكن فراغ
siginfo_handler(صحيح sig)
{
	received_siginfo = 1;
}
#پایان_اگر

ساكن فراغ
main_sigchld_handler(صحيح sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
ساكن صحيح
should_drop_connection(صحيح startups)
{
	صحيح p, r;

	إذا (startups < options.max_startups_begin)
		أرجع 0;
	إذا (startups >= options.max_startups)
		أرجع 1;
	إذا (options.max_startups_نرخ == 100)
		أرجع 1;

	p  = 100 - options.max_startups_نرخ;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_نرخ;
	r = arc4random_یکنواخت(100);

	debug_f("p %d, r %d", p, r);
	أرجع (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
ساكن صحيح
drop_connection(صحيح sock, صحيح startups, صحيح notify_pipe)
{
	ساكن بنية log_ratelimit_ctx ratelimit_maxstartups;
	ساكن بنية log_ratelimit_ctx ratelimit_penalty;
	ساكن صحيح init_انجامشده;
	حرف *laddr, *raddr;
	ثابت حرف *reason = عدم, *subreason = عدم;
	ثابت حرف پیام[] = "Not allowed at this time\r\n";
	بنية log_ratelimit_ctx *rl = عدم;
	صحيح ratelimited;
	u_int ndropped;

	إذا (!init_انجامشده) {
		init_انجامشده = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	إذا (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} وإلا {
		/* MaxStartups */
		إذا (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			أرجع 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(عدم), عدم, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_پورت(sock),
	    laddr, get_local_پورت(sock),
	    subreason != عدم ? subreason : reason);
	حرر(laddr);
	حرر(raddr);
	إذا (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(فراغ)اكتب(sock, پیام, حجم(پیام) - 1);
	أرجع 1;
}

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_نسخه);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	خروج(1);
}

ساكن بنية sshbuf *
pack_hostkeys(فراغ)
{
	بنية sshbuf *m = عدم, *keybuf = عدم, *hostkeys = عدم;
	صحيح r;
	u_int i;
	اندازه_t len;

	إذا ((m = sshbuf_new()) == عدم ||
	    (keybuf = sshbuf_new()) == عدم ||
	    (hostkeys = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	لكل (i = 0; i < options.رقم_host_کلید_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		إذا (sensitive_داده.host_کلیدها[i] != عدم &&
		    (r = sshkey_خصوصی_serialize(sensitive_داده.host_کلیدها[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		إذا ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		إذا (sensitive_داده.host_pubkeys[i] != عدم) {
			إذا ((r = sshkey_puts(sensitive_داده.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} وإلا {
			إذا ((r = sshbuf_put_string(hostkeys, عدم, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		إذا (sensitive_داده.host_certificates[i] != عدم) {
			إذا ((r = sshkey_puts(
			    sensitive_داده.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} وإلا {
			إذا ((r = sshbuf_put_string(hostkeys, عدم, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	إذا ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	إذا ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	أرجع m;
}

ساكن بنية sshbuf *
pack_config(بنية sshbuf *conf)
{
	بنية sshbuf *m = عدم, *inc = عدم;
	بنية include_قلم *قلم = عدم;
	اندازه_t len;
	صحيح r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	إذا ((m = sshbuf_new()) == عدم ||
	    (inc = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(قلم, &includes, مدخل) {
		إذا ((r = sshbuf_put_cstring(inc, قلم->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, قلم->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, قلم->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	إذا ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	إذا ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	أرجع m;
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
ساكن فراغ
send_rexec_state(صحيح fd)
{
	بنية sshbuf *کلیدها;
	u_int mlen;
	pid_t pid;

	إذا ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	إذا (pid != 0)
		أرجع;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	إذا (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	کلیدها = pack_hostkeys();
	mlen = sshbuf_len(کلیدها);
	إذا (atomicio(vwrite, fd, sshbuf_mutable_ptr(کلیدها), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(کلیدها);
	debug3_f("done");
	خروج(0);
}

/*
 * Listen for TCP connections
 */
ساكن فراغ
listen_on_addrs(بنية listenaddr *la)
{
	صحيح ret, listen_sock;
	بنية addrinfo *ai;
	حرف ntop[NI_MAXHOST], strport[NI_MAXSERV];

	لكل (ai = la->addrs; ai; ai = ai->ai_next) {
		إذا (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			استمر;
		إذا (رقم_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		إذا ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, حجم(ntop), strport, حجم(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			استمر;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		إذا (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			استمر;
		}
		إذا (مجموعه_nonblock(listen_sock) == -1) {
			close(listen_sock);
			استمر;
		}
		إذا (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			استمر;
		}
		/* Socket options */
		مجموعه_reuseaddr(listen_sock);
		إذا (la->rdomain != عدم &&
		    مجموعه_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			استمر;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		إذا (ai->ai_family == AF_INET6)
			sock_مجموعه_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		إذا (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			استمر;
		}
		listen_socks[رقم_listen_socks] = listen_sock;
		رقم_listen_socks++;

		/* Start listening on the port. */
		إذا (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == عدم ? "" : " rdomain ",
		    la->rdomain == عدم ? "" : la->rdomain);
	}
}

ساكن فراغ
server_listen(فراغ)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.در_هر_منبع_max_startups,
	    options.در_هر_منبع_masklen_ipv4,
	    options.در_هر_منبع_masklen_ipv6,
	    &options.در_هر_منبع_penalty,
	    options.در_هر_منبع_penalty_exempt);

	لكل (i = 0; i < options.رقم_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		حرر(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    حجم(options.listen_addrs[i]));
	}
	حرر(options.listen_addrs);
	options.listen_addrs = عدم;
	options.رقم_listen_addrs = 0;

	إذا (!رقم_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
ساكن فراغ
server_accept_loop(صحيح *sock_درون, صحيح *sock_بیرون, صحيح *newsock, صحيح *config_s,
    صحيح log_stderr)
{
	بنية pollfd *pfd = عدم;
	صحيح i, ret, npfd, r;
	صحيح oactive = -1, listening = 0, lameduck = 0;
	صحيح *startup_pollfd;
	ssize_t len;
	ثابت u_char *ptr;
	حرف c = 0;
	بنية sockaddr_storage from;
	بنية early_فرزند *فرزند;
	بنية sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	فرزند_alloc();
	startup_pollfd = xcalloc(options.max_startups, حجم(صحيح));

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm/hup/chld/info, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
#اگر_تعریف_شده SIGINFO
	sigaddset(&nsigset, SIGINFO);
#پایان_اگر
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(رقم_listen_socks + options.max_startups,
	    حجم(بنية pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	لكل (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		إذا (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (صحيح) received_sigterm);
			close_listen_socks();
			إذا (options.pid_file != عدم)
				unlink(options.pid_file);
			خروج(received_sigterm == SIGTERM ? 0 : 255);
		}
		إذا (received_sigchld) {
			فرزند_reap_all_exited();
			received_sigchld = 0;
		}
		إذا (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		إذا (oactive != children_فعال) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_فعال,
			    options.max_startups_begin, options.max_startups);
			oactive = children_فعال;
		}
		إذا (received_sighup) {
			إذا (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			إذا (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, عدم);
				sighup_restart();
			}
		}

		لكل (i = 0; i < رقم_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = رقم_listen_socks;
		لكل (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			إذا (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				إذا (children[i].config != عدم ||
				    children[i].کلیدها != عدم)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, عدم, &osigset);
		إذا (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			إذا (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, عدم);
		إذا (ret == -1)
			استمر;

		لكل (i = 0; i < options.max_startups; i++) {
			إذا (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				استمر;
			إذا (children[i].config)
				buf = children[i].config;
			وإلا إذا (children[i].کلیدها)
				buf = children[i].کلیدها;
			وإلا {
				error_f("no buffer to send");
				استمر;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = اكتب(children[i].pipefd, ptr, len);
			إذا (ret == -1 && (errno == EINTR || errno == EAGAIN))
				استمر;
			إذا (ret <= 0) {
				إذا (children[i].early)
					listening--;
				فرزند_close(&(children[i]), 0, 0);
				استمر;
			}
			إذا (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				إذا (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = عدم;
					children[i].کلیدها = pack_hostkeys();
				} وإلا إذا (children[i].کلیدها == buf) {
					/* sent both config and keys */
					children[i].کلیدها = عدم;
				} وإلا {
					fatal("config buf not set");
				}

			} وإلا {
				إذا ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		لكل (i = 0; i < options.max_startups; i++) {
			إذا (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				استمر;
			بدل (اقرأ(children[i].pipefd, &c, حجم(c))) {
			حالة -1:
				إذا (errno == EINTR || errno == EAGAIN)
					استمر;
				إذا (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			حالة 0:
				/* child closed pipe */
				إذا (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (دراز)children[i].pid, children[i].id);
				فرزند_close(&(children[i]), 0, 0);
				اكسر;
			حالة 1:
				إذا (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					اذهب problem_فرزند;
				}
				إذا (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (دراز)children[i].pid,
					    children[i].id);
				} وإلا إذا (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (دراز)children[i].pid,
					    children[i].id);
					فرزند_close(&(children[i]), 1, 0);
				} وإلا {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (صحيح)c, (دراز)children[i].pid,
					    children[i].id, children[i].early);
 problem_فرزند:
					إذا (children[i].early)
						listening--;
					إذا (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					فرزند_close(&(children[i]), 0, 0);
				}
				اكسر;
			}
		}
		لكل (i = 0; i < رقم_listen_socks; i++) {
			إذا (!(pfd[i].revents & POLLIN))
				استمر;
			fromlen = حجم(from);
			*newsock = accept(listen_socks[i],
			    (بنية sockaddr *)&from, &fromlen);
			إذا (*newsock == -1) {
				إذا (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				إذا (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				استمر;
			}
			إذا (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				استمر;
			}
			إذا (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				استمر;
			}
			إذا (drop_connection(*newsock,
			    children_فعال, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				استمر;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			إذا (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_درون = *newsock;
				*sock_بیرون = *newsock;
				send_rexec_state(config_s[0]);
				close(config_s[0]);
				حرر(pfd);
				حرر(startup_pollfd);
				أرجع;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			platform_pre_fork();
			مجموعه_nonblock(config_s[0]);
			listening++;
			فرزند = فرزند_ثبات(config_s[0], *newsock);
			إذا ((فرزند->pid = fork()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				platform_post_fork_فرزند();
				close_startup_pipes();
				close_listen_socks();
				*sock_درون = *newsock;
				*sock_بیرون = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				close(config_s[0]);
				حرر(pfd);
				حرر(startup_pollfd);
				أرجع;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_والد(فرزند->pid);
			إذا (فرزند->pid == -1)
				error("fork: %.100s", strerror(errno));
			وإلا
				debug("Forked child %ld.", (دراز)فرزند->pid);

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

ساكن فراغ
accumulate_host_timing_secret(بنية sshbuf *server_cfg,
    بنية sshkey *کلید)
{
	ساكن بنية ssh_digest_ctx *ctx;
	u_char *hash;
	اندازه_t len;
	بنية sshbuf *buf;
	صحيح r;

	إذا (ctx == عدم && (ctx = ssh_digest_شروع(SSH_DIGEST_SHA512)) == عدم)
		fatal_f("ssh_digest_start");
	إذا (کلید == عدم) { /* finalize */
		/* add server config in case we are using agent for host keys */
		إذا (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_بایتها(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		إذا (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = عدم;
		أرجع;
	}
	إذا ((buf = sshbuf_new()) == عدم)
		fatal_f("could not allocate buffer");
	إذا ((r = sshkey_خصوصی_serialize(کلید, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(کلید));
	إذا (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

ساكن حرف *
prepare_proctitle(صحيح ac, حرف **av)
{
	حرف *ret = عدم;
	صحيح i;

	لكل (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	أرجع ret;
}

/* Disconnect from the controlling tty. */
ساكن فراغ
disconnect_controlling_tty(فراغ)
{
#اگر_تعریف_شده TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	صحيح fd;

	إذا ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(فراغ) ioctl(fd, TIOCNOTTY, عدم);
		close(fd);
	}
#پایان_اگر /* TIOCNOTTY */
}

ساكن فراغ
print_config(بنية connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_تطابق_config(&options, &includes, connection_info);
	dump_config(&options);
	خروج(0);
}

/*
 * Main program for the daemon.
 */
صحيح
اصلی(صحيح ac, حرف **av)
{
	خارجي حرف *optarg;
	خارجي صحيح optind;
	صحيح log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	حرف *config_file_name = مسیر_SERVER_CONFIG_FILE;
	صحيح r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	صحيح sock_درون = -1, sock_بیرون = -1, newsock = -1, rexec_argc = 0;
	صحيح devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	صحيح need_chroot = 1;
	حرف *آرگومانها, *fp, *سطر, *logfile = عدم, **rexec_argv = عدم;
	بنية stat sb;
	u_int i, j;
	نما_t new_umask;
	بنية sshkey *کلید;
	بنية sshkey *pubkey;
	بنية connection_info connection_info;
	بنية utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, حجم(connection_info));
#اگر_تعریف_شده HAVE_SECUREWARE
	(فراغ)مجموعه_auth_parameters(ac, av);
#پایان_اگر
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, عدم);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, حجم(*saved_argv));
	لكل (i = 0; (صحيح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = عدم;

#اگر_تعریف_نشده HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#پایان_اگر

	إذا (geteuid() == 0 && setgroups(0, عدم) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	آرگومانها = argv_assemble(ac, av); /* logged later */
	طالما ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		بدل (opt) {
		حالة '4':
			options.آدرس_family = AF_INET;
			اكسر;
		حالة '6':
			options.آدرس_family = AF_INET6;
			اكسر;
		حالة 'f':
			config_file_name = optarg;
			اكسر;
		حالة 'c':
			servconf_جمع_کن_hostcert("[command-line]", 0,
			    &options, optarg);
			اكسر;
		حالة 'd':
			إذا (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} وإلا إذا (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			اكسر;
		حالة 'D':
			no_daemon_flag = 1;
			اكسر;
		حالة 'G':
			do_dump_cfg = 1;
			اكسر;
		حالة 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		حالة 'e':
			log_stderr = 1;
			اكسر;
		حالة 'i':
			inetd_flag = 1;
			اكسر;
		حالة 'r':
			logit("-r option is deprecated");
			اكسر;
		حالة 'R':
			fatal("-R not supported here");
			اكسر;
		حالة 'Q':
			/* ignored */
			اكسر;
		حالة 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			اكسر;
		حالة 'b':
			/* protocol 1, ignored */
			اكسر;
		حالة 'p':
			options.ports_from_cmdline = 1;
			إذا (options.رقم_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				خروج(1);
			}
			options.ports[options.رقم_ports++] = a2port(optarg);
			إذا (options.ports[options.رقم_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				خروج(1);
			}
			اكسر;
		حالة 'g':
			إذا ((options.login_grace_زمان = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				خروج(1);
			}
			اكسر;
		حالة 'k':
			/* protocol 1, ignored */
			اكسر;
		حالة 'h':
			servconf_جمع_کن_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			اكسر;
		حالة 't':
			test_flag = 1;
			اكسر;
		حالة 'T':
			test_flag = 2;
			اكسر;
		حالة 'C':
			إذا (parse_server_تطابق_testspec(&connection_info,
			    optarg) == -1)
				خروج(1);
			have_connection_info = 1;
			اكسر;
		حالة 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, عدم);
			إذا (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				خروج(1);
			}
			اكسر;
		حالة 'o':
			سطر = xstrdup(optarg);
			إذا (process_server_config_سطر(&options, سطر,
			    "command-line", 0, عدم, عدم, &includes) != 0)
				خروج(1);
			حرر(سطر);
			اكسر;
		حالة 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_نسخه);
			خروج(0);
		افتراضي:
			usage();
			اكسر;
		}
	}

	إذا (getexecpath(execpath, حجم execpath) != 0) {
		إذا (strlcpy(execpath, av[0], حجم execpath) >=
		    حجم execpath) {
			fprintf(stderr, "execution path is too long\n");
			خروج(1);
		}
	}
	إذا (!test_flag && !inetd_flag && !do_dump_cfg && !مسیر_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	إذا ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	طالما (devnull < REEXEC_MIN_FREE_FD) {
		إذا ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	دانه_rng();

	/* If requested, redirect the logs to the specified logfile. */
	إذا (logfile != عدم) {
		حرف *cp, pid_s[32];

		snprintf(pid_s, حجم(pid_s), "%ld", (بیعلامت دراز)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (حرف *)عدم);
		log_redirect_stderr_مقصد(cp);
		حرر(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_مجموعه ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_مجموعه ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/*
	 * Unset KRB5CCNAME, otherwise the user's session may inherit it from
	 * root's environment
	 */
	إذا (getenv("KRB5CCNAME") != عدم)
		(فراغ) unsetenv("KRB5CCNAME");

	sensitive_داده.have_ssh2_کلید = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	إذا (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_نسخه, SSH_OPENSSL_نسخه);
	إذا (uname(&utsname) != 0) {
		memset(&utsname, 0, حجم(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", حجم(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.نسخه, utsname.machine);
	debug3("Started with: %s", آرگومانها);
	حرر(آرگومانها);

	/* Fetch our configuration */
	إذا ((cfg = sshbuf_new()) == عدم)
		fatal("sshbuf_new config failed");
	إذا (strcasecmp(config_file_name, "none") != 0)
		بارگیری_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, عدم, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	إذا (options.authorized_کلیدها_command_user == عدم &&
	    (options.authorized_کلیدها_command != عدم &&
	    strcasecmp(options.authorized_کلیدها_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	إذا (options.authorized_principals_command_user == عدم &&
	    (options.authorized_principals_command != عدم &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	إذا (options.رقم_auth_methods != 0) {
		لكل (i = 0; i < options.رقم_auth_methods; i++) {
			إذا (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				اكسر;
		}
		إذا (i >= options.رقم_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	إذا (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		خروج(1);
	}

	إذا (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_داده.host_کلیدها = xcalloc(options.رقم_host_کلید_files,
	    حجم(بنية sshkey *));
	sensitive_داده.host_pubkeys = xcalloc(options.رقم_host_کلید_files,
	    حجم(بنية sshkey *));

	إذا (options.host_کلید_agent) {
		إذا (strcmp(options.host_کلید_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_کلید_agent, 1);
		إذا ((r = ssh_get_authentication_socket(عدم)) == 0)
			have_agent = 1;
		وإلا
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_کلید_agent);
	}

	لكل (i = 0; i < options.رقم_host_کلید_files; i++) {
		صحيح ll = options.host_کلید_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		إذا (options.host_کلید_files[i] == عدم)
			استمر;
		إذا ((r = sshkey_بارگیری_خصوصی(options.host_کلید_files[i], "",
		    &کلید, عدم)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_کلید_files[i]);
		إذا (sshkey_is_sk(کلید) &&
		    کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_کلید_files[i]);
			کلید->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		إذا (r == 0 && کلید != عدم &&
		    (r = sshkey_shield_خصوصی(کلید)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_کلید_files[i]);
			sshkey_free(کلید);
			کلید = عدم;
		}
		إذا ((r = sshkey_بارگیری_عمومی(options.host_کلید_files[i],
		    &pubkey, عدم)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_کلید_files[i]);
		إذا (pubkey != عدم && کلید != عدم) {
			إذا (!sshkey_equal(pubkey, کلید)) {
				error("Public key for %s does not match "
				    "private key", options.host_کلید_files[i]);
				sshkey_free(pubkey);
				pubkey = عدم;
			}
		}
		إذا (pubkey == عدم && کلید != عدم) {
			إذا ((r = sshkey_from_خصوصی(کلید, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_کلید_files[i]);
		}
		إذا (pubkey != عدم && (r = sshkey_check_rsa_درازی(pubkey,
		    options.required_rsa_اندازه)) != 0) {
			error_fr(r, "Host key %s", options.host_کلید_files[i]);
			sshkey_free(pubkey);
			sshkey_free(کلید);
			استمر;
		}
		sensitive_داده.host_کلیدها[i] = کلید;
		sensitive_داده.host_pubkeys[i] = pubkey;

		إذا (کلید == عدم && pubkey != عدم && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_کلید_files[i]);
			keytype = pubkey->type;
		} وإلا إذا (کلید != عدم) {
			keytype = کلید->type;
			accumulate_host_timing_secret(cfg, کلید);
		} وإلا {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_کلید_files[i]);
			sensitive_داده.host_کلیدها[i] = عدم;
			sensitive_داده.host_pubkeys[i] = عدم;
			استمر;
		}

		بدل (keytype) {
		حالة کلید_RSA:
		حالة کلید_ECDSA:
		حالة کلید_ED25519:
		حالة کلید_MLDSA44_ED25519:
		حالة کلید_ECDSA_SK:
		حالة کلید_ED25519_SK:
			إذا (have_agent || کلید != عدم)
				sensitive_داده.have_ssh2_کلید = 1;
			اكسر;
		}
		إذا ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == عدم)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    کلید ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		حرر(fp);
	}
	accumulate_host_timing_secret(cfg, عدم);
	إذا (!sensitive_داده.have_ssh2_کلید) {
		logit("sshd: no hostkeys available -- exiting.");
		خروج(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_داده.host_certificates = xcalloc(options.رقم_host_کلید_files,
	    حجم(بنية sshkey *));
	لكل (i = 0; i < options.رقم_host_کلید_files; i++)
		sensitive_داده.host_certificates[i] = عدم;

	لكل (i = 0; i < options.رقم_host_cert_files; i++) {
		إذا (options.host_cert_files[i] == عدم)
			استمر;
		إذا ((r = sshkey_بارگیری_عمومی(options.host_cert_files[i],
		    &کلید, عدم)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			استمر;
		}
		إذا (!sshkey_is_cert(کلید)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(کلید);
			استمر;
		}
		/* Find matching private key */
		لكل (j = 0; j < options.رقم_host_کلید_files; j++) {
			إذا (sshkey_equal_عمومی(کلید,
			    sensitive_داده.host_pubkeys[j])) {
				sensitive_داده.host_certificates[j] = کلید;
				اكسر;
			}
		}
		إذا (j >= options.رقم_host_کلید_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(کلید);
			استمر;
		}
		sensitive_داده.host_certificates[j] = کلید;
		debug("host certificate: #%u type %d %s", j, کلید->type,
		    sshkey_type(کلید));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	إذا ((getpwnam(SSH_PRIVSEP_USER)) == عدم && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	إذا (need_chroot) {
		إذا ((stat(مسیر_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    مسیر_PRIVSEP_CHROOT_DIR);
#اگر_تعریف_شده HAVE_CYGWIN
		إذا (check_ntsec(مسیر_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#وإلا
		إذا (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#پایان_اگر
			fatal("%s must be owned by root and not group or "
			    "world-writable.", مسیر_PRIVSEP_CHROOT_DIR);
	}

	إذا (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	إذا (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	إذا (test_flag)
		خروج(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	إذا (setgroups(0, عدم) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	إذا (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, حجم(حرف *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_مسیر;
	لكل (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = عدم;
	إذا (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	إذا (stat(options.sshd_auth_مسیر, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_مسیر);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(فراغ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	إذا (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	لكل (i = 0; i < options.رقم_log_verbose; i++)
		log_verbose_جمع_کن(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	إذا (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		إذا (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	إذا (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	إذا (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} وإلا {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
#اگر_تعریف_شده SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#پایان_اگر

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		إذا (options.pid_file != عدم && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			إذا (f == عدم) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} وإلا {
				fprintf(f, "%ld\n", (دراز) getpid());
				fclose(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_درون, &sock_بیرون,
		    &newsock, config_s, log_stderr);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	إذا (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_درون, sock_بیرون, newsock, config_s[0], config_s[1]);
	إذا (!inetd_flag) {
		إذا (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		إذا (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		إذا (newsock > STDOUT_FILENO)
			close(newsock);
	}
	إذا (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		إذا (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_مقصد(عدم);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
فراغ
cleanup_exit(صحيح i)
{
	_exit(i);
}
