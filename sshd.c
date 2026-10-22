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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#شامل <sys/socket.h>
#شامل <sys/stat.h>
#شامل <sys/time.h>
#شامل <sys/queue.h>
#شامل <sys/wait.h>
#شامل <sys/utsname.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <grp.h>
#شامل <poll.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <time.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <limits.h>

#اگر_تعریف_شدہ HAVE_SECUREWARE
#شامل <sys/security.h>
#شامل <prot.h>
#اگر_ختم

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "sshpty.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "compat.h"
#شامل "digest.h"
#شامل "sshkey.h"
#شامل "authfile.h"
#شامل "pathnames.h"
#شامل "canohost.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "authfd.h"
#شامل "msg.h"
#شامل "version.h"
#شامل "ssherr.h"
#شامل "sk-api.h"
#شامل "addr.h"
#شامل "srclimit.h"
#شامل "atomicio.h"
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "monitor_wrap.h"

/* Re-exec fds */
#تعریف_کرو REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#تعریف_کرو REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#تعریف_کرو REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

خارجی حرف *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
صحیح debug_flag = 0;

/* Saved arguments to main(). */
ساکن حرف execpath[PATH_MAX];
ساکن حرف **saved_argv;
ساکن صحیح saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#تعریف_کرو	MAX_LISTEN_SOCKS	16
ساکن صحیح listen_socks[MAX_LISTEN_SOCKS];
ساکن صحیح عدد_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ساخت {
	ساخت sshkey	**host_کلیدیں;		/* all private host keys */
	ساخت sshkey	**host_pubkeys;		/* all public host keys */
	ساخت sshkey	**host_certificates;	/* all public host certificates */
	صحیح		have_ssh2_کلید;
} sensitive_ڈیٹا;

/* This is set to true when a signal is received. */
ساکن متلون sig_atomic_t received_siginfo = 0;
ساکن متلون sig_atomic_t received_sigchld = 0;
ساکن متلون sig_atomic_t received_sighup = 0;
ساکن متلون sig_atomic_t received_sigterm = 0;

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
ساخت early_بچہ {
	صحیح pipefd;
	صحیح early;		/* Indicates child closed listener */
	حرف *id;		/* human readable connection identifier */
	pid_t pid;
	ساخت xaddr addr;
	صحیح have_addr;
	صحیح حالت_2, have_حالت;
	ساخت sshbuf *config;
	ساخت sshbuf *کلیدیں;
};
ساکن ساخت early_بچہ *children;
ساکن صحیح children_فعال;

/* sshd_config buffer */
ساخت sshbuf *cfg;
ساخت sshbuf *config;	/* packed */

/* Included files from the configuration file */
ساخت include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ساخت sshbuf *loginmsg;

/* Unprivileged user */
ساخت passwd *privsep_pw = تہی;

ساکن حرف *listener_proctitle;

/*
 * Close all listening sockets
 */
ساکن خالی
close_listen_socks(خالی)
{
	صحیح i;

	برائے (i = 0; i < عدد_listen_socks; i++)
		close(listen_socks[i]);
	عدد_listen_socks = 0;
}

/* Allocate and initialise the children array */
ساکن خالی
بچہ_alloc(خالی)
{
	صحیح i;

	children = xcalloc(options.max_startups, حجم(*children));
	برائے (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
ساکن ساخت early_بچہ *
بچہ_رجسٹر(صحیح pipefd, صحیح sockfd)
{
	صحیح i, lport, rport;
	حرف *laddr = تہی, *raddr = تہی;
	ساخت early_بچہ *بچہ = تہی;
	ساخت sockaddr_storage addr;
	socklen_t addrlen = حجم(addr);
	ساخت sockaddr *sa = (ساخت sockaddr *)&addr;

	برائے (i = 0; i < options.max_startups; i++) {
		اگر (children[i].pipefd != -1 ||
		    children[i].config != تہی ||
		    children[i].کلیدیں != تہی ||
		    children[i].pid > 0)
			جاری;
		بچہ = &(children[i]);
		توڑو;
	}
	اگر (بچہ == تہی) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	بچہ->pipefd = pipefd;
	بچہ->early = 1;
	اگر ((بچہ->config = sshbuf_fromb(config)) == تہی)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	اگر (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_مقصد_xaddr(sa, addrlen, &بچہ->addr) == 0)
		بچہ->have_addr = 1;
	/* format peer address string for logs */
	اگر ((lport = get_local_پورٹ(sockfd)) == 0 ||
	    (rport = get_peer_پورٹ(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&بچہ->id, "connection from %s", raddr);
	} ورنہ {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&بچہ->id, "connection from %s to %s", raddr, laddr);
	}
	آزاد(laddr);
	آزاد(raddr);
	اگر (++children_فعال > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	واپس بچہ;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
ساکن خالی
بچہ_اختتام(ساخت early_بچہ *بچہ)
{
	اگر (children_فعال == 0)
		fatal_f("internal error: children_active underflow");
	اگر (بچہ->pipefd != -1) {
		srclimit_مکمل(بچہ->pipefd);
		close(بچہ->pipefd);
	}
	sshbuf_free(بچہ->config);
	sshbuf_free(بچہ->کلیدیں);
	آزاد(بچہ->id);
	memset(بچہ, '\0', حجم(*بچہ));
	بچہ->pipefd = -1;
	بچہ->pid = -1;
	children_فعال--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
ساکن خالی
بچہ_close(ساخت early_بچہ *بچہ, صحیح force_final, صحیح quiet)
{
	اگر (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	اگر (بچہ->pipefd != -1) {
		srclimit_مکمل(بچہ->pipefd);
		close(بچہ->pipefd);
		بچہ->pipefd = -1;
	}
	اگر (بچہ->pid == -1 || force_final)
		بچہ_اختتام(بچہ);
}

/* Record a child exit. Safe to call from signal handlers */
ساکن خالی
بچہ_exit(pid_t pid, صحیح حالت_2)
{
	صحیح i;

	اگر (children == تہی || pid <= 0)
		واپس;
	برائے (i = 0; i < options.max_startups; i++) {
		اگر (children[i].pid == pid) {
			children[i].have_حالت = 1;
			children[i].حالت_2 = حالت_2;
			توڑو;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
ساکن خالی
بچہ_reap(ساخت early_بچہ *بچہ)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	صحیح was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ثابت حرف *بچہ_حالت;

	اگر (بچہ->config)
		بچہ_حالت = " (sending config)";
	ورنہ اگر (بچہ->کلیدیں)
		بچہ_حالت = " (sending keys)";
	ورنہ اگر (بچہ->early)
		بچہ_حالت = " (early)";
	ورنہ
		بچہ_حالت = "";

	/* Log exit information */
	اگر (WIFSIGNALED(بچہ->حالت_2)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		اگر ((was_crash = signal_is_crash(WTERMSIG(بچہ->حالت_2))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (طویل)بچہ->pid, بچہ->id,
		    WTERMSIG(بچہ->حالت_2), بچہ_حالت);
		اگر (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} ورنہ اگر (!WIFEXITED(بچہ->حالت_2)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (طویل)بچہ->pid, بچہ->id, بچہ->حالت_2,
		    بچہ_حالت);
	} ورنہ {
		/* Normal exit. We care about the status */
		انتخاب (WEXITSTATUS(بچہ->حالت_2)) {
		حالت 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (طویل)بچہ->pid, بچہ->id,
			    بچہ_حالت);
			توڑو;
		حالت EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", بچہ->id, (طویل)بچہ->pid,
			    بچہ_حالت);
			توڑو;
		حالت EXIT_بچہ_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (طویل)بچہ->pid, بچہ->id, بچہ_حالت);
			توڑو;
		حالت EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (طویل)بچہ->pid, بچہ->id, بچہ_حالت);
			توڑو;
		حالت EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (طویل)بچہ->pid, بچہ->id, بچہ_حالت);
			توڑو;
		حالت EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (طویل)بچہ->pid, بچہ->id, بچہ_حالت);
			توڑو;
		طےشدہ:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (طویل)بچہ->pid, بچہ->id,
			    WEXITSTATUS(بچہ->حالت_2), بچہ_حالت);
			توڑو;
		}
	}

	اگر (بچہ->have_addr)
		srclimit_penalise(&بچہ->addr, penalty_type);

	بچہ->pid = -1;
	بچہ->have_حالت = 0;
	اگر (بچہ->pipefd == -1)
		بچہ_اختتام(بچہ);
}

/* Reap all children that have exited; called after SIGCHLD */
ساکن خالی
بچہ_reap_all_exited(خالی)
{
	صحیح i;
	pid_t pid;
	صحیح حالت_2;

	اگر (children == تہی)
		واپس;

	برائے (;;) {
		اگر ((pid = waitpid(-1, &حالت_2, WNOHANG)) == 0)
			توڑو;
		ورنہ اگر (pid == -1) {
			اگر (errno == EINTR || errno == EAGAIN)
				جاری;
			اگر (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			توڑو;
		}
		بچہ_exit(pid, حالت_2);
	}

	برائے (i = 0; i < options.max_startups; i++) {
		اگر (!children[i].have_حالت)
			جاری;
		بچہ_reap(&(children[i]));
	}
}

ساکن خالی
close_startup_pipes(خالی)
{
	صحیح i;

	اگر (children == تہی)
		واپس;
	برائے (i = 0; i < options.max_startups; i++) {
		اگر (children[i].pipefd != -1)
			بچہ_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
ساکن خالی
show_info(خالی)
{
	صحیح i;
	ثابت حرف *بچہ_حالت;

	/* XXX print listening sockets here too */
	اگر (children == تہی)
		واپس;
	logit("%d active startups", children_فعال);
	برائے (i = 0; i < options.max_startups; i++) {
		اگر (children[i].pipefd == -1 && children[i].pid <= 0)
			جاری;
		اگر (children[i].config)
			بچہ_حالت = " (sending config)";
		ورنہ اگر (children[i].کلیدیں)
			بچہ_حالت = " (sending keys)";
		ورنہ اگر (children[i].early)
			بچہ_حالت = " (early)";
		ورنہ
			بچہ_حالت = "";
		logit("child %d: fd=%d pid=%ld %s%s", i, children[i].pipefd,
		    (طویل)children[i].pid, children[i].id, بچہ_حالت);
	}
	srclimit_penalty_info();
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

ساکن خالی
sighup_handler(صحیح sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
ساکن خالی
sighup_restart(خالی)
{
	logit("Received SIGHUP; restarting.");
	اگر (options.pid_file != تہی)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(execpath, saved_argv);
	logit("RESTART FAILED: execpath='%.100s', error: %.100s.", execpath,
	    strerror(errno));
	باہر_نکلو(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
ساکن خالی
sigterm_handler(صحیح sig)
{
	received_sigterm = sig;
}

#اگر_تعریف_شدہ SIGINFO
ساکن خالی
siginfo_handler(صحیح sig)
{
	received_siginfo = 1;
}
#اگر_ختم

ساکن خالی
main_sigchld_handler(صحیح sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
ساکن صحیح
should_drop_connection(صحیح startups)
{
	صحیح p, r;

	اگر (startups < options.max_startups_begin)
		واپس 0;
	اگر (startups >= options.max_startups)
		واپس 1;
	اگر (options.max_startups_شرح == 100)
		واپس 1;

	p  = 100 - options.max_startups_شرح;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_شرح;
	r = arc4random_یکساں(100);

	debug_f("p %d, r %d", p, r);
	واپس (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
ساکن صحیح
drop_connection(صحیح sock, صحیح startups, صحیح notify_pipe)
{
	ساکن ساخت log_ratelimit_ctx ratelimit_maxstartups;
	ساکن ساخت log_ratelimit_ctx ratelimit_penalty;
	ساکن صحیح init_مکمل;
	حرف *laddr, *raddr;
	ثابت حرف *reason = تہی, *subreason = تہی;
	ثابت حرف پیغام[] = "Not allowed at this time\r\n";
	ساخت log_ratelimit_ctx *rl = تہی;
	صحیح ratelimited;
	u_int ndropped;

	اگر (!init_مکمل) {
		init_مکمل = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	اگر (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} ورنہ {
		/* MaxStartups */
		اگر (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			واپس 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(تہی), تہی, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_پورٹ(sock),
	    laddr, get_local_پورٹ(sock),
	    subreason != تہی ? subreason : reason);
	آزاد(laddr);
	آزاد(raddr);
	اگر (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(خالی)اكتب(sock, پیغام, حجم(پیغام) - 1);
	واپس 1;
}

ساکن خالی
usage(خالی)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_نسخہ);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	باہر_نکلو(1);
}

ساکن ساخت sshbuf *
pack_hostkeys(خالی)
{
	ساخت sshbuf *m = تہی, *keybuf = تہی, *hostkeys = تہی;
	صحیح r;
	u_int i;
	سائز_t len;

	اگر ((m = sshbuf_new()) == تہی ||
	    (keybuf = sshbuf_new()) == تہی ||
	    (hostkeys = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		اگر (sensitive_ڈیٹا.host_کلیدیں[i] != تہی &&
		    (r = sshkey_نجی_serialize(sensitive_ڈیٹا.host_کلیدیں[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		اگر ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		اگر (sensitive_ڈیٹا.host_pubkeys[i] != تہی) {
			اگر ((r = sshkey_puts(sensitive_ڈیٹا.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} ورنہ {
			اگر ((r = sshbuf_put_string(hostkeys, تہی, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		اگر (sensitive_ڈیٹا.host_certificates[i] != تہی) {
			اگر ((r = sshkey_puts(
			    sensitive_ڈیٹا.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} ورنہ {
			اگر ((r = sshbuf_put_string(hostkeys, تہی, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	اگر ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	اگر ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	واپس m;
}

ساکن ساخت sshbuf *
pack_config(ساخت sshbuf *conf)
{
	ساخت sshbuf *m = تہی, *inc = تہی;
	ساخت include_شے *شے = تہی;
	سائز_t len;
	صحیح r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	اگر ((m = sshbuf_new()) == تہی ||
	    (inc = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(شے, &includes, اندراج_2) {
		اگر ((r = sshbuf_put_cstring(inc, شے->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, شے->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, شے->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	اگر ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	اگر ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	واپس m;
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
ساکن خالی
send_rexec_state(صحیح fd)
{
	ساخت sshbuf *کلیدیں;
	u_int mlen;
	pid_t pid;

	اگر ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	اگر (pid != 0)
		واپس;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	اگر (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	کلیدیں = pack_hostkeys();
	mlen = sshbuf_len(کلیدیں);
	اگر (atomicio(vwrite, fd, sshbuf_mutable_ptr(کلیدیں), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(کلیدیں);
	debug3_f("done");
	باہر_نکلو(0);
}

/*
 * Listen for TCP connections
 */
ساکن خالی
listen_on_addrs(ساخت listenaddr *la)
{
	صحیح ret, listen_sock;
	ساخت addrinfo *ai;
	حرف ntop[NI_MAXHOST], strport[NI_MAXSERV];

	برائے (ai = la->addrs; ai; ai = ai->ai_next) {
		اگر (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			جاری;
		اگر (عدد_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		اگر ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, حجم(ntop), strport, حجم(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			جاری;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		اگر (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			جاری;
		}
		اگر (سیٹ_nonblock(listen_sock) == -1) {
			close(listen_sock);
			جاری;
		}
		اگر (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			جاری;
		}
		/* Socket options */
		سیٹ_reuseaddr(listen_sock);
		اگر (la->rdomain != تہی &&
		    سیٹ_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			جاری;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		اگر (ai->ai_family == AF_INET6)
			sock_سیٹ_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		اگر (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			جاری;
		}
		listen_socks[عدد_listen_socks] = listen_sock;
		عدد_listen_socks++;

		/* Start listening on the port. */
		اگر (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == تہی ? "" : " rdomain ",
		    la->rdomain == تہی ? "" : la->rdomain);
	}
}

ساکن خالی
server_listen(خالی)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.فی_ماخذ_max_startups,
	    options.فی_ماخذ_masklen_ipv4,
	    options.فی_ماخذ_masklen_ipv6,
	    &options.فی_ماخذ_penalty,
	    options.فی_ماخذ_penalty_exempt);

	برائے (i = 0; i < options.عدد_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		آزاد(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    حجم(options.listen_addrs[i]));
	}
	آزاد(options.listen_addrs);
	options.listen_addrs = تہی;
	options.عدد_listen_addrs = 0;

	اگر (!عدد_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
ساکن خالی
server_accept_loop(صحیح *sock_اندر, صحیح *sock_برآمد, صحیح *newsock, صحیح *config_s,
    صحیح log_stderr)
{
	ساخت pollfd *pfd = تہی;
	صحیح i, ret, npfd, r;
	صحیح oactive = -1, listening = 0, lameduck = 0;
	صحیح *startup_pollfd;
	ssize_t len;
	ثابت u_char *ptr;
	حرف c = 0;
	ساخت sockaddr_storage from;
	ساخت early_بچہ *بچہ;
	ساخت sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	بچہ_alloc();
	startup_pollfd = xcalloc(options.max_startups, حجم(صحیح));

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm/hup/chld/info, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
#اگر_تعریف_شدہ SIGINFO
	sigaddset(&nsigset, SIGINFO);
#اگر_ختم
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(عدد_listen_socks + options.max_startups,
	    حجم(ساخت pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	برائے (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		اگر (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (صحیح) received_sigterm);
			close_listen_socks();
			اگر (options.pid_file != تہی)
				unlink(options.pid_file);
			باہر_نکلو(received_sigterm == SIGTERM ? 0 : 255);
		}
		اگر (received_sigchld) {
			بچہ_reap_all_exited();
			received_sigchld = 0;
		}
		اگر (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		اگر (oactive != children_فعال) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_فعال,
			    options.max_startups_begin, options.max_startups);
			oactive = children_فعال;
		}
		اگر (received_sighup) {
			اگر (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			اگر (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, تہی);
				sighup_restart();
			}
		}

		برائے (i = 0; i < عدد_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = عدد_listen_socks;
		برائے (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			اگر (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				اگر (children[i].config != تہی ||
				    children[i].کلیدیں != تہی)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, تہی, &osigset);
		اگر (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			اگر (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, تہی);
		اگر (ret == -1)
			جاری;

		برائے (i = 0; i < options.max_startups; i++) {
			اگر (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				جاری;
			اگر (children[i].config)
				buf = children[i].config;
			ورنہ اگر (children[i].کلیدیں)
				buf = children[i].کلیدیں;
			ورنہ {
				error_f("no buffer to send");
				جاری;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = اكتب(children[i].pipefd, ptr, len);
			اگر (ret == -1 && (errno == EINTR || errno == EAGAIN))
				جاری;
			اگر (ret <= 0) {
				اگر (children[i].early)
					listening--;
				بچہ_close(&(children[i]), 0, 0);
				جاری;
			}
			اگر (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				اگر (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = تہی;
					children[i].کلیدیں = pack_hostkeys();
				} ورنہ اگر (children[i].کلیدیں == buf) {
					/* sent both config and keys */
					children[i].کلیدیں = تہی;
				} ورنہ {
					fatal("config buf not set");
				}

			} ورنہ {
				اگر ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		برائے (i = 0; i < options.max_startups; i++) {
			اگر (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				جاری;
			انتخاب (اقرأ(children[i].pipefd, &c, حجم(c))) {
			حالت -1:
				اگر (errno == EINTR || errno == EAGAIN)
					جاری;
				اگر (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			حالت 0:
				/* child closed pipe */
				اگر (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (طویل)children[i].pid, children[i].id);
				بچہ_close(&(children[i]), 0, 0);
				توڑو;
			حالت 1:
				اگر (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					جاؤ problem_بچہ;
				}
				اگر (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (طویل)children[i].pid,
					    children[i].id);
				} ورنہ اگر (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (طویل)children[i].pid,
					    children[i].id);
					بچہ_close(&(children[i]), 1, 0);
				} ورنہ {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (صحیح)c, (طویل)children[i].pid,
					    children[i].id, children[i].early);
 problem_بچہ:
					اگر (children[i].early)
						listening--;
					اگر (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					بچہ_close(&(children[i]), 0, 0);
				}
				توڑو;
			}
		}
		برائے (i = 0; i < عدد_listen_socks; i++) {
			اگر (!(pfd[i].revents & POLLIN))
				جاری;
			fromlen = حجم(from);
			*newsock = accept(listen_socks[i],
			    (ساخت sockaddr *)&from, &fromlen);
			اگر (*newsock == -1) {
				اگر (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				اگر (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				جاری;
			}
			اگر (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				جاری;
			}
			اگر (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				جاری;
			}
			اگر (drop_connection(*newsock,
			    children_فعال, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				جاری;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			اگر (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_اندر = *newsock;
				*sock_برآمد = *newsock;
				send_rexec_state(config_s[0]);
				close(config_s[0]);
				آزاد(pfd);
				آزاد(startup_pollfd);
				واپس;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			platform_pre_fork();
			سیٹ_nonblock(config_s[0]);
			listening++;
			بچہ = بچہ_رجسٹر(config_s[0], *newsock);
			اگر ((بچہ->pid = fork()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				platform_post_fork_بچہ();
				close_startup_pipes();
				close_listen_socks();
				*sock_اندر = *newsock;
				*sock_برآمد = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				close(config_s[0]);
				آزاد(pfd);
				آزاد(startup_pollfd);
				واپس;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_والد(بچہ->pid);
			اگر (بچہ->pid == -1)
				error("fork: %.100s", strerror(errno));
			ورنہ
				debug("Forked child %ld.", (طویل)بچہ->pid);

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

ساکن خالی
accumulate_host_timing_secret(ساخت sshbuf *server_cfg,
    ساخت sshkey *کلید)
{
	ساکن ساخت ssh_digest_ctx *ctx;
	u_char *hash;
	سائز_t len;
	ساخت sshbuf *buf;
	صحیح r;

	اگر (ctx == تہی && (ctx = ssh_digest_آغاز(SSH_DIGEST_SHA512)) == تہی)
		fatal_f("ssh_digest_start");
	اگر (کلید == تہی) { /* finalize */
		/* add server config in case we are using agent for host keys */
		اگر (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_بائٹیں(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		اگر (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = تہی;
		واپس;
	}
	اگر ((buf = sshbuf_new()) == تہی)
		fatal_f("could not allocate buffer");
	اگر ((r = sshkey_نجی_serialize(کلید, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(کلید));
	اگر (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

ساکن حرف *
prepare_proctitle(صحیح ac, حرف **av)
{
	حرف *ret = تہی;
	صحیح i;

	برائے (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	واپس ret;
}

/* Disconnect from the controlling tty. */
ساکن خالی
disconnect_controlling_tty(خالی)
{
#اگر_تعریف_شدہ TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	صحیح fd;

	اگر ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(خالی) ioctl(fd, TIOCNOTTY, تہی);
		close(fd);
	}
#اگر_ختم /* TIOCNOTTY */
}

ساکن خالی
print_config(ساخت connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_مطابقت_config(&options, &includes, connection_info);
	dump_config(&options);
	باہر_نکلو(0);
}

/*
 * Main program for the daemon.
 */
صحیح
مین(صحیح ac, حرف **av)
{
	خارجی حرف *optarg;
	خارجی صحیح optind;
	صحیح log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	حرف *config_file_name = راستہ_SERVER_CONFIG_FILE;
	صحیح r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	صحیح sock_اندر = -1, sock_برآمد = -1, newsock = -1, rexec_argc = 0;
	صحیح devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	صحیح need_chroot = 1;
	حرف *دلائل, *fp, *سطر, *logfile = تہی, **rexec_argv = تہی;
	ساخت stat sb;
	u_int i, j;
	منوال_t new_umask;
	ساخت sshkey *کلید;
	ساخت sshkey *pubkey;
	ساخت connection_info connection_info;
	ساخت utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, حجم(connection_info));
#اگر_تعریف_شدہ HAVE_SECUREWARE
	(خالی)سیٹ_auth_parameters(ac, av);
#اگر_ختم
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, تہی);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, حجم(*saved_argv));
	برائے (i = 0; (صحیح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = تہی;

#اگر_غیر_تعریف_شدہ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#اگر_ختم

	اگر (geteuid() == 0 && setgroups(0, تہی) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	دلائل = argv_assemble(ac, av); /* logged later */
	جب ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		انتخاب (opt) {
		حالت '4':
			options.پتہ_family = AF_INET;
			توڑو;
		حالت '6':
			options.پتہ_family = AF_INET6;
			توڑو;
		حالت 'f':
			config_file_name = optarg;
			توڑو;
		حالت 'c':
			servconf_جوڑو_hostcert("[command-line]", 0,
			    &options, optarg);
			توڑو;
		حالت 'd':
			اگر (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ورنہ اگر (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			توڑو;
		حالت 'D':
			no_daemon_flag = 1;
			توڑو;
		حالت 'G':
			do_dump_cfg = 1;
			توڑو;
		حالت 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		حالت 'e':
			log_stderr = 1;
			توڑو;
		حالت 'i':
			inetd_flag = 1;
			توڑو;
		حالت 'r':
			logit("-r option is deprecated");
			توڑو;
		حالت 'R':
			fatal("-R not supported here");
			توڑو;
		حالت 'Q':
			/* ignored */
			توڑو;
		حالت 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			توڑو;
		حالت 'b':
			/* protocol 1, ignored */
			توڑو;
		حالت 'p':
			options.ports_from_cmdline = 1;
			اگر (options.عدد_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				باہر_نکلو(1);
			}
			options.ports[options.عدد_ports++] = a2port(optarg);
			اگر (options.ports[options.عدد_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				باہر_نکلو(1);
			}
			توڑو;
		حالت 'g':
			اگر ((options.login_grace_وقت = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				باہر_نکلو(1);
			}
			توڑو;
		حالت 'k':
			/* protocol 1, ignored */
			توڑو;
		حالت 'h':
			servconf_جوڑو_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			توڑو;
		حالت 't':
			test_flag = 1;
			توڑو;
		حالت 'T':
			test_flag = 2;
			توڑو;
		حالت 'C':
			اگر (parse_server_مطابقت_testspec(&connection_info,
			    optarg) == -1)
				باہر_نکلو(1);
			have_connection_info = 1;
			توڑو;
		حالت 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, تہی);
			اگر (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				باہر_نکلو(1);
			}
			توڑو;
		حالت 'o':
			سطر = xstrdup(optarg);
			اگر (process_server_config_سطر(&options, سطر,
			    "command-line", 0, تہی, تہی, &includes) != 0)
				باہر_نکلو(1);
			آزاد(سطر);
			توڑو;
		حالت 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_نسخہ);
			باہر_نکلو(0);
		طےشدہ:
			usage();
			توڑو;
		}
	}

	اگر (getexecpath(execpath, حجم execpath) != 0) {
		اگر (strlcpy(execpath, av[0], حجم execpath) >=
		    حجم execpath) {
			fprintf(stderr, "execution path is too long\n");
			باہر_نکلو(1);
		}
	}
	اگر (!test_flag && !inetd_flag && !do_dump_cfg && !راستہ_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	اگر ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	جب (devnull < REEXEC_MIN_FREE_FD) {
		اگر ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	بیج_rng();

	/* If requested, redirect the logs to the specified logfile. */
	اگر (logfile != تہی) {
		حرف *cp, pid_s[32];

		snprintf(pid_s, حجم(pid_s), "%ld", (غیرعلامتی طویل)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (حرف *)تہی);
		log_redirect_stderr_مقصد(cp);
		آزاد(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_سیٹ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_سیٹ ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/*
	 * Unset KRB5CCNAME, otherwise the user's session may inherit it from
	 * root's environment
	 */
	اگر (getenv("KRB5CCNAME") != تہی)
		(خالی) unsetenv("KRB5CCNAME");

	sensitive_ڈیٹا.have_ssh2_کلید = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	اگر (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_نسخہ, SSH_OPENSSL_نسخہ);
	اگر (uname(&utsname) != 0) {
		memset(&utsname, 0, حجم(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", حجم(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.نسخہ, utsname.machine);
	debug3("Started with: %s", دلائل);
	آزاد(دلائل);

	/* Fetch our configuration */
	اگر ((cfg = sshbuf_new()) == تہی)
		fatal("sshbuf_new config failed");
	اگر (strcasecmp(config_file_name, "none") != 0)
		بھرو_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, تہی, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	اگر (options.authorized_کلیدیں_command_user == تہی &&
	    (options.authorized_کلیدیں_command != تہی &&
	    strcasecmp(options.authorized_کلیدیں_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	اگر (options.authorized_principals_command_user == تہی &&
	    (options.authorized_principals_command != تہی &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	اگر (options.عدد_auth_methods != 0) {
		برائے (i = 0; i < options.عدد_auth_methods; i++) {
			اگر (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				توڑو;
		}
		اگر (i >= options.عدد_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	اگر (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		باہر_نکلو(1);
	}

	اگر (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_ڈیٹا.host_کلیدیں = xcalloc(options.عدد_host_کلید_files,
	    حجم(ساخت sshkey *));
	sensitive_ڈیٹا.host_pubkeys = xcalloc(options.عدد_host_کلید_files,
	    حجم(ساخت sshkey *));

	اگر (options.host_کلید_agent) {
		اگر (strcmp(options.host_کلید_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_کلید_agent, 1);
		اگر ((r = ssh_get_authentication_socket(تہی)) == 0)
			have_agent = 1;
		ورنہ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_کلید_agent);
	}

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		صحیح ll = options.host_کلید_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		اگر (options.host_کلید_files[i] == تہی)
			جاری;
		اگر ((r = sshkey_بھرو_نجی(options.host_کلید_files[i], "",
		    &کلید, تہی)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_کلید_files[i]);
		اگر (sshkey_is_sk(کلید) &&
		    کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_کلید_files[i]);
			کلید->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		اگر (r == 0 && کلید != تہی &&
		    (r = sshkey_shield_نجی(کلید)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_کلید_files[i]);
			sshkey_free(کلید);
			کلید = تہی;
		}
		اگر ((r = sshkey_بھرو_عوامی(options.host_کلید_files[i],
		    &pubkey, تہی)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_کلید_files[i]);
		اگر (pubkey != تہی && کلید != تہی) {
			اگر (!sshkey_equal(pubkey, کلید)) {
				error("Public key for %s does not match "
				    "private key", options.host_کلید_files[i]);
				sshkey_free(pubkey);
				pubkey = تہی;
			}
		}
		اگر (pubkey == تہی && کلید != تہی) {
			اگر ((r = sshkey_from_نجی(کلید, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_کلید_files[i]);
		}
		اگر (pubkey != تہی && (r = sshkey_check_rsa_لمبائی(pubkey,
		    options.required_rsa_سائز)) != 0) {
			error_fr(r, "Host key %s", options.host_کلید_files[i]);
			sshkey_free(pubkey);
			sshkey_free(کلید);
			جاری;
		}
		sensitive_ڈیٹا.host_کلیدیں[i] = کلید;
		sensitive_ڈیٹا.host_pubkeys[i] = pubkey;

		اگر (کلید == تہی && pubkey != تہی && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_کلید_files[i]);
			keytype = pubkey->type;
		} ورنہ اگر (کلید != تہی) {
			keytype = کلید->type;
			accumulate_host_timing_secret(cfg, کلید);
		} ورنہ {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_کلید_files[i]);
			sensitive_ڈیٹا.host_کلیدیں[i] = تہی;
			sensitive_ڈیٹا.host_pubkeys[i] = تہی;
			جاری;
		}

		انتخاب (keytype) {
		حالت کلید_RSA:
		حالت کلید_ECDSA:
		حالت کلید_ED25519:
		حالت کلید_MLDSA44_ED25519:
		حالت کلید_ECDSA_SK:
		حالت کلید_ED25519_SK:
			اگر (have_agent || کلید != تہی)
				sensitive_ڈیٹا.have_ssh2_کلید = 1;
			توڑو;
		}
		اگر ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == تہی)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    کلید ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		آزاد(fp);
	}
	accumulate_host_timing_secret(cfg, تہی);
	اگر (!sensitive_ڈیٹا.have_ssh2_کلید) {
		logit("sshd: no hostkeys available -- exiting.");
		باہر_نکلو(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_ڈیٹا.host_certificates = xcalloc(options.عدد_host_کلید_files,
	    حجم(ساخت sshkey *));
	برائے (i = 0; i < options.عدد_host_کلید_files; i++)
		sensitive_ڈیٹا.host_certificates[i] = تہی;

	برائے (i = 0; i < options.عدد_host_cert_files; i++) {
		اگر (options.host_cert_files[i] == تہی)
			جاری;
		اگر ((r = sshkey_بھرو_عوامی(options.host_cert_files[i],
		    &کلید, تہی)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			جاری;
		}
		اگر (!sshkey_is_cert(کلید)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(کلید);
			جاری;
		}
		/* Find matching private key */
		برائے (j = 0; j < options.عدد_host_کلید_files; j++) {
			اگر (sshkey_equal_عوامی(کلید,
			    sensitive_ڈیٹا.host_pubkeys[j])) {
				sensitive_ڈیٹا.host_certificates[j] = کلید;
				توڑو;
			}
		}
		اگر (j >= options.عدد_host_کلید_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(کلید);
			جاری;
		}
		sensitive_ڈیٹا.host_certificates[j] = کلید;
		debug("host certificate: #%u type %d %s", j, کلید->type,
		    sshkey_type(کلید));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	اگر ((getpwnam(SSH_PRIVSEP_USER)) == تہی && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	اگر (need_chroot) {
		اگر ((stat(راستہ_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    راستہ_PRIVSEP_CHROOT_DIR);
#اگر_تعریف_شدہ HAVE_CYGWIN
		اگر (check_ntsec(راستہ_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#ورنہ
		اگر (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#اگر_ختم
			fatal("%s must be owned by root and not group or "
			    "world-writable.", راستہ_PRIVSEP_CHROOT_DIR);
	}

	اگر (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	اگر (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	اگر (test_flag)
		باہر_نکلو(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	اگر (setgroups(0, تہی) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	اگر (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, حجم(حرف *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_راستہ;
	برائے (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = تہی;
	اگر (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	اگر (stat(options.sshd_auth_راستہ, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_راستہ);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(خالی) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	اگر (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	برائے (i = 0; i < options.عدد_log_verbose; i++)
		log_verbose_جوڑو(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	اگر (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		اگر (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	اگر (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	اگر (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} ورنہ {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
#اگر_تعریف_شدہ SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#اگر_ختم

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		اگر (options.pid_file != تہی && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			اگر (f == تہی) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} ورنہ {
				fprintf(f, "%ld\n", (طویل) getpid());
				fclose(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_اندر, &sock_برآمد,
		    &newsock, config_s, log_stderr);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	اگر (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_اندر, sock_برآمد, newsock, config_s[0], config_s[1]);
	اگر (!inetd_flag) {
		اگر (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		اگر (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		اگر (newsock > STDOUT_FILENO)
			close(newsock);
	}
	اگر (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		اگر (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_مقصد(تہی);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
خالی
cleanup_exit(صحیح i)
{
	_exit(i);
}
