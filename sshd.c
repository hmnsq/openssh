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

#ifdef HAVE_SECUREWARE
#شامل <sys/security.h>
#شامل <prot.h>
#endif

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
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

بیرونی نویسه *__progname;

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
ایستا نویسه execpath[PATH_MAX];
ایستا نویسه **saved_argv;
ایستا صحیح saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
ایستا صحیح listen_socks[MAX_LISTEN_SOCKS];
ایستا صحیح رقم_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ساختار {
	ساختار sshkey	**host_کلیدها;		/* all private host keys */
	ساختار sshkey	**host_pubkeys;		/* all public host keys */
	ساختار sshkey	**host_certificates;	/* all public host certificates */
	صحیح		have_ssh2_کلید;
} sensitive_data;

/* This is set to true when a signal is received. */
ایستا فرار sig_atomic_t received_siginfo = 0;
ایستا فرار sig_atomic_t received_sigchld = 0;
ایستا فرار sig_atomic_t received_sighup = 0;
ایستا فرار sig_atomic_t received_sigterm = 0;

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
ساختار early_child {
	صحیح pipefd;
	صحیح early;		/* Indicates child closed listener */
	نویسه *id;		/* human readable connection identifier */
	pid_t pid;
	ساختار xaddr addr;
	صحیح have_addr;
	صحیح status, have_status;
	ساختار sshbuf *config;
	ساختار sshbuf *کلیدها;
};
ایستا ساختار early_child *children;
ایستا صحیح children_active;

/* sshd_config buffer */
ساختار sshbuf *cfg;
ساختار sshbuf *config;	/* packed */

/* Included files from the configuration file */
ساختار include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ساختار sshbuf *loginmsg;

/* Unprivileged user */
ساختار passwd *privsep_pw = پوچ;

ایستا نویسه *listener_proctitle;

/*
 * Close all listening sockets
 */
ایستا تهی
close_listen_socks(تهی)
{
	صحیح i;

	برای (i = 0; i < رقم_listen_socks; i++)
		close(listen_socks[i]);
	رقم_listen_socks = 0;
}

/* Allocate and initialise the children array */
ایستا تهی
child_alloc(تهی)
{
	صحیح i;

	children = xcalloc(options.max_startups, اندازه(*children));
	برای (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
ایستا ساختار early_child *
child_register(صحیح pipefd, صحیح sockfd)
{
	صحیح i, lport, rport;
	نویسه *laddr = پوچ, *raddr = پوچ;
	ساختار early_child *child = پوچ;
	ساختار sockaddr_storage addr;
	socklen_t addrlen = اندازه(addr);
	ساختار sockaddr *sa = (ساختار sockaddr *)&addr;

	برای (i = 0; i < options.max_startups; i++) {
		اگر (children[i].pipefd != -1 ||
		    children[i].config != پوچ ||
		    children[i].کلیدها != پوچ ||
		    children[i].pid > 0)
			ادامه;
		child = &(children[i]);
		بشکن;
	}
	اگر (child == پوچ) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	اگر ((child->config = sshbuf_fromb(config)) == پوچ)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	اگر (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	اگر ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} وگرنه {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	آزاد(laddr);
	آزاد(raddr);
	اگر (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	بازگشت child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
ایستا تهی
child_finish(ساختار early_child *child)
{
	اگر (children_active == 0)
		fatal_f("internal error: children_active underflow");
	اگر (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->کلیدها);
	آزاد(child->id);
	memset(child, '\0', اندازه(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
ایستا تهی
child_close(ساختار early_child *child, صحیح force_final, صحیح quiet)
{
	اگر (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	اگر (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	اگر (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
ایستا تهی
child_exit(pid_t pid, صحیح status)
{
	صحیح i;

	اگر (children == پوچ || pid <= 0)
		بازگشت;
	برای (i = 0; i < options.max_startups; i++) {
		اگر (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			بشکن;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
ایستا تهی
child_reap(ساختار early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	صحیح was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ثابت نویسه *child_status;

	اگر (child->config)
		child_status = " (sending config)";
	وگرنه اگر (child->کلیدها)
		child_status = " (sending keys)";
	وگرنه اگر (child->early)
		child_status = " (early)";
	وگرنه
		child_status = "";

	/* Log exit information */
	اگر (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		اگر ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		اگر (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} وگرنه اگر (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} وگرنه {
		/* Normal exit. We care about the status */
		انتخاب (WEXITSTATUS(child->status)) {
		حالت 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			بشکن;
		حالت EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			بشکن;
		حالت EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			بشکن;
		حالت EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			بشکن;
		حالت EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			بشکن;
		حالت EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			بشکن;
		پیشفرض:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			بشکن;
		}
	}

	اگر (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	اگر (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
ایستا تهی
child_reap_all_exited(تهی)
{
	صحیح i;
	pid_t pid;
	صحیح status;

	اگر (children == پوچ)
		بازگشت;

	برای (;;) {
		اگر ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			بشکن;
		وگرنه اگر (pid == -1) {
			اگر (errno == EINTR || errno == EAGAIN)
				ادامه;
			اگر (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			بشکن;
		}
		child_exit(pid, status);
	}

	برای (i = 0; i < options.max_startups; i++) {
		اگر (!children[i].have_status)
			ادامه;
		child_reap(&(children[i]));
	}
}

ایستا تهی
close_startup_pipes(تهی)
{
	صحیح i;

	اگر (children == پوچ)
		بازگشت;
	برای (i = 0; i < options.max_startups; i++) {
		اگر (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
ایستا تهی
show_info(تهی)
{
	صحیح i;
	ثابت نویسه *child_status;

	/* XXX print listening sockets here too */
	اگر (children == پوچ)
		بازگشت;
	logit("%d active startups", children_active);
	برای (i = 0; i < options.max_startups; i++) {
		اگر (children[i].pipefd == -1 && children[i].pid <= 0)
			ادامه;
		اگر (children[i].config)
			child_status = " (sending config)";
		وگرنه اگر (children[i].کلیدها)
			child_status = " (sending keys)";
		وگرنه اگر (children[i].early)
			child_status = " (early)";
		وگرنه
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

ایستا تهی
sighup_handler(صحیح sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
ایستا تهی
sighup_restart(تهی)
{
	logit("Received SIGHUP; restarting.");
	اگر (options.pid_file != پوچ)
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
ایستا تهی
sigterm_handler(صحیح sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
ایستا تهی
siginfo_handler(صحیح sig)
{
	received_siginfo = 1;
}
#endif

ایستا تهی
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
ایستا صحیح
should_drop_connection(صحیح startups)
{
	صحیح p, r;

	اگر (startups < options.max_startups_begin)
		بازگشت 0;
	اگر (startups >= options.max_startups)
		بازگشت 1;
	اگر (options.max_startups_rate == 100)
		بازگشت 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	بازگشت (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
ایستا صحیح
drop_connection(صحیح sock, صحیح startups, صحیح notify_pipe)
{
	ایستا ساختار log_ratelimit_ctx ratelimit_maxstartups;
	ایستا ساختار log_ratelimit_ctx ratelimit_penalty;
	ایستا صحیح init_done;
	نویسه *laddr, *raddr;
	ثابت نویسه *reason = پوچ, *subreason = پوچ;
	ثابت نویسه پیام[] = "Not allowed at this time\r\n";
	ساختار log_ratelimit_ctx *rl = پوچ;
	صحیح ratelimited;
	u_int ndropped;

	اگر (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	اگر (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} وگرنه {
		/* MaxStartups */
		اگر (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			بازگشت 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(پوچ), پوچ, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != پوچ ? subreason : reason);
	آزاد(laddr);
	آزاد(raddr);
	اگر (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(تهی)اكتب(sock, پیام, اندازه(پیام) - 1);
	بازگشت 1;
}

ایستا تهی
usage(تهی)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

ایستا ساختار sshbuf *
pack_hostkeys(تهی)
{
	ساختار sshbuf *m = پوچ, *keybuf = پوچ, *hostkeys = پوچ;
	صحیح r;
	u_int i;
	size_t len;

	اگر ((m = sshbuf_new()) == پوچ ||
	    (keybuf = sshbuf_new()) == پوچ ||
	    (hostkeys = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		اگر (sensitive_data.host_کلیدها[i] != پوچ &&
		    (r = sshkey_private_serialize(sensitive_data.host_کلیدها[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		اگر ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		اگر (sensitive_data.host_pubkeys[i] != پوچ) {
			اگر ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} وگرنه {
			اگر ((r = sshbuf_put_string(hostkeys, پوچ, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		اگر (sensitive_data.host_certificates[i] != پوچ) {
			اگر ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} وگرنه {
			اگر ((r = sshbuf_put_string(hostkeys, پوچ, 0)) != 0)
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
	بازگشت m;
}

ایستا ساختار sshbuf *
pack_config(ساختار sshbuf *conf)
{
	ساختار sshbuf *m = پوچ, *inc = پوچ;
	ساختار include_item *item = پوچ;
	size_t len;
	صحیح r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	اگر ((m = sshbuf_new()) == پوچ ||
	    (inc = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		اگر ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
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
	بازگشت m;
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
ایستا تهی
send_rexec_state(صحیح fd)
{
	ساختار sshbuf *کلیدها;
	u_int mlen;
	pid_t pid;

	اگر ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	اگر (pid != 0)
		بازگشت;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	اگر (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	کلیدها = pack_hostkeys();
	mlen = sshbuf_len(کلیدها);
	اگر (atomicio(vwrite, fd, sshbuf_mutable_ptr(کلیدها), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(کلیدها);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
ایستا تهی
listen_on_addrs(ساختار listenaddr *la)
{
	صحیح ret, listen_sock;
	ساختار addrinfo *ai;
	نویسه ntop[NI_MAXHOST], strport[NI_MAXSERV];

	برای (ai = la->addrs; ai; ai = ai->ai_next) {
		اگر (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			ادامه;
		اگر (رقم_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		اگر ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, اندازه(ntop), strport, اندازه(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			ادامه;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		اگر (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			ادامه;
		}
		اگر (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			ادامه;
		}
		اگر (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			ادامه;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		اگر (la->rdomain != پوچ &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			ادامه;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		اگر (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		اگر (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			ادامه;
		}
		listen_socks[رقم_listen_socks] = listen_sock;
		رقم_listen_socks++;

		/* Start listening on the port. */
		اگر (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == پوچ ? "" : " rdomain ",
		    la->rdomain == پوچ ? "" : la->rdomain);
	}
}

ایستا تهی
server_listen(تهی)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	برای (i = 0; i < options.رقم_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		آزاد(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    اندازه(options.listen_addrs[i]));
	}
	آزاد(options.listen_addrs);
	options.listen_addrs = پوچ;
	options.رقم_listen_addrs = 0;

	اگر (!رقم_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
ایستا تهی
server_accept_loop(صحیح *sock_in, صحیح *sock_out, صحیح *newsock, صحیح *config_s,
    صحیح log_stderr)
{
	ساختار pollfd *pfd = پوچ;
	صحیح i, ret, npfd, r;
	صحیح oactive = -1, listening = 0, lameduck = 0;
	صحیح *startup_pollfd;
	ssize_t len;
	ثابت u_char *ptr;
	نویسه c = 0;
	ساختار sockaddr_storage from;
	ساختار early_child *child;
	ساختار sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, اندازه(صحیح));

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
	pfd = xcalloc(رقم_listen_socks + options.max_startups,
	    اندازه(ساختار pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	برای (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		اگر (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (صحیح) received_sigterm);
			close_listen_socks();
			اگر (options.pid_file != پوچ)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		اگر (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		اگر (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		اگر (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
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
				sigprocmask(SIG_SETMASK, &osigset, پوچ);
				sighup_restart();
			}
		}

		برای (i = 0; i < رقم_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = رقم_listen_socks;
		برای (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			اگر (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				اگر (children[i].config != پوچ ||
				    children[i].کلیدها != پوچ)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, پوچ, &osigset);
		اگر (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			اگر (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, پوچ);
		اگر (ret == -1)
			ادامه;

		برای (i = 0; i < options.max_startups; i++) {
			اگر (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				ادامه;
			اگر (children[i].config)
				buf = children[i].config;
			وگرنه اگر (children[i].کلیدها)
				buf = children[i].کلیدها;
			وگرنه {
				error_f("no buffer to send");
				ادامه;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = اكتب(children[i].pipefd, ptr, len);
			اگر (ret == -1 && (errno == EINTR || errno == EAGAIN))
				ادامه;
			اگر (ret <= 0) {
				اگر (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				ادامه;
			}
			اگر (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				اگر (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = پوچ;
					children[i].کلیدها = pack_hostkeys();
				} وگرنه اگر (children[i].کلیدها == buf) {
					/* sent both config and keys */
					children[i].کلیدها = پوچ;
				} وگرنه {
					fatal("config buf not set");
				}

			} وگرنه {
				اگر ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		برای (i = 0; i < options.max_startups; i++) {
			اگر (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				ادامه;
			انتخاب (اقرأ(children[i].pipefd, &c, اندازه(c))) {
			حالت -1:
				اگر (errno == EINTR || errno == EAGAIN)
					ادامه;
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
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				بشکن;
			حالت 1:
				اگر (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					برو problem_child;
				}
				اگر (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} وگرنه اگر (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} وگرنه {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (صحیح)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					اگر (children[i].early)
						listening--;
					اگر (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				بشکن;
			}
		}
		برای (i = 0; i < رقم_listen_socks; i++) {
			اگر (!(pfd[i].revents & POLLIN))
				ادامه;
			fromlen = اندازه(from);
			*newsock = accept(listen_socks[i],
			    (ساختار sockaddr *)&from, &fromlen);
			اگر (*newsock == -1) {
				اگر (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				اگر (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				ادامه;
			}
			اگر (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				ادامه;
			}
			اگر (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				ادامه;
			}
			اگر (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				ادامه;
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
				*sock_in = *newsock;
				*sock_out = *newsock;
				send_rexec_state(config_s[0]);
				close(config_s[0]);
				آزاد(pfd);
				آزاد(startup_pollfd);
				بازگشت;
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
			اگر ((child->pid = fork()) == 0) {
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
				آزاد(pfd);
				آزاد(startup_pollfd);
				بازگشت;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			اگر (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			وگرنه
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

ایستا تهی
accumulate_host_timing_secret(ساختار sshbuf *server_cfg,
    ساختار sshkey *کلید)
{
	ایستا ساختار ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	ساختار sshbuf *buf;
	صحیح r;

	اگر (ctx == پوچ && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == پوچ)
		fatal_f("ssh_digest_start");
	اگر (کلید == پوچ) { /* finalize */
		/* add server config in case we are using agent for host keys */
		اگر (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		اگر (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = پوچ;
		بازگشت;
	}
	اگر ((buf = sshbuf_new()) == پوچ)
		fatal_f("could not allocate buffer");
	اگر ((r = sshkey_private_serialize(کلید, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(کلید));
	اگر (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

ایستا نویسه *
prepare_proctitle(صحیح ac, نویسه **av)
{
	نویسه *ret = پوچ;
	صحیح i;

	برای (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	بازگشت ret;
}

/* Disconnect from the controlling tty. */
ایستا تهی
disconnect_controlling_tty(تهی)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	صحیح fd;

	اگر ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(تهی) ioctl(fd, TIOCNOTTY, پوچ);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

ایستا تهی
print_config(ساختار connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
صحیح
اصلی(صحیح ac, نویسه **av)
{
	بیرونی نویسه *optarg;
	بیرونی صحیح optind;
	صحیح log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	نویسه *config_file_name = _PATH_SERVER_CONFIG_FILE;
	صحیح r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	صحیح sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	صحیح devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	صحیح need_chroot = 1;
	نویسه *args, *fp, *سطر, *logfile = پوچ, **rexec_argv = پوچ;
	ساختار stat sb;
	u_int i, j;
	mode_t new_umask;
	ساختار sshkey *کلید;
	ساختار sshkey *pubkey;
	ساختار connection_info connection_info;
	ساختار utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, اندازه(connection_info));
#ifdef HAVE_SECUREWARE
	(تهی)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, پوچ);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, اندازه(*saved_argv));
	برای (i = 0; (صحیح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = پوچ;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	اگر (geteuid() == 0 && setgroups(0, پوچ) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	وقتی ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		انتخاب (opt) {
		حالت '4':
			options.address_family = AF_INET;
			بشکن;
		حالت '6':
			options.address_family = AF_INET6;
			بشکن;
		حالت 'f':
			config_file_name = optarg;
			بشکن;
		حالت 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			بشکن;
		حالت 'd':
			اگر (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} وگرنه اگر (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			بشکن;
		حالت 'D':
			no_daemon_flag = 1;
			بشکن;
		حالت 'G':
			do_dump_cfg = 1;
			بشکن;
		حالت 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		حالت 'e':
			log_stderr = 1;
			بشکن;
		حالت 'i':
			inetd_flag = 1;
			بشکن;
		حالت 'r':
			logit("-r option is deprecated");
			بشکن;
		حالت 'R':
			fatal("-R not supported here");
			بشکن;
		حالت 'Q':
			/* ignored */
			بشکن;
		حالت 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			بشکن;
		حالت 'b':
			/* protocol 1, ignored */
			بشکن;
		حالت 'p':
			options.ports_from_cmdline = 1;
			اگر (options.رقم_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.رقم_ports++] = a2port(optarg);
			اگر (options.ports[options.رقم_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			بشکن;
		حالت 'g':
			اگر ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			بشکن;
		حالت 'k':
			/* protocol 1, ignored */
			بشکن;
		حالت 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			بشکن;
		حالت 't':
			test_flag = 1;
			بشکن;
		حالت 'T':
			test_flag = 2;
			بشکن;
		حالت 'C':
			اگر (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			بشکن;
		حالت 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, پوچ);
			اگر (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			بشکن;
		حالت 'o':
			سطر = xstrdup(optarg);
			اگر (process_server_config_سطر(&options, سطر,
			    "command-line", 0, پوچ, پوچ, &includes) != 0)
				exit(1);
			آزاد(سطر);
			بشکن;
		حالت 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		پیشفرض:
			usage();
			بشکن;
		}
	}

	اگر (getexecpath(execpath, اندازه execpath) != 0) {
		اگر (strlcpy(execpath, av[0], اندازه execpath) >=
		    اندازه execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	اگر (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	اگر ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	وقتی (devnull < REEXEC_MIN_FREE_FD) {
		اگر ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	اگر (logfile != پوچ) {
		نویسه *cp, pid_s[32];

		snprintf(pid_s, اندازه(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (نویسه *)پوچ);
		log_redirect_stderr_to(cp);
		آزاد(cp);
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
	اگر (getenv("KRB5CCNAME") != پوچ)
		(تهی) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_کلید = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	اگر (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	اگر (uname(&utsname) != 0) {
		memset(&utsname, 0, اندازه(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", اندازه(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	آزاد(args);

	/* Fetch our configuration */
	اگر ((cfg = sshbuf_new()) == پوچ)
		fatal("sshbuf_new config failed");
	اگر (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, پوچ, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	اگر (options.authorized_کلیدها_command_user == پوچ &&
	    (options.authorized_کلیدها_command != پوچ &&
	    strcasecmp(options.authorized_کلیدها_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	اگر (options.authorized_principals_command_user == پوچ &&
	    (options.authorized_principals_command != پوچ &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	اگر (options.رقم_auth_methods != 0) {
		برای (i = 0; i < options.رقم_auth_methods; i++) {
			اگر (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				بشکن;
		}
		اگر (i >= options.رقم_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	اگر (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	اگر (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_کلیدها = xcalloc(options.رقم_host_کلید_files,
	    اندازه(ساختار sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.رقم_host_کلید_files,
	    اندازه(ساختار sshkey *));

	اگر (options.host_کلید_agent) {
		اگر (strcmp(options.host_کلید_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_کلید_agent, 1);
		اگر ((r = ssh_get_authentication_socket(پوچ)) == 0)
			have_agent = 1;
		وگرنه
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_کلید_agent);
	}

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		صحیح ll = options.host_کلید_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		اگر (options.host_کلید_files[i] == پوچ)
			ادامه;
		اگر ((r = sshkey_load_private(options.host_کلید_files[i], "",
		    &کلید, پوچ)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_کلید_files[i]);
		اگر (sshkey_is_sk(کلید) &&
		    کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_کلید_files[i]);
			کلید->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		اگر (r == 0 && کلید != پوچ &&
		    (r = sshkey_shield_private(کلید)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_کلید_files[i]);
			sshkey_free(کلید);
			کلید = پوچ;
		}
		اگر ((r = sshkey_load_public(options.host_کلید_files[i],
		    &pubkey, پوچ)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_کلید_files[i]);
		اگر (pubkey != پوچ && کلید != پوچ) {
			اگر (!sshkey_equal(pubkey, کلید)) {
				error("Public key for %s does not match "
				    "private key", options.host_کلید_files[i]);
				sshkey_free(pubkey);
				pubkey = پوچ;
			}
		}
		اگر (pubkey == پوچ && کلید != پوچ) {
			اگر ((r = sshkey_from_private(کلید, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_کلید_files[i]);
		}
		اگر (pubkey != پوچ && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_کلید_files[i]);
			sshkey_free(pubkey);
			sshkey_free(کلید);
			ادامه;
		}
		sensitive_data.host_کلیدها[i] = کلید;
		sensitive_data.host_pubkeys[i] = pubkey;

		اگر (کلید == پوچ && pubkey != پوچ && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_کلید_files[i]);
			keytype = pubkey->type;
		} وگرنه اگر (کلید != پوچ) {
			keytype = کلید->type;
			accumulate_host_timing_secret(cfg, کلید);
		} وگرنه {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_کلید_files[i]);
			sensitive_data.host_کلیدها[i] = پوچ;
			sensitive_data.host_pubkeys[i] = پوچ;
			ادامه;
		}

		انتخاب (keytype) {
		حالت کلید_RSA:
		حالت کلید_ECDSA:
		حالت کلید_ED25519:
		حالت کلید_MLDSA44_ED25519:
		حالت کلید_ECDSA_SK:
		حالت کلید_ED25519_SK:
			اگر (have_agent || کلید != پوچ)
				sensitive_data.have_ssh2_کلید = 1;
			بشکن;
		}
		اگر ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == پوچ)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    کلید ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		آزاد(fp);
	}
	accumulate_host_timing_secret(cfg, پوچ);
	اگر (!sensitive_data.have_ssh2_کلید) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.رقم_host_کلید_files,
	    اندازه(ساختار sshkey *));
	برای (i = 0; i < options.رقم_host_کلید_files; i++)
		sensitive_data.host_certificates[i] = پوچ;

	برای (i = 0; i < options.رقم_host_cert_files; i++) {
		اگر (options.host_cert_files[i] == پوچ)
			ادامه;
		اگر ((r = sshkey_load_public(options.host_cert_files[i],
		    &کلید, پوچ)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			ادامه;
		}
		اگر (!sshkey_is_cert(کلید)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(کلید);
			ادامه;
		}
		/* Find matching private key */
		برای (j = 0; j < options.رقم_host_کلید_files; j++) {
			اگر (sshkey_equal_public(کلید,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = کلید;
				بشکن;
			}
		}
		اگر (j >= options.رقم_host_کلید_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(کلید);
			ادامه;
		}
		sensitive_data.host_certificates[j] = کلید;
		debug("host certificate: #%u type %d %s", j, کلید->type,
		    sshkey_type(کلید));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	اگر ((getpwnam(SSH_PRIVSEP_USER)) == پوچ && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	اگر (need_chroot) {
		اگر ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		اگر (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#وگرنه
		اگر (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
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
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	اگر (setgroups(0, پوچ) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	اگر (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, اندازه(نویسه *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	برای (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = پوچ;
	اگر (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	اگر (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(تهی) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	اگر (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	برای (i = 0; i < options.رقم_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

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
	} وگرنه {
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
		اگر (options.pid_file != پوچ && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			اگر (f == پوچ) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} وگرنه {
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
	اگر (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
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
	log_redirect_stderr_to(پوچ);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
تهی
cleanup_exit(صحیح i)
{
	_exit(i);
}
