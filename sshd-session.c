/* $OpenBSD: sshd-session.c,v 1.26 2026/09/16 00:13:58 djm Exp $ */
/*
 * SSH2 implementation:
 * Privilege Separation:
 *
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
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/tree.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <grp.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>

#ifdef HAVE_SECUREWARE
#অন্তর্ভাব <sys/security.h>
#অন্তর্ভাব <prot.h>
#endif
 
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "sshpty.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "uidswap.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "dispatch.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "session.h"
#অন্তর্ভাব "monitor.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "version.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sk-api.h"
#অন্তর্ভাব "srclimit.h"
#অন্তর্ভাব "dh.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

বাহ্য বর্ণ *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
বর্ণ *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
পূর্ণাঙ্ক debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
স্থির পূর্ণাঙ্ক inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
স্থির পূর্ণাঙ্ক log_stderr = 0;

/* Saved arguments to main(). */
স্থির বর্ণ **saved_argv;
স্থির পূর্ণাঙ্ক saved_argc;

/* Daemon's agent connection */
পূর্ণাঙ্ক auth_sock = -1;
স্থির পূর্ণাঙ্ক have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
সংরচনা {
	u_int		অঙ্ক_hostkeys;
	সংরচনা sshkey	**host_চাবিগুলি;		/* all private host keys */
	সংরচনা sshkey	**host_pubkeys;		/* all public host keys */
	সংরচনা sshkey	**host_certificates;	/* all public host certificates */
} sensitive_data;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

স্থির পূর্ণাঙ্ক startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
সংরচনা monitor *pmonitor = রিক্ত;
পূর্ণাঙ্ক privsep_is_preauth = 1;
স্থির পূর্ণাঙ্ক privsep_chroot = 1;

/* Unprivileged user */
সংরচনা passwd *privsep_pw = রিক্ত;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = রিক্ত;
সংরচনা ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
সংরচনা sshauthopt *auth_opts = রিক্ত;

/* sshd_config buffer */
সংরচনা sshbuf *cfg;

/* Included files from the configuration file */
সংরচনা include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
সংরচনা sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
শূন্য destroy_sensitive_data(শূন্য);
শূন্য demote_sensitive_data(শূন্য);

/* XXX reduce to stub once postauth split */
পূর্ণাঙ্ক
mm_is_monitor(শূন্য)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	প্রত্যাগম (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
স্থির শূন্য
grace_alarm_handler(পূর্ণাঙ্ক sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	যদি (getpgid(0) == getpid()) {
		সংরচনা sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, পরিমাণ(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#যদি defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#endif
		(শূন্য)sigaction(SIGTERM, &sa, রিক্ত);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
শূন্য
destroy_sensitive_data(শূন্য)
{
	u_int i;

	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		যদি (sensitive_data.host_চাবিগুলি[i]) {
			sshkey_free(sensitive_data.host_চাবিগুলি[i]);
			sensitive_data.host_চাবিগুলি[i] = রিক্ত;
		}
		যদি (sensitive_data.host_certificates[i]) {
			sshkey_free(sensitive_data.host_certificates[i]);
			sensitive_data.host_certificates[i] = রিক্ত;
		}
	}
}

/* Demote private to public keys for network child */
শূন্য
demote_sensitive_data(শূন্য)
{
	সংরচনা sshkey *tmp;
	u_int i;
	পূর্ণাঙ্ক r;

	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		যদি (sensitive_data.host_চাবিগুলি[i]) {
			যদি ((r = sshkey_from_private(
			    sensitive_data.host_চাবিগুলি[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_data.host_চাবিগুলি[i]));
			sshkey_free(sensitive_data.host_চাবিগুলি[i]);
			sensitive_data.host_চাবিগুলি[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

সংরচনা sshbuf *
pack_hostkeys(শূন্য)
{
	সংরচনা sshbuf *keybuf = রিক্ত, *hostkeys = রিক্ত;
	পূর্ণাঙ্ক r;
	u_int i;

	যদি ((hostkeys = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		/* public key */
		যদি (sensitive_data.host_pubkeys[i] != রিক্ত) {
			যদি ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} অন্যথা {
			যদি ((r = sshbuf_put_string(hostkeys, রিক্ত, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		যদি (sensitive_data.host_certificates[i] != রিক্ত) {
			যদি ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} অন্যথা {
			যদি ((r = sshbuf_put_string(hostkeys, রিক্ত, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	sshbuf_free(keybuf);
	প্রত্যাগম hostkeys;
}

স্থির পূর্ণাঙ্ক
privsep_preauth(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	যদি ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	অন্যথা যদি (pid != 0) {
		debug2("Network child is on pid %ld", (long)pid);

		pmonitor->m_pid = pid;
		যদি (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			যদি (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		প্রত্যাগম 1;
	} অন্যথা {
		/* child */
		close(pmonitor->m_sendfd);
		close(pmonitor->m_log_recvfd);

		/*
		 * Arrange unpriv-preauth child process fds:
		 * 0, 1 network socket
		 * 2 optional stderr
		 * 3 reserved
		 * 4 monitor message socket
		 * 5 monitor logging socket
		 *
		 * We know that the monitor sockets will have fds > 4 because
		 * of the reserved fds in main()
		 */

		যদি (ssh_packet_get_connection_in(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_in(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		যদি (ssh_packet_get_connection_out(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_out(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_to(রিক্ত); /* dup can clobber log fd */
		যদি (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		যদি (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_path;
		execv(options.sshd_auth_path, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_path, strerror(errno));
	}
}

স্থির শূন্য
privsep_postauth(সংরচনা ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	যদি (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	অন্যথা যদি (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (long)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_child_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		exit(0);
	}

	/* child */

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_data();

	reseed_prngs();

#ifndef SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#endif

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_set_authenticated(ssh);
}

স্থির সংরচনা sshkey *
get_hostkey_by_type(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid, পূর্ণাঙ্ক need_private, সংরচনা ssh *ssh)
{
	u_int i;
	সংরচনা sshkey *চাবি;

	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		বিকল্প (type) {
		পক্ষ চাবি_RSA_CERT:
		পক্ষ চাবি_ECDSA_CERT:
		পক্ষ চাবি_ED25519_CERT:
		পক্ষ চাবি_ECDSA_SK_CERT:
		পক্ষ চাবি_ED25519_SK_CERT:
		পক্ষ চাবি_MLDSA44_ED25519_CERT:
			চাবি = sensitive_data.host_certificates[i];
			ভঙ্গ;
		স্বভাব:
			চাবি = sensitive_data.host_চাবিগুলি[i];
			যদি (চাবি == রিক্ত && !need_private)
				চাবি = sensitive_data.host_pubkeys[i];
			ভঙ্গ;
		}
		যদি (চাবি == রিক্ত || চাবি->type != type)
			অনুবর্ত;
		বিকল্প (type) {
		পক্ষ চাবি_ECDSA:
		পক্ষ চাবি_ECDSA_SK:
		পক্ষ চাবি_ECDSA_CERT:
		পক্ষ চাবি_ECDSA_SK_CERT:
			যদি (চাবি->ecdsa_nid != nid)
				অনুবর্ত;
			/* FALLTHROUGH */
		স্বভাব:
			প্রত্যাগম need_private ?
			    sensitive_data.host_চাবিগুলি[i] : চাবি;
		}
	}
	প্রত্যাগম রিক্ত;
}

সংরচনা sshkey *
get_hostkey_public_by_type(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid, সংরচনা ssh *ssh)
{
	প্রত্যাগম get_hostkey_by_type(type, nid, 0, ssh);
}

সংরচনা sshkey *
get_hostkey_private_by_type(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid, সংরচনা ssh *ssh)
{
	প্রত্যাগম get_hostkey_by_type(type, nid, 1, ssh);
}

সংরচনা sshkey *
get_hostkey_by_index(পূর্ণাঙ্ক ind)
{
	যদি (ind < 0 || (u_int)ind >= options.অঙ্ক_host_চাবি_files)
		প্রত্যাগম (রিক্ত);
	প্রত্যাগম (sensitive_data.host_চাবিগুলি[ind]);
}

সংরচনা sshkey *
get_hostkey_public_by_index(পূর্ণাঙ্ক ind, সংরচনা ssh *ssh)
{
	যদি (ind < 0 || (u_int)ind >= options.অঙ্ক_host_চাবি_files)
		প্রত্যাগম (রিক্ত);
	প্রত্যাগম (sensitive_data.host_pubkeys[ind]);
}

পূর্ণাঙ্ক
get_hostkey_index(সংরচনা sshkey *চাবি, পূর্ণাঙ্ক compare, সংরচনা ssh *ssh)
{
	u_int i;

	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		যদি (sshkey_is_cert(চাবি)) {
			যদি (চাবি == sensitive_data.host_certificates[i] ||
			    (compare && sensitive_data.host_certificates[i] &&
			    sshkey_equal(চাবি,
			    sensitive_data.host_certificates[i])))
				প্রত্যাগম (i);
		} অন্যথা {
			যদি (চাবি == sensitive_data.host_চাবিগুলি[i] ||
			    (compare && sensitive_data.host_চাবিগুলি[i] &&
			    sshkey_equal(চাবি, sensitive_data.host_চাবিগুলি[i])))
				প্রত্যাগম (i);
			যদি (চাবি == sensitive_data.host_pubkeys[i] ||
			    (compare && sensitive_data.host_pubkeys[i] &&
			    sshkey_equal(চাবি, sensitive_data.host_pubkeys[i])))
				প্রত্যাগম (i);
		}
	}
	প্রত্যাগম (-1);
}

/* Inform the client of all hostkeys */
স্থির শূন্য
notify_hostkeys(সংরচনা ssh *ssh)
{
	সংরচনা sshbuf *buf;
	সংরচনা sshkey *চাবি;
	u_int i, nkeys;
	পূর্ণাঙ্ক r;
	বর্ণ *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	যদি (ssh->compat & SSH_BUG_HOSTKEYS)
		প্রত্যাগম;

	যদি ((buf = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	প্রতি (i = nkeys = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		চাবি = get_hostkey_public_by_index(i, ssh);
		যদি (চাবি == রিক্ত || চাবি->type == চাবি_UNSPEC ||
		    sshkey_is_cert(চাবি))
			অনুবর্ত;
		fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(চাবি), fp);
		মুক্ত(fp);
		যদি (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		যদি ((r = sshkey_putb(চাবি, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		যদি ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	যদি (nkeys == 0)
		fatal_f("no hostkeys");
	যদি ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

স্থির শূন্য
parse_hostkeys(সংরচনা sshbuf *hostkeys)
{
	পূর্ণাঙ্ক r;
	u_int অঙ্ক_চাবিগুলি = 0;
	সংরচনা sshkey *k;
	সংরচনা sshbuf *kbuf;
	ধ্রুব u_char *cp;
	size_t len;

	যাবত্ (sshbuf_len(hostkeys) != 0) {
		যদি (অঙ্ক_চাবিগুলি > 2048)
			fatal_f("too many hostkeys");
		sensitive_data.host_চাবিগুলি = xrecallocarray(
		    sensitive_data.host_চাবিগুলি, অঙ্ক_চাবিগুলি, অঙ্ক_চাবিগুলি + 1,
		    পরিমাণ(*sensitive_data.host_pubkeys));
		sensitive_data.host_pubkeys = xrecallocarray(
		    sensitive_data.host_pubkeys, অঙ্ক_চাবিগুলি, অঙ্ক_চাবিগুলি + 1,
		    পরিমাণ(*sensitive_data.host_pubkeys));
		sensitive_data.host_certificates = xrecallocarray(
		    sensitive_data.host_certificates, অঙ্ক_চাবিগুলি, অঙ্ক_চাবিগুলি + 1,
		    পরিমাণ(*sensitive_data.host_certificates));
		/* private key */
		k = রিক্ত;
		যদি ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		যদি (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_private_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_চাবিগুলি[অঙ্ক_চাবিগুলি] = k;
		sshbuf_free(kbuf);
		যদি (k)
			debug2_f("privkey %u: %s", অঙ্ক_চাবিগুলি, sshkey_ssh_name(k));
		/* public key */
		k = রিক্ত;
		যদি ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		যদি (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_pubkeys[অঙ্ক_চাবিগুলি] = k;
		যদি (k)
			debug2_f("pubkey %u: %s", অঙ্ক_চাবিগুলি, sshkey_ssh_name(k));
		/* certificate */
		k = রিক্ত;
		যদি ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		যদি (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_certificates[অঙ্ক_চাবিগুলি] = k;
		যদি (k)
			debug2_f("cert %u: %s", অঙ্ক_চাবিগুলি, sshkey_ssh_name(k));
		অঙ্ক_চাবিগুলি++;
	}
	sensitive_data.অঙ্ক_hostkeys = অঙ্ক_চাবিগুলি;
}

স্থির শূন্য
recv_rexec_state(পূর্ণাঙ্ক fd, সংরচনা sshbuf *conf, uint64_t *timing_secretp)
{
	সংরচনা sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	size_t len;
	পূর্ণাঙ্ক r;
	সংরচনা include_item *item;

	debug3_f("entering fd = %d", fd);

	যদি ((m = sshbuf_new()) == রিক্ত || (inc = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	/* receive config */
	যদি (ssh_বার্তা_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	যদি ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	যদি (ver != 0)
		fatal_f("rexec version mismatch");
	যদি ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	যদি (conf != রিক্ত && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	যাবত্ (sshbuf_len(inc) != 0) {
		item = xcalloc(1, পরিমাণ(*item));
		যদি ((item->contents = sshbuf_new()) == রিক্ত)
			fatal_f("sshbuf_new failed");
		যদি ((r = sshbuf_get_cstring(inc, &item->selector, রিক্ত)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, রিক্ত)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	যদি (ssh_বার্তা_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	যদি ((r = sshbuf_get_u8(m, রিক্ত)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	মুক্ত(cp);
	sshbuf_free(m);
	sshbuf_free(hostkeys);
	sshbuf_free(inc);

	debug3_f("done");
}

/*
 * If IP options are supported, make sure there are none (log and
 * return an error if any are found).  Basically we are worried about
 * source routing; it can be used to pretend you are somebody
 * (ip-address) you are not. That itself may be "almost acceptable"
 * under certain circumstances, but rhosts authentication is useless
 * if source routing is accepted. Notice also that if we just dropped
 * source routing here, the other side could use IP spoofing to do
 * rest of the interaction and could still bypass security.  So we
 * exit here if we detect any IP options.
 */
স্থির শূন্য
check_ip_options(সংরচনা ssh *ssh)
{
#ifdef IP_OPTIONS
	পূর্ণাঙ্ক sock_in = ssh_packet_get_connection_in(ssh);
	সংরচনা sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_size = পরিমাণ(opts), fromlen = পরিমাণ(from);
	বর্ণ text[পরিমাণ(opts) * 3 + 1];

	memset(&from, 0, পরিমাণ(from));
	যদি (getpeername(sock_in, (সংরচনা sockaddr *)&from,
	    &fromlen) == -1)
		প্রত্যাগম;
	যদি (from.ss_family != AF_INET)
		প্রত্যাগম;
	/* XXX IPv6 options? */

	যদি (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_size) >= 0 && option_size != 0) {
		text[0] = '\0';
		প্রতি (i = 0; i < option_size; i++)
			snprintf(text + i*3, পরিমাণ(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#endif /* IP_OPTIONS */
}

/* Set the routing domain for this process */
স্থির শূন্য
set_process_rdomain(সংরচনা ssh *ssh, ধ্রুব বর্ণ *name)
{
#যদি defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	যদি (name == রিক্ত)
		প্রত্যাগম; /* default */

	যদি (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		যদি ((name = ssh_packet_rdomain_in(ssh)) == রিক্ত)
			প্রত্যাগম;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	প্রত্যাগম sys_set_process_rdomain(name);
#নোচেদ্যদি defined(__OpenBSD__)
	পূর্ণাঙ্ক rtable, ortable = getrtable();
	ধ্রুব বর্ণ *errstr;

	যদি (name == রিক্ত)
		প্রত্যাগম; /* default */

	যদি (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		যদি ((name = ssh_packet_rdomain_in(ssh)) == রিক্ত)
			প্রত্যাগম;
	}

	rtable = (পূর্ণাঙ্ক)strtonum(name, 0, 255, &errstr);
	যদি (errstr != রিক্ত) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	যদি (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#অন্যথা /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#endif
}

/*
 * Main program for the daemon.
 */
পূর্ণাঙ্ক
main(পূর্ণাঙ্ক ac, বর্ণ **av)
{
	সংরচনা ssh *ssh = রিক্ত;
	বাহ্য বর্ণ *optarg;
	বাহ্য পূর্ণাঙ্ক optind;
	পূর্ণাঙ্ক devnull, r, opt, remote_port;
	পূর্ণাঙ্ক sock_in = -1, sock_out = -1, rexeced_flag = 0, have_চাবি = 0;
	ধ্রুব বর্ণ *remote_ip, *rdomain;
	বর্ণ *সারি, *laddr, *logfile = রিক্ত;
	u_int i;
	uint64_t ibytes, obytes;
	mode_t new_umask;
	Authctxt *authctxt;
	সংরচনা connection_info *connection_info = রিক্ত;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	সংরচনা itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, রিক্ত);

#ifdef HAVE_SECUREWARE
	(শূন্য)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, পরিমাণ(*saved_argv));
	প্রতি (i = 0; (পূর্ণাঙ্ক)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = রিক্ত;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	যাবত্ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		বিকল্প (opt) {
		পক্ষ '4':
			options.address_family = AF_INET;
			ভঙ্গ;
		পক্ষ '6':
			options.address_family = AF_INET6;
			ভঙ্গ;
		পক্ষ 'f':
			config_file_name = optarg;
			ভঙ্গ;
		পক্ষ 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			ভঙ্গ;
		পক্ষ 'd':
			যদি (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} অন্যথা যদি (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ভঙ্গ;
		পক্ষ 'D':
			/* ignore */
			ভঙ্গ;
		পক্ষ 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		পক্ষ 'e':
			log_stderr = 1;
			ভঙ্গ;
		পক্ষ 'i':
			inetd_flag = 1;
			ভঙ্গ;
		পক্ষ 'r':
			/* ignore */
			ভঙ্গ;
		পক্ষ 'R':
			rexeced_flag = 1;
			ভঙ্গ;
		পক্ষ 'Q':
			/* ignored */
			ভঙ্গ;
		পক্ষ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ভঙ্গ;
		পক্ষ 'b':
			/* protocol 1, ignored */
			ভঙ্গ;
		পক্ষ 'p':
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
			ভঙ্গ;
		পক্ষ 'g':
			যদি ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			ভঙ্গ;
		পক্ষ 'k':
			/* protocol 1, ignored */
			ভঙ্গ;
		পক্ষ 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			ভঙ্গ;
		পক্ষ 't':
		পক্ষ 'T':
		পক্ষ 'G':
			fatal("test/dump modes not supported");
			ভঙ্গ;
		পক্ষ 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			যদি (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			ভঙ্গ;
		পক্ষ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, রিক্ত);
			যদি (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			ভঙ্গ;
		পক্ষ 'o':
			সারি = xstrdup(optarg);
			যদি (process_server_config_সারি(&options, সারি,
			    "command-line", 0, রিক্ত, রিক্ত, &includes) != 0)
				exit(1);
			মুক্ত(সারি);
			ভঙ্গ;
		পক্ষ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		স্বভাব:
			usage();
			ভঙ্গ;
		}
	}

	/* Check that there are no remaining arguments. */
	যদি (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	যদি (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	যদি ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	যাবত্ (devnull < PRIVSEP_MIN_FREE_FD) {
		যদি ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	যদি (logfile != রিক্ত) {
		বর্ণ *cp, pid_s[32];

		snprintf(pid_s, পরিমাণ(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd-session",
		    (বর্ণ *)রিক্ত);
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

	/* Fetch our configuration */
	যদি ((cfg = sshbuf_new()) == রিক্ত)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, রিক্ত, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	যদি ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == রিক্ত) {
		যদি (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} অন্যথা {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	যদি (!debug_flag && !inetd_flag) {
		যদি ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(শূন্য)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	যদি (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

	/* Check that options are sensible */
	যদি (options.authorized_চাবিগুলি_command_user == রিক্ত &&
	    (options.authorized_চাবিগুলি_command != রিক্ত &&
	    strcasecmp(options.authorized_চাবিগুলি_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	যদি (options.authorized_principals_command_user == রিক্ত &&
	    (options.authorized_principals_command != রিক্ত &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match block, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	যদি (options.অঙ্ক_auth_methods != 0) {
		প্রতি (i = 0; i < options.অঙ্ক_auth_methods; i++) {
			যদি (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				ভঙ্গ;
		}
		যদি (i >= options.অঙ্ক_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

#ifdef WITH_OPENSSL
	যদি (options.moduli_file != রিক্ত)
		dh_set_moduli_file(options.moduli_file);
#endif

	যদি (options.host_চাবি_agent) {
		যদি (strcmp(options.host_চাবি_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_চাবি_agent, 1);
		যদি ((r = ssh_get_authentication_socket(রিক্ত)) == 0)
			have_agent = 1;
		অন্যথা
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_চাবি_agent);
	}

	যদি (options.অঙ্ক_host_চাবি_files != sensitive_data.অঙ্ক_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.অঙ্ক_host_চাবি_files, sensitive_data.অঙ্ক_hostkeys);
	}

	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		যদি (sensitive_data.host_চাবিগুলি[i] != রিক্ত ||
		    (have_agent && sensitive_data.host_pubkeys[i] != রিক্ত)) {
			have_চাবি = 1;
			ভঙ্গ;
		}
	}
	যদি (!have_চাবি)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(শূন্য) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	যদি (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	প্রতি (i = 0; i < options.অঙ্ক_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	যদি (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} অন্যথা {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	যদি (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_out);
	FD_CLOSEONEXEC(sock_in);

	/* We will not restart on SIGHUP since it no longer makes sense. */
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);
	ssh_signal(SIGINT, SIG_DFL);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	যদি ((ssh = ssh_packet_set_connection(রিক্ত, sock_in, sock_out)) == রিক্ত)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_set_af(ssh, options.address_family);
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	/* Set SO_KEEPALIVE if requested. */
	যদি (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		set_keepalive(sock_in); /* logs errors */

	যদি ((remote_port = ssh_remote_port(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#ifdef SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_port);
#endif

	rdomain = ssh_packet_rdomain_in(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_in);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_port, laddr,  ssh_local_port(ssh),
	    rdomain == রিক্ত ? "" : " rdomain \"",
	    rdomain == রিক্ত ? "" : rdomain,
	    rdomain == রিক্ত ? "" : "\"");
	মুক্ত(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	যদি (!debug_flag && options.login_grace_time > 0) {
		পূর্ণাঙ্ক ujitter = arc4random_uniform(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		যদি (setitimer(ITIMER_REAL, &itv, রিক্ত) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, পরিমাণ(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	যদি ((auth_opts = sshauthopt_new_with_চাবিগুলি_defaults()) == রিক্ত)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	যদি ((loginmsg = sshbuf_new()) == রিক্ত)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	যদি (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	যদি (setitimer(ITIMER_REAL, &itv, রিক্ত) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	যদি (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(শূন্য)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	যদি (options.routing_domain != রিক্ত)
		set_process_rdomain(ssh, options.routing_domain);

#ifdef SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#endif

#ifdef GSSAPI
	যদি (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#endif
#ifdef USE_PAM
	যদি (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#endif

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_set_timeout(ssh, options.client_alive_interval,
	    options.client_alive_গুনতি_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (unsigned long long)obytes, (unsigned long long)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_port);

#ifdef USE_PAM
	যদি (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

#ifdef SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#endif

	ssh_packet_close(ssh);

	mm_terminate();

	exit(0);
}

পূর্ণাঙ্ক
sshd_hostkey_sign(সংরচনা ssh *ssh, সংরচনা sshkey *privkey,
    সংরচনা sshkey *pubkey, u_char **signature, size_t *slenp,
    ধ্রুব u_char *data, size_t dlen, ধ্রুব বর্ণ *alg)
{
	যদি (privkey) {
		যদি (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, রিক্ত,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} অন্যথা {
		যদি (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, রিক্ত,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	প্রত্যাগম 0;
}

/* server specific fatal cleanup */
শূন্য
cleanup_exit(পূর্ণাঙ্ক i)
{
	যদি (the_active_state != রিক্ত && the_authctxt != রিক্ত) {
		do_cleanup(the_active_state, the_authctxt);
		যদি (privsep_is_preauth &&
		    pmonitor != রিক্ত && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			যদি (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ifdef SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	যদি (the_active_state != রিক্ত && mm_is_monitor())
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#endif
	/* Override default fatal exit value when auth was attempted */
	যদি (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	যদি (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
