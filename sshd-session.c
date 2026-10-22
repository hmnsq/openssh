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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#شامل <sys/wait.h>
#شامل <sys/tree.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/time.h>
#شامل <sys/queue.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <grp.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>
#شامل <limits.h>

#ifdef HAVE_SECUREWARE
#شامل <sys/security.h>
#شامل <prot.h>
#endif
 
#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "sshpty.h"
#شامل "packet.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "match.h"
#شامل "servconf.h"
#شامل "uidswap.h"
#شامل "compat.h"
#شامل "cipher.h"
#شامل "digest.h"
#شامل "sshkey.h"
#شامل "kex.h"
#شامل "authfile.h"
#شامل "pathnames.h"
#شامل "atomicio.h"
#شامل "canohost.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "authfd.h"
#شامل "msg.h"
#شامل "dispatch.h"
#شامل "channels.h"
#شامل "session.h"
#شامل "monitor.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "auth-options.h"
#شامل "version.h"
#شامل "ssherr.h"
#شامل "sk-api.h"
#شامل "srclimit.h"
#شامل "dh.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

بیرونی نویسه *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
نویسه *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
صحیح debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ایستا صحیح inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
ایستا صحیح log_stderr = 0;

/* Saved arguments to main(). */
ایستا نویسه **saved_argv;
ایستا صحیح saved_argc;

/* Daemon's agent connection */
صحیح auth_sock = -1;
ایستا صحیح have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ساختار {
	u_int		رقم_hostkeys;
	ساختار sshkey	**host_کلیدها;		/* all private host keys */
	ساختار sshkey	**host_pubkeys;		/* all public host keys */
	ساختار sshkey	**host_certificates;	/* all public host certificates */
} sensitive_data;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

ایستا صحیح startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
ساختار monitor *pmonitor = پوچ;
صحیح privsep_is_preauth = 1;
ایستا صحیح privsep_chroot = 1;

/* Unprivileged user */
ساختار passwd *privsep_pw = پوچ;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = پوچ;
ساختار ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ساختار sshauthopt *auth_opts = پوچ;

/* sshd_config buffer */
ساختار sshbuf *cfg;

/* Included files from the configuration file */
ساختار include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ساختار sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
تهی destroy_sensitive_data(تهی);
تهی demote_sensitive_data(تهی);

/* XXX reduce to stub once postauth split */
صحیح
mm_is_monitor(تهی)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	بازگشت (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
ایستا تهی
grace_alarm_handler(صحیح sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	اگر (getpgid(0) == getpid()) {
		ساختار sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, اندازه(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#اگر defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#endif
		(تهی)sigaction(SIGTERM, &sa, پوچ);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
تهی
destroy_sensitive_data(تهی)
{
	u_int i;

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		اگر (sensitive_data.host_کلیدها[i]) {
			sshkey_free(sensitive_data.host_کلیدها[i]);
			sensitive_data.host_کلیدها[i] = پوچ;
		}
		اگر (sensitive_data.host_certificates[i]) {
			sshkey_free(sensitive_data.host_certificates[i]);
			sensitive_data.host_certificates[i] = پوچ;
		}
	}
}

/* Demote private to public keys for network child */
تهی
demote_sensitive_data(تهی)
{
	ساختار sshkey *tmp;
	u_int i;
	صحیح r;

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		اگر (sensitive_data.host_کلیدها[i]) {
			اگر ((r = sshkey_from_private(
			    sensitive_data.host_کلیدها[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_data.host_کلیدها[i]));
			sshkey_free(sensitive_data.host_کلیدها[i]);
			sensitive_data.host_کلیدها[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

ساختار sshbuf *
pack_hostkeys(تهی)
{
	ساختار sshbuf *keybuf = پوچ, *hostkeys = پوچ;
	صحیح r;
	u_int i;

	اگر ((hostkeys = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
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

	sshbuf_free(keybuf);
	بازگشت hostkeys;
}

ایستا صحیح
privsep_preauth(ساختار ssh *ssh)
{
	صحیح r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	اگر ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	وگرنه اگر (pid != 0) {
		debug2("Network child is on pid %ld", (long)pid);

		pmonitor->m_pid = pid;
		اگر (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			اگر (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		بازگشت 1;
	} وگرنه {
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

		اگر (ssh_packet_get_connection_in(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_in(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		اگر (ssh_packet_get_connection_out(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_out(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_to(پوچ); /* dup can clobber log fd */
		اگر (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		اگر (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_path;
		execv(options.sshd_auth_path, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_path, strerror(errno));
	}
}

ایستا تهی
privsep_postauth(ساختار ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	اگر (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	وگرنه اگر (pmonitor->m_pid != 0) {
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

ایستا ساختار sshkey *
get_hostkey_by_type(صحیح type, صحیح nid, صحیح need_private, ساختار ssh *ssh)
{
	u_int i;
	ساختار sshkey *کلید;

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		انتخاب (type) {
		حالت کلید_RSA_CERT:
		حالت کلید_ECDSA_CERT:
		حالت کلید_ED25519_CERT:
		حالت کلید_ECDSA_SK_CERT:
		حالت کلید_ED25519_SK_CERT:
		حالت کلید_MLDSA44_ED25519_CERT:
			کلید = sensitive_data.host_certificates[i];
			بشکن;
		پیشفرض:
			کلید = sensitive_data.host_کلیدها[i];
			اگر (کلید == پوچ && !need_private)
				کلید = sensitive_data.host_pubkeys[i];
			بشکن;
		}
		اگر (کلید == پوچ || کلید->type != type)
			ادامه;
		انتخاب (type) {
		حالت کلید_ECDSA:
		حالت کلید_ECDSA_SK:
		حالت کلید_ECDSA_CERT:
		حالت کلید_ECDSA_SK_CERT:
			اگر (کلید->ecdsa_nid != nid)
				ادامه;
			/* FALLTHROUGH */
		پیشفرض:
			بازگشت need_private ?
			    sensitive_data.host_کلیدها[i] : کلید;
		}
	}
	بازگشت پوچ;
}

ساختار sshkey *
get_hostkey_public_by_type(صحیح type, صحیح nid, ساختار ssh *ssh)
{
	بازگشت get_hostkey_by_type(type, nid, 0, ssh);
}

ساختار sshkey *
get_hostkey_private_by_type(صحیح type, صحیح nid, ساختار ssh *ssh)
{
	بازگشت get_hostkey_by_type(type, nid, 1, ssh);
}

ساختار sshkey *
get_hostkey_by_index(صحیح ind)
{
	اگر (ind < 0 || (u_int)ind >= options.رقم_host_کلید_files)
		بازگشت (پوچ);
	بازگشت (sensitive_data.host_کلیدها[ind]);
}

ساختار sshkey *
get_hostkey_public_by_index(صحیح ind, ساختار ssh *ssh)
{
	اگر (ind < 0 || (u_int)ind >= options.رقم_host_کلید_files)
		بازگشت (پوچ);
	بازگشت (sensitive_data.host_pubkeys[ind]);
}

صحیح
get_hostkey_index(ساختار sshkey *کلید, صحیح compare, ساختار ssh *ssh)
{
	u_int i;

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		اگر (sshkey_is_cert(کلید)) {
			اگر (کلید == sensitive_data.host_certificates[i] ||
			    (compare && sensitive_data.host_certificates[i] &&
			    sshkey_equal(کلید,
			    sensitive_data.host_certificates[i])))
				بازگشت (i);
		} وگرنه {
			اگر (کلید == sensitive_data.host_کلیدها[i] ||
			    (compare && sensitive_data.host_کلیدها[i] &&
			    sshkey_equal(کلید, sensitive_data.host_کلیدها[i])))
				بازگشت (i);
			اگر (کلید == sensitive_data.host_pubkeys[i] ||
			    (compare && sensitive_data.host_pubkeys[i] &&
			    sshkey_equal(کلید, sensitive_data.host_pubkeys[i])))
				بازگشت (i);
		}
	}
	بازگشت (-1);
}

/* Inform the client of all hostkeys */
ایستا تهی
notify_hostkeys(ساختار ssh *ssh)
{
	ساختار sshbuf *buf;
	ساختار sshkey *کلید;
	u_int i, nkeys;
	صحیح r;
	نویسه *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	اگر (ssh->compat & SSH_BUG_HOSTKEYS)
		بازگشت;

	اگر ((buf = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	برای (i = nkeys = 0; i < options.رقم_host_کلید_files; i++) {
		کلید = get_hostkey_public_by_index(i, ssh);
		اگر (کلید == پوچ || کلید->type == کلید_UNSPEC ||
		    sshkey_is_cert(کلید))
			ادامه;
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(کلید), fp);
		آزاد(fp);
		اگر (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			اگر ((r = sshpkt_start(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		اگر ((r = sshkey_putb(کلید, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		اگر ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	اگر (nkeys == 0)
		fatal_f("no hostkeys");
	اگر ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

ایستا تهی
parse_hostkeys(ساختار sshbuf *hostkeys)
{
	صحیح r;
	u_int رقم_کلیدها = 0;
	ساختار sshkey *k;
	ساختار sshbuf *kbuf;
	ثابت u_char *cp;
	size_t len;

	وقتی (sshbuf_len(hostkeys) != 0) {
		اگر (رقم_کلیدها > 2048)
			fatal_f("too many hostkeys");
		sensitive_data.host_کلیدها = xrecallocarray(
		    sensitive_data.host_کلیدها, رقم_کلیدها, رقم_کلیدها + 1,
		    اندازه(*sensitive_data.host_pubkeys));
		sensitive_data.host_pubkeys = xrecallocarray(
		    sensitive_data.host_pubkeys, رقم_کلیدها, رقم_کلیدها + 1,
		    اندازه(*sensitive_data.host_pubkeys));
		sensitive_data.host_certificates = xrecallocarray(
		    sensitive_data.host_certificates, رقم_کلیدها, رقم_کلیدها + 1,
		    اندازه(*sensitive_data.host_certificates));
		/* private key */
		k = پوچ;
		اگر ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		اگر (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_private_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_کلیدها[رقم_کلیدها] = k;
		sshbuf_free(kbuf);
		اگر (k)
			debug2_f("privkey %u: %s", رقم_کلیدها, sshkey_ssh_name(k));
		/* public key */
		k = پوچ;
		اگر ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		اگر (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_pubkeys[رقم_کلیدها] = k;
		اگر (k)
			debug2_f("pubkey %u: %s", رقم_کلیدها, sshkey_ssh_name(k));
		/* certificate */
		k = پوچ;
		اگر ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		اگر (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_certificates[رقم_کلیدها] = k;
		اگر (k)
			debug2_f("cert %u: %s", رقم_کلیدها, sshkey_ssh_name(k));
		رقم_کلیدها++;
	}
	sensitive_data.رقم_hostkeys = رقم_کلیدها;
}

ایستا تهی
recv_rexec_state(صحیح fd, ساختار sshbuf *conf, uint64_t *timing_secretp)
{
	ساختار sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	size_t len;
	صحیح r;
	ساختار include_item *item;

	debug3_f("entering fd = %d", fd);

	اگر ((m = sshbuf_new()) == پوچ || (inc = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	/* receive config */
	اگر (ssh_پیام_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	اگر ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	اگر (ver != 0)
		fatal_f("rexec version mismatch");
	اگر ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	اگر (conf != پوچ && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	وقتی (sshbuf_len(inc) != 0) {
		item = xcalloc(1, اندازه(*item));
		اگر ((item->contents = sshbuf_new()) == پوچ)
			fatal_f("sshbuf_new failed");
		اگر ((r = sshbuf_get_cstring(inc, &item->selector, پوچ)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, پوچ)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	اگر (ssh_پیام_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	اگر ((r = sshbuf_get_u8(m, پوچ)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	آزاد(cp);
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
ایستا تهی
check_ip_options(ساختار ssh *ssh)
{
#ifdef IP_OPTIONS
	صحیح sock_in = ssh_packet_get_connection_in(ssh);
	ساختار sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_size = اندازه(opts), fromlen = اندازه(from);
	نویسه text[اندازه(opts) * 3 + 1];

	memset(&from, 0, اندازه(from));
	اگر (getpeername(sock_in, (ساختار sockaddr *)&from,
	    &fromlen) == -1)
		بازگشت;
	اگر (from.ss_family != AF_INET)
		بازگشت;
	/* XXX IPv6 options? */

	اگر (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_size) >= 0 && option_size != 0) {
		text[0] = '\0';
		برای (i = 0; i < option_size; i++)
			snprintf(text + i*3, اندازه(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#endif /* IP_OPTIONS */
}

/* Set the routing domain for this process */
ایستا تهی
set_process_rdomain(ساختار ssh *ssh, ثابت نویسه *name)
{
#اگر defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	اگر (name == پوچ)
		بازگشت; /* default */

	اگر (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		اگر ((name = ssh_packet_rdomain_in(ssh)) == پوچ)
			بازگشت;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	بازگشت sys_set_process_rdomain(name);
#وگرنهاگر defined(__OpenBSD__)
	صحیح rtable, ortable = getrtable();
	ثابت نویسه *errstr;

	اگر (name == پوچ)
		بازگشت; /* default */

	اگر (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		اگر ((name = ssh_packet_rdomain_in(ssh)) == پوچ)
			بازگشت;
	}

	rtable = (صحیح)strtonum(name, 0, 255, &errstr);
	اگر (errstr != پوچ) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	اگر (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#وگرنه /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#endif
}

/*
 * Main program for the daemon.
 */
صحیح
اصلی(صحیح ac, نویسه **av)
{
	ساختار ssh *ssh = پوچ;
	بیرونی نویسه *optarg;
	بیرونی صحیح optind;
	صحیح devnull, r, opt, remote_port;
	صحیح sock_in = -1, sock_out = -1, rexeced_flag = 0, have_کلید = 0;
	ثابت نویسه *remote_ip, *rdomain;
	نویسه *سطر, *laddr, *logfile = پوچ;
	u_int i;
	uint64_t ibytes, obytes;
	mode_t new_umask;
	Authctxt *authctxt;
	ساختار connection_info *connection_info = پوچ;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	ساختار itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, پوچ);

#ifdef HAVE_SECUREWARE
	(تهی)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, اندازه(*saved_argv));
	برای (i = 0; (صحیح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = پوچ;

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
			/* ignore */
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
			/* ignore */
			بشکن;
		حالت 'R':
			rexeced_flag = 1;
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
		حالت 'T':
		حالت 'G':
			fatal("test/dump modes not supported");
			بشکن;
		حالت 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			اگر (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			بشکن;
		حالت 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, پوچ);
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

	/* Check that there are no remaining arguments. */
	اگر (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	اگر (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	اگر ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	وقتی (devnull < PRIVSEP_MIN_FREE_FD) {
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
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	اگر ((cfg = sshbuf_new()) == پوچ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, پوچ, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	اگر ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == پوچ) {
		اگر (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} وگرنه {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	اگر (!debug_flag && !inetd_flag) {
		اگر ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(تهی)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	اگر (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

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
	 * daemonisation in the presence of Match block, but this catches
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

#ifdef WITH_OPENSSL
	اگر (options.moduli_file != پوچ)
		dh_set_moduli_file(options.moduli_file);
#endif

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

	اگر (options.رقم_host_کلید_files != sensitive_data.رقم_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.رقم_host_کلید_files, sensitive_data.رقم_hostkeys);
	}

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		اگر (sensitive_data.host_کلیدها[i] != پوچ ||
		    (have_agent && sensitive_data.host_pubkeys[i] != پوچ)) {
			have_کلید = 1;
			بشکن;
		}
	}
	اگر (!have_کلید)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(تهی) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	اگر (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	برای (i = 0; i < options.رقم_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	اگر (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} وگرنه {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	اگر (stdfd_devnull(1, 1, !log_stderr) == -1)
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
	اگر ((ssh = ssh_packet_set_connection(پوچ, sock_in, sock_out)) == پوچ)
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
	اگر (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		set_keepalive(sock_in); /* logs errors */

	اگر ((remote_port = ssh_remote_port(ssh)) < 0) {
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
	    rdomain == پوچ ? "" : " rdomain \"",
	    rdomain == پوچ ? "" : rdomain,
	    rdomain == پوچ ? "" : "\"");
	آزاد(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	اگر (!debug_flag && options.login_grace_time > 0) {
		صحیح ujitter = arc4random_uniform(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		اگر (setitimer(ITIMER_REAL, &itv, پوچ) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, اندازه(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	اگر ((auth_opts = sshauthopt_new_with_کلیدها_defaults()) == پوچ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	اگر ((loginmsg = sshbuf_new()) == پوچ)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	اگر (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	اگر (setitimer(ITIMER_REAL, &itv, پوچ) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	اگر (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(تهی)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	اگر (options.routing_domain != پوچ)
		set_process_rdomain(ssh, options.routing_domain);

#ifdef SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#endif

#ifdef GSSAPI
	اگر (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#endif
#ifdef USE_PAM
	اگر (options.use_pam) {
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
	    options.client_alive_شمار_max);

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
	اگر (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

#ifdef SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#endif

	ssh_packet_close(ssh);

	mm_terminate();

	exit(0);
}

صحیح
sshd_hostkey_sign(ساختار ssh *ssh, ساختار sshkey *privkey,
    ساختار sshkey *pubkey, u_char **signature, size_t *slenp,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg)
{
	اگر (privkey) {
		اگر (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, پوچ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} وگرنه {
		اگر (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, پوچ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	بازگشت 0;
}

/* server specific fatal cleanup */
تهی
cleanup_exit(صحیح i)
{
	اگر (the_active_state != پوچ && the_authctxt != پوچ) {
		do_cleanup(the_active_state, the_authctxt);
		اگر (privsep_is_preauth &&
		    pmonitor != پوچ && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			اگر (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ifdef SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	اگر (the_active_state != پوچ && mm_is_monitor())
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#endif
	/* Override default fatal exit value when auth was attempted */
	اگر (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	اگر (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
