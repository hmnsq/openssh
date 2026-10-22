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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>
#ضمن <sys/wait.h>
#ضمن <sys/tree.h>
#ضمن <sys/stat.h>
#ضمن <sys/socket.h>
#ضمن <sys/time.h>
#ضمن <sys/queue.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <grp.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>
#ضمن <limits.h>

#اگر_تعریف_شده HAVE_SECUREWARE
#ضمن <sys/security.h>
#ضمن <prot.h>
#پایان_اگر
 
#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "sshpty.h"
#ضمن "packet.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"
#ضمن "match.h"
#ضمن "servconf.h"
#ضمن "uidswap.h"
#ضمن "compat.h"
#ضمن "cipher.h"
#ضمن "digest.h"
#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "authfile.h"
#ضمن "pathnames.h"
#ضمن "atomicio.h"
#ضمن "canohost.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "authfd.h"
#ضمن "msg.h"
#ضمن "dispatch.h"
#ضمن "channels.h"
#ضمن "session.h"
#ضمن "monitor.h"
#اگر_تعریف_شده GSSAPI
#ضمن "ssh-gss.h"
#پایان_اگر
#ضمن "monitor_wrap.h"
#ضمن "auth-options.h"
#ضمن "version.h"
#ضمن "ssherr.h"
#ضمن "sk-api.h"
#ضمن "srclimit.h"
#ضمن "dh.h"

/* Re-exec fds */
#تعریف_کن REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#تعریف_کن REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#تعریف_کن REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#تعریف_کن PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#تعریف_کن PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#تعریف_کن PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

خارجي حرف *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
حرف *config_file_name = مسیر_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
صحيح debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ساكن صحيح inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
ساكن صحيح log_stderr = 0;

/* Saved arguments to main(). */
ساكن حرف **saved_argv;
ساكن صحيح saved_argc;

/* Daemon's agent connection */
صحيح auth_sock = -1;
ساكن صحيح have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
بنية {
	u_int		رقم_hostkeys;
	بنية sshkey	**host_کلیدها;		/* all private host keys */
	بنية sshkey	**host_pubkeys;		/* all public host keys */
	بنية sshkey	**host_certificates;	/* all public host certificates */
} sensitive_داده;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

ساكن صحيح startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
بنية monitor *pmonitor = عدم;
صحيح privsep_is_preauth = 1;
ساكن صحيح privsep_chroot = 1;

/* Unprivileged user */
بنية passwd *privsep_pw = عدم;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = عدم;
بنية ssh *the_فعال_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
بنية sshauthopt *auth_opts = عدم;

/* sshd_config buffer */
بنية sshbuf *cfg;

/* Included files from the configuration file */
بنية include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
بنية sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
فراغ destroy_sensitive_داده(فراغ);
فراغ demote_sensitive_داده(فراغ);

/* XXX reduce to stub once postauth split */
صحيح
mm_is_monitor(فراغ)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	أرجع (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
ساكن فراغ
grace_alarm_handler(صحيح sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	إذا (getpgid(0) == getpid()) {
		بنية sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, حجم(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#إذا defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#پایان_اگر
		(فراغ)sigaction(SIGTERM, &sa, عدم);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
فراغ
destroy_sensitive_داده(فراغ)
{
	u_int i;

	لكل (i = 0; i < options.رقم_host_کلید_files; i++) {
		إذا (sensitive_داده.host_کلیدها[i]) {
			sshkey_free(sensitive_داده.host_کلیدها[i]);
			sensitive_داده.host_کلیدها[i] = عدم;
		}
		إذا (sensitive_داده.host_certificates[i]) {
			sshkey_free(sensitive_داده.host_certificates[i]);
			sensitive_داده.host_certificates[i] = عدم;
		}
	}
}

/* Demote private to public keys for network child */
فراغ
demote_sensitive_داده(فراغ)
{
	بنية sshkey *tmp;
	u_int i;
	صحيح r;

	لكل (i = 0; i < options.رقم_host_کلید_files; i++) {
		إذا (sensitive_داده.host_کلیدها[i]) {
			إذا ((r = sshkey_from_خصوصی(
			    sensitive_داده.host_کلیدها[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_داده.host_کلیدها[i]));
			sshkey_free(sensitive_داده.host_کلیدها[i]);
			sensitive_داده.host_کلیدها[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

بنية sshbuf *
pack_hostkeys(فراغ)
{
	بنية sshbuf *keybuf = عدم, *hostkeys = عدم;
	صحيح r;
	u_int i;

	إذا ((hostkeys = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	لكل (i = 0; i < options.رقم_host_کلید_files; i++) {
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

	sshbuf_free(keybuf);
	أرجع hostkeys;
}

ساكن صحيح
privsep_preauth(بنية ssh *ssh)
{
	صحيح r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	إذا ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	وإلا إذا (pid != 0) {
		debug2("Network child is on pid %ld", (دراز)pid);

		pmonitor->m_pid = pid;
		إذا (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			إذا (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_فرزند_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		أرجع 1;
	} وإلا {
		/*فرزند*/
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

		إذا (ssh_packet_get_connection_درون(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_درون(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		إذا (ssh_packet_get_connection_بیرون(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_بیرون(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_مقصد(عدم); /* dup can clobber log fd */
		إذا (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		إذا (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_مسیر;
		execv(options.sshd_auth_مسیر, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_مسیر, strerror(errno));
	}
}

ساكن فراغ
privsep_postauth(بنية ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	إذا (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	وإلا إذا (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (دراز)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_فرزند_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		خروج(0);
	}

	/*فرزند*/

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_داده();

	reseed_prngs();

#اگر_تعریف_نشده SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#پایان_اگر

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_مجموعه_authenticated(ssh);
}

ساكن بنية sshkey *
get_hostkey_by_type(صحيح type, صحيح nid, صحيح need_خصوصی, بنية ssh *ssh)
{
	u_int i;
	بنية sshkey *کلید;

	لكل (i = 0; i < options.رقم_host_کلید_files; i++) {
		بدل (type) {
		حالة کلید_RSA_CERT:
		حالة کلید_ECDSA_CERT:
		حالة کلید_ED25519_CERT:
		حالة کلید_ECDSA_SK_CERT:
		حالة کلید_ED25519_SK_CERT:
		حالة کلید_MLDSA44_ED25519_CERT:
			کلید = sensitive_داده.host_certificates[i];
			اكسر;
		افتراضي:
			کلید = sensitive_داده.host_کلیدها[i];
			إذا (کلید == عدم && !need_خصوصی)
				کلید = sensitive_داده.host_pubkeys[i];
			اكسر;
		}
		إذا (کلید == عدم || کلید->type != type)
			استمر;
		بدل (type) {
		حالة کلید_ECDSA:
		حالة کلید_ECDSA_SK:
		حالة کلید_ECDSA_CERT:
		حالة کلید_ECDSA_SK_CERT:
			إذا (کلید->ecdsa_nid != nid)
				استمر;
			/* FALLTHROUGH */
		افتراضي:
			أرجع need_خصوصی ?
			    sensitive_داده.host_کلیدها[i] : کلید;
		}
	}
	أرجع عدم;
}

بنية sshkey *
get_hostkey_عمومی_by_type(صحيح type, صحيح nid, بنية ssh *ssh)
{
	أرجع get_hostkey_by_type(type, nid, 0, ssh);
}

بنية sshkey *
get_hostkey_خصوصی_by_type(صحيح type, صحيح nid, بنية ssh *ssh)
{
	أرجع get_hostkey_by_type(type, nid, 1, ssh);
}

بنية sshkey *
get_hostkey_by_شاخص(صحيح ind)
{
	إذا (ind < 0 || (u_int)ind >= options.رقم_host_کلید_files)
		أرجع (عدم);
	أرجع (sensitive_داده.host_کلیدها[ind]);
}

بنية sshkey *
get_hostkey_عمومی_by_شاخص(صحيح ind, بنية ssh *ssh)
{
	إذا (ind < 0 || (u_int)ind >= options.رقم_host_کلید_files)
		أرجع (عدم);
	أرجع (sensitive_داده.host_pubkeys[ind]);
}

صحيح
get_hostkey_شاخص(بنية sshkey *کلید, صحيح compare, بنية ssh *ssh)
{
	u_int i;

	لكل (i = 0; i < options.رقم_host_کلید_files; i++) {
		إذا (sshkey_is_cert(کلید)) {
			إذا (کلید == sensitive_داده.host_certificates[i] ||
			    (compare && sensitive_داده.host_certificates[i] &&
			    sshkey_equal(کلید,
			    sensitive_داده.host_certificates[i])))
				أرجع (i);
		} وإلا {
			إذا (کلید == sensitive_داده.host_کلیدها[i] ||
			    (compare && sensitive_داده.host_کلیدها[i] &&
			    sshkey_equal(کلید, sensitive_داده.host_کلیدها[i])))
				أرجع (i);
			إذا (کلید == sensitive_داده.host_pubkeys[i] ||
			    (compare && sensitive_داده.host_pubkeys[i] &&
			    sshkey_equal(کلید, sensitive_داده.host_pubkeys[i])))
				أرجع (i);
		}
	}
	أرجع (-1);
}

/* Inform the client of all hostkeys */
ساكن فراغ
notify_hostkeys(بنية ssh *ssh)
{
	بنية sshbuf *buf;
	بنية sshkey *کلید;
	u_int i, nkeys;
	صحيح r;
	حرف *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	إذا (ssh->compat & SSH_BUG_HOSTKEYS)
		أرجع;

	إذا ((buf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	لكل (i = nkeys = 0; i < options.رقم_host_کلید_files; i++) {
		کلید = get_hostkey_عمومی_by_شاخص(i, ssh);
		إذا (کلید == عدم || کلید->type == کلید_UNSPEC ||
		    sshkey_is_cert(کلید))
			استمر;
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(کلید), fp);
		حرر(fp);
		إذا (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		إذا ((r = sshkey_putb(کلید, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		إذا ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	إذا (nkeys == 0)
		fatal_f("no hostkeys");
	إذا ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

ساكن فراغ
parse_hostkeys(بنية sshbuf *hostkeys)
{
	صحيح r;
	u_int رقم_کلیدها = 0;
	بنية sshkey *k;
	بنية sshbuf *kbuf;
	ثابت u_char *cp;
	اندازه_t len;

	طالما (sshbuf_len(hostkeys) != 0) {
		إذا (رقم_کلیدها > 2048)
			fatal_f("too many hostkeys");
		sensitive_داده.host_کلیدها = xrecallocarray(
		    sensitive_داده.host_کلیدها, رقم_کلیدها, رقم_کلیدها + 1,
		    حجم(*sensitive_داده.host_pubkeys));
		sensitive_داده.host_pubkeys = xrecallocarray(
		    sensitive_داده.host_pubkeys, رقم_کلیدها, رقم_کلیدها + 1,
		    حجم(*sensitive_داده.host_pubkeys));
		sensitive_داده.host_certificates = xrecallocarray(
		    sensitive_داده.host_certificates, رقم_کلیدها, رقم_کلیدها + 1,
		    حجم(*sensitive_داده.host_certificates));
		/* private key */
		k = عدم;
		إذا ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		إذا (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_خصوصی_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_داده.host_کلیدها[رقم_کلیدها] = k;
		sshbuf_free(kbuf);
		إذا (k)
			debug2_f("privkey %u: %s", رقم_کلیدها, sshkey_ssh_name(k));
		/* public key */
		k = عدم;
		إذا ((r = sshbuf_get_string_مستقیم(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		إذا (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_داده.host_pubkeys[رقم_کلیدها] = k;
		إذا (k)
			debug2_f("pubkey %u: %s", رقم_کلیدها, sshkey_ssh_name(k));
		/* certificate */
		k = عدم;
		إذا ((r = sshbuf_get_string_مستقیم(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		إذا (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_داده.host_certificates[رقم_کلیدها] = k;
		إذا (k)
			debug2_f("cert %u: %s", رقم_کلیدها, sshkey_ssh_name(k));
		رقم_کلیدها++;
	}
	sensitive_داده.رقم_hostkeys = رقم_کلیدها;
}

ساكن فراغ
recv_rexec_state(صحيح fd, بنية sshbuf *conf, uint64_t *timing_secretp)
{
	بنية sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	اندازه_t len;
	صحيح r;
	بنية include_قلم *قلم;

	debug3_f("entering fd = %d", fd);

	إذا ((m = sshbuf_new()) == عدم || (inc = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* receive config */
	إذا (ssh_پیام_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	إذا ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	إذا (ver != 0)
		fatal_f("rexec version mismatch");
	إذا ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	إذا (conf != عدم && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	طالما (sshbuf_len(inc) != 0) {
		قلم = xcalloc(1, حجم(*قلم));
		إذا ((قلم->contents = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new failed");
		إذا ((r = sshbuf_get_cstring(inc, &قلم->selector, عدم)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &قلم->filename, عدم)) != 0 ||
		    (r = sshbuf_get_stringb(inc, قلم->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, قلم, مدخل);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	إذا (ssh_پیام_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	إذا ((r = sshbuf_get_u8(m, عدم)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	حرر(cp);
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
ساكن فراغ
check_ip_options(بنية ssh *ssh)
{
#اگر_تعریف_شده IP_OPTIONS
	صحيح sock_درون = ssh_packet_get_connection_درون(ssh);
	بنية sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_اندازه = حجم(opts), fromlen = حجم(from);
	حرف متن[حجم(opts) * 3 + 1];

	memset(&from, 0, حجم(from));
	إذا (getpeername(sock_درون, (بنية sockaddr *)&from,
	    &fromlen) == -1)
		أرجع;
	إذا (from.ss_family != AF_INET)
		أرجع;
	/* XXX IPv6 options? */

	إذا (getsockopt(sock_درون, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_اندازه) >= 0 && option_اندازه != 0) {
		متن[0] = '\0';
		لكل (i = 0; i < option_اندازه; i++)
			snprintf(متن + i*3, حجم(متن) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh), متن);
	}
#پایان_اگر /* IP_OPTIONS */
}

/* Set the routing domain for this process */
ساكن فراغ
مجموعه_process_rdomain(بنية ssh *ssh, ثابت حرف *name)
{
#إذا defined(HAVE_SYS_مجموعه_PROCESS_RDOMAIN)
	إذا (name == عدم)
		أرجع; /* default */

	إذا (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		إذا ((name = ssh_packet_rdomain_درون(ssh)) == عدم)
			أرجع;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	أرجع sys_مجموعه_process_rdomain(name);
#وإلاإذا defined(__OpenBSD__)
	صحيح rtable, ortable = getrtable();
	ثابت حرف *errstr;

	إذا (name == عدم)
		أرجع; /* default */

	إذا (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		إذا ((name = ssh_packet_rdomain_درون(ssh)) == عدم)
			أرجع;
	}

	rtable = (صحيح)strtonum(name, 0, 255, &errstr);
	إذا (errstr != عدم) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	إذا (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#وإلا /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#پایان_اگر
}

/*
 * Main program for the daemon.
 */
صحيح
اصلی(صحيح ac, حرف **av)
{
	بنية ssh *ssh = عدم;
	خارجي حرف *optarg;
	خارجي صحيح optind;
	صحيح devnull, r, opt, remote_پورت;
	صحيح sock_درون = -1, sock_بیرون = -1, rexeced_flag = 0, have_کلید = 0;
	ثابت حرف *remote_ip, *rdomain;
	حرف *سطر, *laddr, *logfile = عدم;
	u_int i;
	uint64_t ibytes, obytes;
	نما_t new_umask;
	Authctxt *authctxt;
	بنية connection_info *connection_info = عدم;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	بنية itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, عدم);

#اگر_تعریف_شده HAVE_SECUREWARE
	(فراغ)مجموعه_auth_parameters(ac, av);
#پایان_اگر
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, حجم(*saved_argv));
	لكل (i = 0; (صحيح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = عدم;

#اگر_تعریف_نشده HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#پایان_اگر

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
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
			/* ignore */
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
			/* ignore */
			اكسر;
		حالة 'R':
			rexeced_flag = 1;
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
		حالة 'T':
		حالة 'G':
			fatal("test/dump modes not supported");
			اكسر;
		حالة 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			إذا (parse_server_تطابق_testspec(connection_info,
			    optarg) == -1)
				خروج(1);
			اكسر;
		حالة 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, عدم);
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

	/* Check that there are no remaining arguments. */
	إذا (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		خروج(1);
	}

	إذا (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_شروع();

	/* Reserve fds we'll need later for reexec things */
	إذا ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	طالما (devnull < PRIVSEP_MIN_FREE_FD) {
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
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	إذا ((cfg = sshbuf_new()) == عدم)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, عدم, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_نسخه, SSH_OPENSSL_نسخه);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	إذا ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == عدم) {
		إذا (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} وإلا {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, طول_رشته(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	إذا (!debug_flag && !inetd_flag) {
		إذا ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(فراغ)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	إذا (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

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
	 * daemonisation in the presence of Match block, but this catches
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

#اگر_تعریف_شده WITH_OPENSSL
	إذا (options.moduli_file != عدم)
		dh_مجموعه_moduli_file(options.moduli_file);
#پایان_اگر

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

	إذا (options.رقم_host_کلید_files != sensitive_داده.رقم_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.رقم_host_کلید_files, sensitive_داده.رقم_hostkeys);
	}

	لكل (i = 0; i < options.رقم_host_کلید_files; i++) {
		إذا (sensitive_داده.host_کلیدها[i] != عدم ||
		    (have_agent && sensitive_داده.host_pubkeys[i] != عدم)) {
			have_کلید = 1;
			اكسر;
		}
	}
	إذا (!have_کلید)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(فراغ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	إذا (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	لكل (i = 0; i < options.رقم_log_verbose; i++)
		log_verbose_جمع_کن(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	إذا (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_درون = dup(STDIN_FILENO);
		sock_بیرون = dup(STDOUT_FILENO);
	} وإلا {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_درون = sock_بیرون = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	إذا (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_درون, sock_بیرون);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_بیرون);
	FD_CLOSEONEXEC(sock_درون);

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
	إذا ((ssh = ssh_packet_مجموعه_connection(عدم, sock_درون, sock_بیرون)) == عدم)
		fatal("Unable to create connection");
	the_فعال_state = ssh;
	ssh_packet_مجموعه_server(ssh);
	ssh_packet_مجموعه_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_مجموعه_af(ssh, options.آدرس_family);
	channel_مجموعه_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	/* Set SO_KEEPALIVE if requested. */
	إذا (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		مجموعه_keepalive(sock_درون); /* logs errors */

	إذا ((remote_پورت = ssh_remote_پورت(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#اگر_تعریف_شده SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_پورت);
#پایان_اگر

	rdomain = ssh_packet_rdomain_درون(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_درون);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_پورت, laddr,  ssh_local_پورت(ssh),
	    rdomain == عدم ? "" : " rdomain \"",
	    rdomain == عدم ? "" : rdomain,
	    rdomain == عدم ? "" : "\"");
	حرر(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	إذا (!debug_flag && options.login_grace_زمان > 0) {
		صحيح ujitter = arc4random_یکنواخت(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_زمان;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		إذا (setitimer(ITIMER_REAL, &itv, عدم) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_مجموعه_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, حجم(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	إذا ((auth_opts = sshauthopt_new_with_کلیدها_defaults()) == عدم)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	إذا ((loginmsg = sshbuf_new()) == عدم)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	إذا (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	إذا (setitimer(ITIMER_REAL, &itv, عدم) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	إذا (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(فراغ)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	إذا (options.routing_domain != عدم)
		مجموعه_process_rdomain(ssh, options.routing_domain);

#اگر_تعریف_شده SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#پایان_اگر

#اگر_تعریف_شده GSSAPI
	إذا (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#پایان_اگر
#اگر_تعریف_شده USE_PAM
	إذا (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#پایان_اگر

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_مجموعه_timeout(ssh, options.client_alive_interval,
	    options.client_alive_شمار_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_بایتها(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (بیعلامت دراز دراز)obytes, (بیعلامت دراز دراز)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_پورت);

#اگر_تعریف_شده USE_PAM
	إذا (options.use_pam)
		پایان_pam();
#پایان_اگر /* USE_PAM */

#اگر_تعریف_شده SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#پایان_اگر

	ssh_packet_close(ssh);

	mm_terminate();

	خروج(0);
}

صحيح
sshd_hostkey_sign(بنية ssh *ssh, بنية sshkey *privkey,
    بنية sshkey *pubkey, u_char **signature, اندازه_t *slenp,
    ثابت u_char *داده, اندازه_t dlen, ثابت حرف *alg)
{
	إذا (privkey) {
		إذا (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    داده, dlen, alg, options.sk_provider, عدم,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} وإلا {
		إذا (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    داده, dlen, alg, options.sk_provider, عدم,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	أرجع 0;
}

/* server specific fatal cleanup */
فراغ
cleanup_exit(صحيح i)
{
	إذا (the_فعال_state != عدم && the_authctxt != عدم) {
		do_cleanup(the_فعال_state, the_authctxt);
		إذا (privsep_is_preauth &&
		    pmonitor != عدم && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			إذا (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#اگر_تعریف_شده SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	إذا (the_فعال_state != عدم && mm_is_monitor())
		audit_event(the_فعال_state, SSH_CONNECTION_ABANDON);
#پایان_اگر
	/* Override default fatal exit value when auth was attempted */
	إذا (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	إذا (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
