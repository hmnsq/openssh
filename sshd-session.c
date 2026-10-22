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

#اگر_تعریف_شدہ HAVE_SECUREWARE
#شامل <sys/security.h>
#شامل <prot.h>
#اگر_ختم
 
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
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "monitor_wrap.h"
#شامل "auth-options.h"
#شامل "version.h"
#شامل "ssherr.h"
#شامل "sk-api.h"
#شامل "srclimit.h"
#شامل "dh.h"

/* Re-exec fds */
#تعریف_کرو REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#تعریف_کرو REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#تعریف_کرو REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#تعریف_کرو PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#تعریف_کرو PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#تعریف_کرو PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

خارجی حرف *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
حرف *config_file_name = راستہ_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
صحیح debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ساکن صحیح inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
ساکن صحیح log_stderr = 0;

/* Saved arguments to main(). */
ساکن حرف **saved_argv;
ساکن صحیح saved_argc;

/* Daemon's agent connection */
صحیح auth_sock = -1;
ساکن صحیح have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ساخت {
	u_int		عدد_hostkeys;
	ساخت sshkey	**host_کلیدیں;		/* all private host keys */
	ساخت sshkey	**host_pubkeys;		/* all public host keys */
	ساخت sshkey	**host_certificates;	/* all public host certificates */
} sensitive_ڈیٹا;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

ساکن صحیح startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
ساخت monitor *pmonitor = تہی;
صحیح privsep_is_preauth = 1;
ساکن صحیح privsep_chroot = 1;

/* Unprivileged user */
ساخت passwd *privsep_pw = تہی;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = تہی;
ساخت ssh *the_فعال_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ساخت sshauthopt *auth_opts = تہی;

/* sshd_config buffer */
ساخت sshbuf *cfg;

/* Included files from the configuration file */
ساخت include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ساخت sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
خالی destroy_sensitive_ڈیٹا(خالی);
خالی demote_sensitive_ڈیٹا(خالی);

/* XXX reduce to stub once postauth split */
صحیح
mm_is_monitor(خالی)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	واپس (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
ساکن خالی
grace_alarm_handler(صحیح sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	اگر (getpgid(0) == getpid()) {
		ساخت sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, حجم(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#اگر defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#اگر_ختم
		(خالی)sigaction(SIGTERM, &sa, تہی);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
خالی
destroy_sensitive_ڈیٹا(خالی)
{
	u_int i;

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		اگر (sensitive_ڈیٹا.host_کلیدیں[i]) {
			sshkey_free(sensitive_ڈیٹا.host_کلیدیں[i]);
			sensitive_ڈیٹا.host_کلیدیں[i] = تہی;
		}
		اگر (sensitive_ڈیٹا.host_certificates[i]) {
			sshkey_free(sensitive_ڈیٹا.host_certificates[i]);
			sensitive_ڈیٹا.host_certificates[i] = تہی;
		}
	}
}

/* Demote private to public keys for network child */
خالی
demote_sensitive_ڈیٹا(خالی)
{
	ساخت sshkey *tmp;
	u_int i;
	صحیح r;

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		اگر (sensitive_ڈیٹا.host_کلیدیں[i]) {
			اگر ((r = sshkey_from_نجی(
			    sensitive_ڈیٹا.host_کلیدیں[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_ڈیٹا.host_کلیدیں[i]));
			sshkey_free(sensitive_ڈیٹا.host_کلیدیں[i]);
			sensitive_ڈیٹا.host_کلیدیں[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

ساخت sshbuf *
pack_hostkeys(خالی)
{
	ساخت sshbuf *keybuf = تہی, *hostkeys = تہی;
	صحیح r;
	u_int i;

	اگر ((hostkeys = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
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

	sshbuf_free(keybuf);
	واپس hostkeys;
}

ساکن صحیح
privsep_preauth(ساخت ssh *ssh)
{
	صحیح r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	اگر ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	ورنہ اگر (pid != 0) {
		debug2("Network child is on pid %ld", (طویل)pid);

		pmonitor->m_pid = pid;
		اگر (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			اگر (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_بچہ_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		واپس 1;
	} ورنہ {
		/*بچہ*/
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

		اگر (ssh_packet_get_connection_اندر(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_اندر(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		اگر (ssh_packet_get_connection_برآمد(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_برآمد(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_مقصد(تہی); /* dup can clobber log fd */
		اگر (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		اگر (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_راستہ;
		execv(options.sshd_auth_راستہ, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_راستہ, strerror(errno));
	}
}

ساکن خالی
privsep_postauth(ساخت ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	اگر (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	ورنہ اگر (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (طویل)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_بچہ_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		باہر_نکلو(0);
	}

	/*بچہ*/

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_ڈیٹا();

	reseed_prngs();

#اگر_غیر_تعریف_شدہ SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#اگر_ختم

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_سیٹ_authenticated(ssh);
}

ساکن ساخت sshkey *
get_hostkey_by_type(صحیح type, صحیح nid, صحیح need_نجی, ساخت ssh *ssh)
{
	u_int i;
	ساخت sshkey *کلید;

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		انتخاب (type) {
		حالت کلید_RSA_CERT:
		حالت کلید_ECDSA_CERT:
		حالت کلید_ED25519_CERT:
		حالت کلید_ECDSA_SK_CERT:
		حالت کلید_ED25519_SK_CERT:
		حالت کلید_MLDSA44_ED25519_CERT:
			کلید = sensitive_ڈیٹا.host_certificates[i];
			توڑو;
		طےشدہ:
			کلید = sensitive_ڈیٹا.host_کلیدیں[i];
			اگر (کلید == تہی && !need_نجی)
				کلید = sensitive_ڈیٹا.host_pubkeys[i];
			توڑو;
		}
		اگر (کلید == تہی || کلید->type != type)
			جاری;
		انتخاب (type) {
		حالت کلید_ECDSA:
		حالت کلید_ECDSA_SK:
		حالت کلید_ECDSA_CERT:
		حالت کلید_ECDSA_SK_CERT:
			اگر (کلید->ecdsa_nid != nid)
				جاری;
			/* FALLTHROUGH */
		طےشدہ:
			واپس need_نجی ?
			    sensitive_ڈیٹا.host_کلیدیں[i] : کلید;
		}
	}
	واپس تہی;
}

ساخت sshkey *
get_hostkey_عوامی_by_type(صحیح type, صحیح nid, ساخت ssh *ssh)
{
	واپس get_hostkey_by_type(type, nid, 0, ssh);
}

ساخت sshkey *
get_hostkey_نجی_by_type(صحیح type, صحیح nid, ساخت ssh *ssh)
{
	واپس get_hostkey_by_type(type, nid, 1, ssh);
}

ساخت sshkey *
get_hostkey_by_اشاریہ(صحیح ind)
{
	اگر (ind < 0 || (u_int)ind >= options.عدد_host_کلید_files)
		واپس (تہی);
	واپس (sensitive_ڈیٹا.host_کلیدیں[ind]);
}

ساخت sshkey *
get_hostkey_عوامی_by_اشاریہ(صحیح ind, ساخت ssh *ssh)
{
	اگر (ind < 0 || (u_int)ind >= options.عدد_host_کلید_files)
		واپس (تہی);
	واپس (sensitive_ڈیٹا.host_pubkeys[ind]);
}

صحیح
get_hostkey_اشاریہ(ساخت sshkey *کلید, صحیح compare, ساخت ssh *ssh)
{
	u_int i;

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		اگر (sshkey_is_cert(کلید)) {
			اگر (کلید == sensitive_ڈیٹا.host_certificates[i] ||
			    (compare && sensitive_ڈیٹا.host_certificates[i] &&
			    sshkey_equal(کلید,
			    sensitive_ڈیٹا.host_certificates[i])))
				واپس (i);
		} ورنہ {
			اگر (کلید == sensitive_ڈیٹا.host_کلیدیں[i] ||
			    (compare && sensitive_ڈیٹا.host_کلیدیں[i] &&
			    sshkey_equal(کلید, sensitive_ڈیٹا.host_کلیدیں[i])))
				واپس (i);
			اگر (کلید == sensitive_ڈیٹا.host_pubkeys[i] ||
			    (compare && sensitive_ڈیٹا.host_pubkeys[i] &&
			    sshkey_equal(کلید, sensitive_ڈیٹا.host_pubkeys[i])))
				واپس (i);
		}
	}
	واپس (-1);
}

/* Inform the client of all hostkeys */
ساکن خالی
notify_hostkeys(ساخت ssh *ssh)
{
	ساخت sshbuf *buf;
	ساخت sshkey *کلید;
	u_int i, nkeys;
	صحیح r;
	حرف *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	اگر (ssh->compat & SSH_BUG_HOSTKEYS)
		واپس;

	اگر ((buf = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	برائے (i = nkeys = 0; i < options.عدد_host_کلید_files; i++) {
		کلید = get_hostkey_عوامی_by_اشاریہ(i, ssh);
		اگر (کلید == تہی || کلید->type == کلید_UNSPEC ||
		    sshkey_is_cert(کلید))
			جاری;
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(کلید), fp);
		آزاد(fp);
		اگر (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
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

ساکن خالی
parse_hostkeys(ساخت sshbuf *hostkeys)
{
	صحیح r;
	u_int عدد_کلیدیں = 0;
	ساخت sshkey *k;
	ساخت sshbuf *kbuf;
	ثابت u_char *cp;
	سائز_t len;

	جب (sshbuf_len(hostkeys) != 0) {
		اگر (عدد_کلیدیں > 2048)
			fatal_f("too many hostkeys");
		sensitive_ڈیٹا.host_کلیدیں = xrecallocarray(
		    sensitive_ڈیٹا.host_کلیدیں, عدد_کلیدیں, عدد_کلیدیں + 1,
		    حجم(*sensitive_ڈیٹا.host_pubkeys));
		sensitive_ڈیٹا.host_pubkeys = xrecallocarray(
		    sensitive_ڈیٹا.host_pubkeys, عدد_کلیدیں, عدد_کلیدیں + 1,
		    حجم(*sensitive_ڈیٹا.host_pubkeys));
		sensitive_ڈیٹا.host_certificates = xrecallocarray(
		    sensitive_ڈیٹا.host_certificates, عدد_کلیدیں, عدد_کلیدیں + 1,
		    حجم(*sensitive_ڈیٹا.host_certificates));
		/* private key */
		k = تہی;
		اگر ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		اگر (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_نجی_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ڈیٹا.host_کلیدیں[عدد_کلیدیں] = k;
		sshbuf_free(kbuf);
		اگر (k)
			debug2_f("privkey %u: %s", عدد_کلیدیں, sshkey_ssh_name(k));
		/* public key */
		k = تہی;
		اگر ((r = sshbuf_get_string_براہ_راست(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		اگر (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ڈیٹا.host_pubkeys[عدد_کلیدیں] = k;
		اگر (k)
			debug2_f("pubkey %u: %s", عدد_کلیدیں, sshkey_ssh_name(k));
		/* certificate */
		k = تہی;
		اگر ((r = sshbuf_get_string_براہ_راست(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		اگر (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ڈیٹا.host_certificates[عدد_کلیدیں] = k;
		اگر (k)
			debug2_f("cert %u: %s", عدد_کلیدیں, sshkey_ssh_name(k));
		عدد_کلیدیں++;
	}
	sensitive_ڈیٹا.عدد_hostkeys = عدد_کلیدیں;
}

ساکن خالی
recv_rexec_state(صحیح fd, ساخت sshbuf *conf, uint64_t *timing_secretp)
{
	ساخت sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	سائز_t len;
	صحیح r;
	ساخت include_شے *شے;

	debug3_f("entering fd = %d", fd);

	اگر ((m = sshbuf_new()) == تہی || (inc = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	/* receive config */
	اگر (ssh_پیغام_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	اگر ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	اگر (ver != 0)
		fatal_f("rexec version mismatch");
	اگر ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	اگر (conf != تہی && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	جب (sshbuf_len(inc) != 0) {
		شے = xcalloc(1, حجم(*شے));
		اگر ((شے->contents = sshbuf_new()) == تہی)
			fatal_f("sshbuf_new failed");
		اگر ((r = sshbuf_get_cstring(inc, &شے->selector, تہی)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &شے->filename, تہی)) != 0 ||
		    (r = sshbuf_get_stringb(inc, شے->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, شے, اندراج_2);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	اگر (ssh_پیغام_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	اگر ((r = sshbuf_get_u8(m, تہی)) != 0 ||
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
ساکن خالی
check_ip_options(ساخت ssh *ssh)
{
#اگر_تعریف_شدہ IP_OPTIONS
	صحیح sock_اندر = ssh_packet_get_connection_اندر(ssh);
	ساخت sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_سائز = حجم(opts), fromlen = حجم(from);
	حرف متن[حجم(opts) * 3 + 1];

	memset(&from, 0, حجم(from));
	اگر (getpeername(sock_اندر, (ساخت sockaddr *)&from,
	    &fromlen) == -1)
		واپس;
	اگر (from.ss_family != AF_INET)
		واپس;
	/* XXX IPv6 options? */

	اگر (getsockopt(sock_اندر, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_سائز) >= 0 && option_سائز != 0) {
		متن[0] = '\0';
		برائے (i = 0; i < option_سائز; i++)
			snprintf(متن + i*3, حجم(متن) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh), متن);
	}
#اگر_ختم /* IP_OPTIONS */
}

/* Set the routing domain for this process */
ساکن خالی
سیٹ_process_rdomain(ساخت ssh *ssh, ثابت حرف *name)
{
#اگر defined(HAVE_SYS_سیٹ_PROCESS_RDOMAIN)
	اگر (name == تہی)
		واپس; /* default */

	اگر (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		اگر ((name = ssh_packet_rdomain_اندر(ssh)) == تہی)
			واپس;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	واپس sys_سیٹ_process_rdomain(name);
#وگرنہ_اگر defined(__OpenBSD__)
	صحیح rtable, ortable = getrtable();
	ثابت حرف *errstr;

	اگر (name == تہی)
		واپس; /* default */

	اگر (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		اگر ((name = ssh_packet_rdomain_اندر(ssh)) == تہی)
			واپس;
	}

	rtable = (صحیح)strtonum(name, 0, 255, &errstr);
	اگر (errstr != تہی) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	اگر (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#ورنہ /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#اگر_ختم
}

/*
 * Main program for the daemon.
 */
صحیح
مین(صحیح ac, حرف **av)
{
	ساخت ssh *ssh = تہی;
	خارجی حرف *optarg;
	خارجی صحیح optind;
	صحیح devnull, r, opt, remote_پورٹ;
	صحیح sock_اندر = -1, sock_برآمد = -1, rexeced_flag = 0, have_کلید = 0;
	ثابت حرف *remote_ip, *rdomain;
	حرف *سطر, *laddr, *logfile = تہی;
	u_int i;
	uint64_t ibytes, obytes;
	منوال_t new_umask;
	Authctxt *authctxt;
	ساخت connection_info *connection_info = تہی;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	ساخت itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, تہی);

#اگر_تعریف_شدہ HAVE_SECUREWARE
	(خالی)سیٹ_auth_parameters(ac, av);
#اگر_ختم
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, حجم(*saved_argv));
	برائے (i = 0; (صحیح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = تہی;

#اگر_غیر_تعریف_شدہ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#اگر_ختم

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
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
			/* ignore */
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
			/* ignore */
			توڑو;
		حالت 'R':
			rexeced_flag = 1;
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
		حالت 'T':
		حالت 'G':
			fatal("test/dump modes not supported");
			توڑو;
		حالت 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			اگر (parse_server_مطابقت_testspec(connection_info,
			    optarg) == -1)
				باہر_نکلو(1);
			توڑو;
		حالت 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, تہی);
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

	/* Check that there are no remaining arguments. */
	اگر (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		باہر_نکلو(1);
	}

	اگر (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_آغاز();

	/* Reserve fds we'll need later for reexec things */
	اگر ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	جب (devnull < PRIVSEP_MIN_FREE_FD) {
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
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	اگر ((cfg = sshbuf_new()) == تہی)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, تہی, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_نسخہ, SSH_OPENSSL_نسخہ);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	اگر ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == تہی) {
		اگر (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ورنہ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, لڑی_لمبائی(privsep_pw->pw_passwd));
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
		(خالی)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	اگر (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

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
	 * daemonisation in the presence of Match block, but this catches
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

#اگر_تعریف_شدہ WITH_OPENSSL
	اگر (options.moduli_file != تہی)
		dh_سیٹ_moduli_file(options.moduli_file);
#اگر_ختم

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

	اگر (options.عدد_host_کلید_files != sensitive_ڈیٹا.عدد_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.عدد_host_کلید_files, sensitive_ڈیٹا.عدد_hostkeys);
	}

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		اگر (sensitive_ڈیٹا.host_کلیدیں[i] != تہی ||
		    (have_agent && sensitive_ڈیٹا.host_pubkeys[i] != تہی)) {
			have_کلید = 1;
			توڑو;
		}
	}
	اگر (!have_کلید)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(خالی) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	اگر (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	برائے (i = 0; i < options.عدد_log_verbose; i++)
		log_verbose_جوڑو(options.log_verbose[i]);

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
		sock_اندر = dup(STDIN_FILENO);
		sock_برآمد = dup(STDOUT_FILENO);
	} ورنہ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_اندر = sock_برآمد = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	اگر (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_اندر, sock_برآمد);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_برآمد);
	FD_CLOSEONEXEC(sock_اندر);

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
	اگر ((ssh = ssh_packet_سیٹ_connection(تہی, sock_اندر, sock_برآمد)) == تہی)
		fatal("Unable to create connection");
	the_فعال_state = ssh;
	ssh_packet_سیٹ_server(ssh);
	ssh_packet_سیٹ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_سیٹ_af(ssh, options.پتہ_family);
	channel_سیٹ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	/* Set SO_KEEPALIVE if requested. */
	اگر (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		سیٹ_keepalive(sock_اندر); /* logs errors */

	اگر ((remote_پورٹ = ssh_remote_پورٹ(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_پورٹ);
#اگر_ختم

	rdomain = ssh_packet_rdomain_اندر(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_اندر);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_پورٹ, laddr,  ssh_local_پورٹ(ssh),
	    rdomain == تہی ? "" : " rdomain \"",
	    rdomain == تہی ? "" : rdomain,
	    rdomain == تہی ? "" : "\"");
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
	اگر (!debug_flag && options.login_grace_وقت > 0) {
		صحیح ujitter = arc4random_یکساں(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_وقت;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		اگر (setitimer(ITIMER_REAL, &itv, تہی) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_سیٹ_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, حجم(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	اگر ((auth_opts = sshauthopt_new_with_کلیدیں_defaults()) == تہی)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	اگر ((loginmsg = sshbuf_new()) == تہی)
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
	اگر (setitimer(ITIMER_REAL, &itv, تہی) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	اگر (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(خالی)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	اگر (options.routing_domain != تہی)
		سیٹ_process_rdomain(ssh, options.routing_domain);

#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#اگر_ختم

#اگر_تعریف_شدہ GSSAPI
	اگر (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#اگر_ختم
#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#اگر_ختم

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_سیٹ_timeout(ssh, options.client_alive_interval,
	    options.client_alive_گنتی_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_بائٹیں(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (غیرعلامتی طویل طویل)obytes, (غیرعلامتی طویل طویل)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_پورٹ);

#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam)
		اختتام_pam();
#اگر_ختم /* USE_PAM */

#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#اگر_ختم

	ssh_packet_close(ssh);

	mm_terminate();

	باہر_نکلو(0);
}

صحیح
sshd_hostkey_sign(ساخت ssh *ssh, ساخت sshkey *privkey,
    ساخت sshkey *pubkey, u_char **signature, سائز_t *slenp,
    ثابت u_char *ڈیٹا, سائز_t dlen, ثابت حرف *alg)
{
	اگر (privkey) {
		اگر (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    ڈیٹا, dlen, alg, options.sk_provider, تہی,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ورنہ {
		اگر (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    ڈیٹا, dlen, alg, options.sk_provider, تہی,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	واپس 0;
}

/* server specific fatal cleanup */
خالی
cleanup_exit(صحیح i)
{
	اگر (the_فعال_state != تہی && the_authctxt != تہی) {
		do_cleanup(the_فعال_state, the_authctxt);
		اگر (privsep_is_preauth &&
		    pmonitor != تہی && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			اگر (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	اگر (the_فعال_state != تہی && mm_is_monitor())
		audit_event(the_فعال_state, SSH_CONNECTION_ABANDON);
#اگر_ختم
	/* Override default fatal exit value when auth was attempted */
	اگر (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	اگر (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
