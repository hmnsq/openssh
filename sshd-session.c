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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/tree.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <grp.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#ifdef HAVE_SECUREWARE
#அந்தர்பாவ <sys/security.h>
#அந்தர்பாவ <prot.h>
#endif
 
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshpty.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "session.h"
#அந்தர்பாவ "monitor.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "version.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sk-api.h"
#அந்தர்பாவ "srclimit.h"
#அந்தர்பாவ "dh.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

வெளி எழுத்து *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
எழுத்து *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
முழு debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
நிலையான முழு inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
நிலையான முழு log_stderr = 0;

/* Saved arguments to main(). */
நிலையான எழுத்து **saved_argv;
நிலையான முழு saved_argc;

/* Daemon's agent connection */
முழு auth_sock = -1;
நிலையான முழு have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
கட்டமைப்பு {
	u_int		இலக்கம்_hostkeys;
	கட்டமைப்பு sshkey	**host_சாவிகள்;		/* all private host keys */
	கட்டமைப்பு sshkey	**host_pubkeys;		/* all public host keys */
	கட்டமைப்பு sshkey	**host_certificates;	/* all public host certificates */
} sensitive_data;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

நிலையான முழு startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
கட்டமைப்பு monitor *pmonitor = வெற்று;
முழு privsep_is_preauth = 1;
நிலையான முழு privsep_chroot = 1;

/* Unprivileged user */
கட்டமைப்பு passwd *privsep_pw = வெற்று;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = வெற்று;
கட்டமைப்பு ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
கட்டமைப்பு sshauthopt *auth_opts = வெற்று;

/* sshd_config buffer */
கட்டமைப்பு sshbuf *cfg;

/* Included files from the configuration file */
கட்டமைப்பு include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
கட்டமைப்பு sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
வெறுமை destroy_sensitive_data(வெறுமை);
வெறுமை demote_sensitive_data(வெறுமை);

/* XXX reduce to stub once postauth split */
முழு
mm_is_monitor(வெறுமை)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	திரும்பு (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
நிலையான வெறுமை
grace_alarm_handler(முழு sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	எனில் (getpgid(0) == getpid()) {
		கட்டமைப்பு sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, அளவு(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#எனில் defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#endif
		(வெறுமை)sigaction(SIGTERM, &sa, வெற்று);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
வெறுமை
destroy_sensitive_data(வெறுமை)
{
	u_int i;

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		எனில் (sensitive_data.host_சாவிகள்[i]) {
			sshkey_free(sensitive_data.host_சாவிகள்[i]);
			sensitive_data.host_சாவிகள்[i] = வெற்று;
		}
		எனில் (sensitive_data.host_certificates[i]) {
			sshkey_free(sensitive_data.host_certificates[i]);
			sensitive_data.host_certificates[i] = வெற்று;
		}
	}
}

/* Demote private to public keys for network child */
வெறுமை
demote_sensitive_data(வெறுமை)
{
	கட்டமைப்பு sshkey *tmp;
	u_int i;
	முழு r;

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		எனில் (sensitive_data.host_சாவிகள்[i]) {
			எனில் ((r = sshkey_from_private(
			    sensitive_data.host_சாவிகள்[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_data.host_சாவிகள்[i]));
			sshkey_free(sensitive_data.host_சாவிகள்[i]);
			sensitive_data.host_சாவிகள்[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

கட்டமைப்பு sshbuf *
pack_hostkeys(வெறுமை)
{
	கட்டமைப்பு sshbuf *keybuf = வெற்று, *hostkeys = வெற்று;
	முழு r;
	u_int i;

	எனில் ((hostkeys = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		/* public key */
		எனில் (sensitive_data.host_pubkeys[i] != வெற்று) {
			எனில் ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} இல்லையெனில் {
			எனில் ((r = sshbuf_put_string(hostkeys, வெற்று, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		எனில் (sensitive_data.host_certificates[i] != வெற்று) {
			எனில் ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} இல்லையெனில் {
			எனில் ((r = sshbuf_put_string(hostkeys, வெற்று, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	sshbuf_free(keybuf);
	திரும்பு hostkeys;
}

நிலையான முழு
privsep_preauth(கட்டமைப்பு ssh *ssh)
{
	முழு r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	எனில் ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	இல்லையெனில் எனில் (pid != 0) {
		debug2("Network child is on pid %ld", (long)pid);

		pmonitor->m_pid = pid;
		எனில் (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			எனில் (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		திரும்பு 1;
	} இல்லையெனில் {
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

		எனில் (ssh_packet_get_connection_in(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_in(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		எனில் (ssh_packet_get_connection_out(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_out(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_to(வெற்று); /* dup can clobber log fd */
		எனில் (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		எனில் (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_path;
		execv(options.sshd_auth_path, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_path, strerror(errno));
	}
}

நிலையான வெறுமை
privsep_postauth(கட்டமைப்பு ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	எனில் (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	இல்லையெனில் எனில் (pmonitor->m_pid != 0) {
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

நிலையான கட்டமைப்பு sshkey *
get_hostkey_by_type(முழு type, முழு nid, முழு need_private, கட்டமைப்பு ssh *ssh)
{
	u_int i;
	கட்டமைப்பு sshkey *சாவி;

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		தேர்வு (type) {
		நிலை சாவி_RSA_CERT:
		நிலை சாவி_ECDSA_CERT:
		நிலை சாவி_ED25519_CERT:
		நிலை சாவி_ECDSA_SK_CERT:
		நிலை சாவி_ED25519_SK_CERT:
		நிலை சாவி_MLDSA44_ED25519_CERT:
			சாவி = sensitive_data.host_certificates[i];
			நிறுத்து;
		இயல்பு:
			சாவி = sensitive_data.host_சாவிகள்[i];
			எனில் (சாவி == வெற்று && !need_private)
				சாவி = sensitive_data.host_pubkeys[i];
			நிறுத்து;
		}
		எனில் (சாவி == வெற்று || சாவி->type != type)
			தொடர்;
		தேர்வு (type) {
		நிலை சாவி_ECDSA:
		நிலை சாவி_ECDSA_SK:
		நிலை சாவி_ECDSA_CERT:
		நிலை சாவி_ECDSA_SK_CERT:
			எனில் (சாவி->ecdsa_nid != nid)
				தொடர்;
			/* FALLTHROUGH */
		இயல்பு:
			திரும்பு need_private ?
			    sensitive_data.host_சாவிகள்[i] : சாவி;
		}
	}
	திரும்பு வெற்று;
}

கட்டமைப்பு sshkey *
get_hostkey_public_by_type(முழு type, முழு nid, கட்டமைப்பு ssh *ssh)
{
	திரும்பு get_hostkey_by_type(type, nid, 0, ssh);
}

கட்டமைப்பு sshkey *
get_hostkey_private_by_type(முழு type, முழு nid, கட்டமைப்பு ssh *ssh)
{
	திரும்பு get_hostkey_by_type(type, nid, 1, ssh);
}

கட்டமைப்பு sshkey *
get_hostkey_by_index(முழு ind)
{
	எனில் (ind < 0 || (u_int)ind >= options.இலக்கம்_host_சாவி_files)
		திரும்பு (வெற்று);
	திரும்பு (sensitive_data.host_சாவிகள்[ind]);
}

கட்டமைப்பு sshkey *
get_hostkey_public_by_index(முழு ind, கட்டமைப்பு ssh *ssh)
{
	எனில் (ind < 0 || (u_int)ind >= options.இலக்கம்_host_சாவி_files)
		திரும்பு (வெற்று);
	திரும்பு (sensitive_data.host_pubkeys[ind]);
}

முழு
get_hostkey_index(கட்டமைப்பு sshkey *சாவி, முழு compare, கட்டமைப்பு ssh *ssh)
{
	u_int i;

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		எனில் (sshkey_is_cert(சாவி)) {
			எனில் (சாவி == sensitive_data.host_certificates[i] ||
			    (compare && sensitive_data.host_certificates[i] &&
			    sshkey_equal(சாவி,
			    sensitive_data.host_certificates[i])))
				திரும்பு (i);
		} இல்லையெனில் {
			எனில் (சாவி == sensitive_data.host_சாவிகள்[i] ||
			    (compare && sensitive_data.host_சாவிகள்[i] &&
			    sshkey_equal(சாவி, sensitive_data.host_சாவிகள்[i])))
				திரும்பு (i);
			எனில் (சாவி == sensitive_data.host_pubkeys[i] ||
			    (compare && sensitive_data.host_pubkeys[i] &&
			    sshkey_equal(சாவி, sensitive_data.host_pubkeys[i])))
				திரும்பு (i);
		}
	}
	திரும்பு (-1);
}

/* Inform the client of all hostkeys */
நிலையான வெறுமை
notify_hostkeys(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு sshbuf *buf;
	கட்டமைப்பு sshkey *சாவி;
	u_int i, nkeys;
	முழு r;
	எழுத்து *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	எனில் (ssh->compat & SSH_BUG_HOSTKEYS)
		திரும்பு;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	க்கு (i = nkeys = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		சாவி = get_hostkey_public_by_index(i, ssh);
		எனில் (சாவி == வெற்று || சாவி->type == சாவி_UNSPEC ||
		    sshkey_is_cert(சாவி))
			தொடர்;
		fp = sshkey_fingerprint(சாவி, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(சாவி), fp);
		விடுவி(fp);
		எனில் (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		எனில் ((r = sshkey_putb(சாவி, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		எனில் ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	எனில் (nkeys == 0)
		fatal_f("no hostkeys");
	எனில் ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
}

நிலையான வெறுமை
usage(வெறுமை)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

நிலையான வெறுமை
parse_hostkeys(கட்டமைப்பு sshbuf *hostkeys)
{
	முழு r;
	u_int இலக்கம்_சாவிகள் = 0;
	கட்டமைப்பு sshkey *k;
	கட்டமைப்பு sshbuf *kbuf;
	மாறிலி u_char *cp;
	size_t len;

	போது (sshbuf_len(hostkeys) != 0) {
		எனில் (இலக்கம்_சாவிகள் > 2048)
			fatal_f("too many hostkeys");
		sensitive_data.host_சாவிகள் = xrecallocarray(
		    sensitive_data.host_சாவிகள், இலக்கம்_சாவிகள், இலக்கம்_சாவிகள் + 1,
		    அளவு(*sensitive_data.host_pubkeys));
		sensitive_data.host_pubkeys = xrecallocarray(
		    sensitive_data.host_pubkeys, இலக்கம்_சாவிகள், இலக்கம்_சாவிகள் + 1,
		    அளவு(*sensitive_data.host_pubkeys));
		sensitive_data.host_certificates = xrecallocarray(
		    sensitive_data.host_certificates, இலக்கம்_சாவிகள், இலக்கம்_சாவிகள் + 1,
		    அளவு(*sensitive_data.host_certificates));
		/* private key */
		k = வெற்று;
		எனில் ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		எனில் (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_private_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_சாவிகள்[இலக்கம்_சாவிகள்] = k;
		sshbuf_free(kbuf);
		எனில் (k)
			debug2_f("privkey %u: %s", இலக்கம்_சாவிகள், sshkey_ssh_name(k));
		/* public key */
		k = வெற்று;
		எனில் ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		எனில் (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_pubkeys[இலக்கம்_சாவிகள்] = k;
		எனில் (k)
			debug2_f("pubkey %u: %s", இலக்கம்_சாவிகள், sshkey_ssh_name(k));
		/* certificate */
		k = வெற்று;
		எனில் ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		எனில் (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_certificates[இலக்கம்_சாவிகள்] = k;
		எனில் (k)
			debug2_f("cert %u: %s", இலக்கம்_சாவிகள், sshkey_ssh_name(k));
		இலக்கம்_சாவிகள்++;
	}
	sensitive_data.இலக்கம்_hostkeys = இலக்கம்_சாவிகள்;
}

நிலையான வெறுமை
recv_rexec_state(முழு fd, கட்டமைப்பு sshbuf *conf, uint64_t *timing_secretp)
{
	கட்டமைப்பு sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	size_t len;
	முழு r;
	கட்டமைப்பு include_item *item;

	debug3_f("entering fd = %d", fd);

	எனில் ((m = sshbuf_new()) == வெற்று || (inc = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	/* receive config */
	எனில் (ssh_செய்தி_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	எனில் ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	எனில் (ver != 0)
		fatal_f("rexec version mismatch");
	எனில் ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	எனில் (conf != வெற்று && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	போது (sshbuf_len(inc) != 0) {
		item = xcalloc(1, அளவு(*item));
		எனில் ((item->contents = sshbuf_new()) == வெற்று)
			fatal_f("sshbuf_new failed");
		எனில் ((r = sshbuf_get_cstring(inc, &item->selector, வெற்று)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, வெற்று)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	எனில் (ssh_செய்தி_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	எனில் ((r = sshbuf_get_u8(m, வெற்று)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	விடுவி(cp);
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
நிலையான வெறுமை
check_ip_options(கட்டமைப்பு ssh *ssh)
{
#ifdef IP_OPTIONS
	முழு sock_in = ssh_packet_get_connection_in(ssh);
	கட்டமைப்பு sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_size = அளவு(opts), fromlen = அளவு(from);
	எழுத்து text[அளவு(opts) * 3 + 1];

	memset(&from, 0, அளவு(from));
	எனில் (getpeername(sock_in, (கட்டமைப்பு sockaddr *)&from,
	    &fromlen) == -1)
		திரும்பு;
	எனில் (from.ss_family != AF_INET)
		திரும்பு;
	/* XXX IPv6 options? */

	எனில் (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_size) >= 0 && option_size != 0) {
		text[0] = '\0';
		க்கு (i = 0; i < option_size; i++)
			snprintf(text + i*3, அளவு(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#endif /* IP_OPTIONS */
}

/* Set the routing domain for this process */
நிலையான வெறுமை
set_process_rdomain(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *name)
{
#எனில் defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	எனில் (name == வெற்று)
		திரும்பு; /* default */

	எனில் (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		எனில் ((name = ssh_packet_rdomain_in(ssh)) == வெற்று)
			திரும்பு;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	திரும்பு sys_set_process_rdomain(name);
#அல்லதெனில் defined(__OpenBSD__)
	முழு rtable, ortable = getrtable();
	மாறிலி எழுத்து *errstr;

	எனில் (name == வெற்று)
		திரும்பு; /* default */

	எனில் (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		எனில் ((name = ssh_packet_rdomain_in(ssh)) == வெற்று)
			திரும்பு;
	}

	rtable = (முழு)strtonum(name, 0, 255, &errstr);
	எனில் (errstr != வெற்று) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	எனில் (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#இல்லையெனில் /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#endif
}

/*
 * Main program for the daemon.
 */
முழு
முதன்மை(முழு ac, எழுத்து **av)
{
	கட்டமைப்பு ssh *ssh = வெற்று;
	வெளி எழுத்து *optarg;
	வெளி முழு optind;
	முழு devnull, r, opt, remote_port;
	முழு sock_in = -1, sock_out = -1, rexeced_flag = 0, have_சாவி = 0;
	மாறிலி எழுத்து *remote_ip, *rdomain;
	எழுத்து *வரி, *laddr, *logfile = வெற்று;
	u_int i;
	uint64_t ibytes, obytes;
	mode_t new_umask;
	Authctxt *authctxt;
	கட்டமைப்பு connection_info *connection_info = வெற்று;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	கட்டமைப்பு itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, வெற்று);

#ifdef HAVE_SECUREWARE
	(வெறுமை)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, அளவு(*saved_argv));
	க்கு (i = 0; (முழு)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = வெற்று;

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
	போது ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		தேர்வு (opt) {
		நிலை '4':
			options.address_family = AF_INET;
			நிறுத்து;
		நிலை '6':
			options.address_family = AF_INET6;
			நிறுத்து;
		நிலை 'f':
			config_file_name = optarg;
			நிறுத்து;
		நிலை 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			நிறுத்து;
		நிலை 'd':
			எனில் (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} இல்லையெனில் எனில் (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			நிறுத்து;
		நிலை 'D':
			/* ignore */
			நிறுத்து;
		நிலை 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		நிலை 'e':
			log_stderr = 1;
			நிறுத்து;
		நிலை 'i':
			inetd_flag = 1;
			நிறுத்து;
		நிலை 'r':
			/* ignore */
			நிறுத்து;
		நிலை 'R':
			rexeced_flag = 1;
			நிறுத்து;
		நிலை 'Q':
			/* ignored */
			நிறுத்து;
		நிலை 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			நிறுத்து;
		நிலை 'b':
			/* protocol 1, ignored */
			நிறுத்து;
		நிலை 'p':
			options.ports_from_cmdline = 1;
			எனில் (options.இலக்கம்_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.இலக்கம்_ports++] = a2port(optarg);
			எனில் (options.ports[options.இலக்கம்_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			நிறுத்து;
		நிலை 'g':
			எனில் ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			நிறுத்து;
		நிலை 'k':
			/* protocol 1, ignored */
			நிறுத்து;
		நிலை 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			நிறுத்து;
		நிலை 't':
		நிலை 'T':
		நிலை 'G':
			fatal("test/dump modes not supported");
			நிறுத்து;
		நிலை 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			எனில் (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			நிறுத்து;
		நிலை 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, வெற்று);
			எனில் (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			நிறுத்து;
		நிலை 'o':
			வரி = xstrdup(optarg);
			எனில் (process_server_config_வரி(&options, வரி,
			    "command-line", 0, வெற்று, வெற்று, &includes) != 0)
				exit(1);
			விடுவி(வரி);
			நிறுத்து;
		நிலை 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		இயல்பு:
			usage();
			நிறுத்து;
		}
	}

	/* Check that there are no remaining arguments. */
	எனில் (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	எனில் (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	எனில் ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	போது (devnull < PRIVSEP_MIN_FREE_FD) {
		எனில் ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	எனில் (logfile != வெற்று) {
		எழுத்து *cp, pid_s[32];

		snprintf(pid_s, அளவு(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd-session",
		    (எழுத்து *)வெற்று);
		log_redirect_stderr_to(cp);
		விடுவி(cp);
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
	எனில் ((cfg = sshbuf_new()) == வெற்று)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, வெற்று, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	எனில் ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == வெற்று) {
		எனில் (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} இல்லையெனில் {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	எனில் (!debug_flag && !inetd_flag) {
		எனில் ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(வெறுமை)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	எனில் (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

	/* Check that options are sensible */
	எனில் (options.authorized_சாவிகள்_command_user == வெற்று &&
	    (options.authorized_சாவிகள்_command != வெற்று &&
	    strcasecmp(options.authorized_சாவிகள்_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	எனில் (options.authorized_principals_command_user == வெற்று &&
	    (options.authorized_principals_command != வெற்று &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match block, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	எனில் (options.இலக்கம்_auth_methods != 0) {
		க்கு (i = 0; i < options.இலக்கம்_auth_methods; i++) {
			எனில் (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				நிறுத்து;
		}
		எனில் (i >= options.இலக்கம்_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

#ifdef WITH_OPENSSL
	எனில் (options.moduli_file != வெற்று)
		dh_set_moduli_file(options.moduli_file);
#endif

	எனில் (options.host_சாவி_agent) {
		எனில் (strcmp(options.host_சாவி_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_சாவி_agent, 1);
		எனில் ((r = ssh_get_authentication_socket(வெற்று)) == 0)
			have_agent = 1;
		இல்லையெனில்
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_சாவி_agent);
	}

	எனில் (options.இலக்கம்_host_சாவி_files != sensitive_data.இலக்கம்_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.இலக்கம்_host_சாவி_files, sensitive_data.இலக்கம்_hostkeys);
	}

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		எனில் (sensitive_data.host_சாவிகள்[i] != வெற்று ||
		    (have_agent && sensitive_data.host_pubkeys[i] != வெற்று)) {
			have_சாவி = 1;
			நிறுத்து;
		}
	}
	எனில் (!have_சாவி)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(வெறுமை) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	எனில் (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	க்கு (i = 0; i < options.இலக்கம்_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	எனில் (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or rexec */
	எனில் (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} இல்லையெனில் {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	எனில் (stdfd_devnull(1, 1, !log_stderr) == -1)
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
	எனில் ((ssh = ssh_packet_set_connection(வெற்று, sock_in, sock_out)) == வெற்று)
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
	எனில் (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		set_keepalive(sock_in); /* logs errors */

	எனில் ((remote_port = ssh_remote_port(ssh)) < 0) {
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
	    rdomain == வெற்று ? "" : " rdomain \"",
	    rdomain == வெற்று ? "" : rdomain,
	    rdomain == வெற்று ? "" : "\"");
	விடுவி(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	எனில் (!debug_flag && options.login_grace_time > 0) {
		முழு ujitter = arc4random_uniform(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		எனில் (setitimer(ITIMER_REAL, &itv, வெற்று) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, அளவு(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	எனில் ((auth_opts = sshauthopt_new_with_சாவிகள்_defaults()) == வெற்று)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	எனில் ((loginmsg = sshbuf_new()) == வெற்று)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	எனில் (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	எனில் (setitimer(ITIMER_REAL, &itv, வெற்று) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	எனில் (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(வெறுமை)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	எனில் (options.routing_domain != வெற்று)
		set_process_rdomain(ssh, options.routing_domain);

#ifdef SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#endif

#ifdef GSSAPI
	எனில் (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#endif
#ifdef USE_PAM
	எனில் (options.use_pam) {
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
	    options.client_alive_மொத்தம்_max);

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
	எனில் (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

#ifdef SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#endif

	ssh_packet_close(ssh);

	mm_terminate();

	exit(0);
}

முழு
sshd_hostkey_sign(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshkey *privkey,
    கட்டமைப்பு sshkey *pubkey, u_char **signature, size_t *slenp,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg)
{
	எனில் (privkey) {
		எனில் (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, வெற்று,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} இல்லையெனில் {
		எனில் (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, வெற்று,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	திரும்பு 0;
}

/* server specific fatal cleanup */
வெறுமை
cleanup_exit(முழு i)
{
	எனில் (the_active_state != வெற்று && the_authctxt != வெற்று) {
		do_cleanup(the_active_state, the_authctxt);
		எனில் (privsep_is_preauth &&
		    pmonitor != வெற்று && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			எனில் (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ifdef SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	எனில் (the_active_state != வெற்று && mm_is_monitor())
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#endif
	/* Override default fatal exit value when auth was attempted */
	எனில் (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	எனில் (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
