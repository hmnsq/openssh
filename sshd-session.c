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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/tree.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <grp.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#यदि_परिभाषितम् HAVE_SECUREWARE
#अन्तर्भाव <sys/security.h>
#अन्तर्भाव <prot.h>
#यदि_अन्तः
 
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "session.h"
#अन्तर्भाव "monitor.h"
#यदि_परिभाषितम् GSSAPI
#अन्तर्भाव "ssh-gss.h"
#यदि_अन्तः
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "version.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "srclimit.h"
#अन्तर्भाव "dh.h"

/* Re-exec fds */
#परिभाषय REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#परिभाषय REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#परिभाषय REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#परिभाषय PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#परिभाषय PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#परिभाषय PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

बाह्य वर्ण *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
वर्ण *config_file_name = मार्गः_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
पूर्णाङ्क debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
स्थिर पूर्णाङ्क inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
स्थिर पूर्णाङ्क log_stderr = 0;

/* Saved arguments to main(). */
स्थिर वर्ण **saved_argv;
स्थिर पूर्णाङ्क saved_argc;

/* Daemon's agent connection */
पूर्णाङ्क auth_sock = -1;
स्थिर पूर्णाङ्क have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
संरचना {
	u_int		अङ्कः_hostkeys;
	संरचना sshkey	**host_कुञ्चिकाः;		/* all private host keys */
	संरचना sshkey	**host_pubkeys;		/* all public host keys */
	संरचना sshkey	**host_certificates;	/* all public host certificates */
} sensitive_दत्त;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

स्थिर पूर्णाङ्क startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
संरचना monitor *pmonitor = रिक्त;
पूर्णाङ्क privsep_is_preauth = 1;
स्थिर पूर्णाङ्क privsep_chroot = 1;

/* Unprivileged user */
संरचना passwd *privsep_pw = रिक्त;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = रिक्त;
संरचना ssh *the_सक्रिय_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
संरचना sshauthopt *auth_opts = रिक्त;

/* sshd_config buffer */
संरचना sshbuf *cfg;

/* Included files from the configuration file */
संरचना include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
संरचना sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
शून्य destroy_sensitive_दत्त(शून्य);
शून्य demote_sensitive_दत्त(शून्य);

/* XXX reduce to stub once postauth split */
पूर्णाङ्क
mm_is_monitor(शून्य)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	प्रत्यागम (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
स्थिर शून्य
grace_alarm_handler(पूर्णाङ्क sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	यदि (getpgid(0) == getpid()) {
		संरचना sigaction sa;

		/* mask all other signals while in handler */
		स्मृतिं_पूरय(&sa, 0, परिमाण(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#यदि defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#यदि_अन्तः
		(शून्य)sigaction(SIGTERM, &sa, रिक्त);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
शून्य
destroy_sensitive_दत्त(शून्य)
{
	u_int i;

	प्रति (i = 0; i < options.अङ्कः_host_कुञ्चिका_files; i++) {
		यदि (sensitive_दत्त.host_कुञ्चिकाः[i]) {
			sshkey_free(sensitive_दत्त.host_कुञ्चिकाः[i]);
			sensitive_दत्त.host_कुञ्चिकाः[i] = रिक्त;
		}
		यदि (sensitive_दत्त.host_certificates[i]) {
			sshkey_free(sensitive_दत्त.host_certificates[i]);
			sensitive_दत्त.host_certificates[i] = रिक्त;
		}
	}
}

/* Demote private to public keys for network child */
शून्य
demote_sensitive_दत्त(शून्य)
{
	संरचना sshkey *tmp;
	u_int i;
	पूर्णाङ्क r;

	प्रति (i = 0; i < options.अङ्कः_host_कुञ्चिका_files; i++) {
		यदि (sensitive_दत्त.host_कुञ्चिकाः[i]) {
			यदि ((r = sshkey_from_वैयक्तिकम्(
			    sensitive_दत्त.host_कुञ्चिकाः[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_दत्त.host_कुञ्चिकाः[i]));
			sshkey_free(sensitive_दत्त.host_कुञ्चिकाः[i]);
			sensitive_दत्त.host_कुञ्चिकाः[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

संरचना sshbuf *
pack_hostkeys(शून्य)
{
	संरचना sshbuf *keybuf = रिक्त, *hostkeys = रिक्त;
	पूर्णाङ्क r;
	u_int i;

	यदि ((hostkeys = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	प्रति (i = 0; i < options.अङ्कः_host_कुञ्चिका_files; i++) {
		/* public key */
		यदि (sensitive_दत्त.host_pubkeys[i] != रिक्त) {
			यदि ((r = sshkey_puts(sensitive_दत्त.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} अन्यथा {
			यदि ((r = sshbuf_put_string(hostkeys, रिक्त, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		यदि (sensitive_दत्त.host_certificates[i] != रिक्त) {
			यदि ((r = sshkey_puts(
			    sensitive_दत्त.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} अन्यथा {
			यदि ((r = sshbuf_put_string(hostkeys, रिक्त, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	sshbuf_free(keybuf);
	प्रत्यागम hostkeys;
}

स्थिर पूर्णाङ्क
privsep_preauth(संरचना ssh *ssh)
{
	पूर्णाङ्क r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	यदि ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	अन्यथा यदि (pid != 0) {
		debug2("Network child is on pid %ld", (दीर्घ)pid);

		pmonitor->m_pid = pid;
		यदि (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			यदि (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		प्रत्यागम 1;
	} अन्यथा {
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

		यदि (ssh_packet_get_connection_अन्तर्(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_अन्तर्(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		यदि (ssh_packet_get_connection_बहिर्गमनम्(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_बहिर्गमनम्(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_गन्तव्यम्(रिक्त); /* dup can clobber log fd */
		यदि (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		यदि (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_मार्गः;
		execv(options.sshd_auth_मार्गः, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_मार्गः, strerror(errno));
	}
}

स्थिर शून्य
privsep_postauth(संरचना ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	यदि (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	अन्यथा यदि (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (दीर्घ)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_child_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		निर्गच्छ(0);
	}

	/* child */

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_दत्त();

	reseed_prngs();

#यदि_अपरिभाषितम् SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#यदि_अन्तः

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_समुच्चयः_authenticated(ssh);
}

स्थिर संरचना sshkey *
get_hostkey_by_type(पूर्णाङ्क type, पूर्णाङ्क nid, पूर्णाङ्क need_वैयक्तिकम्, संरचना ssh *ssh)
{
	u_int i;
	संरचना sshkey *कुञ्चिका;

	प्रति (i = 0; i < options.अङ्कः_host_कुञ्चिका_files; i++) {
		विकल्प (type) {
		पक्ष कुञ्चिका_RSA_CERT:
		पक्ष कुञ्चिका_ECDSA_CERT:
		पक्ष कुञ्चिका_ED25519_CERT:
		पक्ष कुञ्चिका_ECDSA_SK_CERT:
		पक्ष कुञ्चिका_ED25519_SK_CERT:
		पक्ष कुञ्चिका_MLDSA44_ED25519_CERT:
			कुञ्चिका = sensitive_दत्त.host_certificates[i];
			भङ्ग;
		स्वभाव:
			कुञ्चिका = sensitive_दत्त.host_कुञ्चिकाः[i];
			यदि (कुञ्चिका == रिक्त && !need_वैयक्तिकम्)
				कुञ्चिका = sensitive_दत्त.host_pubkeys[i];
			भङ्ग;
		}
		यदि (कुञ्चिका == रिक्त || कुञ्चिका->type != type)
			अनुवर्त;
		विकल्प (type) {
		पक्ष कुञ्चिका_ECDSA:
		पक्ष कुञ्चिका_ECDSA_SK:
		पक्ष कुञ्चिका_ECDSA_CERT:
		पक्ष कुञ्चिका_ECDSA_SK_CERT:
			यदि (कुञ्चिका->ecdsa_nid != nid)
				अनुवर्त;
			/* FALLTHROUGH */
		स्वभाव:
			प्रत्यागम need_वैयक्तिकम् ?
			    sensitive_दत्त.host_कुञ्चिकाः[i] : कुञ्चिका;
		}
	}
	प्रत्यागम रिक्त;
}

संरचना sshkey *
get_hostkey_लौकिकम्_by_type(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	प्रत्यागम get_hostkey_by_type(type, nid, 0, ssh);
}

संरचना sshkey *
get_hostkey_वैयक्तिकम्_by_type(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	प्रत्यागम get_hostkey_by_type(type, nid, 1, ssh);
}

संरचना sshkey *
get_hostkey_by_सूचकांक(पूर्णाङ्क ind)
{
	यदि (ind < 0 || (u_int)ind >= options.अङ्कः_host_कुञ्चिका_files)
		प्रत्यागम (रिक्त);
	प्रत्यागम (sensitive_दत्त.host_कुञ्चिकाः[ind]);
}

संरचना sshkey *
get_hostkey_लौकिकम्_by_सूचकांक(पूर्णाङ्क ind, संरचना ssh *ssh)
{
	यदि (ind < 0 || (u_int)ind >= options.अङ्कः_host_कुञ्चिका_files)
		प्रत्यागम (रिक्त);
	प्रत्यागम (sensitive_दत्त.host_pubkeys[ind]);
}

पूर्णाङ्क
get_hostkey_सूचकांक(संरचना sshkey *कुञ्चिका, पूर्णाङ्क compare, संरचना ssh *ssh)
{
	u_int i;

	प्रति (i = 0; i < options.अङ्कः_host_कुञ्चिका_files; i++) {
		यदि (sshkey_is_cert(कुञ्चिका)) {
			यदि (कुञ्चिका == sensitive_दत्त.host_certificates[i] ||
			    (compare && sensitive_दत्त.host_certificates[i] &&
			    sshkey_equal(कुञ्चिका,
			    sensitive_दत्त.host_certificates[i])))
				प्रत्यागम (i);
		} अन्यथा {
			यदि (कुञ्चिका == sensitive_दत्त.host_कुञ्चिकाः[i] ||
			    (compare && sensitive_दत्त.host_कुञ्चिकाः[i] &&
			    sshkey_equal(कुञ्चिका, sensitive_दत्त.host_कुञ्चिकाः[i])))
				प्रत्यागम (i);
			यदि (कुञ्चिका == sensitive_दत्त.host_pubkeys[i] ||
			    (compare && sensitive_दत्त.host_pubkeys[i] &&
			    sshkey_equal(कुञ्चिका, sensitive_दत्त.host_pubkeys[i])))
				प्रत्यागम (i);
		}
	}
	प्रत्यागम (-1);
}

/* Inform the client of all hostkeys */
स्थिर शून्य
notify_hostkeys(संरचना ssh *ssh)
{
	संरचना sshbuf *buf;
	संरचना sshkey *कुञ्चिका;
	u_int i, nkeys;
	पूर्णाङ्क r;
	वर्ण *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	यदि (ssh->compat & SSH_BUG_HOSTKEYS)
		प्रत्यागम;

	यदि ((buf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	प्रति (i = nkeys = 0; i < options.अङ्कः_host_कुञ्चिका_files; i++) {
		कुञ्चिका = get_hostkey_लौकिकम्_by_सूचकांक(i, ssh);
		यदि (कुञ्चिका == रिक्त || कुञ्चिका->type == कुञ्चिका_UNSPEC ||
		    sshkey_is_cert(कुञ्चिका))
			अनुवर्त;
		fp = sshkey_fingerprint(कुञ्चिका, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(कुञ्चिका), fp);
		मुक्त(fp);
		यदि (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		यदि ((r = sshkey_putb(कुञ्चिका, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		यदि ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	यदि (nkeys == 0)
		fatal_f("no hostkeys");
	यदि ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
}

स्थिर शून्य
usage(शून्य)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_संस्करणम्);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	निर्गच्छ(1);
}

स्थिर शून्य
parse_hostkeys(संरचना sshbuf *hostkeys)
{
	पूर्णाङ्क r;
	u_int अङ्कः_कुञ्चिकाः = 0;
	संरचना sshkey *k;
	संरचना sshbuf *kbuf;
	ध्रुव u_char *cp;
	आकार_t len;

	यावत् (sshbuf_len(hostkeys) != 0) {
		यदि (अङ्कः_कुञ्चिकाः > 2048)
			fatal_f("too many hostkeys");
		sensitive_दत्त.host_कुञ्चिकाः = xrecallocarray(
		    sensitive_दत्त.host_कुञ्चिकाः, अङ्कः_कुञ्चिकाः, अङ्कः_कुञ्चिकाः + 1,
		    परिमाण(*sensitive_दत्त.host_pubkeys));
		sensitive_दत्त.host_pubkeys = xrecallocarray(
		    sensitive_दत्त.host_pubkeys, अङ्कः_कुञ्चिकाः, अङ्कः_कुञ्चिकाः + 1,
		    परिमाण(*sensitive_दत्त.host_pubkeys));
		sensitive_दत्त.host_certificates = xrecallocarray(
		    sensitive_दत्त.host_certificates, अङ्कः_कुञ्चिकाः, अङ्कः_कुञ्चिकाः + 1,
		    परिमाण(*sensitive_दत्त.host_certificates));
		/* private key */
		k = रिक्त;
		यदि ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		यदि (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_वैयक्तिकम्_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_दत्त.host_कुञ्चिकाः[अङ्कः_कुञ्चिकाः] = k;
		sshbuf_free(kbuf);
		यदि (k)
			debug2_f("privkey %u: %s", अङ्कः_कुञ्चिकाः, sshkey_ssh_name(k));
		/* public key */
		k = रिक्त;
		यदि ((r = sshbuf_get_string_प्रत्यक्षम्(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		यदि (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_दत्त.host_pubkeys[अङ्कः_कुञ्चिकाः] = k;
		यदि (k)
			debug2_f("pubkey %u: %s", अङ्कः_कुञ्चिकाः, sshkey_ssh_name(k));
		/* certificate */
		k = रिक्त;
		यदि ((r = sshbuf_get_string_प्रत्यक्षम्(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		यदि (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_दत्त.host_certificates[अङ्कः_कुञ्चिकाः] = k;
		यदि (k)
			debug2_f("cert %u: %s", अङ्कः_कुञ्चिकाः, sshkey_ssh_name(k));
		अङ्कः_कुञ्चिकाः++;
	}
	sensitive_दत्त.अङ्कः_hostkeys = अङ्कः_कुञ्चिकाः;
}

स्थिर शून्य
recv_rexec_state(पूर्णाङ्क fd, संरचना sshbuf *conf, uint64_t *timing_secretp)
{
	संरचना sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	आकार_t len;
	पूर्णाङ्क r;
	संरचना include_item *item;

	debug3_f("entering fd = %d", fd);

	यदि ((m = sshbuf_new()) == रिक्त || (inc = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* receive config */
	यदि (ssh_सन्देशः_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	यदि ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	यदि (ver != 0)
		fatal_f("rexec version mismatch");
	यदि ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	यदि (conf != रिक्त && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	यावत् (sshbuf_len(inc) != 0) {
		item = xcalloc(1, परिमाण(*item));
		यदि ((item->contents = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new failed");
		यदि ((r = sshbuf_get_cstring(inc, &item->selector, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, रिक्त)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, प्रविष्टिः);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	यदि (ssh_सन्देशः_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	यदि ((r = sshbuf_get_u8(m, रिक्त)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	मुक्त(cp);
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
स्थिर शून्य
check_ip_options(संरचना ssh *ssh)
{
#यदि_परिभाषितम् IP_OPTIONS
	पूर्णाङ्क sock_अन्तर् = ssh_packet_get_connection_अन्तर्(ssh);
	संरचना sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_आकार = परिमाण(opts), fromlen = परिमाण(from);
	वर्ण text[परिमाण(opts) * 3 + 1];

	स्मृतिं_पूरय(&from, 0, परिमाण(from));
	यदि (getpeername(sock_अन्तर्, (संरचना sockaddr *)&from,
	    &fromlen) == -1)
		प्रत्यागम;
	यदि (from.ss_family != AF_INET)
		प्रत्यागम;
	/* XXX IPv6 options? */

	यदि (getsockopt(sock_अन्तर्, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_आकार) >= 0 && option_आकार != 0) {
		text[0] = '\0';
		प्रति (i = 0; i < option_आकार; i++)
			snprintf(text + i*3, परिमाण(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh), text);
	}
#यदि_अन्तः /* IP_OPTIONS */
}

/* Set the routing domain for this process */
स्थिर शून्य
समुच्चयः_process_rdomain(संरचना ssh *ssh, ध्रुव वर्ण *name)
{
#यदि defined(HAVE_SYS_समुच्चयः_PROCESS_RDOMAIN)
	यदि (name == रिक्त)
		प्रत्यागम; /* default */

	यदि (वाक्यं_तुलय(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		यदि ((name = ssh_packet_rdomain_अन्तर्(ssh)) == रिक्त)
			प्रत्यागम;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	प्रत्यागम sys_समुच्चयः_process_rdomain(name);
#नोचेद्यदि defined(__OpenBSD__)
	पूर्णाङ्क rtable, ortable = getrtable();
	ध्रुव वर्ण *errstr;

	यदि (name == रिक्त)
		प्रत्यागम; /* default */

	यदि (वाक्यं_तुलय(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		यदि ((name = ssh_packet_rdomain_अन्तर्(ssh)) == रिक्त)
			प्रत्यागम;
	}

	rtable = (पूर्णाङ्क)strtonum(name, 0, 255, &errstr);
	यदि (errstr != रिक्त) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	यदि (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#अन्यथा /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#यदि_अन्तः
}

/*
 * Main program for the daemon.
 */
पूर्णाङ्क
मुख्यम्(पूर्णाङ्क ac, वर्ण **av)
{
	संरचना ssh *ssh = रिक्त;
	बाह्य वर्ण *optarg;
	बाह्य पूर्णाङ्क optind;
	पूर्णाङ्क devnull, r, opt, remote_पत्तनम्;
	पूर्णाङ्क sock_अन्तर् = -1, sock_बहिर्गमनम् = -1, rexeced_flag = 0, have_कुञ्चिका = 0;
	ध्रुव वर्ण *remote_ip, *rdomain;
	वर्ण *पङ्क्तिः, *laddr, *logfile = रिक्त;
	u_int i;
	uint64_t ibytes, obytes;
	बहुलकम्_t new_umask;
	Authctxt *authctxt;
	संरचना connection_info *connection_info = रिक्त;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	संरचना itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, रिक्त);

#यदि_परिभाषितम् HAVE_SECUREWARE
	(शून्य)समुच्चयः_auth_parameters(ac, av);
#यदि_अन्तः
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, परिमाण(*saved_argv));
	प्रति (i = 0; (पूर्णाङ्क)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = रिक्त;

#यदि_अपरिभाषितम् HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#यदि_अन्तः

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	यावत् ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		विकल्प (opt) {
		पक्ष '4':
			options.स्थानाङ्कः_family = AF_INET;
			भङ्ग;
		पक्ष '6':
			options.स्थानाङ्कः_family = AF_INET6;
			भङ्ग;
		पक्ष 'f':
			config_file_name = optarg;
			भङ्ग;
		पक्ष 'c':
			servconf_सङ्कलय_hostcert("[command-line]", 0,
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
			/* ignore */
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
			/* ignore */
			भङ्ग;
		पक्ष 'R':
			rexeced_flag = 1;
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
			यदि (options.अङ्कः_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				निर्गच्छ(1);
			}
			options.ports[options.अङ्कः_ports++] = a2port(optarg);
			यदि (options.ports[options.अङ्कः_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				निर्गच्छ(1);
			}
			भङ्ग;
		पक्ष 'g':
			यदि ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				निर्गच्छ(1);
			}
			भङ्ग;
		पक्ष 'k':
			/* protocol 1, ignored */
			भङ्ग;
		पक्ष 'h':
			servconf_सङ्कलय_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			भङ्ग;
		पक्ष 't':
		पक्ष 'T':
		पक्ष 'G':
			fatal("test/dump modes not supported");
			भङ्ग;
		पक्ष 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			यदि (parse_server_मेलनम्_testspec(connection_info,
			    optarg) == -1)
				निर्गच्छ(1);
			भङ्ग;
		पक्ष 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, रिक्त);
			यदि (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				निर्गच्छ(1);
			}
			भङ्ग;
		पक्ष 'o':
			पङ्क्तिः = xstrdup(optarg);
			यदि (process_server_config_पङ्क्तिः(&options, पङ्क्तिः,
			    "command-line", 0, रिक्त, रिक्त, &includes) != 0)
				निर्गच्छ(1);
			मुक्त(पङ्क्तिः);
			भङ्ग;
		पक्ष 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_संस्करणम्);
			निर्गच्छ(0);
		स्वभाव:
			usage();
			भङ्ग;
		}
	}

	/* Check that there are no remaining arguments. */
	यदि (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		निर्गच्छ(1);
	}

	यदि (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	यदि ((devnull = उद्घाटय(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	यावत् (devnull < PRIVSEP_MIN_FREE_FD) {
		यदि ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	बीजम्_rng();

	/* If requested, redirect the logs to the specified logfile. */
	यदि (logfile != रिक्त) {
		वर्ण *cp, pid_s[32];

		snprintf(pid_s, परिमाण(pid_s), "%ld", (अचिह्नित दीर्घ)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd-session",
		    (वर्ण *)रिक्त);
		log_redirect_stderr_गन्तव्यम्(cp);
		मुक्त(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_समुच्चयः ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_समुच्चयः ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/* Fetch our configuration */
	यदि ((cfg = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, रिक्त, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_संस्करणम्, SSH_OPENSSL_संस्करणम्);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	यदि ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == रिक्त) {
		यदि (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} अन्यथा {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, वाक्यदैर्घ्यम्(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	यदि (!debug_flag && !inetd_flag) {
		यदि ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(शून्य)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	यदि (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

	/* Check that options are sensible */
	यदि (options.authorized_कुञ्चिकाः_command_user == रिक्त &&
	    (options.authorized_कुञ्चिकाः_command != रिक्त &&
	    strcasecmp(options.authorized_कुञ्चिकाः_command, "none") != 0))
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
	 * daemonisation in the presence of Match block, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	यदि (options.अङ्कः_auth_methods != 0) {
		प्रति (i = 0; i < options.अङ्कः_auth_methods; i++) {
			यदि (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				भङ्ग;
		}
		यदि (i >= options.अङ्कः_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

#यदि_परिभाषितम् WITH_OPENSSL
	यदि (options.moduli_file != रिक्त)
		dh_समुच्चयः_moduli_file(options.moduli_file);
#यदि_अन्तः

	यदि (options.host_कुञ्चिका_agent) {
		यदि (वाक्यं_तुलय(options.host_कुञ्चिका_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_कुञ्चिका_agent, 1);
		यदि ((r = ssh_get_authentication_socket(रिक्त)) == 0)
			have_agent = 1;
		अन्यथा
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_कुञ्चिका_agent);
	}

	यदि (options.अङ्कः_host_कुञ्चिका_files != sensitive_दत्त.अङ्कः_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.अङ्कः_host_कुञ्चिका_files, sensitive_दत्त.अङ्कः_hostkeys);
	}

	प्रति (i = 0; i < options.अङ्कः_host_कुञ्चिका_files; i++) {
		यदि (sensitive_दत्त.host_कुञ्चिकाः[i] != रिक्त ||
		    (have_agent && sensitive_दत्त.host_pubkeys[i] != रिक्त)) {
			have_कुञ्चिका = 1;
			भङ्ग;
		}
	}
	यदि (!have_कुञ्चिका)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(शून्य) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	यदि (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	प्रति (i = 0; i < options.अङ्कः_log_verbose; i++)
		log_verbose_सङ्कलय(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	यदि (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_अन्तर् = dup(STDIN_FILENO);
		sock_बहिर्गमनम् = dup(STDOUT_FILENO);
	} अन्यथा {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_अन्तर् = sock_बहिर्गमनम् = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	यदि (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_अन्तर्, sock_बहिर्गमनम्);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_बहिर्गमनम्);
	FD_CLOSEONEXEC(sock_अन्तर्);

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
	यदि ((ssh = ssh_packet_समुच्चयः_connection(रिक्त, sock_अन्तर्, sock_बहिर्गमनम्)) == रिक्त)
		fatal("Unable to create connection");
	the_सक्रिय_state = ssh;
	ssh_packet_समुच्चयः_server(ssh);
	ssh_packet_समुच्चयः_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_समुच्चयः_af(ssh, options.स्थानाङ्कः_family);
	channel_समुच्चयः_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	/* Set SO_KEEPALIVE if requested. */
	यदि (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		समुच्चयः_keepalive(sock_अन्तर्); /* logs errors */

	यदि ((remote_पत्तनम् = ssh_remote_पत्तनम्(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#यदि_परिभाषितम् SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_पत्तनम्);
#यदि_अन्तः

	rdomain = ssh_packet_rdomain_अन्तर्(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_अन्तर्);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_पत्तनम्, laddr,  ssh_local_पत्तनम्(ssh),
	    rdomain == रिक्त ? "" : " rdomain \"",
	    rdomain == रिक्त ? "" : rdomain,
	    rdomain == रिक्त ? "" : "\"");
	मुक्त(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	यदि (!debug_flag && options.login_grace_time > 0) {
		पूर्णाङ्क ujitter = arc4random_एकरूपम्(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		यदि (setitimer(ITIMER_REAL, &itv, रिक्त) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_समुच्चयः_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, परिमाण(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	यदि ((auth_opts = sshauthopt_new_with_कुञ्चिकाः_defaults()) == रिक्त)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	यदि ((loginmsg = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	यदि (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	यदि (setitimer(ITIMER_REAL, &itv, रिक्त) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	यदि (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(शून्य)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	यदि (options.routing_domain != रिक्त)
		समुच्चयः_process_rdomain(ssh, options.routing_domain);

#यदि_परिभाषितम् SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#यदि_अन्तः

#यदि_परिभाषितम् GSSAPI
	यदि (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#यदि_अन्तः
#यदि_परिभाषितम् USE_PAM
	यदि (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#यदि_अन्तः

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_समुच्चयः_timeout(ssh, options.client_alive_interval,
	    options.client_alive_गणनम्_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_अष्टकानि(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (अचिह्नित दीर्घ दीर्घ)obytes, (अचिह्नित दीर्घ दीर्घ)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_पत्तनम्);

#यदि_परिभाषितम् USE_PAM
	यदि (options.use_pam)
		finish_pam();
#यदि_अन्तः /* USE_PAM */

#यदि_परिभाषितम् SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#यदि_अन्तः

	ssh_packet_close(ssh);

	mm_terminate();

	निर्गच्छ(0);
}

पूर्णाङ्क
sshd_hostkey_sign(संरचना ssh *ssh, संरचना sshkey *privkey,
    संरचना sshkey *pubkey, u_char **signature, आकार_t *slenp,
    ध्रुव u_char *दत्त, आकार_t dlen, ध्रुव वर्ण *alg)
{
	यदि (privkey) {
		यदि (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    दत्त, dlen, alg, options.sk_provider, रिक्त,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} अन्यथा {
		यदि (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    दत्त, dlen, alg, options.sk_provider, रिक्त,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	प्रत्यागम 0;
}

/* server specific fatal cleanup */
शून्य
cleanup_exit(पूर्णाङ्क i)
{
	यदि (the_सक्रिय_state != रिक्त && the_authctxt != रिक्त) {
		do_cleanup(the_सक्रिय_state, the_authctxt);
		यदि (privsep_is_preauth &&
		    pmonitor != रिक्त && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			यदि (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#यदि_परिभाषितम् SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	यदि (the_सक्रिय_state != रिक्त && mm_is_monitor())
		audit_event(the_सक्रिय_state, SSH_CONNECTION_ABANDON);
#यदि_अन्तः
	/* Override default fatal exit value when auth was attempted */
	यदि (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	यदि (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
