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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/tree.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <grp.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#నిర్వచితమైతే HAVE_SECUREWARE
#అన్తర్భావ <sys/security.h>
#అన్తర్భావ <prot.h>
#అయితే_ముగింపు
 
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "sshpty.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "session.h"
#అన్తర్భావ "monitor.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "version.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sk-api.h"
#అన్తర్భావ "srclimit.h"
#అన్తర్భావ "dh.h"

/* Re-exec fds */
#నిర్వచించు REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#నిర్వచించు REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#నిర్వచించు REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#నిర్వచించు PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#నిర్వచించు PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#నిర్వచించు PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

బాహ్య అక్షరం *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
అక్షరం *config_file_name = మార్గం_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
పూర్ణాంకం debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
స్థిర పూర్ణాంకం inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
స్థిర పూర్ణాంకం log_stderr = 0;

/* Saved arguments to main(). */
స్థిర అక్షరం **saved_argv;
స్థిర పూర్ణాంకం saved_argc;

/* Daemon's agent connection */
పూర్ణాంకం auth_sock = -1;
స్థిర పూర్ణాంకం have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
నిర్మాణం {
	u_int		అంకె_hostkeys;
	నిర్మాణం sshkey	**host_కీలకాలు;		/* all private host keys */
	నిర్మాణం sshkey	**host_pubkeys;		/* all public host keys */
	నిర్మాణం sshkey	**host_certificates;	/* all public host certificates */
} sensitive_దత్తాంశం;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

స్థిర పూర్ణాంకం startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
నిర్మాణం monitor *pmonitor = ఖాళీ;
పూర్ణాంకం privsep_is_preauth = 1;
స్థిర పూర్ణాంకం privsep_chroot = 1;

/* Unprivileged user */
నిర్మాణం passwd *privsep_pw = ఖాళీ;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ఖాళీ;
నిర్మాణం ssh *the_చురుకైన_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
నిర్మాణం sshauthopt *auth_opts = ఖాళీ;

/* sshd_config buffer */
నిర్మాణం sshbuf *cfg;

/* Included files from the configuration file */
నిర్మాణం include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
నిర్మాణం sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
శూన్య destroy_sensitive_దత్తాంశం(శూన్య);
శూన్య demote_sensitive_దత్తాంశం(శూన్య);

/* XXX reduce to stub once postauth split */
పూర్ణాంకం
mm_is_monitor(శూన్య)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	తిరిగి (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
స్థిర శూన్య
grace_alarm_handler(పూర్ణాంకం sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	ఒకవేళ (getpgid(0) == getpid()) {
		నిర్మాణం sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, పరిమాణం(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#ఒకవేళ defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#అయితే_ముగింపు
		(శూన్య)sigaction(SIGTERM, &sa, ఖాళీ);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
శూన్య
destroy_sensitive_దత్తాంశం(శూన్య)
{
	u_int i;

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		ఒకవేళ (sensitive_దత్తాంశం.host_కీలకాలు[i]) {
			sshkey_free(sensitive_దత్తాంశం.host_కీలకాలు[i]);
			sensitive_దత్తాంశం.host_కీలకాలు[i] = ఖాళీ;
		}
		ఒకవేళ (sensitive_దత్తాంశం.host_certificates[i]) {
			sshkey_free(sensitive_దత్తాంశం.host_certificates[i]);
			sensitive_దత్తాంశం.host_certificates[i] = ఖాళీ;
		}
	}
}

/* Demote private to public keys for network child */
శూన్య
demote_sensitive_దత్తాంశం(శూన్య)
{
	నిర్మాణం sshkey *tmp;
	u_int i;
	పూర్ణాంకం r;

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		ఒకవేళ (sensitive_దత్తాంశం.host_కీలకాలు[i]) {
			ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(
			    sensitive_దత్తాంశం.host_కీలకాలు[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_దత్తాంశం.host_కీలకాలు[i]));
			sshkey_free(sensitive_దత్తాంశం.host_కీలకాలు[i]);
			sensitive_దత్తాంశం.host_కీలకాలు[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

నిర్మాణం sshbuf *
pack_hostkeys(శూన్య)
{
	నిర్మాణం sshbuf *keybuf = ఖాళీ, *hostkeys = ఖాళీ;
	పూర్ణాంకం r;
	u_int i;

	ఒకవేళ ((hostkeys = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		/* public key */
		ఒకవేళ (sensitive_దత్తాంశం.host_pubkeys[i] != ఖాళీ) {
			ఒకవేళ ((r = sshkey_puts(sensitive_దత్తాంశం.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} లేకపోతే {
			ఒకవేళ ((r = sshbuf_put_string(hostkeys, ఖాళీ, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		ఒకవేళ (sensitive_దత్తాంశం.host_certificates[i] != ఖాళీ) {
			ఒకవేళ ((r = sshkey_puts(
			    sensitive_దత్తాంశం.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} లేకపోతే {
			ఒకవేళ ((r = sshbuf_put_string(hostkeys, ఖాళీ, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	sshbuf_free(keybuf);
	తిరిగి hostkeys;
}

స్థిర పూర్ణాంకం
privsep_preauth(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	ఒకవేళ ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	లేకపోతే ఒకవేళ (pid != 0) {
		debug2("Network child is on pid %ld", (దీర్ఘ)pid);

		pmonitor->m_pid = pid;
		ఒకవేళ (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			ఒకవేళ (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_బిడ్డ_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		తిరిగి 1;
	} లేకపోతే {
		/*బిడ్డ*/
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

		ఒకవేళ (ssh_packet_get_connection_లోపల(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_లోపల(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		ఒకవేళ (ssh_packet_get_connection_బహిర్గతం(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_బహిర్గతం(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_గమ్యం(ఖాళీ); /* dup can clobber log fd */
		ఒకవేళ (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		ఒకవేళ (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_మార్గం;
		execv(options.sshd_auth_మార్గం, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_మార్గం, strerror(errno));
	}
}

స్థిర శూన్య
privsep_postauth(నిర్మాణం ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	ఒకవేళ (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	లేకపోతే ఒకవేళ (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (దీర్ఘ)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_బిడ్డ_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		నిష్క్రమించు(0);
	}

	/*బిడ్డ*/

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_దత్తాంశం();

	reseed_prngs();

#నిర్వచితం_కాకపోతే SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#అయితే_ముగింపు

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_సమితి_authenticated(ssh);
}

స్థిర నిర్మాణం sshkey *
get_hostkey_by_type(పూర్ణాంకం type, పూర్ణాంకం nid, పూర్ణాంకం need_వ్యక్తిగత, నిర్మాణం ssh *ssh)
{
	u_int i;
	నిర్మాణం sshkey *కీలకం;

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		ఎంపిక (type) {
		స్థితి కీలకం_RSA_CERT:
		స్థితి కీలకం_ECDSA_CERT:
		స్థితి కీలకం_ED25519_CERT:
		స్థితి కీలకం_ECDSA_SK_CERT:
		స్థితి కీలకం_ED25519_SK_CERT:
		స్థితి కీలకం_MLDSA44_ED25519_CERT:
			కీలకం = sensitive_దత్తాంశం.host_certificates[i];
			ఆపు;
		అప్రమేయ:
			కీలకం = sensitive_దత్తాంశం.host_కీలకాలు[i];
			ఒకవేళ (కీలకం == ఖాళీ && !need_వ్యక్తిగత)
				కీలకం = sensitive_దత్తాంశం.host_pubkeys[i];
			ఆపు;
		}
		ఒకవేళ (కీలకం == ఖాళీ || కీలకం->type != type)
			కొనసాగు;
		ఎంపిక (type) {
		స్థితి కీలకం_ECDSA:
		స్థితి కీలకం_ECDSA_SK:
		స్థితి కీలకం_ECDSA_CERT:
		స్థితి కీలకం_ECDSA_SK_CERT:
			ఒకవేళ (కీలకం->ecdsa_nid != nid)
				కొనసాగు;
			/* FALLTHROUGH */
		అప్రమేయ:
			తిరిగి need_వ్యక్తిగత ?
			    sensitive_దత్తాంశం.host_కీలకాలు[i] : కీలకం;
		}
	}
	తిరిగి ఖాళీ;
}

నిర్మాణం sshkey *
get_hostkey_ప్రజా_by_type(పూర్ణాంకం type, పూర్ణాంకం nid, నిర్మాణం ssh *ssh)
{
	తిరిగి get_hostkey_by_type(type, nid, 0, ssh);
}

నిర్మాణం sshkey *
get_hostkey_వ్యక్తిగత_by_type(పూర్ణాంకం type, పూర్ణాంకం nid, నిర్మాణం ssh *ssh)
{
	తిరిగి get_hostkey_by_type(type, nid, 1, ssh);
}

నిర్మాణం sshkey *
get_hostkey_by_సూచీ(పూర్ణాంకం ind)
{
	ఒకవేళ (ind < 0 || (u_int)ind >= options.అంకె_host_కీలకం_files)
		తిరిగి (ఖాళీ);
	తిరిగి (sensitive_దత్తాంశం.host_కీలకాలు[ind]);
}

నిర్మాణం sshkey *
get_hostkey_ప్రజా_by_సూచీ(పూర్ణాంకం ind, నిర్మాణం ssh *ssh)
{
	ఒకవేళ (ind < 0 || (u_int)ind >= options.అంకె_host_కీలకం_files)
		తిరిగి (ఖాళీ);
	తిరిగి (sensitive_దత్తాంశం.host_pubkeys[ind]);
}

పూర్ణాంకం
get_hostkey_సూచీ(నిర్మాణం sshkey *కీలకం, పూర్ణాంకం compare, నిర్మాణం ssh *ssh)
{
	u_int i;

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		ఒకవేళ (sshkey_is_cert(కీలకం)) {
			ఒకవేళ (కీలకం == sensitive_దత్తాంశం.host_certificates[i] ||
			    (compare && sensitive_దత్తాంశం.host_certificates[i] &&
			    sshkey_equal(కీలకం,
			    sensitive_దత్తాంశం.host_certificates[i])))
				తిరిగి (i);
		} లేకపోతే {
			ఒకవేళ (కీలకం == sensitive_దత్తాంశం.host_కీలకాలు[i] ||
			    (compare && sensitive_దత్తాంశం.host_కీలకాలు[i] &&
			    sshkey_equal(కీలకం, sensitive_దత్తాంశం.host_కీలకాలు[i])))
				తిరిగి (i);
			ఒకవేళ (కీలకం == sensitive_దత్తాంశం.host_pubkeys[i] ||
			    (compare && sensitive_దత్తాంశం.host_pubkeys[i] &&
			    sshkey_equal(కీలకం, sensitive_దత్తాంశం.host_pubkeys[i])))
				తిరిగి (i);
		}
	}
	తిరిగి (-1);
}

/* Inform the client of all hostkeys */
స్థిర శూన్య
notify_hostkeys(నిర్మాణం ssh *ssh)
{
	నిర్మాణం sshbuf *buf;
	నిర్మాణం sshkey *కీలకం;
	u_int i, nkeys;
	పూర్ణాంకం r;
	అక్షరం *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	ఒకవేళ (ssh->compat & SSH_BUG_HOSTKEYS)
		తిరిగి;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	కొరకు (i = nkeys = 0; i < options.అంకె_host_కీలకం_files; i++) {
		కీలకం = get_hostkey_ప్రజా_by_సూచీ(i, ssh);
		ఒకవేళ (కీలకం == ఖాళీ || కీలకం->type == కీలకం_UNSPEC ||
		    sshkey_is_cert(కీలకం))
			కొనసాగు;
		fp = sshkey_fingerprint(కీలకం, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(కీలకం), fp);
		విడుదల(fp);
		ఒకవేళ (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		ఒకవేళ ((r = sshkey_putb(కీలకం, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		ఒకవేళ ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	ఒకవేళ (nkeys == 0)
		fatal_f("no hostkeys");
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
}

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_సంస్కరణ);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	నిష్క్రమించు(1);
}

స్థిర శూన్య
parse_hostkeys(నిర్మాణం sshbuf *hostkeys)
{
	పూర్ణాంకం r;
	u_int అంకె_కీలకాలు = 0;
	నిర్మాణం sshkey *k;
	నిర్మాణం sshbuf *kbuf;
	స్థిరరాశి u_char *cp;
	కొలత_t len;

	అయితే (sshbuf_len(hostkeys) != 0) {
		ఒకవేళ (అంకె_కీలకాలు > 2048)
			fatal_f("too many hostkeys");
		sensitive_దత్తాంశం.host_కీలకాలు = xrecallocarray(
		    sensitive_దత్తాంశం.host_కీలకాలు, అంకె_కీలకాలు, అంకె_కీలకాలు + 1,
		    పరిమాణం(*sensitive_దత్తాంశం.host_pubkeys));
		sensitive_దత్తాంశం.host_pubkeys = xrecallocarray(
		    sensitive_దత్తాంశం.host_pubkeys, అంకె_కీలకాలు, అంకె_కీలకాలు + 1,
		    పరిమాణం(*sensitive_దత్తాంశం.host_pubkeys));
		sensitive_దత్తాంశం.host_certificates = xrecallocarray(
		    sensitive_దత్తాంశం.host_certificates, అంకె_కీలకాలు, అంకె_కీలకాలు + 1,
		    పరిమాణం(*sensitive_దత్తాంశం.host_certificates));
		/* private key */
		k = ఖాళీ;
		ఒకవేళ ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		ఒకవేళ (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_వ్యక్తిగత_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_దత్తాంశం.host_కీలకాలు[అంకె_కీలకాలు] = k;
		sshbuf_free(kbuf);
		ఒకవేళ (k)
			debug2_f("privkey %u: %s", అంకె_కీలకాలు, sshkey_ssh_name(k));
		/* public key */
		k = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ఒకవేళ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_దత్తాంశం.host_pubkeys[అంకె_కీలకాలు] = k;
		ఒకవేళ (k)
			debug2_f("pubkey %u: %s", అంకె_కీలకాలు, sshkey_ssh_name(k));
		/* certificate */
		k = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ఒకవేళ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_దత్తాంశం.host_certificates[అంకె_కీలకాలు] = k;
		ఒకవేళ (k)
			debug2_f("cert %u: %s", అంకె_కీలకాలు, sshkey_ssh_name(k));
		అంకె_కీలకాలు++;
	}
	sensitive_దత్తాంశం.అంకె_hostkeys = అంకె_కీలకాలు;
}

స్థిర శూన్య
recv_rexec_state(పూర్ణాంకం fd, నిర్మాణం sshbuf *conf, uint64_t *timing_secretp)
{
	నిర్మాణం sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	కొలత_t len;
	పూర్ణాంకం r;
	నిర్మాణం include_అంశం *అంశం;

	debug3_f("entering fd = %d", fd);

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ || (inc = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	/* receive config */
	ఒకవేళ (ssh_సందేశం_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ఒకవేళ ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ఒకవేళ (ver != 0)
		fatal_f("rexec version mismatch");
	ఒకవేళ ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	ఒకవేళ (conf != ఖాళీ && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	అయితే (sshbuf_len(inc) != 0) {
		అంశం = xcalloc(1, పరిమాణం(*అంశం));
		ఒకవేళ ((అంశం->contents = sshbuf_new()) == ఖాళీ)
			fatal_f("sshbuf_new failed");
		ఒకవేళ ((r = sshbuf_get_cstring(inc, &అంశం->selector, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &అంశం->filename, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_stringb(inc, అంశం->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, అంశం, నమోదు_2);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	ఒకవేళ (ssh_సందేశం_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ఒకవేళ ((r = sshbuf_get_u8(m, ఖాళీ)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	విడుదల(cp);
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
స్థిర శూన్య
check_ip_options(నిర్మాణం ssh *ssh)
{
#నిర్వచితమైతే IP_OPTIONS
	పూర్ణాంకం sock_లోపల = ssh_packet_get_connection_లోపల(ssh);
	నిర్మాణం sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_కొలత = పరిమాణం(opts), fromlen = పరిమాణం(from);
	అక్షరం పాఠ్యం[పరిమాణం(opts) * 3 + 1];

	memset(&from, 0, పరిమాణం(from));
	ఒకవేళ (getpeername(sock_లోపల, (నిర్మాణం sockaddr *)&from,
	    &fromlen) == -1)
		తిరిగి;
	ఒకవేళ (from.ss_family != AF_INET)
		తిరిగి;
	/* XXX IPv6 options? */

	ఒకవేళ (getsockopt(sock_లోపల, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_కొలత) >= 0 && option_కొలత != 0) {
		పాఠ్యం[0] = '\0';
		కొరకు (i = 0; i < option_కొలత; i++)
			snprintf(పాఠ్యం + i*3, పరిమాణం(పాఠ్యం) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh), పాఠ్యం);
	}
#అయితే_ముగింపు /* IP_OPTIONS */
}

/* Set the routing domain for this process */
స్థిర శూన్య
సమితి_process_rdomain(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *name)
{
#ఒకవేళ defined(HAVE_SYS_సమితి_PROCESS_RDOMAIN)
	ఒకవేళ (name == ఖాళీ)
		తిరిగి; /* default */

	ఒకవేళ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ఒకవేళ ((name = ssh_packet_rdomain_లోపల(ssh)) == ఖాళీ)
			తిరిగి;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	తిరిగి sys_సమితి_process_rdomain(name);
#లేదావేళ defined(__OpenBSD__)
	పూర్ణాంకం rtable, ortable = getrtable();
	స్థిరరాశి అక్షరం *errstr;

	ఒకవేళ (name == ఖాళీ)
		తిరిగి; /* default */

	ఒకవేళ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ఒకవేళ ((name = ssh_packet_rdomain_లోపల(ssh)) == ఖాళీ)
			తిరిగి;
	}

	rtable = (పూర్ణాంకం)strtonum(name, 0, 255, &errstr);
	ఒకవేళ (errstr != ఖాళీ) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	ఒకవేళ (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#లేకపోతే /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#అయితే_ముగింపు
}

/*
 * Main program for the daemon.
 */
పూర్ణాంకం
ప్రధాన(పూర్ణాంకం ac, అక్షరం **av)
{
	నిర్మాణం ssh *ssh = ఖాళీ;
	బాహ్య అక్షరం *optarg;
	బాహ్య పూర్ణాంకం optind;
	పూర్ణాంకం devnull, r, opt, remote_పోర్టు;
	పూర్ణాంకం sock_లోపల = -1, sock_బహిర్గతం = -1, rexeced_flag = 0, have_కీలకం = 0;
	స్థిరరాశి అక్షరం *remote_ip, *rdomain;
	అక్షరం *పంక్తి, *laddr, *logfile = ఖాళీ;
	u_int i;
	uint64_t ibytes, obytes;
	బహుళకం_t new_umask;
	Authctxt *authctxt;
	నిర్మాణం connection_info *connection_info = ఖాళీ;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	నిర్మాణం itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ఖాళీ);

#నిర్వచితమైతే HAVE_SECUREWARE
	(శూన్య)సమితి_auth_parameters(ac, av);
#అయితే_ముగింపు
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, పరిమాణం(*saved_argv));
	కొరకు (i = 0; (పూర్ణాంకం)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ఖాళీ;

#నిర్వచితం_కాకపోతే HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#అయితే_ముగింపు

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	అయితే ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ఎంపిక (opt) {
		స్థితి '4':
			options.చిరునామా_family = AF_INET;
			ఆపు;
		స్థితి '6':
			options.చిరునామా_family = AF_INET6;
			ఆపు;
		స్థితి 'f':
			config_file_name = optarg;
			ఆపు;
		స్థితి 'c':
			servconf_కూడు_hostcert("[command-line]", 0,
			    &options, optarg);
			ఆపు;
		స్థితి 'd':
			ఒకవేళ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} లేకపోతే ఒకవేళ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ఆపు;
		స్థితి 'D':
			/* ignore */
			ఆపు;
		స్థితి 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		స్థితి 'e':
			log_stderr = 1;
			ఆపు;
		స్థితి 'i':
			inetd_flag = 1;
			ఆపు;
		స్థితి 'r':
			/* ignore */
			ఆపు;
		స్థితి 'R':
			rexeced_flag = 1;
			ఆపు;
		స్థితి 'Q':
			/* ignored */
			ఆపు;
		స్థితి 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ఆపు;
		స్థితి 'b':
			/* protocol 1, ignored */
			ఆపు;
		స్థితి 'p':
			options.ports_from_cmdline = 1;
			ఒకవేళ (options.అంకె_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				నిష్క్రమించు(1);
			}
			options.ports[options.అంకె_ports++] = a2port(optarg);
			ఒకవేళ (options.ports[options.అంకె_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				నిష్క్రమించు(1);
			}
			ఆపు;
		స్థితి 'g':
			ఒకవేళ ((options.login_grace_సమయం = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				నిష్క్రమించు(1);
			}
			ఆపు;
		స్థితి 'k':
			/* protocol 1, ignored */
			ఆపు;
		స్థితి 'h':
			servconf_కూడు_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			ఆపు;
		స్థితి 't':
		స్థితి 'T':
		స్థితి 'G':
			fatal("test/dump modes not supported");
			ఆపు;
		స్థితి 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			ఒకవేళ (parse_server_సరిపోలిక_testspec(connection_info,
			    optarg) == -1)
				నిష్క్రమించు(1);
			ఆపు;
		స్థితి 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ఖాళీ);
			ఒకవేళ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				నిష్క్రమించు(1);
			}
			ఆపు;
		స్థితి 'o':
			పంక్తి = xstrdup(optarg);
			ఒకవేళ (process_server_config_పంక్తి(&options, పంక్తి,
			    "command-line", 0, ఖాళీ, ఖాళీ, &includes) != 0)
				నిష్క్రమించు(1);
			విడుదల(పంక్తి);
			ఆపు;
		స్థితి 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_సంస్కరణ);
			నిష్క్రమించు(0);
		అప్రమేయ:
			usage();
			ఆపు;
		}
	}

	/* Check that there are no remaining arguments. */
	ఒకవేళ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		నిష్క్రమించు(1);
	}

	ఒకవేళ (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_ప్రారంభం();

	/* Reserve fds we'll need later for reexec things */
	ఒకవేళ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	అయితే (devnull < PRIVSEP_MIN_FREE_FD) {
		ఒకవేళ ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	విత్తనం_rng();

	/* If requested, redirect the logs to the specified logfile. */
	ఒకవేళ (logfile != ఖాళీ) {
		అక్షరం *cp, pid_s[32];

		snprintf(pid_s, పరిమాణం(pid_s), "%ld", (గుర్తులేని దీర్ఘ)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd-session",
		    (అక్షరం *)ఖాళీ);
		log_redirect_stderr_గమ్యం(cp);
		విడుదల(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_సమితి ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_సమితి ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/* Fetch our configuration */
	ఒకవేళ ((cfg = sshbuf_new()) == ఖాళీ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, ఖాళీ, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_సంస్కరణ, SSH_OPENSSL_సంస్కరణ);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ఒకవేళ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ఖాళీ) {
		ఒకవేళ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} లేకపోతే {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, అక్షరశ్రేణి_పొడవు(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	ఒకవేళ (!debug_flag && !inetd_flag) {
		ఒకవేళ ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(శూన్య)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	ఒకవేళ (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

	/* Check that options are sensible */
	ఒకవేళ (options.authorized_కీలకాలు_command_user == ఖాళీ &&
	    (options.authorized_కీలకాలు_command != ఖాళీ &&
	    strcasecmp(options.authorized_కీలకాలు_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	ఒకవేళ (options.authorized_principals_command_user == ఖాళీ &&
	    (options.authorized_principals_command != ఖాళీ &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match block, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	ఒకవేళ (options.అంకె_auth_methods != 0) {
		కొరకు (i = 0; i < options.అంకె_auth_methods; i++) {
			ఒకవేళ (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				ఆపు;
		}
		ఒకవేళ (i >= options.అంకె_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

#నిర్వచితమైతే WITH_OPENSSL
	ఒకవేళ (options.moduli_file != ఖాళీ)
		dh_సమితి_moduli_file(options.moduli_file);
#అయితే_ముగింపు

	ఒకవేళ (options.host_కీలకం_agent) {
		ఒకవేళ (strcmp(options.host_కీలకం_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_కీలకం_agent, 1);
		ఒకవేళ ((r = ssh_get_authentication_socket(ఖాళీ)) == 0)
			have_agent = 1;
		లేకపోతే
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_కీలకం_agent);
	}

	ఒకవేళ (options.అంకె_host_కీలకం_files != sensitive_దత్తాంశం.అంకె_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.అంకె_host_కీలకం_files, sensitive_దత్తాంశం.అంకె_hostkeys);
	}

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		ఒకవేళ (sensitive_దత్తాంశం.host_కీలకాలు[i] != ఖాళీ ||
		    (have_agent && sensitive_దత్తాంశం.host_pubkeys[i] != ఖాళీ)) {
			have_కీలకం = 1;
			ఆపు;
		}
	}
	ఒకవేళ (!have_కీలకం)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(శూన్య) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ఒకవేళ (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	కొరకు (i = 0; i < options.అంకె_log_verbose; i++)
		log_verbose_కూడు(options.log_verbose[i]);

	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ఒకవేళ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or rexec */
	ఒకవేళ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_లోపల = dup(STDIN_FILENO);
		sock_బహిర్గతం = dup(STDOUT_FILENO);
	} లేకపోతే {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_లోపల = sock_బహిర్గతం = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	ఒకవేళ (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_లోపల, sock_బహిర్గతం);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_బహిర్గతం);
	FD_CLOSEONEXEC(sock_లోపల);

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
	ఒకవేళ ((ssh = ssh_packet_సమితి_connection(ఖాళీ, sock_లోపల, sock_బహిర్గతం)) == ఖాళీ)
		fatal("Unable to create connection");
	the_చురుకైన_state = ssh;
	ssh_packet_సమితి_server(ssh);
	ssh_packet_సమితి_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_సమితి_af(ssh, options.చిరునామా_family);
	channel_సమితి_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	/* Set SO_KEEPALIVE if requested. */
	ఒకవేళ (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		సమితి_keepalive(sock_లోపల); /* logs errors */

	ఒకవేళ ((remote_పోర్టు = ssh_remote_పోర్టు(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#నిర్వచితమైతే SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_పోర్టు);
#అయితే_ముగింపు

	rdomain = ssh_packet_rdomain_లోపల(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_లోపల);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_పోర్టు, laddr,  ssh_local_పోర్టు(ssh),
	    rdomain == ఖాళీ ? "" : " rdomain \"",
	    rdomain == ఖాళీ ? "" : rdomain,
	    rdomain == ఖాళీ ? "" : "\"");
	విడుదల(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	ఒకవేళ (!debug_flag && options.login_grace_సమయం > 0) {
		పూర్ణాంకం ujitter = arc4random_ఏకరీతి(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_సమయం;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		ఒకవేళ (setitimer(ITIMER_REAL, &itv, ఖాళీ) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_సమితి_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, పరిమాణం(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ఒకవేళ ((auth_opts = sshauthopt_new_with_కీలకాలు_defaults()) == ఖాళీ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ఒకవేళ ((loginmsg = sshbuf_new()) == ఖాళీ)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	ఒకవేళ (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	ఒకవేళ (setitimer(ITIMER_REAL, &itv, ఖాళీ) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	ఒకవేళ (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(శూన్య)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	ఒకవేళ (options.routing_domain != ఖాళీ)
		సమితి_process_rdomain(ssh, options.routing_domain);

#నిర్వచితమైతే SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#అయితే_ముగింపు

#నిర్వచితమైతే GSSAPI
	ఒకవేళ (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#అయితే_ముగింపు
#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#అయితే_ముగింపు

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_సమితి_timeout(ssh, options.client_alive_interval,
	    options.client_alive_లెక్క_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_బైట్లు(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)obytes, (గుర్తులేని దీర్ఘ దీర్ఘ)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_పోర్టు);

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam)
		ముగింపు_pam();
#అయితే_ముగింపు /* USE_PAM */

#నిర్వచితమైతే SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#అయితే_ముగింపు

	ssh_packet_close(ssh);

	mm_terminate();

	నిష్క్రమించు(0);
}

పూర్ణాంకం
sshd_hostkey_sign(నిర్మాణం ssh *ssh, నిర్మాణం sshkey *privkey,
    నిర్మాణం sshkey *pubkey, u_char **signature, కొలత_t *slenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen, స్థిరరాశి అక్షరం *alg)
{
	ఒకవేళ (privkey) {
		ఒకవేళ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    దత్తాంశం, dlen, alg, options.sk_provider, ఖాళీ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} లేకపోతే {
		ఒకవేళ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    దత్తాంశం, dlen, alg, options.sk_provider, ఖాళీ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	తిరిగి 0;
}

/* server specific fatal cleanup */
శూన్య
cleanup_exit(పూర్ణాంకం i)
{
	ఒకవేళ (the_చురుకైన_state != ఖాళీ && the_authctxt != ఖాళీ) {
		do_cleanup(the_చురుకైన_state, the_authctxt);
		ఒకవేళ (privsep_is_preauth &&
		    pmonitor != ఖాళీ && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			ఒకవేళ (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#నిర్వచితమైతే SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	ఒకవేళ (the_చురుకైన_state != ఖాళీ && mm_is_monitor())
		audit_event(the_చురుకైన_state, SSH_CONNECTION_ABANDON);
#అయితే_ముగింపు
	/* Override default fatal exit value when auth was attempted */
	ఒకవేళ (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	ఒకవేళ (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
