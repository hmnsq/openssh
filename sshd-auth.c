/* $OpenBSD: sshd-auth.c,v 1.20 2026/09/16 00:29:44 djm Exp $ */
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

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/evp.h>
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
#అన్తర్భావ "ssh-sandbox.h"
#అన్తర్భావ "dh.h"

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

/* Saved arguments to main(). */
స్థిర అక్షరం **saved_argv;
స్థిర పూర్ణాంకం saved_argc;


/* Daemon's agent connection */
పూర్ణాంకం auth_sock = -1;
స్థిర పూర్ణాంకం have_agent = 0;

u_int		అంకె_hostkeys;
నిర్మాణం sshkey	**host_pubkeys;		/* all public host keys */
నిర్మాణం sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
నిర్మాణం monitor *pmonitor = ఖాళీ;
పూర్ణాంకం privsep_is_preauth = 1;
స్థిర పూర్ణాంకం privsep_chroot = 1;

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
స్థిర శూన్య do_ssh2_kex(నిర్మాణం ssh *);

/* Unprivileged user */
నిర్మాణం passwd *privsep_pw = ఖాళీ;

#నిర్వచితం_కాకపోతే HAVE_PLEDGE
స్థిర నిర్మాణం ssh_sandbox *box;
#అయితే_ముగింపు

/* XXX stub */
పూర్ణాంకం
mm_is_monitor(శూన్య)
{
	తిరిగి 0;
}

స్థిర శూన్య
privsep_బిడ్డ_demote(శూన్య)
{
	gid_t gidset[1];

#నిర్వచితం_కాకపోతే HAVE_PLEDGE
	ఒకవేళ ((box = ssh_sandbox_init(pmonitor)) == ఖాళీ)
		fatal_f("ssh_sandbox_init failed");
#అయితే_ముగింపు
	/* Demote the child */
	ఒకవేళ (privsep_chroot) {
		/* Change our root directory */
		ఒకవేళ (chroot(మార్గం_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", మార్గం_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		ఒకవేళ (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		ఒకవేళ (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_సమితి_uid(privsep_pw);
	}

	/* sandbox ourselves */
#నిర్వచితమైతే HAVE_PLEDGE
	ఒకవేళ (pledge("stdio", ఖాళీ) == -1)
		fatal_f("pledge()");
#లేకపోతే
	ssh_sandbox_బిడ్డ(box);
#అయితే_ముగింపు
}

స్థిర శూన్య
append_hostkey_type(నిర్మాణం sshbuf *b, స్థిరరాశి అక్షరం *s)
{
	పూర్ణాంకం r;

	ఒకవేళ (సరిపోలిక_నమూనా_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		తిరిగి;
	}
	ఒకవేళ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

స్థిర అక్షరం *
list_hostkey_types(శూన్య)
{
	నిర్మాణం sshbuf *b;
	నిర్మాణం sshkey *కీలకం;
	అక్షరం *ret;
	u_int i;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		కీలకం = host_pubkeys[i];
		ఒకవేళ (కీలకం == ఖాళీ)
			కొనసాగు;
		ఎంపిక (కీలకం->type) {
		స్థితి కీలకం_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		స్థితి కీలకం_ECDSA:
		స్థితి కీలకం_ED25519:
		స్థితి కీలకం_MLDSA44_ED25519:
		స్థితి కీలకం_ECDSA_SK:
		స్థితి కీలకం_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(కీలకం));
			ఆపు;
		}
		/* If the private key has a cert peer, then list that too */
		కీలకం = host_certificates[i];
		ఒకవేళ (కీలకం == ఖాళీ)
			కొనసాగు;
		ఎంపిక (కీలకం->type) {
		స్థితి కీలకం_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		స్థితి కీలకం_ECDSA_CERT:
		స్థితి కీలకం_ED25519_CERT:
		స్థితి కీలకం_MLDSA44_ED25519_CERT:
		స్థితి కీలకం_ECDSA_SK_CERT:
		స్థితి కీలకం_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(కీలకం));
			ఆపు;
		}
	}
	ఒకవేళ ((ret = sshbuf_dup_string(b)) == ఖాళీ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	తిరిగి ret;
}

నిర్మాణం sshkey *
get_hostkey_ప్రజా_by_type(పూర్ణాంకం type, పూర్ణాంకం nid, నిర్మాణం ssh *ssh)
{
	u_int i;
	నిర్మాణం sshkey *కీలకం;

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		ఎంపిక (type) {
		స్థితి కీలకం_RSA_CERT:
		స్థితి కీలకం_ECDSA_CERT:
		స్థితి కీలకం_ED25519_CERT:
		స్థితి కీలకం_MLDSA44_ED25519_CERT:
		స్థితి కీలకం_ECDSA_SK_CERT:
		స్థితి కీలకం_ED25519_SK_CERT:
			కీలకం = host_certificates[i];
			ఆపు;
		అప్రమేయ:
			కీలకం = host_pubkeys[i];
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
			తిరిగి కీలకం;
		}
	}
	తిరిగి ఖాళీ;
}

/* XXX remove */
నిర్మాణం sshkey *
get_hostkey_వ్యక్తిగత_by_type(పూర్ణాంకం type, పూర్ణాంకం nid, నిర్మాణం ssh *ssh)
{
	తిరిగి ఖాళీ;
}

/* XXX remove */
నిర్మాణం sshkey *
get_hostkey_by_సూచీ(పూర్ణాంకం ind)
{
	తిరిగి ఖాళీ;
}

నిర్మాణం sshkey *
get_hostkey_ప్రజా_by_సూచీ(పూర్ణాంకం ind, నిర్మాణం ssh *ssh)
{
	ఒకవేళ (ind < 0 || (u_int)ind >= options.అంకె_host_కీలకం_files)
		తిరిగి (ఖాళీ);
	తిరిగి host_pubkeys[ind];
}

పూర్ణాంకం
get_hostkey_సూచీ(నిర్మాణం sshkey *కీలకం, పూర్ణాంకం compare, నిర్మాణం ssh *ssh)
{
	u_int i;

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		ఒకవేళ (sshkey_is_cert(కీలకం)) {
			ఒకవేళ (కీలకం == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(కీలకం, host_certificates[i])))
				తిరిగి (i);
		} లేకపోతే {
			ఒకవేళ (కీలకం == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(కీలకం, host_pubkeys[i])))
				తిరిగి (i);
		}
	}
	తిరిగి (-1);
}

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr, "%s, %s\n", SSH_సంస్కరణ, SSH_OPENSSL_సంస్కరణ);
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
	స్థిరరాశి u_char *cp;
	కొలత_t len;

	అయితే (sshbuf_len(hostkeys) != 0) {
		ఒకవేళ (అంకె_కీలకాలు > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    అంకె_కీలకాలు, అంకె_కీలకాలు + 1, పరిమాణం(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    అంకె_కీలకాలు, అంకె_కీలకాలు + 1, పరిమాణం(*host_certificates));
		/* public key */
		k = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ఒకవేళ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[అంకె_కీలకాలు] = k;
		ఒకవేళ (k)
			debug2_f("key %u: %s", అంకె_కీలకాలు, sshkey_ssh_name(k));
		/* certificate */
		k = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ఒకవేళ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[అంకె_కీలకాలు] = k;
		ఒకవేళ (k)
			debug2_f("cert %u: %s", అంకె_కీలకాలు, sshkey_ssh_name(k));
		అంకె_కీలకాలు++;
	}
	అంకె_hostkeys = అంకె_కీలకాలు;
}

స్థిర శూన్య
recv_privsep_state(నిర్మాణం ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	నిర్మాణం sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, ఖాళీ, timing_secretp,
	    &hostkeys, ఖాళీ, ఖాళీ, ఖాళీ, ఖాళీ);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
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
	పూర్ణాంకం r, opt, have_కీలకం = 0;
	పూర్ణాంకం sock_లోపల = -1, sock_బహిర్గతం = -1, rexeced_flag = 0;
	u_int i;
	బహుళకం_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
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

	విత్తనం_rng();

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
			/* ignore */
			ఆపు;
		స్థితి '6':
			/* ignore */
			ఆపు;
		స్థితి 'f':
			/* ignore */
			ఆపు;
		స్థితి 'c':
			/* ignore */
			ఆపు;
		స్థితి 'd':
			ఒకవేళ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} లేకపోతే ఒకవేళ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ఆపు;
		స్థితి 'D':
		స్థితి 'E':
		స్థితి 'e':
			/* ignore */
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
			/* ignored */
			ఆపు;
		స్థితి 'b':
			/* protocol 1, ignored */
			ఆపు;
		స్థితి 'p':
			/* ignored */
			ఆపు;
		స్థితి 'g':
			/* ignored */
			ఆపు;
		స్థితి 'k':
			/* protocol 1, ignored */
			ఆపు;
		స్థితి 'h':
			/* ignored */
			ఆపు;
		స్థితి 't':
		స్థితి 'T':
		స్థితి 'G':
		స్థితి 'C':
			fatal("test/dump modes not supported");
			ఆపు;
		స్థితి 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ఖాళీ);
			ఒకవేళ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				నిష్క్రమించు(1);
			}
			ఆపు;
		స్థితి 'o':
			/* ignored */
			ఆపు;
		స్థితి 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_సంస్కరణ, SSH_OPENSSL_సంస్కరణ);
			నిష్క్రమించు(0);
		అప్రమేయ:
			usage();
			ఆపు;
		}
	}

	ఒకవేళ (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_సమితి ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_సమితి ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, పరిమాణం(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	సమితి_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	ఒకవేళ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		నిష్క్రమించు(1);
	}

	/* Connection passed by stdin/out */
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

	ఒకవేళ (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_లోపల, sock_బహిర్గతం);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	ఒకవేళ ((ssh = ssh_packet_సమితి_connection(ఖాళీ, sock_లోపల, sock_బహిర్గతం)) == ఖాళీ)
		fatal("Unable to create connection");
	the_చురుకైన_state = ssh;
	ssh_packet_సమితి_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	ఒకవేళ ((cfg = sshbuf_new()) == ఖాళీ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[session-auth early]");
	recv_privsep_state(ssh, &options, &timing_secret);
	options.timing_secret = timing_secret; /* XXX eliminate from unpriv */
	ssh_packet_సమితి_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility, 1);
	సమితి_log_handler(mm_log_handler, pmonitor);

	debug("sshd-auth version %s, %s", SSH_సంస్కరణ, SSH_OPENSSL_సంస్కరణ);

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

	ఒకవేళ (options.అంకె_host_కీలకం_files != అంకె_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.అంకె_host_కీలకం_files, అంకె_hostkeys);
	}

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		ఒకవేళ (host_pubkeys[i] != ఖాళీ) {
			have_కీలకం = 1;
			ఆపు;
		}
	}
	ఒకవేళ (!have_కీలకం)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(శూన్య) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	సమితి_log_handler(mm_log_handler, pmonitor);
	కొరకు (i = 0; i < options.అంకె_log_verbose; i++)
		log_verbose_కూడు(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ఒకవేళ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_బహిర్గతం);
	FD_CLOSEONEXEC(sock_లోపల);

	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_సమితి_af(ssh, options.చిరునామా_family);
	channel_సమితి_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

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

#నిర్వచితమైతే GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#అయితే_ముగింపు

	privsep_బిడ్డ_demote();

	/* perform the key exchange */
	/* authenticate user and start session */
	do_ssh2_kex(ssh);
	do_authentication2(ssh);

	/*
	 * The unprivileged child now transfers the current keystate and exits.
	 */
	mm_send_keystate(ssh, pmonitor);
	sshauthopt_free(auth_opts);
	ssh_packet_clear_కీలకాలు(ssh);
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

/* SSH2 key exchange */
స్థిర శూన్య
do_ssh2_kex(నిర్మాణం ssh *ssh)
{
	అక్షరం *hkalgs = ఖాళీ, *myproposal[PROPOSAL_MAX];
	స్థిరరాశి అక్షరం *compression = ఖాళీ;
	నిర్మాణం kex *kex;
	పూర్ణాంకం r;

	ssh_packet_సమితి_rekey_limits(ssh, options.rekey_హద్దు,
	    options.rekey_interval);

	ఒకవేళ (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	విడుదల(hkalgs);

	ఒకవేళ ((r = kex_exchange_identification(ssh, -1,
	    options.సంస్కరణ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	ఒకవేళ ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	ఒకవేళ ((r = kex_అమరిక(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_సమితి_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_సమితి_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#నిర్వచితమైతే WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#అయితే_ముగింపు
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->ఎక్కించు_host_ప్రజా_కీలకం=&get_hostkey_ప్రజా_by_type;
	kex->ఎక్కించు_host_వ్యక్తిగత_కీలకం=&get_hostkey_వ్యక్తిగత_by_type;
	kex->host_కీలకం_సూచీ=&get_hostkey_సూచీ;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_నిరంతరం_fatal(ssh, DISPATCH_ఖండం, &kex->పూర్తి);
	kex_proposal_free_entries(myproposal);

#నిర్వచితమైతే DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#అయితే_ముగింపు
	debug("KEX done");
}

/* server specific fatal cleanup */
శూన్య
cleanup_exit(పూర్ణాంకం i)
{
	_exit(i);
}
