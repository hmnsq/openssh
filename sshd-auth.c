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

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/evp.h>
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
#অন্তর্ভাব "ssh-sandbox.h"
#অন্তর্ভাব "dh.h"

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

বাহ্যিক অক্ষর *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
অক্ষর *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
পূর্ণসংখ্যা debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
স্থির পূর্ণসংখ্যা inetd_flag = 0;

/* Saved arguments to main(). */
স্থির অক্ষর **saved_argv;
স্থির পূর্ণসংখ্যা saved_argc;


/* Daemon's agent connection */
পূর্ণসংখ্যা auth_sock = -1;
স্থির পূর্ণসংখ্যা have_agent = 0;

u_int		অঙ্ক_hostkeys;
কাঠামো sshkey	**host_pubkeys;		/* all public host keys */
কাঠামো sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
কাঠামো monitor *pmonitor = ফাঁকা;
পূর্ণসংখ্যা privsep_is_preauth = 1;
স্থির পূর্ণসংখ্যা privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ফাঁকা;
কাঠামো ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
কাঠামো sshauthopt *auth_opts = ফাঁকা;

/* sshd_config buffer */
কাঠামো sshbuf *cfg;

/* Included files from the configuration file */
কাঠামো include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
কাঠামো sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
স্থির শূন্য do_ssh2_kex(কাঠামো ssh *);

/* Unprivileged user */
কাঠামো passwd *privsep_pw = ফাঁকা;

#ifndef HAVE_PLEDGE
স্থির কাঠামো ssh_sandbox *box;
#endif

/* XXX stub */
পূর্ণসংখ্যা
mm_is_monitor(শূন্য)
{
	ফেরত 0;
}

স্থির শূন্য
privsep_child_demote(শূন্য)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	যদি ((box = ssh_sandbox_init(pmonitor)) == ফাঁকা)
		fatal_f("ssh_sandbox_init failed");
#endif
	/* Demote the child */
	যদি (privsep_chroot) {
		/* Change our root directory */
		যদি (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		যদি (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		যদি (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ifdef HAVE_PLEDGE
	যদি (pledge("stdio", ফাঁকা) == -1)
		fatal_f("pledge()");
#অন্যথা
	ssh_sandbox_child(box);
#endif
}

স্থির শূন্য
append_hostkey_type(কাঠামো sshbuf *b, ধ্রুবক অক্ষর *s)
{
	পূর্ণসংখ্যা r;

	যদি (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		ফেরত;
	}
	যদি ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

স্থির অক্ষর *
list_hostkey_types(শূন্য)
{
	কাঠামো sshbuf *b;
	কাঠামো sshkey *চাবি;
	অক্ষর *ret;
	u_int i;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	জন্য (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		চাবি = host_pubkeys[i];
		যদি (চাবি == ফাঁকা)
			চালু;
		নির্বাচন (চাবি->type) {
		ক্ষেত্র চাবি_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		ক্ষেত্র চাবি_ECDSA:
		ক্ষেত্র চাবি_ED25519:
		ক্ষেত্র চাবি_MLDSA44_ED25519:
		ক্ষেত্র চাবি_ECDSA_SK:
		ক্ষেত্র চাবি_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(চাবি));
			বিরতি;
		}
		/* If the private key has a cert peer, then list that too */
		চাবি = host_certificates[i];
		যদি (চাবি == ফাঁকা)
			চালু;
		নির্বাচন (চাবি->type) {
		ক্ষেত্র চাবি_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		ক্ষেত্র চাবি_ECDSA_CERT:
		ক্ষেত্র চাবি_ED25519_CERT:
		ক্ষেত্র চাবি_MLDSA44_ED25519_CERT:
		ক্ষেত্র চাবি_ECDSA_SK_CERT:
		ক্ষেত্র চাবি_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(চাবি));
			বিরতি;
		}
	}
	যদি ((ret = sshbuf_dup_string(b)) == ফাঁকা)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	ফেরত ret;
}

কাঠামো sshkey *
get_hostkey_public_by_type(পূর্ণসংখ্যা type, পূর্ণসংখ্যা nid, কাঠামো ssh *ssh)
{
	u_int i;
	কাঠামো sshkey *চাবি;

	জন্য (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		নির্বাচন (type) {
		ক্ষেত্র চাবি_RSA_CERT:
		ক্ষেত্র চাবি_ECDSA_CERT:
		ক্ষেত্র চাবি_ED25519_CERT:
		ক্ষেত্র চাবি_MLDSA44_ED25519_CERT:
		ক্ষেত্র চাবি_ECDSA_SK_CERT:
		ক্ষেত্র চাবি_ED25519_SK_CERT:
			চাবি = host_certificates[i];
			বিরতি;
		পূর্বনির্ধারিত:
			চাবি = host_pubkeys[i];
			বিরতি;
		}
		যদি (চাবি == ফাঁকা || চাবি->type != type)
			চালু;
		নির্বাচন (type) {
		ক্ষেত্র চাবি_ECDSA:
		ক্ষেত্র চাবি_ECDSA_SK:
		ক্ষেত্র চাবি_ECDSA_CERT:
		ক্ষেত্র চাবি_ECDSA_SK_CERT:
			যদি (চাবি->ecdsa_nid != nid)
				চালু;
			/* FALLTHROUGH */
		পূর্বনির্ধারিত:
			ফেরত চাবি;
		}
	}
	ফেরত ফাঁকা;
}

/* XXX remove */
কাঠামো sshkey *
get_hostkey_private_by_type(পূর্ণসংখ্যা type, পূর্ণসংখ্যা nid, কাঠামো ssh *ssh)
{
	ফেরত ফাঁকা;
}

/* XXX remove */
কাঠামো sshkey *
get_hostkey_by_সূচক(পূর্ণসংখ্যা ind)
{
	ফেরত ফাঁকা;
}

কাঠামো sshkey *
get_hostkey_public_by_সূচক(পূর্ণসংখ্যা ind, কাঠামো ssh *ssh)
{
	যদি (ind < 0 || (u_int)ind >= options.অঙ্ক_host_চাবি_files)
		ফেরত (ফাঁকা);
	ফেরত host_pubkeys[ind];
}

পূর্ণসংখ্যা
get_hostkey_সূচক(কাঠামো sshkey *চাবি, পূর্ণসংখ্যা compare, কাঠামো ssh *ssh)
{
	u_int i;

	জন্য (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		যদি (sshkey_is_cert(চাবি)) {
			যদি (চাবি == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(চাবি, host_certificates[i])))
				ফেরত (i);
		} অন্যথা {
			যদি (চাবি == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(চাবি, host_pubkeys[i])))
				ফেরত (i);
		}
	}
	ফেরত (-1);
}

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

স্থির শূন্য
parse_hostkeys(কাঠামো sshbuf *hostkeys)
{
	পূর্ণসংখ্যা r;
	u_int অঙ্ক_চাবিগুলি = 0;
	কাঠামো sshkey *k;
	ধ্রুবক u_char *cp;
	আকার_t len;

	যখন (sshbuf_len(hostkeys) != 0) {
		যদি (অঙ্ক_চাবিগুলি > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    অঙ্ক_চাবিগুলি, অঙ্ক_চাবিগুলি + 1, আকার(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    অঙ্ক_চাবিগুলি, অঙ্ক_চাবিগুলি + 1, আকার(*host_certificates));
		/* public key */
		k = ফাঁকা;
		যদি ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		যদি (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[অঙ্ক_চাবিগুলি] = k;
		যদি (k)
			debug2_f("key %u: %s", অঙ্ক_চাবিগুলি, sshkey_ssh_name(k));
		/* certificate */
		k = ফাঁকা;
		যদি ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		যদি (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[অঙ্ক_চাবিগুলি] = k;
		যদি (k)
			debug2_f("cert %u: %s", অঙ্ক_চাবিগুলি, sshkey_ssh_name(k));
		অঙ্ক_চাবিগুলি++;
	}
	অঙ্ক_hostkeys = অঙ্ক_চাবিগুলি;
}

স্থির শূন্য
recv_privsep_state(কাঠামো ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	কাঠামো sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, ফাঁকা, timing_secretp,
	    &hostkeys, ফাঁকা, ফাঁকা, ফাঁকা, ফাঁকা);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা ac, অক্ষর **av)
{
	কাঠামো ssh *ssh = ফাঁকা;
	বাহ্যিক অক্ষর *optarg;
	বাহ্যিক পূর্ণসংখ্যা optind;
	পূর্ণসংখ্যা r, opt, have_চাবি = 0;
	পূর্ণসংখ্যা sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ফাঁকা);

#ifdef HAVE_SECUREWARE
	(শূন্য)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, আকার(*saved_argv));
	জন্য (i = 0; (পূর্ণসংখ্যা)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ফাঁকা;

	seed_rng();

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
	যখন ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		নির্বাচন (opt) {
		ক্ষেত্র '4':
			/* ignore */
			বিরতি;
		ক্ষেত্র '6':
			/* ignore */
			বিরতি;
		ক্ষেত্র 'f':
			/* ignore */
			বিরতি;
		ক্ষেত্র 'c':
			/* ignore */
			বিরতি;
		ক্ষেত্র 'd':
			যদি (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} অন্যথা যদি (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			বিরতি;
		ক্ষেত্র 'D':
		ক্ষেত্র 'E':
		ক্ষেত্র 'e':
			/* ignore */
			বিরতি;
		ক্ষেত্র 'i':
			inetd_flag = 1;
			বিরতি;
		ক্ষেত্র 'r':
			/* ignore */
			বিরতি;
		ক্ষেত্র 'R':
			rexeced_flag = 1;
			বিরতি;
		ক্ষেত্র 'Q':
			/* ignored */
			বিরতি;
		ক্ষেত্র 'q':
			/* ignored */
			বিরতি;
		ক্ষেত্র 'b':
			/* protocol 1, ignored */
			বিরতি;
		ক্ষেত্র 'p':
			/* ignored */
			বিরতি;
		ক্ষেত্র 'g':
			/* ignored */
			বিরতি;
		ক্ষেত্র 'k':
			/* protocol 1, ignored */
			বিরতি;
		ক্ষেত্র 'h':
			/* ignored */
			বিরতি;
		ক্ষেত্র 't':
		ক্ষেত্র 'T':
		ক্ষেত্র 'G':
		ক্ষেত্র 'C':
			fatal("test/dump modes not supported");
			বিরতি;
		ক্ষেত্র 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ফাঁকা);
			যদি (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			বিরতি;
		ক্ষেত্র 'o':
			/* ignored */
			বিরতি;
		ক্ষেত্র 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		পূর্বনির্ধারিত:
			usage();
			বিরতি;
		}
	}

	যদি (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, আকার(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	যদি (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	/* Connection passed by stdin/out */
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

	যদি (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	যদি ((ssh = ssh_packet_set_connection(ফাঁকা, sock_in, sock_out)) == ফাঁকা)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	যদি ((cfg = sshbuf_new()) == ফাঁকা)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[session-auth early]");
	recv_privsep_state(ssh, &options, &timing_secret);
	options.timing_secret = timing_secret; /* XXX eliminate from unpriv */
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);

	debug("sshd-auth version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	যদি ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ফাঁকা) {
		যদি (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} অন্যথা {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ifdef WITH_OPENSSL
	যদি (options.moduli_file != ফাঁকা)
		dh_set_moduli_file(options.moduli_file);
#endif

	যদি (options.host_চাবি_agent) {
		যদি (strcmp(options.host_চাবি_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_চাবি_agent, 1);
		যদি ((r = ssh_get_authentication_socket(ফাঁকা)) == 0)
			have_agent = 1;
		অন্যথা
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_চাবি_agent);
	}

	যদি (options.অঙ্ক_host_চাবি_files != অঙ্ক_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.অঙ্ক_host_চাবি_files, অঙ্ক_hostkeys);
	}

	জন্য (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		যদি (host_pubkeys[i] != ফাঁকা) {
			have_চাবি = 1;
			বিরতি;
		}
	}
	যদি (!have_চাবি)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(শূন্য) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	জন্য (i = 0; i < options.অঙ্ক_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	যদি (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_out);
	FD_CLOSEONEXEC(sock_in);

	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_set_af(ssh, options.address_family);
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, আকার(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	যদি ((auth_opts = sshauthopt_new_with_চাবিগুলি_defaults()) == ফাঁকা)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	যদি ((loginmsg = sshbuf_new()) == ফাঁকা)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

#ifdef GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#endif

	privsep_child_demote();

	/* perform the key exchange */
	/* authenticate user and start session */
	do_ssh2_kex(ssh);
	do_authentication2(ssh);

	/*
	 * The unprivileged child now transfers the current keystate and exits.
	 */
	mm_send_keystate(ssh, pmonitor);
	sshauthopt_free(auth_opts);
	ssh_packet_clear_চাবিগুলি(ssh);
	exit(0);
}

পূর্ণসংখ্যা
sshd_hostkey_sign(কাঠামো ssh *ssh, কাঠামো sshkey *privkey,
    কাঠামো sshkey *pubkey, u_char **signature, আকার_t *slenp,
    ধ্রুবক u_char *তথ্য, আকার_t dlen, ধ্রুবক অক্ষর *alg)
{
	যদি (privkey) {
		যদি (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    তথ্য, dlen, alg, options.sk_provider, ফাঁকা,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} অন্যথা {
		যদি (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    তথ্য, dlen, alg, options.sk_provider, ফাঁকা,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ফেরত 0;
}

/* SSH2 key exchange */
স্থির শূন্য
do_ssh2_kex(কাঠামো ssh *ssh)
{
	অক্ষর *hkalgs = ফাঁকা, *myproposal[PROPOSAL_MAX];
	ধ্রুবক অক্ষর *compression = ফাঁকা;
	কাঠামো kex *kex;
	পূর্ণসংখ্যা r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	যদি (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	মুক্ত(hkalgs);

	যদি ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	যদি ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	যদি ((r = kex_setup(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_set_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_set_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#ifdef WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#endif
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->load_host_public_চাবি=&get_hostkey_public_by_type;
	kex->load_host_private_চাবি=&get_hostkey_private_by_type;
	kex->host_চাবি_সূচক=&get_hostkey_সূচক;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#endif
	debug("KEX done");
}

/* server specific fatal cleanup */
শূন্য
cleanup_exit(পূর্ণসংখ্যা i)
{
	_exit(i);
}
