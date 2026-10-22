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

/* Saved arguments to main(). */
স্থির বর্ণ **saved_argv;
স্থির পূর্ণাঙ্ক saved_argc;


/* Daemon's agent connection */
পূর্ণাঙ্ক auth_sock = -1;
স্থির পূর্ণাঙ্ক have_agent = 0;

u_int		অঙ্ক_hostkeys;
সংরচনা sshkey	**host_pubkeys;		/* all public host keys */
সংরচনা sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
সংরচনা monitor *pmonitor = রিক্ত;
পূর্ণাঙ্ক privsep_is_preauth = 1;
স্থির পূর্ণাঙ্ক privsep_chroot = 1;

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
স্থির শূন্য do_ssh2_kex(সংরচনা ssh *);

/* Unprivileged user */
সংরচনা passwd *privsep_pw = রিক্ত;

#ifndef HAVE_PLEDGE
স্থির সংরচনা ssh_sandbox *box;
#endif

/* XXX stub */
পূর্ণাঙ্ক
mm_is_monitor(শূন্য)
{
	প্রত্যাগম 0;
}

স্থির শূন্য
privsep_child_demote(শূন্য)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	যদি ((box = ssh_sandbox_init(pmonitor)) == রিক্ত)
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
	যদি (pledge("stdio", রিক্ত) == -1)
		fatal_f("pledge()");
#অন্যথা
	ssh_sandbox_child(box);
#endif
}

স্থির শূন্য
append_hostkey_type(সংরচনা sshbuf *b, ধ্রুব বর্ণ *s)
{
	পূর্ণাঙ্ক r;

	যদি (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		প্রত্যাগম;
	}
	যদি ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

স্থির বর্ণ *
list_hostkey_types(শূন্য)
{
	সংরচনা sshbuf *b;
	সংরচনা sshkey *চাবি;
	বর্ণ *ret;
	u_int i;

	যদি ((b = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		চাবি = host_pubkeys[i];
		যদি (চাবি == রিক্ত)
			অনুবর্ত;
		বিকল্প (চাবি->type) {
		পক্ষ চাবি_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		পক্ষ চাবি_ECDSA:
		পক্ষ চাবি_ED25519:
		পক্ষ চাবি_MLDSA44_ED25519:
		পক্ষ চাবি_ECDSA_SK:
		পক্ষ চাবি_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(চাবি));
			ভঙ্গ;
		}
		/* If the private key has a cert peer, then list that too */
		চাবি = host_certificates[i];
		যদি (চাবি == রিক্ত)
			অনুবর্ত;
		বিকল্প (চাবি->type) {
		পক্ষ চাবি_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		পক্ষ চাবি_ECDSA_CERT:
		পক্ষ চাবি_ED25519_CERT:
		পক্ষ চাবি_MLDSA44_ED25519_CERT:
		পক্ষ চাবি_ECDSA_SK_CERT:
		পক্ষ চাবি_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(চাবি));
			ভঙ্গ;
		}
	}
	যদি ((ret = sshbuf_dup_string(b)) == রিক্ত)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	প্রত্যাগম ret;
}

সংরচনা sshkey *
get_hostkey_public_by_type(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid, সংরচনা ssh *ssh)
{
	u_int i;
	সংরচনা sshkey *চাবি;

	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		বিকল্প (type) {
		পক্ষ চাবি_RSA_CERT:
		পক্ষ চাবি_ECDSA_CERT:
		পক্ষ চাবি_ED25519_CERT:
		পক্ষ চাবি_MLDSA44_ED25519_CERT:
		পক্ষ চাবি_ECDSA_SK_CERT:
		পক্ষ চাবি_ED25519_SK_CERT:
			চাবি = host_certificates[i];
			ভঙ্গ;
		স্বভাব:
			চাবি = host_pubkeys[i];
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
			প্রত্যাগম চাবি;
		}
	}
	প্রত্যাগম রিক্ত;
}

/* XXX remove */
সংরচনা sshkey *
get_hostkey_private_by_type(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid, সংরচনা ssh *ssh)
{
	প্রত্যাগম রিক্ত;
}

/* XXX remove */
সংরচনা sshkey *
get_hostkey_by_index(পূর্ণাঙ্ক ind)
{
	প্রত্যাগম রিক্ত;
}

সংরচনা sshkey *
get_hostkey_public_by_index(পূর্ণাঙ্ক ind, সংরচনা ssh *ssh)
{
	যদি (ind < 0 || (u_int)ind >= options.অঙ্ক_host_চাবি_files)
		প্রত্যাগম (রিক্ত);
	প্রত্যাগম host_pubkeys[ind];
}

পূর্ণাঙ্ক
get_hostkey_index(সংরচনা sshkey *চাবি, পূর্ণাঙ্ক compare, সংরচনা ssh *ssh)
{
	u_int i;

	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		যদি (sshkey_is_cert(চাবি)) {
			যদি (চাবি == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(চাবি, host_certificates[i])))
				প্রত্যাগম (i);
		} অন্যথা {
			যদি (চাবি == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(চাবি, host_pubkeys[i])))
				প্রত্যাগম (i);
		}
	}
	প্রত্যাগম (-1);
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
parse_hostkeys(সংরচনা sshbuf *hostkeys)
{
	পূর্ণাঙ্ক r;
	u_int অঙ্ক_চাবিগুলি = 0;
	সংরচনা sshkey *k;
	ধ্রুব u_char *cp;
	size_t len;

	যাবত্ (sshbuf_len(hostkeys) != 0) {
		যদি (অঙ্ক_চাবিগুলি > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    অঙ্ক_চাবিগুলি, অঙ্ক_চাবিগুলি + 1, পরিমাণ(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    অঙ্ক_চাবিগুলি, অঙ্ক_চাবিগুলি + 1, পরিমাণ(*host_certificates));
		/* public key */
		k = রিক্ত;
		যদি ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		যদি (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[অঙ্ক_চাবিগুলি] = k;
		যদি (k)
			debug2_f("key %u: %s", অঙ্ক_চাবিগুলি, sshkey_ssh_name(k));
		/* certificate */
		k = রিক্ত;
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
recv_privsep_state(সংরচনা ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	সংরচনা sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, রিক্ত, timing_secretp,
	    &hostkeys, রিক্ত, রিক্ত, রিক্ত, রিক্ত);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
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
	পূর্ণাঙ্ক r, opt, have_চাবি = 0;
	পূর্ণাঙ্ক sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
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
	যাবত্ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		বিকল্প (opt) {
		পক্ষ '4':
			/* ignore */
			ভঙ্গ;
		পক্ষ '6':
			/* ignore */
			ভঙ্গ;
		পক্ষ 'f':
			/* ignore */
			ভঙ্গ;
		পক্ষ 'c':
			/* ignore */
			ভঙ্গ;
		পক্ষ 'd':
			যদি (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} অন্যথা যদি (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ভঙ্গ;
		পক্ষ 'D':
		পক্ষ 'E':
		পক্ষ 'e':
			/* ignore */
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
			/* ignored */
			ভঙ্গ;
		পক্ষ 'b':
			/* protocol 1, ignored */
			ভঙ্গ;
		পক্ষ 'p':
			/* ignored */
			ভঙ্গ;
		পক্ষ 'g':
			/* ignored */
			ভঙ্গ;
		পক্ষ 'k':
			/* protocol 1, ignored */
			ভঙ্গ;
		পক্ষ 'h':
			/* ignored */
			ভঙ্গ;
		পক্ষ 't':
		পক্ষ 'T':
		পক্ষ 'G':
		পক্ষ 'C':
			fatal("test/dump modes not supported");
			ভঙ্গ;
		পক্ষ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, রিক্ত);
			যদি (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			ভঙ্গ;
		পক্ষ 'o':
			/* ignored */
			ভঙ্গ;
		পক্ষ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		স্বভাব:
			usage();
			ভঙ্গ;
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
	pmonitor = xcalloc(1, পরিমাণ(*pmonitor));
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
	যদি ((ssh = ssh_packet_set_connection(রিক্ত, sock_in, sock_out)) == রিক্ত)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	যদি ((cfg = sshbuf_new()) == রিক্ত)
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

	যদি (options.অঙ্ক_host_চাবি_files != অঙ্ক_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.অঙ্ক_host_চাবি_files, অঙ্ক_hostkeys);
	}

	প্রতি (i = 0; i < options.অঙ্ক_host_চাবি_files; i++) {
		যদি (host_pubkeys[i] != রিক্ত) {
			have_চাবি = 1;
			ভঙ্গ;
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
	প্রতি (i = 0; i < options.অঙ্ক_log_verbose; i++)
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

/* SSH2 key exchange */
স্থির শূন্য
do_ssh2_kex(সংরচনা ssh *ssh)
{
	বর্ণ *hkalgs = রিক্ত, *myproposal[PROPOSAL_MAX];
	ধ্রুব বর্ণ *compression = রিক্ত;
	সংরচনা kex *kex;
	পূর্ণাঙ্ক r;

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
	kex->host_চাবি_index=&get_hostkey_index;
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
cleanup_exit(পূর্ণাঙ্ক i)
{
	_exit(i);
}
