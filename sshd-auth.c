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

#که_تعریف_شوی WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>
#د_که_پای

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
#که_تعریف_شوی GSSAPI
#ضمن "ssh-gss.h"
#د_که_پای
#ضمن "monitor_wrap.h"
#ضمن "auth-options.h"
#ضمن "version.h"
#ضمن "ssherr.h"
#ضمن "sk-api.h"
#ضمن "srclimit.h"
#ضمن "ssh-sandbox.h"
#ضمن "dh.h"

/* Privsep fds */
#تعریف_کړه PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#تعریف_کړه PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#تعریف_کړه PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

خارجي حرف *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
حرف *config_file_name = لار_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
صحيح debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ساكن صحيح inetd_flag = 0;

/* Saved arguments to main(). */
ساكن حرف **saved_argv;
ساكن صحيح saved_argc;


/* Daemon's agent connection */
صحيح auth_sock = -1;
ساكن صحيح have_agent = 0;

u_int		عدد_hostkeys;
بنية sshkey	**host_pubkeys;		/* all public host keys */
بنية sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
بنية monitor *pmonitor = عدم;
صحيح privsep_is_preauth = 1;
ساكن صحيح privsep_chroot = 1;

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
ساكن فراغ do_ssh2_kex(بنية ssh *);

/* Unprivileged user */
بنية passwd *privsep_pw = عدم;

#که_نه_تعریف_شوی HAVE_PLEDGE
ساكن بنية ssh_sandbox *box;
#د_که_پای

/* XXX stub */
صحيح
mm_is_monitor(فراغ)
{
	أرجع 0;
}

ساكن فراغ
privsep_ماشوم_demote(فراغ)
{
	gid_t gidset[1];

#که_نه_تعریف_شوی HAVE_PLEDGE
	إذا ((box = ssh_sandbox_init(pmonitor)) == عدم)
		fatal_f("ssh_sandbox_init failed");
#د_که_پای
	/* Demote the child */
	إذا (privsep_chroot) {
		/* Change our root directory */
		إذا (chroot(لار_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", لار_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		إذا (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		إذا (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_سېټ_uid(privsep_pw);
	}

	/* sandbox ourselves */
#که_تعریف_شوی HAVE_PLEDGE
	إذا (pledge("stdio", عدم) == -1)
		fatal_f("pledge()");
#وإلا
	ssh_sandbox_ماشوم(box);
#د_که_پای
}

ساكن فراغ
append_hostkey_type(بنية sshbuf *b, ثابت حرف *s)
{
	صحيح r;

	إذا (سمون_نمونه_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		أرجع;
	}
	إذا ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

ساكن حرف *
list_hostkey_types(فراغ)
{
	بنية sshbuf *b;
	بنية sshkey *کلی;
	حرف *ret;
	u_int i;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	لكل (i = 0; i < options.عدد_host_کلی_files; i++) {
		کلی = host_pubkeys[i];
		إذا (کلی == عدم)
			استمر;
		بدل (کلی->type) {
		حالة کلی_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		حالة کلی_ECDSA:
		حالة کلی_ED25519:
		حالة کلی_MLDSA44_ED25519:
		حالة کلی_ECDSA_SK:
		حالة کلی_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(کلی));
			اكسر;
		}
		/* If the private key has a cert peer, then list that too */
		کلی = host_certificates[i];
		إذا (کلی == عدم)
			استمر;
		بدل (کلی->type) {
		حالة کلی_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		حالة کلی_ECDSA_CERT:
		حالة کلی_ED25519_CERT:
		حالة کلی_MLDSA44_ED25519_CERT:
		حالة کلی_ECDSA_SK_CERT:
		حالة کلی_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(کلی));
			اكسر;
		}
	}
	إذا ((ret = sshbuf_dup_string(b)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	أرجع ret;
}

بنية sshkey *
get_hostkey_عامه_by_type(صحيح type, صحيح nid, بنية ssh *ssh)
{
	u_int i;
	بنية sshkey *کلی;

	لكل (i = 0; i < options.عدد_host_کلی_files; i++) {
		بدل (type) {
		حالة کلی_RSA_CERT:
		حالة کلی_ECDSA_CERT:
		حالة کلی_ED25519_CERT:
		حالة کلی_MLDSA44_ED25519_CERT:
		حالة کلی_ECDSA_SK_CERT:
		حالة کلی_ED25519_SK_CERT:
			کلی = host_certificates[i];
			اكسر;
		افتراضي:
			کلی = host_pubkeys[i];
			اكسر;
		}
		إذا (کلی == عدم || کلی->type != type)
			استمر;
		بدل (type) {
		حالة کلی_ECDSA:
		حالة کلی_ECDSA_SK:
		حالة کلی_ECDSA_CERT:
		حالة کلی_ECDSA_SK_CERT:
			إذا (کلی->ecdsa_nid != nid)
				استمر;
			/* FALLTHROUGH */
		افتراضي:
			أرجع کلی;
		}
	}
	أرجع عدم;
}

/* XXX remove */
بنية sshkey *
get_hostkey_شخصي_by_type(صحيح type, صحيح nid, بنية ssh *ssh)
{
	أرجع عدم;
}

/* XXX remove */
بنية sshkey *
get_hostkey_by_شاخص(صحيح ind)
{
	أرجع عدم;
}

بنية sshkey *
get_hostkey_عامه_by_شاخص(صحيح ind, بنية ssh *ssh)
{
	إذا (ind < 0 || (u_int)ind >= options.عدد_host_کلی_files)
		أرجع (عدم);
	أرجع host_pubkeys[ind];
}

صحيح
get_hostkey_شاخص(بنية sshkey *کلی, صحيح compare, بنية ssh *ssh)
{
	u_int i;

	لكل (i = 0; i < options.عدد_host_کلی_files; i++) {
		إذا (sshkey_is_cert(کلی)) {
			إذا (کلی == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(کلی, host_certificates[i])))
				أرجع (i);
		} وإلا {
			إذا (کلی == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(کلی, host_pubkeys[i])))
				أرجع (i);
		}
	}
	أرجع (-1);
}

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr, "%s, %s\n", SSH_نسخه, SSH_OPENSSL_نسخه);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	وتل(1);
}

ساكن فراغ
parse_hostkeys(بنية sshbuf *hostkeys)
{
	صحيح r;
	u_int عدد_کلیګانې = 0;
	بنية sshkey *k;
	ثابت u_char *cp;
	اندازه_t len;

	طالما (sshbuf_len(hostkeys) != 0) {
		إذا (عدد_کلیګانې > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    عدد_کلیګانې, عدد_کلیګانې + 1, حجم(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    عدد_کلیګانې, عدد_کلیګانې + 1, حجم(*host_certificates));
		/* public key */
		k = عدم;
		إذا ((r = sshbuf_get_string_مستقیم(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		إذا (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[عدد_کلیګانې] = k;
		إذا (k)
			debug2_f("key %u: %s", عدد_کلیګانې, sshkey_ssh_name(k));
		/* certificate */
		k = عدم;
		إذا ((r = sshbuf_get_string_مستقیم(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		إذا (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[عدد_کلیګانې] = k;
		إذا (k)
			debug2_f("cert %u: %s", عدد_کلیګانې, sshkey_ssh_name(k));
		عدد_کلیګانې++;
	}
	عدد_hostkeys = عدد_کلیګانې;
}

ساكن فراغ
recv_privsep_state(بنية ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	بنية sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, عدم, timing_secretp,
	    &hostkeys, عدم, عدم, عدم, عدم);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
صحيح
اصلي(صحيح ac, حرف **av)
{
	بنية ssh *ssh = عدم;
	خارجي حرف *optarg;
	خارجي صحيح optind;
	صحيح r, opt, have_کلی = 0;
	صحيح sock_دننه = -1, sock_بهر = -1, rexeced_flag = 0;
	u_int i;
	ډېرپېښ_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, عدم);

#که_تعریف_شوی HAVE_SECUREWARE
	(فراغ)سېټ_auth_parameters(ac, av);
#د_که_پای
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, حجم(*saved_argv));
	لكل (i = 0; (صحيح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = عدم;

	تخم_rng();

#که_نه_تعریف_شوی HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#د_که_پای

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	طالما ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		بدل (opt) {
		حالة '4':
			/* ignore */
			اكسر;
		حالة '6':
			/* ignore */
			اكسر;
		حالة 'f':
			/* ignore */
			اكسر;
		حالة 'c':
			/* ignore */
			اكسر;
		حالة 'd':
			إذا (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} وإلا إذا (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			اكسر;
		حالة 'D':
		حالة 'E':
		حالة 'e':
			/* ignore */
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
			/* ignored */
			اكسر;
		حالة 'b':
			/* protocol 1, ignored */
			اكسر;
		حالة 'p':
			/* ignored */
			اكسر;
		حالة 'g':
			/* ignored */
			اكسر;
		حالة 'k':
			/* protocol 1, ignored */
			اكسر;
		حالة 'h':
			/* ignored */
			اكسر;
		حالة 't':
		حالة 'T':
		حالة 'G':
		حالة 'C':
			fatal("test/dump modes not supported");
			اكسر;
		حالة 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, عدم);
			إذا (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				وتل(1);
			}
			اكسر;
		حالة 'o':
			/* ignored */
			اكسر;
		حالة 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_نسخه, SSH_OPENSSL_نسخه);
			وتل(0);
		افتراضي:
			usage();
			اكسر;
		}
	}

	إذا (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_سېټ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_سېټ ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, حجم(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	سېټ_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	إذا (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		وتل(1);
	}

	/* Connection passed by stdin/out */
	إذا (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_دننه = dup(STDIN_FILENO);
		sock_بهر = dup(STDOUT_FILENO);
	} وإلا {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_دننه = sock_بهر = dup(STDIN_FILENO);
	}

	إذا (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_دننه, sock_بهر);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	إذا ((ssh = ssh_packet_سېټ_connection(عدم, sock_دننه, sock_بهر)) == عدم)
		fatal("Unable to create connection");
	the_فعال_state = ssh;
	ssh_packet_سېټ_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	إذا ((cfg = sshbuf_new()) == عدم)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[session-auth early]");
	recv_privsep_state(ssh, &options, &timing_secret);
	options.timing_secret = timing_secret; /* XXX eliminate from unpriv */
	ssh_packet_سېټ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility, 1);
	سېټ_log_handler(mm_log_handler, pmonitor);

	debug("sshd-auth version %s, %s", SSH_نسخه, SSH_OPENSSL_نسخه);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	إذا ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == عدم) {
		إذا (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} وإلا {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, مزي_اوږدوالی(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#که_تعریف_شوی WITH_OPENSSL
	إذا (options.moduli_file != عدم)
		dh_سېټ_moduli_file(options.moduli_file);
#د_که_پای

	إذا (options.host_کلی_agent) {
		إذا (strcmp(options.host_کلی_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_کلی_agent, 1);
		إذا ((r = ssh_get_authentication_socket(عدم)) == 0)
			have_agent = 1;
		وإلا
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_کلی_agent);
	}

	إذا (options.عدد_host_کلی_files != عدد_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.عدد_host_کلی_files, عدد_hostkeys);
	}

	لكل (i = 0; i < options.عدد_host_کلی_files; i++) {
		إذا (host_pubkeys[i] != عدم) {
			have_کلی = 1;
			اكسر;
		}
	}
	إذا (!have_کلی)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(فراغ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	سېټ_log_handler(mm_log_handler, pmonitor);
	لكل (i = 0; i < options.عدد_log_verbose; i++)
		log_verbose_جمع_کړه(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	إذا (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_بهر);
	FD_CLOSEONEXEC(sock_دننه);

	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_سېټ_af(ssh, options.پته_family);
	channel_سېټ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	ssh_packet_سېټ_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, حجم(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	إذا ((auth_opts = sshauthopt_new_with_کلیګانې_defaults()) == عدم)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	إذا ((loginmsg = sshbuf_new()) == عدم)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

#که_تعریف_شوی GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#د_که_پای

	privsep_ماشوم_demote();

	/* perform the key exchange */
	/* authenticate user and start session */
	do_ssh2_kex(ssh);
	do_authentication2(ssh);

	/*
	 * The unprivileged child now transfers the current keystate and exits.
	 */
	mm_send_keystate(ssh, pmonitor);
	sshauthopt_free(auth_opts);
	ssh_packet_clear_کلیګانې(ssh);
	وتل(0);
}

صحيح
sshd_hostkey_sign(بنية ssh *ssh, بنية sshkey *privkey,
    بنية sshkey *pubkey, u_char **signature, اندازه_t *slenp,
    ثابت u_char *معلومات, اندازه_t dlen, ثابت حرف *alg)
{
	إذا (privkey) {
		إذا (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    معلومات, dlen, alg, options.sk_provider, عدم,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} وإلا {
		إذا (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    معلومات, dlen, alg, options.sk_provider, عدم,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	أرجع 0;
}

/* SSH2 key exchange */
ساكن فراغ
do_ssh2_kex(بنية ssh *ssh)
{
	حرف *hkalgs = عدم, *myproposal[PROPOSAL_MAX];
	ثابت حرف *compression = عدم;
	بنية kex *kex;
	صحيح r;

	ssh_packet_سېټ_rekey_limits(ssh, options.rekey_حد,
	    options.rekey_interval);

	إذا (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	حرر(hkalgs);

	إذا ((r = kex_exchange_identification(ssh, -1,
	    options.نسخه_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	إذا ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	إذا ((r = kex_تیاری(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_سېټ_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_سېټ_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#که_تعریف_شوی WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#د_که_پای
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->بارول_host_عامه_کلی=&get_hostkey_عامه_by_type;
	kex->بارول_host_شخصي_کلی=&get_hostkey_شخصي_by_type;
	kex->host_کلی_شاخص=&get_hostkey_شاخص;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_پرلپسې_fatal(ssh, DISPATCH_بلاک, &kex->بشپړ);
	kex_proposal_free_entries(myproposal);

#که_تعریف_شوی DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#د_که_پای
	debug("KEX done");
}

/* server specific fatal cleanup */
فراغ
cleanup_exit(صحيح i)
{
	_exit(i);
}
