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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/evp.h>
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
#شامل "ssh-sandbox.h"
#شامل "dh.h"

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

/* Saved arguments to main(). */
ساکن حرف **saved_argv;
ساکن صحیح saved_argc;


/* Daemon's agent connection */
صحیح auth_sock = -1;
ساکن صحیح have_agent = 0;

u_int		عدد_hostkeys;
ساخت sshkey	**host_pubkeys;		/* all public host keys */
ساخت sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
ساخت monitor *pmonitor = تہی;
صحیح privsep_is_preauth = 1;
ساکن صحیح privsep_chroot = 1;

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
ساکن خالی do_ssh2_kex(ساخت ssh *);

/* Unprivileged user */
ساخت passwd *privsep_pw = تہی;

#اگر_غیر_تعریف_شدہ HAVE_PLEDGE
ساکن ساخت ssh_sandbox *box;
#اگر_ختم

/* XXX stub */
صحیح
mm_is_monitor(خالی)
{
	واپس 0;
}

ساکن خالی
privsep_بچہ_demote(خالی)
{
	gid_t gidset[1];

#اگر_غیر_تعریف_شدہ HAVE_PLEDGE
	اگر ((box = ssh_sandbox_init(pmonitor)) == تہی)
		fatal_f("ssh_sandbox_init failed");
#اگر_ختم
	/* Demote the child */
	اگر (privsep_chroot) {
		/* Change our root directory */
		اگر (chroot(راستہ_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", راستہ_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		اگر (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		اگر (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_سیٹ_uid(privsep_pw);
	}

	/* sandbox ourselves */
#اگر_تعریف_شدہ HAVE_PLEDGE
	اگر (pledge("stdio", تہی) == -1)
		fatal_f("pledge()");
#ورنہ
	ssh_sandbox_بچہ(box);
#اگر_ختم
}

ساکن خالی
append_hostkey_type(ساخت sshbuf *b, ثابت حرف *s)
{
	صحیح r;

	اگر (مطابقت_نمونہ_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		واپس;
	}
	اگر ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

ساکن حرف *
list_hostkey_types(خالی)
{
	ساخت sshbuf *b;
	ساخت sshkey *کلید;
	حرف *ret;
	u_int i;

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		کلید = host_pubkeys[i];
		اگر (کلید == تہی)
			جاری;
		انتخاب (کلید->type) {
		حالت کلید_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		حالت کلید_ECDSA:
		حالت کلید_ED25519:
		حالت کلید_MLDSA44_ED25519:
		حالت کلید_ECDSA_SK:
		حالت کلید_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(کلید));
			توڑو;
		}
		/* If the private key has a cert peer, then list that too */
		کلید = host_certificates[i];
		اگر (کلید == تہی)
			جاری;
		انتخاب (کلید->type) {
		حالت کلید_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		حالت کلید_ECDSA_CERT:
		حالت کلید_ED25519_CERT:
		حالت کلید_MLDSA44_ED25519_CERT:
		حالت کلید_ECDSA_SK_CERT:
		حالت کلید_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(کلید));
			توڑو;
		}
	}
	اگر ((ret = sshbuf_dup_string(b)) == تہی)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	واپس ret;
}

ساخت sshkey *
get_hostkey_عوامی_by_type(صحیح type, صحیح nid, ساخت ssh *ssh)
{
	u_int i;
	ساخت sshkey *کلید;

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		انتخاب (type) {
		حالت کلید_RSA_CERT:
		حالت کلید_ECDSA_CERT:
		حالت کلید_ED25519_CERT:
		حالت کلید_MLDSA44_ED25519_CERT:
		حالت کلید_ECDSA_SK_CERT:
		حالت کلید_ED25519_SK_CERT:
			کلید = host_certificates[i];
			توڑو;
		طےشدہ:
			کلید = host_pubkeys[i];
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
			واپس کلید;
		}
	}
	واپس تہی;
}

/* XXX remove */
ساخت sshkey *
get_hostkey_نجی_by_type(صحیح type, صحیح nid, ساخت ssh *ssh)
{
	واپس تہی;
}

/* XXX remove */
ساخت sshkey *
get_hostkey_by_اشاریہ(صحیح ind)
{
	واپس تہی;
}

ساخت sshkey *
get_hostkey_عوامی_by_اشاریہ(صحیح ind, ساخت ssh *ssh)
{
	اگر (ind < 0 || (u_int)ind >= options.عدد_host_کلید_files)
		واپس (تہی);
	واپس host_pubkeys[ind];
}

صحیح
get_hostkey_اشاریہ(ساخت sshkey *کلید, صحیح compare, ساخت ssh *ssh)
{
	u_int i;

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		اگر (sshkey_is_cert(کلید)) {
			اگر (کلید == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(کلید, host_certificates[i])))
				واپس (i);
		} ورنہ {
			اگر (کلید == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(کلید, host_pubkeys[i])))
				واپس (i);
		}
	}
	واپس (-1);
}

ساکن خالی
usage(خالی)
{
	fprintf(stderr, "%s, %s\n", SSH_نسخہ, SSH_OPENSSL_نسخہ);
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
	ثابت u_char *cp;
	سائز_t len;

	جب (sshbuf_len(hostkeys) != 0) {
		اگر (عدد_کلیدیں > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    عدد_کلیدیں, عدد_کلیدیں + 1, حجم(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    عدد_کلیدیں, عدد_کلیدیں + 1, حجم(*host_certificates));
		/* public key */
		k = تہی;
		اگر ((r = sshbuf_get_string_براہ_راست(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		اگر (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[عدد_کلیدیں] = k;
		اگر (k)
			debug2_f("key %u: %s", عدد_کلیدیں, sshkey_ssh_name(k));
		/* certificate */
		k = تہی;
		اگر ((r = sshbuf_get_string_براہ_راست(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		اگر (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[عدد_کلیدیں] = k;
		اگر (k)
			debug2_f("cert %u: %s", عدد_کلیدیں, sshkey_ssh_name(k));
		عدد_کلیدیں++;
	}
	عدد_hostkeys = عدد_کلیدیں;
}

ساکن خالی
recv_privsep_state(ساخت ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	ساخت sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, تہی, timing_secretp,
	    &hostkeys, تہی, تہی, تہی, تہی);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
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
	صحیح r, opt, have_کلید = 0;
	صحیح sock_اندر = -1, sock_برآمد = -1, rexeced_flag = 0;
	u_int i;
	منوال_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
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

	بیج_rng();

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
			/* ignore */
			توڑو;
		حالت '6':
			/* ignore */
			توڑو;
		حالت 'f':
			/* ignore */
			توڑو;
		حالت 'c':
			/* ignore */
			توڑو;
		حالت 'd':
			اگر (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ورنہ اگر (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			توڑو;
		حالت 'D':
		حالت 'E':
		حالت 'e':
			/* ignore */
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
			/* ignored */
			توڑو;
		حالت 'b':
			/* protocol 1, ignored */
			توڑو;
		حالت 'p':
			/* ignored */
			توڑو;
		حالت 'g':
			/* ignored */
			توڑو;
		حالت 'k':
			/* protocol 1, ignored */
			توڑو;
		حالت 'h':
			/* ignored */
			توڑو;
		حالت 't':
		حالت 'T':
		حالت 'G':
		حالت 'C':
			fatal("test/dump modes not supported");
			توڑو;
		حالت 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, تہی);
			اگر (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				باہر_نکلو(1);
			}
			توڑو;
		حالت 'o':
			/* ignored */
			توڑو;
		حالت 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_نسخہ, SSH_OPENSSL_نسخہ);
			باہر_نکلو(0);
		طےشدہ:
			usage();
			توڑو;
		}
	}

	اگر (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_سیٹ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_سیٹ ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, حجم(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	سیٹ_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	اگر (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		باہر_نکلو(1);
	}

	/* Connection passed by stdin/out */
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

	اگر (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_اندر, sock_برآمد);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	اگر ((ssh = ssh_packet_سیٹ_connection(تہی, sock_اندر, sock_برآمد)) == تہی)
		fatal("Unable to create connection");
	the_فعال_state = ssh;
	ssh_packet_سیٹ_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	اگر ((cfg = sshbuf_new()) == تہی)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[session-auth early]");
	recv_privsep_state(ssh, &options, &timing_secret);
	options.timing_secret = timing_secret; /* XXX eliminate from unpriv */
	ssh_packet_سیٹ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility, 1);
	سیٹ_log_handler(mm_log_handler, pmonitor);

	debug("sshd-auth version %s, %s", SSH_نسخہ, SSH_OPENSSL_نسخہ);

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

	اگر (options.عدد_host_کلید_files != عدد_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.عدد_host_کلید_files, عدد_hostkeys);
	}

	برائے (i = 0; i < options.عدد_host_کلید_files; i++) {
		اگر (host_pubkeys[i] != تہی) {
			have_کلید = 1;
			توڑو;
		}
	}
	اگر (!have_کلید)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(خالی) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	سیٹ_log_handler(mm_log_handler, pmonitor);
	برائے (i = 0; i < options.عدد_log_verbose; i++)
		log_verbose_جوڑو(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	اگر (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_برآمد);
	FD_CLOSEONEXEC(sock_اندر);

	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_سیٹ_af(ssh, options.پتہ_family);
	channel_سیٹ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

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

#اگر_تعریف_شدہ GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#اگر_ختم

	privsep_بچہ_demote();

	/* perform the key exchange */
	/* authenticate user and start session */
	do_ssh2_kex(ssh);
	do_authentication2(ssh);

	/*
	 * The unprivileged child now transfers the current keystate and exits.
	 */
	mm_send_keystate(ssh, pmonitor);
	sshauthopt_free(auth_opts);
	ssh_packet_clear_کلیدیں(ssh);
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

/* SSH2 key exchange */
ساکن خالی
do_ssh2_kex(ساخت ssh *ssh)
{
	حرف *hkalgs = تہی, *myproposal[PROPOSAL_MAX];
	ثابت حرف *compression = تہی;
	ساخت kex *kex;
	صحیح r;

	ssh_packet_سیٹ_rekey_limits(ssh, options.rekey_حد_بندی,
	    options.rekey_interval);

	اگر (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	آزاد(hkalgs);

	اگر ((r = kex_exchange_identification(ssh, -1,
	    options.نسخہ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	اگر ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	اگر ((r = kex_تیاری(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_سیٹ_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_سیٹ_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#اگر_تعریف_شدہ WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#اگر_ختم
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->بھرو_host_عوامی_کلید=&get_hostkey_عوامی_by_type;
	kex->بھرو_host_نجی_کلید=&get_hostkey_نجی_by_type;
	kex->host_کلید_اشاریہ=&get_hostkey_اشاریہ;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_تسلسل_fatal(ssh, DISPATCH_بلاک, &kex->مکمل);
	kex_proposal_free_entries(myproposal);

#اگر_تعریف_شدہ DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#اگر_ختم
	debug("KEX done");
}

/* server specific fatal cleanup */
خالی
cleanup_exit(صحیح i)
{
	_exit(i);
}
