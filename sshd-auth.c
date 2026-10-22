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

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>
#جے_انت

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
#جے_تعریف_شدہ GSSAPI
#ضمن "ssh-gss.h"
#جے_انت
#ضمن "monitor_wrap.h"
#ضمن "auth-options.h"
#ضمن "version.h"
#ضمن "ssherr.h"
#ضمن "sk-api.h"
#ضمن "srclimit.h"
#ضمن "ssh-sandbox.h"
#ضمن "dh.h"

/* Privsep fds */
#تعریف_کرو PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#تعریف_کرو PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#تعریف_کرو PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

خارجي حرف *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
حرف *config_file_name = رستہ_SERVER_CONFIG_FILE;

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
بنية ssh *the_سرگرم_state;

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

#جے_بنا_تعریف HAVE_PLEDGE
ساكن بنية ssh_sandbox *box;
#جے_انت

/* XXX stub */
صحيح
mm_is_monitor(فراغ)
{
	أرجع 0;
}

ساكن فراغ
privsep_بچہ_demote(فراغ)
{
	gid_t gidset[1];

#جے_بنا_تعریف HAVE_PLEDGE
	إذا ((box = ssh_sandbox_init(pmonitor)) == عدم)
		fatal_f("ssh_sandbox_init failed");
#جے_انت
	/* Demote the child */
	إذا (privsep_chroot) {
		/* Change our root directory */
		إذا (chroot(رستہ_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", رستہ_PRIVSEP_CHROOT_DIR,
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
		permanently_سیٹ_uid(privsep_pw);
	}

	/* sandbox ourselves */
#جے_تعریف_شدہ HAVE_PLEDGE
	إذا (pledge("stdio", عدم) == -1)
		fatal_f("pledge()");
#وإلا
	ssh_sandbox_بچہ(box);
#جے_انت
}

ساكن فراغ
append_hostkey_type(بنية sshbuf *b, ثابت حرف *s)
{
	صحيح r;

	إذا (میل_نمونہ_list(s, options.hostkeyalgorithms, 0) != 1) {
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
	بنية sshkey *کلید;
	حرف *ret;
	u_int i;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	لكل (i = 0; i < options.عدد_host_کلید_files; i++) {
		کلید = host_pubkeys[i];
		إذا (کلید == عدم)
			استمر;
		بدل (کلید->type) {
		حالة کلید_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		حالة کلید_ECDSA:
		حالة کلید_ED25519:
		حالة کلید_MLDSA44_ED25519:
		حالة کلید_ECDSA_SK:
		حالة کلید_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(کلید));
			اكسر;
		}
		/* If the private key has a cert peer, then list that too */
		کلید = host_certificates[i];
		إذا (کلید == عدم)
			استمر;
		بدل (کلید->type) {
		حالة کلید_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		حالة کلید_ECDSA_CERT:
		حالة کلید_ED25519_CERT:
		حالة کلید_MLDSA44_ED25519_CERT:
		حالة کلید_ECDSA_SK_CERT:
		حالة کلید_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(کلید));
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
get_hostkey_عوامی_by_type(صحيح type, صحيح nid, بنية ssh *ssh)
{
	u_int i;
	بنية sshkey *کلید;

	لكل (i = 0; i < options.عدد_host_کلید_files; i++) {
		بدل (type) {
		حالة کلید_RSA_CERT:
		حالة کلید_ECDSA_CERT:
		حالة کلید_ED25519_CERT:
		حالة کلید_MLDSA44_ED25519_CERT:
		حالة کلید_ECDSA_SK_CERT:
		حالة کلید_ED25519_SK_CERT:
			کلید = host_certificates[i];
			اكسر;
		افتراضي:
			کلید = host_pubkeys[i];
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
			أرجع کلید;
		}
	}
	أرجع عدم;
}

/* XXX remove */
بنية sshkey *
get_hostkey_نجی_by_type(صحيح type, صحيح nid, بنية ssh *ssh)
{
	أرجع عدم;
}

/* XXX remove */
بنية sshkey *
get_hostkey_by_اشاریہ(صحيح ind)
{
	أرجع عدم;
}

بنية sshkey *
get_hostkey_عوامی_by_اشاریہ(صحيح ind, بنية ssh *ssh)
{
	إذا (ind < 0 || (u_int)ind >= options.عدد_host_کلید_files)
		أرجع (عدم);
	أرجع host_pubkeys[ind];
}

صحيح
get_hostkey_اشاریہ(بنية sshkey *کلید, صحيح compare, بنية ssh *ssh)
{
	u_int i;

	لكل (i = 0; i < options.عدد_host_کلید_files; i++) {
		إذا (sshkey_is_cert(کلید)) {
			إذا (کلید == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(کلید, host_certificates[i])))
				أرجع (i);
		} وإلا {
			إذا (کلید == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(کلید, host_pubkeys[i])))
				أرجع (i);
		}
	}
	أرجع (-1);
}

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr, "%s, %s\n", SSH_نسخہ, SSH_OPENSSL_نسخہ);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	باہر_نکلو(1);
}

ساكن فراغ
parse_hostkeys(بنية sshbuf *hostkeys)
{
	صحيح r;
	u_int عدد_کلیدیں = 0;
	بنية sshkey *k;
	ثابت u_char *cp;
	ناپ_t len;

	طالما (sshbuf_len(hostkeys) != 0) {
		إذا (عدد_کلیدیں > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    عدد_کلیدیں, عدد_کلیدیں + 1, حجم(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    عدد_کلیدیں, عدد_کلیدیں + 1, حجم(*host_certificates));
		/* public key */
		k = عدم;
		إذا ((r = sshbuf_get_string_سدھا(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		إذا (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[عدد_کلیدیں] = k;
		إذا (k)
			debug2_f("key %u: %s", عدد_کلیدیں, sshkey_ssh_name(k));
		/* certificate */
		k = عدم;
		إذا ((r = sshbuf_get_string_سدھا(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		إذا (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[عدد_کلیدیں] = k;
		إذا (k)
			debug2_f("cert %u: %s", عدد_کلیدیں, sshkey_ssh_name(k));
		عدد_کلیدیں++;
	}
	عدد_hostkeys = عدد_کلیدیں;
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
مکھ(صحيح ac, حرف **av)
{
	بنية ssh *ssh = عدم;
	خارجي حرف *optarg;
	خارجي صحيح optind;
	صحيح r, opt, have_کلید = 0;
	صحيح sock_وچ = -1, sock_باہرلا = -1, rexeced_flag = 0;
	u_int i;
	منوال_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, عدم);

#جے_تعریف_شدہ HAVE_SECUREWARE
	(فراغ)سیٹ_auth_parameters(ac, av);
#جے_انت
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, حجم(*saved_argv));
	لكل (i = 0; (صحيح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = عدم;

	بیج_rng();

#جے_بنا_تعریف HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#جے_انت

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
				باہر_نکلو(1);
			}
			اكسر;
		حالة 'o':
			/* ignored */
			اكسر;
		حالة 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_نسخہ, SSH_OPENSSL_نسخہ);
			باہر_نکلو(0);
		افتراضي:
			usage();
			اكسر;
		}
	}

	إذا (!rexeced_flag)
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
	إذا (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		باہر_نکلو(1);
	}

	/* Connection passed by stdin/out */
	إذا (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_وچ = dup(STDIN_FILENO);
		sock_باہرلا = dup(STDOUT_FILENO);
	} وإلا {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_وچ = sock_باہرلا = dup(STDIN_FILENO);
	}

	إذا (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_وچ, sock_باہرلا);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	إذا ((ssh = ssh_packet_سیٹ_connection(عدم, sock_وچ, sock_باہرلا)) == عدم)
		fatal("Unable to create connection");
	the_سرگرم_state = ssh;
	ssh_packet_سیٹ_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	إذا ((cfg = sshbuf_new()) == عدم)
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
	إذا ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == عدم) {
		إذا (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} وإلا {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, لڑی_لمبائی(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#جے_تعریف_شدہ WITH_OPENSSL
	إذا (options.moduli_file != عدم)
		dh_سیٹ_moduli_file(options.moduli_file);
#جے_انت

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

	إذا (options.عدد_host_کلید_files != عدد_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.عدد_host_کلید_files, عدد_hostkeys);
	}

	لكل (i = 0; i < options.عدد_host_کلید_files; i++) {
		إذا (host_pubkeys[i] != عدم) {
			have_کلید = 1;
			اكسر;
		}
	}
	إذا (!have_کلید)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(فراغ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	سیٹ_log_handler(mm_log_handler, pmonitor);
	لكل (i = 0; i < options.عدد_log_verbose; i++)
		log_verbose_جوڑو(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	إذا (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_باہرلا);
	FD_CLOSEONEXEC(sock_وچ);

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
	إذا ((auth_opts = sshauthopt_new_with_کلیدیں_defaults()) == عدم)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	إذا ((loginmsg = sshbuf_new()) == عدم)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

#جے_تعریف_شدہ GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#جے_انت

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

صحيح
sshd_hostkey_sign(بنية ssh *ssh, بنية sshkey *privkey,
    بنية sshkey *pubkey, u_char **signature, ناپ_t *slenp,
    ثابت u_char *انکڑے, ناپ_t dlen, ثابت حرف *alg)
{
	إذا (privkey) {
		إذا (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    انکڑے, dlen, alg, options.sk_provider, عدم,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} وإلا {
		إذا (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    انکڑے, dlen, alg, options.sk_provider, عدم,
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

	ssh_packet_سیٹ_rekey_limits(ssh, options.rekey_حد_بندی,
	    options.rekey_interval);

	إذا (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	حرر(hkalgs);

	إذا ((r = kex_exchange_identification(ssh, -1,
	    options.نسخہ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	إذا ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	إذا ((r = kex_تیاری(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_سیٹ_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_سیٹ_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#جے_تعریف_شدہ WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#جے_انت
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->لدو_host_عوامی_کلید=&get_hostkey_عوامی_by_type;
	kex->لدو_host_نجی_کلید=&get_hostkey_نجی_by_type;
	kex->host_کلید_اشاریہ=&get_hostkey_اشاریہ;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_لگاتار_fatal(ssh, DISPATCH_بلاک, &kex->پورا);
	kex_proposal_free_entries(myproposal);

#جے_تعریف_شدہ DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#جے_انت
	debug("KEX done");
}

/* server specific fatal cleanup */
فراغ
cleanup_exit(صحيح i)
{
	_exit(i);
}
