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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/tree.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "session.h"
#ಅನ್ತರ್ಭಾವ "monitor.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "version.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"
#ಅನ್ತರ್ಭಾವ "ssh-sandbox.h"
#ಅನ್ತರ್ಭಾವ "dh.h"

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

ಬಾಹ್ಯ ವರ್ಣ *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
ವರ್ಣ *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ಪೂರ್ಣಾಙ್ಕ debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ inetd_flag = 0;

/* Saved arguments to main(). */
ಸ್ಥಿರ ವರ್ಣ **saved_argv;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ saved_argc;


/* Daemon's agent connection */
ಪೂರ್ಣಾಙ್ಕ auth_sock = -1;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ have_agent = 0;

u_int		ಅಂಕೆ_hostkeys;
ಸಂರಚನಾ sshkey	**host_pubkeys;		/* all public host keys */
ಸಂರಚನಾ sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
ಸಂರಚನಾ monitor *pmonitor = ರಿಕ್ತ;
ಪೂರ್ಣಾಙ್ಕ privsep_is_preauth = 1;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ರಿಕ್ತ;
ಸಂರಚನಾ ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ಸಂರಚನಾ sshauthopt *auth_opts = ರಿಕ್ತ;

/* sshd_config buffer */
ಸಂರಚನಾ sshbuf *cfg;

/* Included files from the configuration file */
ಸಂರಚನಾ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ಸಂರಚನಾ sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ಸ್ಥಿರ ಶೂನ್ಯ do_ssh2_kex(ಸಂರಚನಾ ssh *);

/* Unprivileged user */
ಸಂರಚನಾ passwd *privsep_pw = ರಿಕ್ತ;

#ifndef HAVE_PLEDGE
ಸ್ಥಿರ ಸಂರಚನಾ ssh_sandbox *box;
#endif

/* XXX stub */
ಪೂರ್ಣಾಙ್ಕ
mm_is_monitor(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
privsep_child_demote(ಶೂನ್ಯ)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	ಯದಿ ((box = ssh_sandbox_init(pmonitor)) == ರಿಕ್ತ)
		fatal_f("ssh_sandbox_init failed");
#endif
	/* Demote the child */
	ಯದಿ (privsep_chroot) {
		/* Change our root directory */
		ಯದಿ (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		ಯದಿ (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		ಯದಿ (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ifdef HAVE_PLEDGE
	ಯದಿ (pledge("stdio", ರಿಕ್ತ) == -1)
		fatal_f("pledge()");
#ಅನ್ಯಥಾ
	ssh_sandbox_child(box);
#endif
}

ಸ್ಥಿರ ಶೂನ್ಯ
append_hostkey_type(ಸಂರಚನಾ sshbuf *b, ಧ್ರುವ ವರ್ಣ *s)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

ಸ್ಥಿರ ವರ್ಣ *
list_hostkey_types(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *b;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	ವರ್ಣ *ret;
	u_int i;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಕೀಲಿ = host_pubkeys[i];
		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
		ಪಕ್ಷ ಕೀಲಿ_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಪಕ್ಷ ಕೀಲಿ_ED25519:
		ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(ಕೀಲಿ));
			ಭಙ್ಗ;
		}
		/* If the private key has a cert peer, then list that too */
		ಕೀಲಿ = host_certificates[i];
		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
		ಪಕ್ಷ ಕೀಲಿ_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_CERT:
		ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(ಕೀಲಿ));
			ಭಙ್ಗ;
		}
	}
	ಯದಿ ((ret = sshbuf_dup_string(b)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸಂರಚನಾ sshkey *
get_hostkey_public_by_type(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid, ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ ಕೀಲಿ_RSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_CERT:
		ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_SK_CERT:
			ಕೀಲಿ = host_certificates[i];
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಕೀಲಿ = host_pubkeys[i];
			ಭಙ್ಗ;
		}
		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || ಕೀಲಿ->type != type)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
			ಯದಿ (ಕೀಲಿ->ecdsa_nid != nid)
				ಅನುವರ್ತ;
			/* FALLTHROUGH */
		ಸ್ವಭಾವ:
			ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ;
		}
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/* XXX remove */
ಸಂರಚನಾ sshkey *
get_hostkey_private_by_type(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid, ಸಂರಚನಾ ssh *ssh)
{
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/* XXX remove */
ಸಂರಚನಾ sshkey *
get_hostkey_by_index(ಪೂರ್ಣಾಙ್ಕ ind)
{
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸಂರಚನಾ sshkey *
get_hostkey_public_by_index(ಪೂರ್ಣಾಙ್ಕ ind, ಸಂರಚನಾ ssh *ssh)
{
	ಯದಿ (ind < 0 || (u_int)ind >= options.ಅಂಕೆ_host_ಕೀಲಿ_files)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ host_pubkeys[ind];
}

ಪೂರ್ಣಾಙ್ಕ
get_hostkey_index(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ compare, ಸಂರಚನಾ ssh *ssh)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಯದಿ (sshkey_is_cert(ಕೀಲಿ)) {
			ಯದಿ (ಕೀಲಿ == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(ಕೀಲಿ, host_certificates[i])))
				ಪ್ರತ್ಯಾಗಮ (i);
		} ಅನ್ಯಥಾ {
			ಯದಿ (ಕೀಲಿ == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(ಕೀಲಿ, host_pubkeys[i])))
				ಪ್ರತ್ಯಾಗಮ (i);
		}
	}
	ಪ್ರತ್ಯಾಗಮ (-1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
parse_hostkeys(ಸಂರಚನಾ sshbuf *hostkeys)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int ಅಂಕೆ_ಕೀಲಿಗಳು = 0;
	ಸಂರಚನಾ sshkey *k;
	ಧ್ರುವ u_char *cp;
	size_t len;

	ಯಾವತ್ (sshbuf_len(hostkeys) != 0) {
		ಯದಿ (ಅಂಕೆ_ಕೀಲಿಗಳು > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1, ಪರಿಮಾಣ(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1, ಪರಿಮಾಣ(*host_certificates));
		/* public key */
		k = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ಯದಿ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		ಯದಿ (k)
			debug2_f("key %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		/* certificate */
		k = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ಯದಿ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		ಯದಿ (k)
			debug2_f("cert %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		ಅಂಕೆ_ಕೀಲಿಗಳು++;
	}
	ಅಂಕೆ_hostkeys = ಅಂಕೆ_ಕೀಲಿಗಳು;
}

ಸ್ಥಿರ ಶೂನ್ಯ
recv_privsep_state(ಸಂರಚನಾ ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	ಸಂರಚನಾ sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, ರಿಕ್ತ, timing_secretp,
	    &hostkeys, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ ac, ವರ್ಣ **av)
{
	ಸಂರಚನಾ ssh *ssh = ರಿಕ್ತ;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಪೂರ್ಣಾಙ್ಕ r, opt, have_ಕೀಲಿ = 0;
	ಪೂರ್ಣಾಙ್ಕ sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ರಿಕ್ತ);

#ifdef HAVE_SECUREWARE
	(ಶೂನ್ಯ)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, ಪರಿಮಾಣ(*saved_argv));
	ಪ್ರತಿ (i = 0; (ಪೂರ್ಣಾಙ್ಕ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ರಿಕ್ತ;

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
	ಯಾವತ್ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ವಿಕಲ್ಪ (opt) {
		ಪಕ್ಷ '4':
			/* ignore */
			ಭಙ್ಗ;
		ಪಕ್ಷ '6':
			/* ignore */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			/* ignore */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'c':
			/* ignore */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'd':
			ಯದಿ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ಅನ್ಯಥಾ ಯದಿ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
		ಪಕ್ಷ 'E':
		ಪಕ್ಷ 'e':
			/* ignore */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'i':
			inetd_flag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'r':
			/* ignore */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'R':
			rexeced_flag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Q':
			/* ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			/* ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'b':
			/* protocol 1, ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			/* ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'g':
			/* ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'k':
			/* protocol 1, ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
			/* ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
		ಪಕ್ಷ 'T':
		ಪಕ್ಷ 'G':
		ಪಕ್ಷ 'C':
			fatal("test/dump modes not supported");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ರಿಕ್ತ);
			ಯದಿ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'o':
			/* ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		ಸ್ವಭಾವ:
			usage();
			ಭಙ್ಗ;
		}
	}

	ಯದಿ (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, ಪರಿಮಾಣ(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	ಯದಿ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	/* Connection passed by stdin/out */
	ಯದಿ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} ಅನ್ಯಥಾ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	ಯದಿ (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	ಯದಿ ((ssh = ssh_packet_set_connection(ರಿಕ್ತ, sock_in, sock_out)) == ರಿಕ್ತ)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	ಯದಿ ((cfg = sshbuf_new()) == ರಿಕ್ತ)
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
	ಯದಿ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ರಿಕ್ತ) {
		ಯದಿ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ಅನ್ಯಥಾ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ifdef WITH_OPENSSL
	ಯದಿ (options.moduli_file != ರಿಕ್ತ)
		dh_set_moduli_file(options.moduli_file);
#endif

	ಯದಿ (options.host_ಕೀಲಿ_agent) {
		ಯದಿ (strcmp(options.host_ಕೀಲಿ_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ಕೀಲಿ_agent, 1);
		ಯದಿ ((r = ssh_get_authentication_socket(ರಿಕ್ತ)) == 0)
			have_agent = 1;
		ಅನ್ಯಥಾ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ಕೀಲಿ_agent);
	}

	ಯದಿ (options.ಅಂಕೆ_host_ಕೀಲಿ_files != ಅಂಕೆ_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.ಅಂಕೆ_host_ಕೀಲಿ_files, ಅಂಕೆ_hostkeys);
	}

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಯದಿ (host_pubkeys[i] != ರಿಕ್ತ) {
			have_ಕೀಲಿ = 1;
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (!have_ಕೀಲಿ)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ಶೂನ್ಯ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ಯದಿ (chdir("/") == -1)
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
	authctxt = xcalloc(1, ಪರಿಮಾಣ(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ಯದಿ ((auth_opts = sshauthopt_new_with_ಕೀಲಿಗಳು_defaults()) == ರಿಕ್ತ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ಯದಿ ((loginmsg = sshbuf_new()) == ರಿಕ್ತ)
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
	ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
	exit(0);
}

ಪೂರ್ಣಾಙ್ಕ
sshd_hostkey_sign(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshkey *privkey,
    ಸಂರಚನಾ sshkey *pubkey, u_char **signature, size_t *slenp,
    ಧ್ರುವ u_char *data, size_t dlen, ಧ್ರುವ ವರ್ಣ *alg)
{
	ಯದಿ (privkey) {
		ಯದಿ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ರಿಕ್ತ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ಅನ್ಯಥಾ {
		ಯದಿ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ರಿಕ್ತ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* SSH2 key exchange */
ಸ್ಥಿರ ಶೂನ್ಯ
do_ssh2_kex(ಸಂರಚನಾ ssh *ssh)
{
	ವರ್ಣ *hkalgs = ರಿಕ್ತ, *myproposal[PROPOSAL_MAX];
	ಧ್ರುವ ವರ್ಣ *compression = ರಿಕ್ತ;
	ಸಂರಚನಾ kex *kex;
	ಪೂರ್ಣಾಙ್ಕ r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	ಯದಿ (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	ಮುಕ್ತ(hkalgs);

	ಯದಿ ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	ಯದಿ ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	ಯದಿ ((r = kex_setup(ssh, myproposal)) != 0)
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
	kex->load_host_public_ಕೀಲಿ=&get_hostkey_public_by_type;
	kex->load_host_private_ಕೀಲಿ=&get_hostkey_private_by_type;
	kex->host_ಕೀಲಿ_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#endif
	debug("KEX done");
}

/* server specific fatal cleanup */
ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ i)
{
	_exit(i);
}
