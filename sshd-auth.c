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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/tree.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "srclimit.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sandbox.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"

/* Privsep fds */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

ਬਾਹਰੀ ਅੱਖਰ *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
ਅੱਖਰ *config_file_name = ਰਸਤਾ_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ਪੂਰਨ debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ਸਥਿਰ ਪੂਰਨ inetd_flag = 0;

/* Saved arguments to main(). */
ਸਥਿਰ ਅੱਖਰ **saved_argv;
ਸਥਿਰ ਪੂਰਨ saved_argc;


/* Daemon's agent connection */
ਪੂਰਨ auth_sock = -1;
ਸਥਿਰ ਪੂਰਨ have_agent = 0;

u_int		ਅੰਕ_hostkeys;
ਬਣਤਰ sshkey	**host_pubkeys;		/* all public host keys */
ਬਣਤਰ sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
ਬਣਤਰ monitor *pmonitor = ਨਿਰਾ;
ਪੂਰਨ privsep_is_preauth = 1;
ਸਥਿਰ ਪੂਰਨ privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ਨਿਰਾ;
ਬਣਤਰ ssh *the_ਸਰਗਰਮ_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ਬਣਤਰ sshauthopt *auth_opts = ਨਿਰਾ;

/* sshd_config buffer */
ਬਣਤਰ sshbuf *cfg;

/* Included files from the configuration file */
ਬਣਤਰ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ਬਣਤਰ sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ਸਥਿਰ ਖਾਲੀ do_ssh2_kex(ਬਣਤਰ ssh *);

/* Unprivileged user */
ਬਣਤਰ passwd *privsep_pw = ਨਿਰਾ;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PLEDGE
ਸਥਿਰ ਬਣਤਰ ssh_sandbox *box;
#ਜੇ_ਅੰਤ

/* XXX stub */
ਪੂਰਨ
mm_is_monitor(ਖਾਲੀ)
{
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
privsep_ਬੱਚਾ_demote(ਖਾਲੀ)
{
	gid_t gidset[1];

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PLEDGE
	ਜੇ ((box = ssh_sandbox_init(pmonitor)) == ਨਿਰਾ)
		fatal_f("ssh_sandbox_init failed");
#ਜੇ_ਅੰਤ
	/* Demote the child */
	ਜੇ (privsep_chroot) {
		/* Change our root directory */
		ਜੇ (chroot(ਰਸਤਾ_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", ਰਸਤਾ_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		ਜੇ (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		ਜੇ (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_ਸੈੱਟ_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_PLEDGE
	ਜੇ (pledge("stdio", ਨਿਰਾ) == -1)
		fatal_f("pledge()");
#ਨਹੀਂਤਾਂ
	ssh_sandbox_ਬੱਚਾ(box);
#ਜੇ_ਅੰਤ
}

ਸਥਿਰ ਖਾਲੀ
append_hostkey_type(ਬਣਤਰ sshbuf *b, ਅਚਲ ਅੱਖਰ *s)
{
	ਪੂਰਨ r;

	ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		ਵਾਪਸ;
	}
	ਜੇ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

ਸਥਿਰ ਅੱਖਰ *
list_hostkey_types(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *b;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	ਅੱਖਰ *ret;
	u_int i;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਕੁੰਜੀ = host_pubkeys[i];
		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
			ਜਾਰੀ;
		ਚੋਣ (ਕੁੰਜੀ->type) {
		ਹਾਲਤ ਕੁੰਜੀ_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519:
		ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(ਕੁੰਜੀ));
			ਰੋਕੋ;
		}
		/* If the private key has a cert peer, then list that too */
		ਕੁੰਜੀ = host_certificates[i];
		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
			ਜਾਰੀ;
		ਚੋਣ (ਕੁੰਜੀ->type) {
		ਹਾਲਤ ਕੁੰਜੀ_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(ਕੁੰਜੀ));
			ਰੋਕੋ;
		}
	}
	ਜੇ ((ret = sshbuf_dup_string(b)) == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	ਵਾਪਸ ret;
}

ਬਣਤਰ sshkey *
get_hostkey_ਜਨਤਕ_by_type(ਪੂਰਨ type, ਪੂਰਨ nid, ਬਣਤਰ ssh *ssh)
{
	u_int i;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਚੋਣ (type) {
		ਹਾਲਤ ਕੁੰਜੀ_RSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK_CERT:
			ਕੁੰਜੀ = host_certificates[i];
			ਰੋਕੋ;
		ਮੂਲ:
			ਕੁੰਜੀ = host_pubkeys[i];
			ਰੋਕੋ;
		}
		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || ਕੁੰਜੀ->type != type)
			ਜਾਰੀ;
		ਚੋਣ (type) {
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
			ਜੇ (ਕੁੰਜੀ->ecdsa_nid != nid)
				ਜਾਰੀ;
			/* FALLTHROUGH */
		ਮੂਲ:
			ਵਾਪਸ ਕੁੰਜੀ;
		}
	}
	ਵਾਪਸ ਨਿਰਾ;
}

/* XXX remove */
ਬਣਤਰ sshkey *
get_hostkey_ਨਿੱਜੀ_by_type(ਪੂਰਨ type, ਪੂਰਨ nid, ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ਨਿਰਾ;
}

/* XXX remove */
ਬਣਤਰ sshkey *
get_hostkey_by_ਸੂਚਕਾਂਕ(ਪੂਰਨ ind)
{
	ਵਾਪਸ ਨਿਰਾ;
}

ਬਣਤਰ sshkey *
get_hostkey_ਜਨਤਕ_by_ਸੂਚਕਾਂਕ(ਪੂਰਨ ind, ਬਣਤਰ ssh *ssh)
{
	ਜੇ (ind < 0 || (u_int)ind >= options.ਅੰਕ_host_ਕੁੰਜੀ_files)
		ਵਾਪਸ (ਨਿਰਾ);
	ਵਾਪਸ host_pubkeys[ind];
}

ਪੂਰਨ
get_hostkey_ਸੂਚਕਾਂਕ(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਪੂਰਨ compare, ਬਣਤਰ ssh *ssh)
{
	u_int i;

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
			ਜੇ (ਕੁੰਜੀ == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(ਕੁੰਜੀ, host_certificates[i])))
				ਵਾਪਸ (i);
		} ਨਹੀਂਤਾਂ {
			ਜੇ (ਕੁੰਜੀ == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(ਕੁੰਜੀ, host_pubkeys[i])))
				ਵਾਪਸ (i);
		}
	}
	ਵਾਪਸ (-1);
}

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr, "%s, %s\n", SSH_ਸੰਸਕਰਣ, SSH_OPENSSL_ਸੰਸਕਰਣ);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਸਥਿਰ ਖਾਲੀ
parse_hostkeys(ਬਣਤਰ sshbuf *hostkeys)
{
	ਪੂਰਨ r;
	u_int ਅੰਕ_ਕੁੰਜੀਆਂ = 0;
	ਬਣਤਰ sshkey *k;
	ਅਚਲ u_char *cp;
	ਮਾਪ_t len;

	ਜਦੋਂ (sshbuf_len(hostkeys) != 0) {
		ਜੇ (ਅੰਕ_ਕੁੰਜੀਆਂ > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    ਅੰਕ_ਕੁੰਜੀਆਂ, ਅੰਕ_ਕੁੰਜੀਆਂ + 1, ਆਕਾਰ(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    ਅੰਕ_ਕੁੰਜੀਆਂ, ਅੰਕ_ਕੁੰਜੀਆਂ + 1, ਆਕਾਰ(*host_certificates));
		/* public key */
		k = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ਜੇ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[ਅੰਕ_ਕੁੰਜੀਆਂ] = k;
		ਜੇ (k)
			debug2_f("key %u: %s", ਅੰਕ_ਕੁੰਜੀਆਂ, sshkey_ssh_name(k));
		/* certificate */
		k = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ਜੇ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[ਅੰਕ_ਕੁੰਜੀਆਂ] = k;
		ਜੇ (k)
			debug2_f("cert %u: %s", ਅੰਕ_ਕੁੰਜੀਆਂ, sshkey_ssh_name(k));
		ਅੰਕ_ਕੁੰਜੀਆਂ++;
	}
	ਅੰਕ_hostkeys = ਅੰਕ_ਕੁੰਜੀਆਂ;
}

ਸਥਿਰ ਖਾਲੀ
recv_privsep_state(ਬਣਤਰ ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	ਬਣਤਰ sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, ਨਿਰਾ, timing_secretp,
	    &hostkeys, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ ac, ਅੱਖਰ **av)
{
	ਬਣਤਰ ssh *ssh = ਨਿਰਾ;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਪੂਰਨ r, opt, have_ਕੁੰਜੀ = 0;
	ਪੂਰਨ sock_ਵਿੱਚ = -1, sock_ਬਾਹਰਲਾ = -1, rexeced_flag = 0;
	u_int i;
	ਬਹੁਲਕ_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ਨਿਰਾ);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SECUREWARE
	(ਖਾਲੀ)ਸੈੱਟ_auth_parameters(ac, av);
#ਜੇ_ਅੰਤ
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, ਆਕਾਰ(*saved_argv));
	ਲਈ (i = 0; (ਪੂਰਨ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ਨਿਰਾ;

	ਬੀਜ_rng();

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#ਜੇ_ਅੰਤ

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	ਜਦੋਂ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ਚੋਣ (opt) {
		ਹਾਲਤ '4':
			/* ignore */
			ਰੋਕੋ;
		ਹਾਲਤ '6':
			/* ignore */
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			/* ignore */
			ਰੋਕੋ;
		ਹਾਲਤ 'c':
			/* ignore */
			ਰੋਕੋ;
		ਹਾਲਤ 'd':
			ਜੇ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ਨਹੀਂਤਾਂ ਜੇ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
		ਹਾਲਤ 'E':
		ਹਾਲਤ 'e':
			/* ignore */
			ਰੋਕੋ;
		ਹਾਲਤ 'i':
			inetd_flag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'r':
			/* ignore */
			ਰੋਕੋ;
		ਹਾਲਤ 'R':
			rexeced_flag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'Q':
			/* ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			/* ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'b':
			/* protocol 1, ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			/* ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'g':
			/* ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'k':
			/* protocol 1, ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
			/* ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 't':
		ਹਾਲਤ 'T':
		ਹਾਲਤ 'G':
		ਹਾਲਤ 'C':
			fatal("test/dump modes not supported");
			ਰੋਕੋ;
		ਹਾਲਤ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ਨਿਰਾ);
			ਜੇ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'o':
			/* ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_ਸੰਸਕਰਣ, SSH_OPENSSL_ਸੰਸਕਰਣ);
			ਬਾਹਰ_ਨਿਕਲੋ(0);
		ਮੂਲ:
			usage();
			ਰੋਕੋ;
		}
	}

	ਜੇ (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_ਸੈੱਟ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_ਸੈੱਟ ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, ਆਕਾਰ(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	ਸੈੱਟ_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	ਜੇ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	/* Connection passed by stdin/out */
	ਜੇ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_ਵਿੱਚ = dup(STDIN_FILENO);
		sock_ਬਾਹਰਲਾ = dup(STDOUT_FILENO);
	} ਨਹੀਂਤਾਂ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_ਵਿੱਚ = sock_ਬਾਹਰਲਾ = dup(STDIN_FILENO);
	}

	ਜੇ (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_ਵਿੱਚ, sock_ਬਾਹਰਲਾ);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	ਜੇ ((ssh = ssh_packet_ਸੈੱਟ_connection(ਨਿਰਾ, sock_ਵਿੱਚ, sock_ਬਾਹਰਲਾ)) == ਨਿਰਾ)
		fatal("Unable to create connection");
	the_ਸਰਗਰਮ_state = ssh;
	ssh_packet_ਸੈੱਟ_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	ਜੇ ((cfg = sshbuf_new()) == ਨਿਰਾ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[session-auth early]");
	recv_privsep_state(ssh, &options, &timing_secret);
	options.timing_secret = timing_secret; /* XXX eliminate from unpriv */
	ssh_packet_ਸੈੱਟ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility, 1);
	ਸੈੱਟ_log_handler(mm_log_handler, pmonitor);

	debug("sshd-auth version %s, %s", SSH_ਸੰਸਕਰਣ, SSH_OPENSSL_ਸੰਸਕਰਣ);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ਜੇ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ਨਿਰਾ) {
		ਜੇ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ਨਹੀਂਤਾਂ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, ਲੜੀ_ਲੰਬਾਈ(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਜੇ (options.moduli_file != ਨਿਰਾ)
		dh_ਸੈੱਟ_moduli_file(options.moduli_file);
#ਜੇ_ਅੰਤ

	ਜੇ (options.host_ਕੁੰਜੀ_agent) {
		ਜੇ (strcmp(options.host_ਕੁੰਜੀ_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ਕੁੰਜੀ_agent, 1);
		ਜੇ ((r = ssh_get_authentication_socket(ਨਿਰਾ)) == 0)
			have_agent = 1;
		ਨਹੀਂਤਾਂ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ਕੁੰਜੀ_agent);
	}

	ਜੇ (options.ਅੰਕ_host_ਕੁੰਜੀ_files != ਅੰਕ_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.ਅੰਕ_host_ਕੁੰਜੀ_files, ਅੰਕ_hostkeys);
	}

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਜੇ (host_pubkeys[i] != ਨਿਰਾ) {
			have_ਕੁੰਜੀ = 1;
			ਰੋਕੋ;
		}
	}
	ਜੇ (!have_ਕੁੰਜੀ)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ਖਾਲੀ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	ਸੈੱਟ_log_handler(mm_log_handler, pmonitor);
	ਲਈ (i = 0; i < options.ਅੰਕ_log_verbose; i++)
		log_verbose_ਜੋੜੋ(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ਜੇ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_ਬਾਹਰਲਾ);
	FD_CLOSEONEXEC(sock_ਵਿੱਚ);

	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_ਸੈੱਟ_af(ssh, options.ਪਤਾ_family);
	channel_ਸੈੱਟ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	ssh_packet_ਸੈੱਟ_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, ਆਕਾਰ(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ਜੇ ((auth_opts = sshauthopt_new_with_ਕੁੰਜੀਆਂ_defaults()) == ਨਿਰਾ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ਜੇ ((loginmsg = sshbuf_new()) == ਨਿਰਾ)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#ਜੇ_ਅੰਤ

	privsep_ਬੱਚਾ_demote();

	/* perform the key exchange */
	/* authenticate user and start session */
	do_ssh2_kex(ssh);
	do_authentication2(ssh);

	/*
	 * The unprivileged child now transfers the current keystate and exits.
	 */
	mm_send_keystate(ssh, pmonitor);
	sshauthopt_free(auth_opts);
	ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);
	ਬਾਹਰ_ਨਿਕਲੋ(0);
}

ਪੂਰਨ
sshd_hostkey_sign(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshkey *privkey,
    ਬਣਤਰ sshkey *pubkey, u_char **signature, ਮਾਪ_t *slenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg)
{
	ਜੇ (privkey) {
		ਜੇ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    ਅੰਕੜੇ, dlen, alg, options.sk_provider, ਨਿਰਾ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ਨਹੀਂਤਾਂ {
		ਜੇ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    ਅੰਕੜੇ, dlen, alg, options.sk_provider, ਨਿਰਾ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ਵਾਪਸ 0;
}

/* SSH2 key exchange */
ਸਥਿਰ ਖਾਲੀ
do_ssh2_kex(ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ *hkalgs = ਨਿਰਾ, *myproposal[PROPOSAL_MAX];
	ਅਚਲ ਅੱਖਰ *compression = ਨਿਰਾ;
	ਬਣਤਰ kex *kex;
	ਪੂਰਨ r;

	ssh_packet_ਸੈੱਟ_rekey_limits(ssh, options.rekey_ਹੱਦਬੰਦੀ,
	    options.rekey_interval);

	ਜੇ (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	ਮੁਕਤ(hkalgs);

	ਜੇ ((r = kex_exchange_identification(ssh, -1,
	    options.ਸੰਸਕਰਣ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	ਜੇ ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	ਜੇ ((r = kex_ਤਿਆਰੀ(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_ਸੈੱਟ_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_ਸੈੱਟ_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#ਜੇ_ਅੰਤ
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->ਲੱਦੋ_host_ਜਨਤਕ_ਕੁੰਜੀ=&get_hostkey_ਜਨਤਕ_by_type;
	kex->ਲੱਦੋ_host_ਨਿੱਜੀ_ਕੁੰਜੀ=&get_hostkey_ਨਿੱਜੀ_by_type;
	kex->host_ਕੁੰਜੀ_ਸੂਚਕਾਂਕ=&get_hostkey_ਸੂਚਕਾਂਕ;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_ਲੜੀਵਾਰ_fatal(ssh, DISPATCH_ਖੰਡ, &kex->ਪੂਰਾ);
	kex_proposal_free_entries(myproposal);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#ਜੇ_ਅੰਤ
	debug("KEX done");
}

/* server specific fatal cleanup */
ਖਾਲੀ
cleanup_exit(ਪੂਰਨ i)
{
	_exit(i);
}
