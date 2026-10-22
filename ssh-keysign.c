/* $OpenBSD: ssh-keysign.c,v 1.81 2026/06/14 03:59:34 djm Exp $ */
/*
 * Copyright (c) 2002 Markus Friedl.  All rights reserved.
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

#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rand.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਬਾਹਰੀ ਅੱਖਰ *__progname;

ਸਥਿਰ ਪੂਰਨ
valid_request(ਬਣਤਰ passwd *pw, ਅੱਖਰ *host, ਬਣਤਰ sshkey **ret, ਅੱਖਰ **pkalgp,
    u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen)
{
	ਬਣਤਰ sshbuf *b;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	u_char type, *pkblob;
	ਅੱਖਰ *p;
	ਮਾਪ_t blen, len;
	ਅੱਖਰ *pkalg, *luser;
	ਪੂਰਨ r, pktype, fail;

	ਜੇ (ret != ਨਿਰਾ)
		*ret = ਨਿਰਾ;
	ਜੇ (pkalgp != ਨਿਰਾ)
		*pkalgp = ਨਿਰਾ;
	fail = 0;

	ਜੇ ((b = sshbuf_from(ਅੰਕੜੇ, datalen)) == ਨਿਰਾ)
		fatal_f("sshbuf_from failed");

	/* session id */
	ਜੇ ((r = sshbuf_get_string(b, ਨਿਰਾ, &len)) != 0)
		fatal_fr(r, "parse session ID");
	ਜੇ (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	ਜੇ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ਜੇ (type != SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)
		fail++;

	/* server user */
	ਜੇ ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	ਜੇ ((r = sshbuf_get_cstring(b, &p, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse service");
	ਜੇ (strcmp("ssh-connection", p) != 0)
		fail++;
	ਮੁਕਤ(p);

	/*ਵਿਧੀ*/
	ਜੇ ((r = sshbuf_get_cstring(b, &p, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse method");
	ਜੇ (strcmp("hostbased", p) != 0)
		fail++;
	ਮੁਕਤ(p);

	/* pubkey */
	ਜੇ ((r = sshbuf_get_cstring(b, &pkalg, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	ਜੇ (pktype == ਕੁੰਜੀ_UNSPEC)
		fail++;
	ਨਹੀਂਤਾਂ ਜੇ ((r = sshkey_from_blob(pkblob, blen, &ਕੁੰਜੀ)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} ਨਹੀਂਤਾਂ ਜੇ (ਕੁੰਜੀ->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	ਜੇ ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	ਜੇ (len == 0)
		fail++;
	ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਲੰਬਾਈ(host) != len - 1)
		fail++;
	ਨਹੀਂਤਾਂ ਜੇ (p[len - 1] != '.')
		fail++;
	ਨਹੀਂਤਾਂ ਜੇ (strncasecmp(host, p, len - 1) != 0)
		fail++;
	ਮੁਕਤ(p);

	/* local user */
	ਜੇ ((r = sshbuf_get_cstring(b, &luser, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse luser");

	ਜੇ (strcmp(pw->pw_name, luser) != 0)
		fail++;
	ਮੁਕਤ(luser);

	/* end of message */
	ਜੇ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	ਜੇ (!fail) {
		ਜੇ (ret != ਨਿਰਾ) {
			*ret = ਕੁੰਜੀ;
			ਕੁੰਜੀ = ਨਿਰਾ;
		}
		ਜੇ (pkalgp != ਨਿਰਾ) {
			*pkalgp = pkalg;
			pkalg = ਨਿਰਾ;
		}
	}
	sshkey_free(ਕੁੰਜੀ);
	ਮੁਕਤ(pkalg);
	ਮੁਕਤ(pkblob);

	ਵਾਪਸ (fail ? -1 : 0);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਬਣਤਰ sshbuf *b;
	Options options;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਅੰਕ_KEYTYPES 5
	ਬਣਤਰ sshkey *ਕੁੰਜੀਆਂ[ਅੰਕ_KEYTYPES], *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ passwd *pw;
	ਪੂਰਨ r, ਕੁੰਜੀ_fd[ਅੰਕ_KEYTYPES], i, ਮਿਲਿਆ, ਸੰਸਕਰਣ = 2, fd;
	u_char *signature, *ਅੰਕੜੇ, rver;
	ਅੱਖਰ *host, *fp, *pkalg;
	ਮਾਪ_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	ਜੇ ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	ਜੇ (fd > 2)
		close(fd);

	ਜੇ (pledge("stdio rpath getpw dns id", ਨਿਰਾ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	ਲਈ (i = 0; i < ਅੰਕ_KEYTYPES; i++)
		ਕੁੰਜੀ_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	ਕੁੰਜੀ_fd[i++] = open(ਰਸਤਾ_HOST_ECDSA_ਕੁੰਜੀ_FILE, O_RDONLY);
	ਕੁੰਜੀ_fd[i++] = open(ਰਸਤਾ_HOST_ED25519_ਕੁੰਜੀ_FILE, O_RDONLY);
	ਕੁੰਜੀ_fd[i++] = open(ਰਸਤਾ_HOST_RSA_ਕੁੰਜੀ_FILE, O_RDONLY);
	ਕੁੰਜੀ_fd[i++] = open(ਰਸਤਾ_HOST_MLDSA44_ED25519_ਕੁੰਜੀ_FILE, O_RDONLY);

	ਜੇ ((pw = getpwuid(getuid())) == ਨਿਰਾ)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_ਸੈੱਟ_uid(pw);

	ਬੀਜ_rng();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#ਜੇ_ਅੰਤ

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(ਖਾਲੀ)read_config_file(ਰਸਤਾ_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, ਨਿਰਾ);
	(ਖਾਲੀ)fill_default_options(&options);
	ਜੇ (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    ਰਸਤਾ_HOST_CONFIG_FILE);

	ਜੇ (pledge("stdio dns", ਨਿਰਾ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	ਲਈ (i = ਮਿਲਿਆ = 0; i < ਅੰਕ_KEYTYPES; i++) {
		ਜੇ (ਕੁੰਜੀ_fd[i] != -1)
			ਮਿਲਿਆ = 1;
	}
	ਜੇ (ਮਿਲਿਆ == 0)
		fatal("could not open any host key");

	ਮਿਲਿਆ = 0;
	ਲਈ (i = 0; i < ਅੰਕ_KEYTYPES; i++) {
		ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;
		ਜੇ (ਕੁੰਜੀ_fd[i] == -1)
			ਜਾਰੀ;
		r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type_fd(ਕੁੰਜੀ_fd[i], ਕੁੰਜੀ_UNSPEC,
		    ਨਿਰਾ, &ਕੁੰਜੀ, ਨਿਰਾ);
		close(ਕੁੰਜੀ_fd[i]);
		ਜੇ (r != 0)
			debug_r(r, "parse key %d", i);
		ਨਹੀਂਤਾਂ ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ) {
			ਕੁੰਜੀਆਂ[i] = ਕੁੰਜੀ;
			ਮਿਲਿਆ = 1;
		}
	}
	ਜੇ (!ਮਿਲਿਆ)
		fatal("no hostkey found");

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal("%s: sshbuf_new failed", __progname);
	ਜੇ (ssh_ਸੁਨੇਹਾ_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	ਜੇ ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ਜੇ (rver != ਸੰਸਕਰਣ)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, ਸੰਸਕਰਣ);
	ਜੇ ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ਜੇ (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	ਜੇ ((host = get_local_name(fd)) == ਨਿਰਾ)
		fatal("%s: cannot get local name for fd", __progname);

	ਜੇ ((r = sshbuf_get_string(b, &ਅੰਕੜੇ, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ਜੇ (valid_request(pw, host, &ਕੁੰਜੀ, &pkalg, ਅੰਕੜੇ, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	ਮੁਕਤ(host);

	ਮਿਲਿਆ = 0;
	ਲਈ (i = 0; i < ਅੰਕ_KEYTYPES; i++) {
		ਜੇ (ਕੁੰਜੀਆਂ[i] != ਨਿਰਾ &&
		    sshkey_equal_ਜਨਤਕ(ਕੁੰਜੀ, ਕੁੰਜੀਆਂ[i])) {
			ਮਿਲਿਆ = 1;
			ਰੋਕੋ;
		}
	}
	ਜੇ (!ਮਿਲਿਆ) {
		ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(ਕੁੰਜੀ), fp ? fp : "");
	}

	ਜੇ ((r = sshkey_sign(ਕੁੰਜੀਆਂ[i], &signature, &slen, ਅੰਕੜੇ, dlen,
	    pkalg, ਨਿਰਾ, ਨਿਰਾ, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	ਮੁਕਤ(ਅੰਕੜੇ);

	/* send reply */
	sshbuf_reset(b);
	ਜੇ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ਜੇ (ssh_ਸੁਨੇਹਾ_send(STDOUT_FILENO, ਸੰਸਕਰਣ, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	ਵਾਪਸ (0);
}
