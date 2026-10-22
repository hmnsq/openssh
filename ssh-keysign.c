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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <errno.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/rand.h>
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಬಾಹ್ಯ ವರ್ಣ *__progname;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
valid_request(ಸಂರಚನಾ passwd *pw, ವರ್ಣ *host, ಸಂರಚನಾ sshkey **ret, ವರ್ಣ **pkalgp,
    u_char *data, size_t datalen)
{
	ಸಂರಚನಾ sshbuf *b;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	u_char type, *pkblob;
	ವರ್ಣ *p;
	size_t blen, len;
	ವರ್ಣ *pkalg, *luser;
	ಪೂರ್ಣಾಙ್ಕ r, pktype, fail;

	ಯದಿ (ret != ರಿಕ್ತ)
		*ret = ರಿಕ್ತ;
	ಯದಿ (pkalgp != ರಿಕ್ತ)
		*pkalgp = ರಿಕ್ತ;
	fail = 0;

	ಯದಿ ((b = sshbuf_from(data, datalen)) == ರಿಕ್ತ)
		fatal_f("sshbuf_from failed");

	/* session id */
	ಯದಿ ((r = sshbuf_get_string(b, ರಿಕ್ತ, &len)) != 0)
		fatal_fr(r, "parse session ID");
	ಯದಿ (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	ಯದಿ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ಯದಿ (type != SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)
		fail++;

	/* server user */
	ಯದಿ ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	ಯದಿ ((r = sshbuf_get_cstring(b, &p, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse service");
	ಯದಿ (strcmp("ssh-connection", p) != 0)
		fail++;
	ಮುಕ್ತ(p);

	/* method */
	ಯದಿ ((r = sshbuf_get_cstring(b, &p, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse method");
	ಯದಿ (strcmp("hostbased", p) != 0)
		fail++;
	ಮುಕ್ತ(p);

	/* pubkey */
	ಯದಿ ((r = sshbuf_get_cstring(b, &pkalg, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	ಯದಿ (pktype == ಕೀಲಿ_UNSPEC)
		fail++;
	ಅನ್ಯಥಾ ಯದಿ ((r = sshkey_from_blob(pkblob, blen, &ಕೀಲಿ)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} ಅನ್ಯಥಾ ಯದಿ (ಕೀಲಿ->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	ಯದಿ ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	ಯದಿ (len == 0)
		fail++;
	ಅನ್ಯಥಾ ಯದಿ (strlen(host) != len - 1)
		fail++;
	ಅನ್ಯಥಾ ಯದಿ (p[len - 1] != '.')
		fail++;
	ಅನ್ಯಥಾ ಯದಿ (strncasecmp(host, p, len - 1) != 0)
		fail++;
	ಮುಕ್ತ(p);

	/* local user */
	ಯದಿ ((r = sshbuf_get_cstring(b, &luser, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse luser");

	ಯದಿ (strcmp(pw->pw_name, luser) != 0)
		fail++;
	ಮುಕ್ತ(luser);

	/* end of message */
	ಯದಿ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	ಯದಿ (!fail) {
		ಯದಿ (ret != ರಿಕ್ತ) {
			*ret = ಕೀಲಿ;
			ಕೀಲಿ = ರಿಕ್ತ;
		}
		ಯದಿ (pkalgp != ರಿಕ್ತ) {
			*pkalgp = pkalg;
			pkalg = ರಿಕ್ತ;
		}
	}
	sshkey_free(ಕೀಲಿ);
	ಮುಕ್ತ(pkalg);
	ಮುಕ್ತ(pkblob);

	ಪ್ರತ್ಯಾಗಮ (fail ? -1 : 0);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಸಂರಚನಾ sshbuf *b;
	Options options;
#define ಅಂಕೆ_KEYTYPES 5
	ಸಂರಚನಾ sshkey *ಕೀಲಿಗಳು[ಅಂಕೆ_KEYTYPES], *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ passwd *pw;
	ಪೂರ್ಣಾಙ್ಕ r, ಕೀಲಿ_fd[ಅಂಕೆ_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	ವರ್ಣ *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	ಯದಿ ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	ಯದಿ (fd > 2)
		close(fd);

	ಯದಿ (pledge("stdio rpath getpw dns id", ರಿಕ್ತ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_KEYTYPES; i++)
		ಕೀಲಿ_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	ಕೀಲಿ_fd[i++] = open(PATH_HOST_ECDSA_ಕೀಲಿ_FILE, O_RDONLY);
	ಕೀಲಿ_fd[i++] = open(PATH_HOST_ED25519_ಕೀಲಿ_FILE, O_RDONLY);
	ಕೀಲಿ_fd[i++] = open(PATH_HOST_RSA_ಕೀಲಿ_FILE, O_RDONLY);
	ಕೀಲಿ_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE, O_RDONLY);

	ಯದಿ ((pw = getpwuid(getuid())) == ರಿಕ್ತ)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(ಶೂನ್ಯ)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, ರಿಕ್ತ);
	(ಶೂನ್ಯ)fill_default_options(&options);
	ಯದಿ (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	ಯದಿ (pledge("stdio dns", ರಿಕ್ತ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	ಪ್ರತಿ (i = found = 0; i < ಅಂಕೆ_KEYTYPES; i++) {
		ಯದಿ (ಕೀಲಿ_fd[i] != -1)
			found = 1;
	}
	ಯದಿ (found == 0)
		fatal("could not open any host key");

	found = 0;
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_KEYTYPES; i++) {
		ಕೀಲಿಗಳು[i] = ರಿಕ್ತ;
		ಯದಿ (ಕೀಲಿ_fd[i] == -1)
			ಅನುವರ್ತ;
		r = sshkey_load_private_type_fd(ಕೀಲಿ_fd[i], ಕೀಲಿ_UNSPEC,
		    ರಿಕ್ತ, &ಕೀಲಿ, ರಿಕ್ತ);
		close(ಕೀಲಿ_fd[i]);
		ಯದಿ (r != 0)
			debug_r(r, "parse key %d", i);
		ಅನ್ಯಥಾ ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ) {
			ಕೀಲಿಗಳು[i] = ಕೀಲಿ;
			found = 1;
		}
	}
	ಯದಿ (!found)
		fatal("no hostkey found");

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal("%s: sshbuf_new failed", __progname);
	ಯದಿ (ssh_ಸಂದೇಶ_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	ಯದಿ ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ಯದಿ (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	ಯದಿ ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ಯದಿ (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	ಯದಿ ((host = get_local_name(fd)) == ರಿಕ್ತ)
		fatal("%s: cannot get local name for fd", __progname);

	ಯದಿ ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ಯದಿ (valid_request(pw, host, &ಕೀಲಿ, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	ಮುಕ್ತ(host);

	found = 0;
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_KEYTYPES; i++) {
		ಯದಿ (ಕೀಲಿಗಳು[i] != ರಿಕ್ತ &&
		    sshkey_equal_public(ಕೀಲಿ, ಕೀಲಿಗಳು[i])) {
			found = 1;
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (!found) {
		ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(ಕೀಲಿ), fp ? fp : "");
	}

	ಯದಿ ((r = sshkey_sign(ಕೀಲಿಗಳು[i], &signature, &slen, data, dlen,
	    pkalg, ರಿಕ್ತ, ರಿಕ್ತ, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	ಮುಕ್ತ(data);

	/* send reply */
	sshbuf_reset(b);
	ಯದಿ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ಯದಿ (ssh_ಸಂದೇಶ_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	ಪ್ರತ್ಯಾಗಮ (0);
}
