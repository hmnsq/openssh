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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/rand.h>
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಆದರೆ_ಅಂತ್ಯ

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

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
valid_request(ರಚನೆ passwd *pw, ಅಕ್ಷರ *host, ರಚನೆ sshkey **ret, ಅಕ್ಷರ **pkalgp,
    u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen)
{
	ರಚನೆ sshbuf *b;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	u_char type, *pkblob;
	ಅಕ್ಷರ *p;
	ಗಾತ್ರ_t blen, len;
	ಅಕ್ಷರ *pkalg, *luser;
	ಪೂರ್ಣಾಂಕ r, pktype, fail;

	ಆದರೆ (ret != ಖಾಲಿ)
		*ret = ಖಾಲಿ;
	ಆದರೆ (pkalgp != ಖಾಲಿ)
		*pkalgp = ಖಾಲಿ;
	fail = 0;

	ಆದರೆ ((b = sshbuf_from(ದತ್ತಾಂಶ, datalen)) == ಖಾಲಿ)
		fatal_f("sshbuf_from failed");

	/* session id */
	ಆದರೆ ((r = sshbuf_get_string(b, ಖಾಲಿ, &len)) != 0)
		fatal_fr(r, "parse session ID");
	ಆದರೆ (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	ಆದರೆ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ಆದರೆ (type != SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)
		fail++;

	/* server user */
	ಆದರೆ ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	ಆದರೆ ((r = sshbuf_get_cstring(b, &p, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse service");
	ಆದರೆ (strcmp("ssh-connection", p) != 0)
		fail++;
	ಬಿಡುಗಡೆ(p);

	/*ವಿಧಾನ*/
	ಆದರೆ ((r = sshbuf_get_cstring(b, &p, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse method");
	ಆದರೆ (strcmp("hostbased", p) != 0)
		fail++;
	ಬಿಡುಗಡೆ(p);

	/* pubkey */
	ಆದರೆ ((r = sshbuf_get_cstring(b, &pkalg, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	ಆದರೆ (pktype == ಕೀಲಿ_UNSPEC)
		fail++;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshkey_from_blob(pkblob, blen, &ಕೀಲಿ)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಕೀಲಿ->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	ಆದರೆ ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	ಆದರೆ (len == 0)
		fail++;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host) != len - 1)
		fail++;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (p[len - 1] != '.')
		fail++;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strncasecmp(host, p, len - 1) != 0)
		fail++;
	ಬಿಡುಗಡೆ(p);

	/* local user */
	ಆದರೆ ((r = sshbuf_get_cstring(b, &luser, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse luser");

	ಆದರೆ (strcmp(pw->pw_name, luser) != 0)
		fail++;
	ಬಿಡುಗಡೆ(luser);

	/* end of message */
	ಆದರೆ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	ಆದರೆ (!fail) {
		ಆದರೆ (ret != ಖಾಲಿ) {
			*ret = ಕೀಲಿ;
			ಕೀಲಿ = ಖಾಲಿ;
		}
		ಆದರೆ (pkalgp != ಖಾಲಿ) {
			*pkalgp = pkalg;
			pkalg = ಖಾಲಿ;
		}
	}
	sshkey_free(ಕೀಲಿ);
	ಬಿಡುಗಡೆ(pkalg);
	ಬಿಡುಗಡೆ(pkblob);

	ಹಿಂತಿರುಗಿ (fail ? -1 : 0);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ರಚನೆ sshbuf *b;
	Options options;
#ವ್ಯಾಖ್ಯಾನಿಸು ಅಂಕೆ_KEYTYPES 5
	ರಚನೆ sshkey *ಕೀಲಿಗಳು[ಅಂಕೆ_KEYTYPES], *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ passwd *pw;
	ಪೂರ್ಣಾಂಕ r, ಕೀಲಿ_fd[ಅಂಕೆ_KEYTYPES], i, ಸಿಕ್ಕಿತು, ಆವೃತ್ತಿ = 2, fd;
	u_char *signature, *ದತ್ತಾಂಶ, rver;
	ಅಕ್ಷರ *host, *fp, *pkalg;
	ಗಾತ್ರ_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	ಆದರೆ ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		ನಿರ್ಗಮಿಸು(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	ಆದರೆ (fd > 2)
		close(fd);

	ಆದರೆ (pledge("stdio rpath getpw dns id", ಖಾಲಿ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_KEYTYPES; i++)
		ಕೀಲಿ_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	ಕೀಲಿ_fd[i++] = open(ಮಾರ್ಗ_HOST_ECDSA_ಕೀಲಿ_FILE, O_RDONLY);
	ಕೀಲಿ_fd[i++] = open(ಮಾರ್ಗ_HOST_ED25519_ಕೀಲಿ_FILE, O_RDONLY);
	ಕೀಲಿ_fd[i++] = open(ಮಾರ್ಗ_HOST_RSA_ಕೀಲಿ_FILE, O_RDONLY);
	ಕೀಲಿ_fd[i++] = open(ಮಾರ್ಗ_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE, O_RDONLY);

	ಆದರೆ ((pw = getpwuid(getuid())) == ಖಾಲಿ)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_ಗಣ_uid(pw);

	ಬೀಜ_rng();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#ಆದರೆ_ಅಂತ್ಯ

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(ಶೂನ್ಯ)read_config_file(ಮಾರ್ಗ_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, ಖಾಲಿ);
	(ಶೂನ್ಯ)fill_default_options(&options);
	ಆದರೆ (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    ಮಾರ್ಗ_HOST_CONFIG_FILE);

	ಆದರೆ (pledge("stdio dns", ಖಾಲಿ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	ಗಾಗಿ (i = ಸಿಕ್ಕಿತು = 0; i < ಅಂಕೆ_KEYTYPES; i++) {
		ಆದರೆ (ಕೀಲಿ_fd[i] != -1)
			ಸಿಕ್ಕಿತು = 1;
	}
	ಆದರೆ (ಸಿಕ್ಕಿತು == 0)
		fatal("could not open any host key");

	ಸಿಕ್ಕಿತು = 0;
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_KEYTYPES; i++) {
		ಕೀಲಿಗಳು[i] = ಖಾಲಿ;
		ಆದರೆ (ಕೀಲಿ_fd[i] == -1)
			ಮುಂದುವರಿ;
		r = sshkey_ತುಂಬು_ಖಾಸಗಿ_type_fd(ಕೀಲಿ_fd[i], ಕೀಲಿ_UNSPEC,
		    ಖಾಲಿ, &ಕೀಲಿ, ಖಾಲಿ);
		close(ಕೀಲಿ_fd[i]);
		ಆದರೆ (r != 0)
			debug_r(r, "parse key %d", i);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ) {
			ಕೀಲಿಗಳು[i] = ಕೀಲಿ;
			ಸಿಕ್ಕಿತು = 1;
		}
	}
	ಆದರೆ (!ಸಿಕ್ಕಿತು)
		fatal("no hostkey found");

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal("%s: sshbuf_new failed", __progname);
	ಆದರೆ (ssh_ಸಂದೇಶ_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	ಆದರೆ ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ಆದರೆ (rver != ಆವೃತ್ತಿ)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, ಆವೃತ್ತಿ);
	ಆದರೆ ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ಆದರೆ (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	ಆದರೆ ((host = get_local_name(fd)) == ಖಾಲಿ)
		fatal("%s: cannot get local name for fd", __progname);

	ಆದರೆ ((r = sshbuf_get_string(b, &ದತ್ತಾಂಶ, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ಆದರೆ (valid_request(pw, host, &ಕೀಲಿ, &pkalg, ದತ್ತಾಂಶ, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	ಬಿಡುಗಡೆ(host);

	ಸಿಕ್ಕಿತು = 0;
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_KEYTYPES; i++) {
		ಆದರೆ (ಕೀಲಿಗಳು[i] != ಖಾಲಿ &&
		    sshkey_equal_ಬಹಿರಂಗ(ಕೀಲಿ, ಕೀಲಿಗಳು[i])) {
			ಸಿಕ್ಕಿತು = 1;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (!ಸಿಕ್ಕಿತು) {
		ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(ಕೀಲಿ), fp ? fp : "");
	}

	ಆದರೆ ((r = sshkey_sign(ಕೀಲಿಗಳು[i], &signature, &slen, ದತ್ತಾಂಶ, dlen,
	    pkalg, ಖಾಲಿ, ಖಾಲಿ, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	ಬಿಡುಗಡೆ(ದತ್ತಾಂಶ);

	/* send reply */
	sshbuf_reset(b);
	ಆದರೆ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ಆದರೆ (ssh_ಸಂದೇಶ_send(STDOUT_FILENO, ಆವೃತ್ತಿ, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	ಹಿಂತಿರುಗಿ (0);
}
