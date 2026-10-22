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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <errno.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/rand.h>
#अन्तर्भाव <openssl/rsa.h>
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "ssherr.h"

बाह्य वर्ण *__progname;

स्थिर पूर्णाङ्क
valid_request(संरचना passwd *pw, वर्ण *host, संरचना sshkey **ret, वर्ण **pkalgp,
    u_char *data, size_t datalen)
{
	संरचना sshbuf *b;
	संरचना sshkey *कुञ्चिका = रिक्त;
	u_char type, *pkblob;
	वर्ण *p;
	size_t blen, len;
	वर्ण *pkalg, *luser;
	पूर्णाङ्क r, pktype, fail;

	सचे (ret != रिक्त)
		*ret = रिक्त;
	सचे (pkalgp != रिक्त)
		*pkalgp = रिक्त;
	fail = 0;

	सचे ((b = sshbuf_from(data, datalen)) == रिक्त)
		fatal_f("sshbuf_from failed");

	/* session id */
	सचे ((r = sshbuf_get_string(b, रिक्त, &len)) != 0)
		fatal_fr(r, "parse session ID");
	सचे (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	सचे ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	सचे (type != SSH2_सन्देशः_USERAUTH_REQUEST)
		fail++;

	/* server user */
	सचे ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	सचे ((r = sshbuf_get_cstring(b, &p, रिक्त)) != 0)
		fatal_fr(r, "parse service");
	सचे (strcmp("ssh-connection", p) != 0)
		fail++;
	मुक्त(p);

	/* method */
	सचे ((r = sshbuf_get_cstring(b, &p, रिक्त)) != 0)
		fatal_fr(r, "parse method");
	सचे (strcmp("hostbased", p) != 0)
		fail++;
	मुक्त(p);

	/* pubkey */
	सचे ((r = sshbuf_get_cstring(b, &pkalg, रिक्त)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	सचे (pktype == कुञ्चिका_UNSPEC)
		fail++;
	अञ्ञथा सचे ((r = sshkey_from_blob(pkblob, blen, &कुञ्चिका)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} अञ्ञथा सचे (कुञ्चिका->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	सचे ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	सचे (len == 0)
		fail++;
	अञ्ञथा सचे (strlen(host) != len - 1)
		fail++;
	अञ्ञथा सचे (p[len - 1] != '.')
		fail++;
	अञ्ञथा सचे (strncasecmp(host, p, len - 1) != 0)
		fail++;
	मुक्त(p);

	/* local user */
	सचे ((r = sshbuf_get_cstring(b, &luser, रिक्त)) != 0)
		fatal_fr(r, "parse luser");

	सचे (strcmp(pw->pw_name, luser) != 0)
		fail++;
	मुक्त(luser);

	/* end of message */
	सचे (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	सचे (!fail) {
		सचे (ret != रिक्त) {
			*ret = कुञ्चिका;
			कुञ्चिका = रिक्त;
		}
		सचे (pkalgp != रिक्त) {
			*pkalgp = pkalg;
			pkalg = रिक्त;
		}
	}
	sshkey_free(कुञ्चिका);
	मुक्त(pkalg);
	मुक्त(pkblob);

	पटिनिवत्त (fail ? -1 : 0);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	संरचना sshbuf *b;
	Options options;
#define अङ्कः_KEYTYPES 5
	संरचना sshkey *कुञ्चिकाः[अङ्कः_KEYTYPES], *कुञ्चिका = रिक्त;
	संरचना passwd *pw;
	पूर्णाङ्क r, कुञ्चिका_fd[अङ्कः_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	वर्ण *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	सचे ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	सचे (fd > 2)
		close(fd);

	सचे (pledge("stdio rpath getpw dns id", रिक्त) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	अत्थाय (i = 0; i < अङ्कः_KEYTYPES; i++)
		कुञ्चिका_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	कुञ्चिका_fd[i++] = open(PATH_HOST_ECDSA_कुञ्चिका_FILE, O_RDONLY);
	कुञ्चिका_fd[i++] = open(PATH_HOST_ED25519_कुञ्चिका_FILE, O_RDONLY);
	कुञ्चिका_fd[i++] = open(PATH_HOST_RSA_कुञ्चिका_FILE, O_RDONLY);
	कुञ्चिका_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_कुञ्चिका_FILE, O_RDONLY);

	सचे ((pw = getpwuid(getuid())) == रिक्त)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(शून्य)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, रिक्त);
	(शून्य)fill_default_options(&options);
	सचे (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	सचे (pledge("stdio dns", रिक्त) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	अत्थाय (i = found = 0; i < अङ्कः_KEYTYPES; i++) {
		सचे (कुञ्चिका_fd[i] != -1)
			found = 1;
	}
	सचे (found == 0)
		fatal("could not open any host key");

	found = 0;
	अत्थाय (i = 0; i < अङ्कः_KEYTYPES; i++) {
		कुञ्चिकाः[i] = रिक्त;
		सचे (कुञ्चिका_fd[i] == -1)
			अनुवर्त;
		r = sshkey_load_private_type_fd(कुञ्चिका_fd[i], कुञ्चिका_UNSPEC,
		    रिक्त, &कुञ्चिका, रिक्त);
		close(कुञ्चिका_fd[i]);
		सचे (r != 0)
			debug_r(r, "parse key %d", i);
		अञ्ञथा सचे (कुञ्चिका != रिक्त) {
			कुञ्चिकाः[i] = कुञ्चिका;
			found = 1;
		}
	}
	सचे (!found)
		fatal("no hostkey found");

	सचे ((b = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);
	सचे (ssh_सन्देशः_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	सचे ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	सचे (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	सचे ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	सचे (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	सचे ((host = get_local_name(fd)) == रिक्त)
		fatal("%s: cannot get local name for fd", __progname);

	सचे ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	सचे (valid_request(pw, host, &कुञ्चिका, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	मुक्त(host);

	found = 0;
	अत्थाय (i = 0; i < अङ्कः_KEYTYPES; i++) {
		सचे (कुञ्चिकाः[i] != रिक्त &&
		    sshkey_equal_public(कुञ्चिका, कुञ्चिकाः[i])) {
			found = 1;
			भङ्ग;
		}
	}
	सचे (!found) {
		सचे ((fp = sshkey_fingerprint(कुञ्चिका, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(कुञ्चिका), fp ? fp : "");
	}

	सचे ((r = sshkey_sign(कुञ्चिकाः[i], &signature, &slen, data, dlen,
	    pkalg, रिक्त, रिक्त, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	मुक्त(data);

	/* send reply */
	sshbuf_reset(b);
	सचे ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	सचे (ssh_सन्देशः_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	पटिनिवत्त (0);
}
