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

#شامل "includes.h"

#شامل <fcntl.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <errno.h>

#ifdef WITH_OPENSSL
#شامل <openssl/evp.h>
#شامل <openssl/rand.h>
#شامل <openssl/rsa.h>
#شامل "openbsd-compat/openssl-compat.h"
#endif

#شامل "xmalloc.h"
#شامل "log.h"
#شامل "sshkey.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "authfile.h"
#شامل "msg.h"
#شامل "canohost.h"
#شامل "pathnames.h"
#شامل "readconf.h"
#شامل "uidswap.h"
#شامل "ssherr.h"

بیرونی نویسه *__progname;

ایستا صحیح
valid_request(ساختار passwd *pw, نویسه *host, ساختار sshkey **ret, نویسه **pkalgp,
    u_char *data, size_t datalen)
{
	ساختار sshbuf *b;
	ساختار sshkey *کلید = پوچ;
	u_char type, *pkblob;
	نویسه *p;
	size_t blen, len;
	نویسه *pkalg, *luser;
	صحیح r, pktype, fail;

	اگر (ret != پوچ)
		*ret = پوچ;
	اگر (pkalgp != پوچ)
		*pkalgp = پوچ;
	fail = 0;

	اگر ((b = sshbuf_from(data, datalen)) == پوچ)
		fatal_f("sshbuf_from failed");

	/* session id */
	اگر ((r = sshbuf_get_string(b, پوچ, &len)) != 0)
		fatal_fr(r, "parse session ID");
	اگر (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	اگر ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != SSH2_پیام_USERAUTH_REQUEST)
		fail++;

	/* server user */
	اگر ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	اگر ((r = sshbuf_get_cstring(b, &p, پوچ)) != 0)
		fatal_fr(r, "parse service");
	اگر (strcmp("ssh-connection", p) != 0)
		fail++;
	آزاد(p);

	/* method */
	اگر ((r = sshbuf_get_cstring(b, &p, پوچ)) != 0)
		fatal_fr(r, "parse method");
	اگر (strcmp("hostbased", p) != 0)
		fail++;
	آزاد(p);

	/* pubkey */
	اگر ((r = sshbuf_get_cstring(b, &pkalg, پوچ)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	اگر (pktype == کلید_UNSPEC)
		fail++;
	وگرنه اگر ((r = sshkey_from_blob(pkblob, blen, &کلید)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} وگرنه اگر (کلید->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	اگر ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	اگر (len == 0)
		fail++;
	وگرنه اگر (strlen(host) != len - 1)
		fail++;
	وگرنه اگر (p[len - 1] != '.')
		fail++;
	وگرنه اگر (strncasecmp(host, p, len - 1) != 0)
		fail++;
	آزاد(p);

	/* local user */
	اگر ((r = sshbuf_get_cstring(b, &luser, پوچ)) != 0)
		fatal_fr(r, "parse luser");

	اگر (strcmp(pw->pw_name, luser) != 0)
		fail++;
	آزاد(luser);

	/* end of message */
	اگر (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	اگر (!fail) {
		اگر (ret != پوچ) {
			*ret = کلید;
			کلید = پوچ;
		}
		اگر (pkalgp != پوچ) {
			*pkalgp = pkalg;
			pkalg = پوچ;
		}
	}
	sshkey_free(کلید);
	آزاد(pkalg);
	آزاد(pkblob);

	بازگشت (fail ? -1 : 0);
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	ساختار sshbuf *b;
	Options options;
#define رقم_KEYTYPES 5
	ساختار sshkey *کلیدها[رقم_KEYTYPES], *کلید = پوچ;
	ساختار passwd *pw;
	صحیح r, کلید_fd[رقم_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	نویسه *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	اگر ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	اگر (fd > 2)
		close(fd);

	اگر (pledge("stdio rpath getpw dns id", پوچ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	برای (i = 0; i < رقم_KEYTYPES; i++)
		کلید_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	کلید_fd[i++] = open(PATH_HOST_ECDSA_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(PATH_HOST_ED25519_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(PATH_HOST_RSA_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_کلید_FILE, O_RDONLY);

	اگر ((pw = getpwuid(getuid())) == پوچ)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(تهی)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, پوچ);
	(تهی)fill_default_options(&options);
	اگر (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	اگر (pledge("stdio dns", پوچ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	برای (i = found = 0; i < رقم_KEYTYPES; i++) {
		اگر (کلید_fd[i] != -1)
			found = 1;
	}
	اگر (found == 0)
		fatal("could not open any host key");

	found = 0;
	برای (i = 0; i < رقم_KEYTYPES; i++) {
		کلیدها[i] = پوچ;
		اگر (کلید_fd[i] == -1)
			ادامه;
		r = sshkey_load_private_type_fd(کلید_fd[i], کلید_UNSPEC,
		    پوچ, &کلید, پوچ);
		close(کلید_fd[i]);
		اگر (r != 0)
			debug_r(r, "parse key %d", i);
		وگرنه اگر (کلید != پوچ) {
			کلیدها[i] = کلید;
			found = 1;
		}
	}
	اگر (!found)
		fatal("no hostkey found");

	اگر ((b = sshbuf_new()) == پوچ)
		fatal("%s: sshbuf_new failed", __progname);
	اگر (ssh_پیام_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	اگر ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	اگر (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	اگر ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	اگر (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	اگر ((host = get_local_name(fd)) == پوچ)
		fatal("%s: cannot get local name for fd", __progname);

	اگر ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	اگر (valid_request(pw, host, &کلید, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	آزاد(host);

	found = 0;
	برای (i = 0; i < رقم_KEYTYPES; i++) {
		اگر (کلیدها[i] != پوچ &&
		    sshkey_equal_public(کلید, کلیدها[i])) {
			found = 1;
			بشکن;
		}
	}
	اگر (!found) {
		اگر ((fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == پوچ)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(کلید), fp ? fp : "");
	}

	اگر ((r = sshkey_sign(کلیدها[i], &signature, &slen, data, dlen,
	    pkalg, پوچ, پوچ, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	آزاد(data);

	/* send reply */
	sshbuf_reset(b);
	اگر ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	اگر (ssh_پیام_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	بازگشت (0);
}
