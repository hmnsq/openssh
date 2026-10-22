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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/evp.h>
#شامل <openssl/rand.h>
#شامل <openssl/rsa.h>
#شامل "openbsd-compat/openssl-compat.h"
#اگر_ختم

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

خارجی حرف *__progname;

ساکن صحیح
valid_request(ساخت passwd *pw, حرف *host, ساخت sshkey **ret, حرف **pkalgp,
    u_char *ڈیٹا, سائز_t datalen)
{
	ساخت sshbuf *b;
	ساخت sshkey *کلید = تہی;
	u_char type, *pkblob;
	حرف *p;
	سائز_t blen, len;
	حرف *pkalg, *luser;
	صحیح r, pktype, fail;

	اگر (ret != تہی)
		*ret = تہی;
	اگر (pkalgp != تہی)
		*pkalgp = تہی;
	fail = 0;

	اگر ((b = sshbuf_from(ڈیٹا, datalen)) == تہی)
		fatal_f("sshbuf_from failed");

	/* session id */
	اگر ((r = sshbuf_get_string(b, تہی, &len)) != 0)
		fatal_fr(r, "parse session ID");
	اگر (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	اگر ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != SSH2_پیغام_USERAUTH_REQUEST)
		fail++;

	/* server user */
	اگر ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	اگر ((r = sshbuf_get_cstring(b, &p, تہی)) != 0)
		fatal_fr(r, "parse service");
	اگر (strcmp("ssh-connection", p) != 0)
		fail++;
	آزاد(p);

	/*طریقہ*/
	اگر ((r = sshbuf_get_cstring(b, &p, تہی)) != 0)
		fatal_fr(r, "parse method");
	اگر (strcmp("hostbased", p) != 0)
		fail++;
	آزاد(p);

	/* pubkey */
	اگر ((r = sshbuf_get_cstring(b, &pkalg, تہی)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	اگر (pktype == کلید_UNSPEC)
		fail++;
	ورنہ اگر ((r = sshkey_from_blob(pkblob, blen, &کلید)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} ورنہ اگر (کلید->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	اگر ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	اگر (len == 0)
		fail++;
	ورنہ اگر (لڑی_لمبائی(host) != len - 1)
		fail++;
	ورنہ اگر (p[len - 1] != '.')
		fail++;
	ورنہ اگر (strncasecmp(host, p, len - 1) != 0)
		fail++;
	آزاد(p);

	/* local user */
	اگر ((r = sshbuf_get_cstring(b, &luser, تہی)) != 0)
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
		اگر (ret != تہی) {
			*ret = کلید;
			کلید = تہی;
		}
		اگر (pkalgp != تہی) {
			*pkalgp = pkalg;
			pkalg = تہی;
		}
	}
	sshkey_free(کلید);
	آزاد(pkalg);
	آزاد(pkblob);

	واپس (fail ? -1 : 0);
}

صحیح
مین(صحیح argc, حرف **argv)
{
	ساخت sshbuf *b;
	Options options;
#تعریف_کرو عدد_KEYTYPES 5
	ساخت sshkey *کلیدیں[عدد_KEYTYPES], *کلید = تہی;
	ساخت passwd *pw;
	صحیح r, کلید_fd[عدد_KEYTYPES], i, ملا, نسخہ = 2, fd;
	u_char *signature, *ڈیٹا, rver;
	حرف *host, *fp, *pkalg;
	سائز_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	اگر ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		باہر_نکلو(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	اگر (fd > 2)
		close(fd);

	اگر (pledge("stdio rpath getpw dns id", تہی) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	برائے (i = 0; i < عدد_KEYTYPES; i++)
		کلید_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	کلید_fd[i++] = open(راستہ_HOST_ECDSA_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(راستہ_HOST_ED25519_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(راستہ_HOST_RSA_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(راستہ_HOST_MLDSA44_ED25519_کلید_FILE, O_RDONLY);

	اگر ((pw = getpwuid(getuid())) == تہی)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_سیٹ_uid(pw);

	بیج_rng();

#اگر_تعریف_شدہ DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#اگر_ختم

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(خالی)read_config_file(راستہ_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, تہی);
	(خالی)fill_default_options(&options);
	اگر (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    راستہ_HOST_CONFIG_FILE);

	اگر (pledge("stdio dns", تہی) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	برائے (i = ملا = 0; i < عدد_KEYTYPES; i++) {
		اگر (کلید_fd[i] != -1)
			ملا = 1;
	}
	اگر (ملا == 0)
		fatal("could not open any host key");

	ملا = 0;
	برائے (i = 0; i < عدد_KEYTYPES; i++) {
		کلیدیں[i] = تہی;
		اگر (کلید_fd[i] == -1)
			جاری;
		r = sshkey_بھرو_نجی_type_fd(کلید_fd[i], کلید_UNSPEC,
		    تہی, &کلید, تہی);
		close(کلید_fd[i]);
		اگر (r != 0)
			debug_r(r, "parse key %d", i);
		ورنہ اگر (کلید != تہی) {
			کلیدیں[i] = کلید;
			ملا = 1;
		}
	}
	اگر (!ملا)
		fatal("no hostkey found");

	اگر ((b = sshbuf_new()) == تہی)
		fatal("%s: sshbuf_new failed", __progname);
	اگر (ssh_پیغام_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	اگر ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	اگر (rver != نسخہ)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, نسخہ);
	اگر ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	اگر (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	اگر ((host = get_local_name(fd)) == تہی)
		fatal("%s: cannot get local name for fd", __progname);

	اگر ((r = sshbuf_get_string(b, &ڈیٹا, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	اگر (valid_request(pw, host, &کلید, &pkalg, ڈیٹا, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	آزاد(host);

	ملا = 0;
	برائے (i = 0; i < عدد_KEYTYPES; i++) {
		اگر (کلیدیں[i] != تہی &&
		    sshkey_equal_عوامی(کلید, کلیدیں[i])) {
			ملا = 1;
			توڑو;
		}
	}
	اگر (!ملا) {
		اگر ((fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == تہی)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(کلید), fp ? fp : "");
	}

	اگر ((r = sshkey_sign(کلیدیں[i], &signature, &slen, ڈیٹا, dlen,
	    pkalg, تہی, تہی, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	آزاد(ڈیٹا);

	/* send reply */
	sshbuf_reset(b);
	اگر ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	اگر (ssh_پیغام_send(STDOUT_FILENO, نسخہ, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	واپس (0);
}
