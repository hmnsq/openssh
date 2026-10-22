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

#ضمن "includes.h"

#ضمن <fcntl.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <errno.h>

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/evp.h>
#ضمن <openssl/rand.h>
#ضمن <openssl/rsa.h>
#ضمن "openbsd-compat/openssl-compat.h"
#جے_انت

#ضمن "xmalloc.h"
#ضمن "log.h"
#ضمن "sshkey.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "authfile.h"
#ضمن "msg.h"
#ضمن "canohost.h"
#ضمن "pathnames.h"
#ضمن "readconf.h"
#ضمن "uidswap.h"
#ضمن "ssherr.h"

خارجي حرف *__progname;

ساكن صحيح
valid_request(بنية passwd *pw, حرف *host, بنية sshkey **ret, حرف **pkalgp,
    u_char *انکڑے, ناپ_t datalen)
{
	بنية sshbuf *b;
	بنية sshkey *کلید = عدم;
	u_char type, *pkblob;
	حرف *p;
	ناپ_t blen, len;
	حرف *pkalg, *luser;
	صحيح r, pktype, fail;

	إذا (ret != عدم)
		*ret = عدم;
	إذا (pkalgp != عدم)
		*pkalgp = عدم;
	fail = 0;

	إذا ((b = sshbuf_from(انکڑے, datalen)) == عدم)
		fatal_f("sshbuf_from failed");

	/* session id */
	إذا ((r = sshbuf_get_string(b, عدم, &len)) != 0)
		fatal_fr(r, "parse session ID");
	إذا (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	إذا ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	إذا (type != SSH2_پیغام_USERAUTH_REQUEST)
		fail++;

	/* server user */
	إذا ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	إذا ((r = sshbuf_get_cstring(b, &p, عدم)) != 0)
		fatal_fr(r, "parse service");
	إذا (strcmp("ssh-connection", p) != 0)
		fail++;
	حرر(p);

	/*طریقہ*/
	إذا ((r = sshbuf_get_cstring(b, &p, عدم)) != 0)
		fatal_fr(r, "parse method");
	إذا (strcmp("hostbased", p) != 0)
		fail++;
	حرر(p);

	/* pubkey */
	إذا ((r = sshbuf_get_cstring(b, &pkalg, عدم)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	إذا (pktype == کلید_UNSPEC)
		fail++;
	وإلا إذا ((r = sshkey_from_blob(pkblob, blen, &کلید)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} وإلا إذا (کلید->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	إذا ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	إذا (len == 0)
		fail++;
	وإلا إذا (لڑی_لمبائی(host) != len - 1)
		fail++;
	وإلا إذا (p[len - 1] != '.')
		fail++;
	وإلا إذا (strncasecmp(host, p, len - 1) != 0)
		fail++;
	حرر(p);

	/* local user */
	إذا ((r = sshbuf_get_cstring(b, &luser, عدم)) != 0)
		fatal_fr(r, "parse luser");

	إذا (strcmp(pw->pw_name, luser) != 0)
		fail++;
	حرر(luser);

	/* end of message */
	إذا (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	إذا (!fail) {
		إذا (ret != عدم) {
			*ret = کلید;
			کلید = عدم;
		}
		إذا (pkalgp != عدم) {
			*pkalgp = pkalg;
			pkalg = عدم;
		}
	}
	sshkey_free(کلید);
	حرر(pkalg);
	حرر(pkblob);

	أرجع (fail ? -1 : 0);
}

صحيح
مکھ(صحيح argc, حرف **argv)
{
	بنية sshbuf *b;
	Options options;
#تعریف_کرو عدد_KEYTYPES 5
	بنية sshkey *کلیدیں[عدد_KEYTYPES], *کلید = عدم;
	بنية passwd *pw;
	صحيح r, کلید_fd[عدد_KEYTYPES], i, لبھیا, نسخہ = 2, fd;
	u_char *signature, *انکڑے, rver;
	حرف *host, *fp, *pkalg;
	ناپ_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	إذا ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		باہر_نکلو(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	إذا (fd > 2)
		close(fd);

	إذا (pledge("stdio rpath getpw dns id", عدم) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	لكل (i = 0; i < عدد_KEYTYPES; i++)
		کلید_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	کلید_fd[i++] = open(رستہ_HOST_ECDSA_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(رستہ_HOST_ED25519_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(رستہ_HOST_RSA_کلید_FILE, O_RDONLY);
	کلید_fd[i++] = open(رستہ_HOST_MLDSA44_ED25519_کلید_FILE, O_RDONLY);

	إذا ((pw = getpwuid(getuid())) == عدم)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_سیٹ_uid(pw);

	بیج_rng();

#جے_تعریف_شدہ DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#جے_انت

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(فراغ)read_config_file(رستہ_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, عدم);
	(فراغ)fill_default_options(&options);
	إذا (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    رستہ_HOST_CONFIG_FILE);

	إذا (pledge("stdio dns", عدم) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	لكل (i = لبھیا = 0; i < عدد_KEYTYPES; i++) {
		إذا (کلید_fd[i] != -1)
			لبھیا = 1;
	}
	إذا (لبھیا == 0)
		fatal("could not open any host key");

	لبھیا = 0;
	لكل (i = 0; i < عدد_KEYTYPES; i++) {
		کلیدیں[i] = عدم;
		إذا (کلید_fd[i] == -1)
			استمر;
		r = sshkey_لدو_نجی_type_fd(کلید_fd[i], کلید_UNSPEC,
		    عدم, &کلید, عدم);
		close(کلید_fd[i]);
		إذا (r != 0)
			debug_r(r, "parse key %d", i);
		وإلا إذا (کلید != عدم) {
			کلیدیں[i] = کلید;
			لبھیا = 1;
		}
	}
	إذا (!لبھیا)
		fatal("no hostkey found");

	إذا ((b = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);
	إذا (ssh_پیغام_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	إذا ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	إذا (rver != نسخہ)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, نسخہ);
	إذا ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	إذا (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	إذا ((host = get_local_name(fd)) == عدم)
		fatal("%s: cannot get local name for fd", __progname);

	إذا ((r = sshbuf_get_string(b, &انکڑے, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	إذا (valid_request(pw, host, &کلید, &pkalg, انکڑے, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	حرر(host);

	لبھیا = 0;
	لكل (i = 0; i < عدد_KEYTYPES; i++) {
		إذا (کلیدیں[i] != عدم &&
		    sshkey_equal_عوامی(کلید, کلیدیں[i])) {
			لبھیا = 1;
			اكسر;
		}
	}
	إذا (!لبھیا) {
		إذا ((fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == عدم)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(کلید), fp ? fp : "");
	}

	إذا ((r = sshkey_sign(کلیدیں[i], &signature, &slen, انکڑے, dlen,
	    pkalg, عدم, عدم, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	حرر(انکڑے);

	/* send reply */
	sshbuf_reset(b);
	إذا ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	إذا (ssh_پیغام_send(STDOUT_FILENO, نسخہ, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	أرجع (0);
}
