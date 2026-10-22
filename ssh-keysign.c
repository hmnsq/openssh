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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <errno.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <openssl/rand.h>
#అన్తర్భావ <openssl/rsa.h>
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "readconf.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "ssherr.h"

బాహ్య అక్షరం *__progname;

స్థిర పూర్ణాంకం
valid_request(నిర్మాణం passwd *pw, అక్షరం *host, నిర్మాణం sshkey **ret, అక్షరం **pkalgp,
    u_char *దత్తాంశం, కొలత_t datalen)
{
	నిర్మాణం sshbuf *b;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	u_char type, *pkblob;
	అక్షరం *p;
	కొలత_t blen, len;
	అక్షరం *pkalg, *luser;
	పూర్ణాంకం r, pktype, fail;

	ఒకవేళ (ret != ఖాళీ)
		*ret = ఖాళీ;
	ఒకవేళ (pkalgp != ఖాళీ)
		*pkalgp = ఖాళీ;
	fail = 0;

	ఒకవేళ ((b = sshbuf_from(దత్తాంశం, datalen)) == ఖాళీ)
		fatal_f("sshbuf_from failed");

	/* session id */
	ఒకవేళ ((r = sshbuf_get_string(b, ఖాళీ, &len)) != 0)
		fatal_fr(r, "parse session ID");
	ఒకవేళ (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	ఒకవేళ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ఒకవేళ (type != SSH2_సందేశం_USERAUTH_REQUEST)
		fail++;

	/* server user */
	ఒకవేళ ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	ఒకవేళ ((r = sshbuf_get_cstring(b, &p, ఖాళీ)) != 0)
		fatal_fr(r, "parse service");
	ఒకవేళ (strcmp("ssh-connection", p) != 0)
		fail++;
	విడుదల(p);

	/*పద్ధతి*/
	ఒకవేళ ((r = sshbuf_get_cstring(b, &p, ఖాళీ)) != 0)
		fatal_fr(r, "parse method");
	ఒకవేళ (strcmp("hostbased", p) != 0)
		fail++;
	విడుదల(p);

	/* pubkey */
	ఒకవేళ ((r = sshbuf_get_cstring(b, &pkalg, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	ఒకవేళ (pktype == కీలకం_UNSPEC)
		fail++;
	లేకపోతే ఒకవేళ ((r = sshkey_from_blob(pkblob, blen, &కీలకం)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} లేకపోతే ఒకవేళ (కీలకం->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	ఒకవేళ ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	ఒకవేళ (len == 0)
		fail++;
	లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పొడవు(host) != len - 1)
		fail++;
	లేకపోతే ఒకవేళ (p[len - 1] != '.')
		fail++;
	లేకపోతే ఒకవేళ (strncasecmp(host, p, len - 1) != 0)
		fail++;
	విడుదల(p);

	/* local user */
	ఒకవేళ ((r = sshbuf_get_cstring(b, &luser, ఖాళీ)) != 0)
		fatal_fr(r, "parse luser");

	ఒకవేళ (strcmp(pw->pw_name, luser) != 0)
		fail++;
	విడుదల(luser);

	/* end of message */
	ఒకవేళ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	ఒకవేళ (!fail) {
		ఒకవేళ (ret != ఖాళీ) {
			*ret = కీలకం;
			కీలకం = ఖాళీ;
		}
		ఒకవేళ (pkalgp != ఖాళీ) {
			*pkalgp = pkalg;
			pkalg = ఖాళీ;
		}
	}
	sshkey_free(కీలకం);
	విడుదల(pkalg);
	విడుదల(pkblob);

	తిరిగి (fail ? -1 : 0);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	నిర్మాణం sshbuf *b;
	Options options;
#నిర్వచించు అంకె_KEYTYPES 5
	నిర్మాణం sshkey *కీలకాలు[అంకె_KEYTYPES], *కీలకం = ఖాళీ;
	నిర్మాణం passwd *pw;
	పూర్ణాంకం r, కీలకం_fd[అంకె_KEYTYPES], i, దొరికింది, సంస్కరణ = 2, fd;
	u_char *signature, *దత్తాంశం, rver;
	అక్షరం *host, *fp, *pkalg;
	కొలత_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	ఒకవేళ ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		నిష్క్రమించు(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	ఒకవేళ (fd > 2)
		close(fd);

	ఒకవేళ (pledge("stdio rpath getpw dns id", ఖాళీ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	కొరకు (i = 0; i < అంకె_KEYTYPES; i++)
		కీలకం_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	కీలకం_fd[i++] = open(మార్గం_HOST_ECDSA_కీలకం_FILE, O_RDONLY);
	కీలకం_fd[i++] = open(మార్గం_HOST_ED25519_కీలకం_FILE, O_RDONLY);
	కీలకం_fd[i++] = open(మార్గం_HOST_RSA_కీలకం_FILE, O_RDONLY);
	కీలకం_fd[i++] = open(మార్గం_HOST_MLDSA44_ED25519_కీలకం_FILE, O_RDONLY);

	ఒకవేళ ((pw = getpwuid(getuid())) == ఖాళీ)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_సమితి_uid(pw);

	విత్తనం_rng();

#నిర్వచితమైతే DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#అయితే_ముగింపు

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(శూన్య)read_config_file(మార్గం_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, ఖాళీ);
	(శూన్య)fill_default_options(&options);
	ఒకవేళ (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    మార్గం_HOST_CONFIG_FILE);

	ఒకవేళ (pledge("stdio dns", ఖాళీ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	కొరకు (i = దొరికింది = 0; i < అంకె_KEYTYPES; i++) {
		ఒకవేళ (కీలకం_fd[i] != -1)
			దొరికింది = 1;
	}
	ఒకవేళ (దొరికింది == 0)
		fatal("could not open any host key");

	దొరికింది = 0;
	కొరకు (i = 0; i < అంకె_KEYTYPES; i++) {
		కీలకాలు[i] = ఖాళీ;
		ఒకవేళ (కీలకం_fd[i] == -1)
			కొనసాగు;
		r = sshkey_ఎక్కించు_వ్యక్తిగత_type_fd(కీలకం_fd[i], కీలకం_UNSPEC,
		    ఖాళీ, &కీలకం, ఖాళీ);
		close(కీలకం_fd[i]);
		ఒకవేళ (r != 0)
			debug_r(r, "parse key %d", i);
		లేకపోతే ఒకవేళ (కీలకం != ఖాళీ) {
			కీలకాలు[i] = కీలకం;
			దొరికింది = 1;
		}
	}
	ఒకవేళ (!దొరికింది)
		fatal("no hostkey found");

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal("%s: sshbuf_new failed", __progname);
	ఒకవేళ (ssh_సందేశం_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	ఒకవేళ ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ఒకవేళ (rver != సంస్కరణ)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, సంస్కరణ);
	ఒకవేళ ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ఒకవేళ (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	ఒకవేళ ((host = get_local_name(fd)) == ఖాళీ)
		fatal("%s: cannot get local name for fd", __progname);

	ఒకవేళ ((r = sshbuf_get_string(b, &దత్తాంశం, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ఒకవేళ (valid_request(pw, host, &కీలకం, &pkalg, దత్తాంశం, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	విడుదల(host);

	దొరికింది = 0;
	కొరకు (i = 0; i < అంకె_KEYTYPES; i++) {
		ఒకవేళ (కీలకాలు[i] != ఖాళీ &&
		    sshkey_equal_ప్రజా(కీలకం, కీలకాలు[i])) {
			దొరికింది = 1;
			ఆపు;
		}
	}
	ఒకవేళ (!దొరికింది) {
		ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ఖాళీ)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(కీలకం), fp ? fp : "");
	}

	ఒకవేళ ((r = sshkey_sign(కీలకాలు[i], &signature, &slen, దత్తాంశం, dlen,
	    pkalg, ఖాళీ, ఖాళీ, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	విడుదల(దత్తాంశం);

	/* send reply */
	sshbuf_reset(b);
	ఒకవేళ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ఒకవేళ (ssh_సందేశం_send(STDOUT_FILENO, సంస్కరణ, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	తిరిగి (0);
}
