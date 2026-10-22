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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <errno.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব <openssl/rand.h>
#অন্তর্ভাব <openssl/rsa.h>
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "readconf.h"
#অন্তর্ভাব "uidswap.h"
#অন্তর্ভাব "ssherr.h"

বাহ্যিক অক্ষর *__progname;

স্থির পূর্ণসংখ্যা
valid_request(কাঠামো passwd *pw, অক্ষর *host, কাঠামো sshkey **ret, অক্ষর **pkalgp,
    u_char *তথ্য, আকার_t datalen)
{
	কাঠামো sshbuf *b;
	কাঠামো sshkey *চাবি = ফাঁকা;
	u_char type, *pkblob;
	অক্ষর *p;
	আকার_t blen, len;
	অক্ষর *pkalg, *luser;
	পূর্ণসংখ্যা r, pktype, fail;

	যদি (ret != ফাঁকা)
		*ret = ফাঁকা;
	যদি (pkalgp != ফাঁকা)
		*pkalgp = ফাঁকা;
	fail = 0;

	যদি ((b = sshbuf_from(তথ্য, datalen)) == ফাঁকা)
		fatal_f("sshbuf_from failed");

	/* session id */
	যদি ((r = sshbuf_get_string(b, ফাঁকা, &len)) != 0)
		fatal_fr(r, "parse session ID");
	যদি (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	যদি ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != SSH2_বার্তা_USERAUTH_REQUEST)
		fail++;

	/* server user */
	যদি ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	যদি ((r = sshbuf_get_cstring(b, &p, ফাঁকা)) != 0)
		fatal_fr(r, "parse service");
	যদি (strcmp("ssh-connection", p) != 0)
		fail++;
	মুক্ত(p);

	/* method */
	যদি ((r = sshbuf_get_cstring(b, &p, ফাঁকা)) != 0)
		fatal_fr(r, "parse method");
	যদি (strcmp("hostbased", p) != 0)
		fail++;
	মুক্ত(p);

	/* pubkey */
	যদি ((r = sshbuf_get_cstring(b, &pkalg, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	যদি (pktype == চাবি_UNSPEC)
		fail++;
	অন্যথা যদি ((r = sshkey_from_blob(pkblob, blen, &চাবি)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} অন্যথা যদি (চাবি->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	যদি ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	যদি (len == 0)
		fail++;
	অন্যথা যদি (strlen(host) != len - 1)
		fail++;
	অন্যথা যদি (p[len - 1] != '.')
		fail++;
	অন্যথা যদি (strncasecmp(host, p, len - 1) != 0)
		fail++;
	মুক্ত(p);

	/* local user */
	যদি ((r = sshbuf_get_cstring(b, &luser, ফাঁকা)) != 0)
		fatal_fr(r, "parse luser");

	যদি (strcmp(pw->pw_name, luser) != 0)
		fail++;
	মুক্ত(luser);

	/* end of message */
	যদি (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	যদি (!fail) {
		যদি (ret != ফাঁকা) {
			*ret = চাবি;
			চাবি = ফাঁকা;
		}
		যদি (pkalgp != ফাঁকা) {
			*pkalgp = pkalg;
			pkalg = ফাঁকা;
		}
	}
	sshkey_free(চাবি);
	মুক্ত(pkalg);
	মুক্ত(pkblob);

	ফেরত (fail ? -1 : 0);
}

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	কাঠামো sshbuf *b;
	Options options;
#define অঙ্ক_KEYTYPES 5
	কাঠামো sshkey *চাবিগুলি[অঙ্ক_KEYTYPES], *চাবি = ফাঁকা;
	কাঠামো passwd *pw;
	পূর্ণসংখ্যা r, চাবি_fd[অঙ্ক_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *তথ্য, rver;
	অক্ষর *host, *fp, *pkalg;
	আকার_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	যদি ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	যদি (fd > 2)
		close(fd);

	যদি (pledge("stdio rpath getpw dns id", ফাঁকা) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	জন্য (i = 0; i < অঙ্ক_KEYTYPES; i++)
		চাবি_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	চাবি_fd[i++] = open(PATH_HOST_ECDSA_চাবি_FILE, O_RDONLY);
	চাবি_fd[i++] = open(PATH_HOST_ED25519_চাবি_FILE, O_RDONLY);
	চাবি_fd[i++] = open(PATH_HOST_RSA_চাবি_FILE, O_RDONLY);
	চাবি_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_চাবি_FILE, O_RDONLY);

	যদি ((pw = getpwuid(getuid())) == ফাঁকা)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(শূন্য)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, ফাঁকা);
	(শূন্য)fill_default_options(&options);
	যদি (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	যদি (pledge("stdio dns", ফাঁকা) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	জন্য (i = found = 0; i < অঙ্ক_KEYTYPES; i++) {
		যদি (চাবি_fd[i] != -1)
			found = 1;
	}
	যদি (found == 0)
		fatal("could not open any host key");

	found = 0;
	জন্য (i = 0; i < অঙ্ক_KEYTYPES; i++) {
		চাবিগুলি[i] = ফাঁকা;
		যদি (চাবি_fd[i] == -1)
			চালু;
		r = sshkey_load_private_type_fd(চাবি_fd[i], চাবি_UNSPEC,
		    ফাঁকা, &চাবি, ফাঁকা);
		close(চাবি_fd[i]);
		যদি (r != 0)
			debug_r(r, "parse key %d", i);
		অন্যথা যদি (চাবি != ফাঁকা) {
			চাবিগুলি[i] = চাবি;
			found = 1;
		}
	}
	যদি (!found)
		fatal("no hostkey found");

	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal("%s: sshbuf_new failed", __progname);
	যদি (ssh_বার্তা_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	যদি ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	যদি (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	যদি ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	যদি (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	যদি ((host = get_local_name(fd)) == ফাঁকা)
		fatal("%s: cannot get local name for fd", __progname);

	যদি ((r = sshbuf_get_string(b, &তথ্য, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	যদি (valid_request(pw, host, &চাবি, &pkalg, তথ্য, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	মুক্ত(host);

	found = 0;
	জন্য (i = 0; i < অঙ্ক_KEYTYPES; i++) {
		যদি (চাবিগুলি[i] != ফাঁকা &&
		    sshkey_equal_public(চাবি, চাবিগুলি[i])) {
			found = 1;
			বিরতি;
		}
	}
	যদি (!found) {
		যদি ((fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ফাঁকা)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(চাবি), fp ? fp : "");
	}

	যদি ((r = sshkey_sign(চাবিগুলি[i], &signature, &slen, তথ্য, dlen,
	    pkalg, ফাঁকা, ফাঁকা, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	মুক্ত(তথ্য);

	/* send reply */
	sshbuf_reset(b);
	যদি ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	যদি (ssh_বার্তা_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	ফেরত (0);
}
