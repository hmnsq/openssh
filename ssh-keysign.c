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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <paths.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <errno.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/evp.h>
#অন্তর্ভাৱ <openssl/rand.h>
#অন্তর্ভাৱ <openssl/rsa.h>
#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"
#endif

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "authfile.h"
#অন্তর্ভাৱ "msg.h"
#অন্তর্ভাৱ "canohost.h"
#অন্তর্ভাৱ "pathnames.h"
#অন্তর্ভাৱ "readconf.h"
#অন্তর্ভাৱ "uidswap.h"
#অন্তর্ভাৱ "ssherr.h"

বাহ্য ৱর্ণ *__progname;

স্থির পূর্ণাঙ্ক
valid_request(সংরচনা passwd *pw, ৱর্ণ *host, সংরচনা sshkey **ret, ৱর্ণ **pkalgp,
    u_char *data, size_t datalen)
{
	সংরচনা sshbuf *b;
	সংরচনা sshkey *চাবি = রিক্ত;
	u_char type, *pkblob;
	ৱর্ণ *p;
	size_t blen, len;
	ৱর্ণ *pkalg, *luser;
	পূর্ণাঙ্ক r, pktype, fail;

	যদি (ret != রিক্ত)
		*ret = রিক্ত;
	যদি (pkalgp != রিক্ত)
		*pkalgp = রিক্ত;
	fail = 0;

	যদি ((b = sshbuf_from(data, datalen)) == রিক্ত)
		fatal_f("sshbuf_from failed");

	/* session id */
	যদি ((r = sshbuf_get_string(b, রিক্ত, &len)) != 0)
		fatal_fr(r, "parse session ID");
	যদি (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	যদি ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != SSH2_বাৰ্তা_USERAUTH_REQUEST)
		fail++;

	/* server user */
	যদি ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	যদি ((r = sshbuf_get_cstring(b, &p, রিক্ত)) != 0)
		fatal_fr(r, "parse service");
	যদি (strcmp("ssh-connection", p) != 0)
		fail++;
	মুক্ত(p);

	/* method */
	যদি ((r = sshbuf_get_cstring(b, &p, রিক্ত)) != 0)
		fatal_fr(r, "parse method");
	যদি (strcmp("hostbased", p) != 0)
		fail++;
	মুক্ত(p);

	/* pubkey */
	যদি ((r = sshbuf_get_cstring(b, &pkalg, রিক্ত)) != 0 ||
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
	যদি ((r = sshbuf_get_cstring(b, &luser, রিক্ত)) != 0)
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
		যদি (ret != রিক্ত) {
			*ret = চাবি;
			চাবি = রিক্ত;
		}
		যদি (pkalgp != রিক্ত) {
			*pkalgp = pkalg;
			pkalg = রিক্ত;
		}
	}
	sshkey_free(চাবি);
	মুক্ত(pkalg);
	মুক্ত(pkblob);

	ঘূৰাই (fail ? -1 : 0);
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, ৱর্ণ **argv)
{
	সংরচনা sshbuf *b;
	Options options;
#define অঙ্ক_KEYTYPES 5
	সংরচনা sshkey *চাবিগুলি[অঙ্ক_KEYTYPES], *চাবি = রিক্ত;
	সংরচনা passwd *pw;
	পূর্ণাঙ্ক r, চাবি_fd[অঙ্ক_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	ৱর্ণ *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	যদি ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	যদি (fd > 2)
		close(fd);

	যদি (pledge("stdio rpath getpw dns id", রিক্ত) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	বাবে (i = 0; i < অঙ্ক_KEYTYPES; i++)
		চাবি_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	চাবি_fd[i++] = open(PATH_HOST_ECDSA_চাবি_FILE, O_RDONLY);
	চাবি_fd[i++] = open(PATH_HOST_ED25519_চাবি_FILE, O_RDONLY);
	চাবি_fd[i++] = open(PATH_HOST_RSA_চাবি_FILE, O_RDONLY);
	চাবি_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_চাবি_FILE, O_RDONLY);

	যদি ((pw = getpwuid(getuid())) == রিক্ত)
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
	    &options, 0, রিক্ত);
	(শূন্য)fill_default_options(&options);
	যদি (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	যদি (pledge("stdio dns", রিক্ত) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	বাবে (i = found = 0; i < অঙ্ক_KEYTYPES; i++) {
		যদি (চাবি_fd[i] != -1)
			found = 1;
	}
	যদি (found == 0)
		fatal("could not open any host key");

	found = 0;
	বাবে (i = 0; i < অঙ্ক_KEYTYPES; i++) {
		চাবিগুলি[i] = রিক্ত;
		যদি (চাবি_fd[i] == -1)
			অনুৱর্ত;
		r = sshkey_load_private_type_fd(চাবি_fd[i], চাবি_UNSPEC,
		    রিক্ত, &চাবি, রিক্ত);
		close(চাবি_fd[i]);
		যদি (r != 0)
			debug_r(r, "parse key %d", i);
		অন্যথা যদি (চাবি != রিক্ত) {
			চাবিগুলি[i] = চাবি;
			found = 1;
		}
	}
	যদি (!found)
		fatal("no hostkey found");

	যদি ((b = sshbuf_new()) == রিক্ত)
		fatal("%s: sshbuf_new failed", __progname);
	যদি (ssh_বাৰ্তা_recv(STDIN_FILENO, b) < 0)
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
	যদি ((host = get_local_name(fd)) == রিক্ত)
		fatal("%s: cannot get local name for fd", __progname);

	যদি ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	যদি (valid_request(pw, host, &চাবি, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	মুক্ত(host);

	found = 0;
	বাবে (i = 0; i < অঙ্ক_KEYTYPES; i++) {
		যদি (চাবিগুলি[i] != রিক্ত &&
		    sshkey_equal_public(চাবি, চাবিগুলি[i])) {
			found = 1;
			ভঙ্গ;
		}
	}
	যদি (!found) {
		যদি ((fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == রিক্ত)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(চাবি), fp ? fp : "");
	}

	যদি ((r = sshkey_sign(চাবিগুলি[i], &signature, &slen, data, dlen,
	    pkalg, রিক্ত, রিক্ত, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	মুক্ত(data);

	/* send reply */
	sshbuf_reset(b);
	যদি ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	যদি (ssh_বাৰ্তা_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	ঘূৰাই (0);
}
