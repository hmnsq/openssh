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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ <openssl/rand.h>
#ଅନ୍ତର୍ଭାଵ <openssl/rsa.h>
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ବାହ୍ୟ ଅକ୍ଷର *__progname;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
valid_request(ସଂରଚନା passwd *pw, ଅକ୍ଷର *host, ସଂରଚନା sshkey **ret, ଅକ୍ଷର **pkalgp,
    u_char *data, size_t datalen)
{
	ସଂରଚନା sshbuf *b;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	u_char type, *pkblob;
	ଅକ୍ଷର *p;
	size_t blen, len;
	ଅକ୍ଷର *pkalg, *luser;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, pktype, fail;

	ଯଦି (ret != ଖାଲି)
		*ret = ଖାଲି;
	ଯଦି (pkalgp != ଖାଲି)
		*pkalgp = ଖାଲି;
	fail = 0;

	ଯଦି ((b = sshbuf_from(data, datalen)) == ଖାଲି)
		fatal_f("sshbuf_from failed");

	/* session id */
	ଯଦି ((r = sshbuf_get_string(b, ଖାଲି, &len)) != 0)
		fatal_fr(r, "parse session ID");
	ଯଦି (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	ଯଦି ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ଯଦି (type != SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)
		fail++;

	/* server user */
	ଯଦି ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	ଯଦି ((r = sshbuf_get_cstring(b, &p, ଖାଲି)) != 0)
		fatal_fr(r, "parse service");
	ଯଦି (strcmp("ssh-connection", p) != 0)
		fail++;
	ମୁକ୍ତ(p);

	/* method */
	ଯଦି ((r = sshbuf_get_cstring(b, &p, ଖାଲି)) != 0)
		fatal_fr(r, "parse method");
	ଯଦି (strcmp("hostbased", p) != 0)
		fail++;
	ମୁକ୍ତ(p);

	/* pubkey */
	ଯଦି ((r = sshbuf_get_cstring(b, &pkalg, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	ଯଦି (pktype == ଚାବି_UNSPEC)
		fail++;
	ଅନ୍ୟଥା ଯଦି ((r = sshkey_from_blob(pkblob, blen, &ଚାବି)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} ଅନ୍ୟଥା ଯଦି (ଚାବି->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	ଯଦି ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	ଯଦି (len == 0)
		fail++;
	ଅନ୍ୟଥା ଯଦି (strlen(host) != len - 1)
		fail++;
	ଅନ୍ୟଥା ଯଦି (p[len - 1] != '.')
		fail++;
	ଅନ୍ୟଥା ଯଦି (strncasecmp(host, p, len - 1) != 0)
		fail++;
	ମୁକ୍ତ(p);

	/* local user */
	ଯଦି ((r = sshbuf_get_cstring(b, &luser, ଖାଲି)) != 0)
		fatal_fr(r, "parse luser");

	ଯଦି (strcmp(pw->pw_name, luser) != 0)
		fail++;
	ମୁକ୍ତ(luser);

	/* end of message */
	ଯଦି (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	ଯଦି (!fail) {
		ଯଦି (ret != ଖାଲି) {
			*ret = ଚାବି;
			ଚାବି = ଖାଲି;
		}
		ଯଦି (pkalgp != ଖାଲି) {
			*pkalgp = pkalg;
			pkalg = ଖାଲି;
		}
	}
	sshkey_free(ଚାବି);
	ମୁକ୍ତ(pkalg);
	ମୁକ୍ତ(pkblob);

	ଫେରନ୍ତୁ (fail ? -1 : 0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ସଂରଚନା sshbuf *b;
	Options options;
#define ଅଙ୍କ_KEYTYPES 5
	ସଂରଚନା sshkey *ଚାବିଗୁଡ଼ିକ[ଅଙ୍କ_KEYTYPES], *ଚାବି = ଖାଲି;
	ସଂରଚନା passwd *pw;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଚାବି_fd[ଅଙ୍କ_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	ଅକ୍ଷର *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	ଯଦି ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	ଯଦି (fd > 2)
		close(fd);

	ଯଦି (pledge("stdio rpath getpw dns id", ଖାଲି) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	ପାଇଁ (i = 0; i < ଅଙ୍କ_KEYTYPES; i++)
		ଚାବି_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	ଚାବି_fd[i++] = open(PATH_HOST_ECDSA_ଚାବି_FILE, O_RDONLY);
	ଚାବି_fd[i++] = open(PATH_HOST_ED25519_ଚାବି_FILE, O_RDONLY);
	ଚାବି_fd[i++] = open(PATH_HOST_RSA_ଚାବି_FILE, O_RDONLY);
	ଚାବି_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_ଚାବି_FILE, O_RDONLY);

	ଯଦି ((pw = getpwuid(getuid())) == ଖାଲି)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(ଶୂନ୍ୟ)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, ଖାଲି);
	(ଶୂନ୍ୟ)fill_default_options(&options);
	ଯଦି (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	ଯଦି (pledge("stdio dns", ଖାଲି) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	ପାଇଁ (i = found = 0; i < ଅଙ୍କ_KEYTYPES; i++) {
		ଯଦି (ଚାବି_fd[i] != -1)
			found = 1;
	}
	ଯଦି (found == 0)
		fatal("could not open any host key");

	found = 0;
	ପାଇଁ (i = 0; i < ଅଙ୍କ_KEYTYPES; i++) {
		ଚାବିଗୁଡ଼ିକ[i] = ଖାଲି;
		ଯଦି (ଚାବି_fd[i] == -1)
			ଜାରି;
		r = sshkey_load_private_type_fd(ଚାବି_fd[i], ଚାବି_UNSPEC,
		    ଖାଲି, &ଚାବି, ଖାଲି);
		close(ଚାବି_fd[i]);
		ଯଦି (r != 0)
			debug_r(r, "parse key %d", i);
		ଅନ୍ୟଥା ଯଦି (ଚାବି != ଖାଲି) {
			ଚାବିଗୁଡ଼ିକ[i] = ଚାବି;
			found = 1;
		}
	}
	ଯଦି (!found)
		fatal("no hostkey found");

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal("%s: sshbuf_new failed", __progname);
	ଯଦି (ssh_ସନ୍ଦେଶ_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	ଯଦି ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ଯଦି (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	ଯଦି ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ଯଦି (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	ଯଦି ((host = get_local_name(fd)) == ଖାଲି)
		fatal("%s: cannot get local name for fd", __progname);

	ଯଦି ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ଯଦି (valid_request(pw, host, &ଚାବି, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	ମୁକ୍ତ(host);

	found = 0;
	ପାଇଁ (i = 0; i < ଅଙ୍କ_KEYTYPES; i++) {
		ଯଦି (ଚାବିଗୁଡ଼ିକ[i] != ଖାଲି &&
		    sshkey_equal_public(ଚାବି, ଚାବିଗୁଡ଼ିକ[i])) {
			found = 1;
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (!found) {
		ଯଦି ((fp = sshkey_fingerprint(ଚାବି, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ଖାଲି)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(ଚାବି), fp ? fp : "");
	}

	ଯଦି ((r = sshkey_sign(ଚାବିଗୁଡ଼ିକ[i], &signature, &slen, data, dlen,
	    pkalg, ଖାଲି, ଖାଲି, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	ମୁକ୍ତ(data);

	/* send reply */
	sshbuf_reset(b);
	ଯଦି ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ଯଦି (ssh_ସନ୍ଦେଶ_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	ଫେରନ୍ତୁ (0);
}
