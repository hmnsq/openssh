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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <errno.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ <openssl/rand.h>
#અન્તર્ભાવ <openssl/rsa.h>
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "readconf.h"
#અન્તર્ભાવ "uidswap.h"
#અન્તર્ભાવ "ssherr.h"

બાહ્ય અક્ષર *__progname;

સ્થિર પૂર્ણાંક
valid_request(સંરચના passwd *pw, અક્ષર *host, સંરચના sshkey **ret, અક્ષર **pkalgp,
    u_char *data, size_t datalen)
{
	સંરચના sshbuf *b;
	સંરચના sshkey *ચાવી = ખાલી;
	u_char type, *pkblob;
	અક્ષર *p;
	size_t blen, len;
	અક્ષર *pkalg, *luser;
	પૂર્ણાંક r, pktype, fail;

	જો (ret != ખાલી)
		*ret = ખાલી;
	જો (pkalgp != ખાલી)
		*pkalgp = ખાલી;
	fail = 0;

	જો ((b = sshbuf_from(data, datalen)) == ખાલી)
		fatal_f("sshbuf_from failed");

	/* session id */
	જો ((r = sshbuf_get_string(b, ખાલી, &len)) != 0)
		fatal_fr(r, "parse session ID");
	જો (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	જો ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	જો (type != SSH2_સંદેશ_USERAUTH_REQUEST)
		fail++;

	/* server user */
	જો ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	જો ((r = sshbuf_get_cstring(b, &p, ખાલી)) != 0)
		fatal_fr(r, "parse service");
	જો (strcmp("ssh-connection", p) != 0)
		fail++;
	મુક્ત(p);

	/* method */
	જો ((r = sshbuf_get_cstring(b, &p, ખાલી)) != 0)
		fatal_fr(r, "parse method");
	જો (strcmp("hostbased", p) != 0)
		fail++;
	મુક્ત(p);

	/* pubkey */
	જો ((r = sshbuf_get_cstring(b, &pkalg, ખાલી)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	જો (pktype == ચાવી_UNSPEC)
		fail++;
	નહીંતર જો ((r = sshkey_from_blob(pkblob, blen, &ચાવી)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} નહીંતર જો (ચાવી->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	જો ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	જો (len == 0)
		fail++;
	નહીંતર જો (strlen(host) != len - 1)
		fail++;
	નહીંતર જો (p[len - 1] != '.')
		fail++;
	નહીંતર જો (strncasecmp(host, p, len - 1) != 0)
		fail++;
	મુક્ત(p);

	/* local user */
	જો ((r = sshbuf_get_cstring(b, &luser, ખાલી)) != 0)
		fatal_fr(r, "parse luser");

	જો (strcmp(pw->pw_name, luser) != 0)
		fail++;
	મુક્ત(luser);

	/* end of message */
	જો (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	જો (!fail) {
		જો (ret != ખાલી) {
			*ret = ચાવી;
			ચાવી = ખાલી;
		}
		જો (pkalgp != ખાલી) {
			*pkalgp = pkalg;
			pkalg = ખાલી;
		}
	}
	sshkey_free(ચાવી);
	મુક્ત(pkalg);
	મુક્ત(pkblob);

	પાછા (fail ? -1 : 0);
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	સંરચના sshbuf *b;
	Options options;
#define અંક_KEYTYPES 5
	સંરચના sshkey *ચાવીઓ[અંક_KEYTYPES], *ચાવી = ખાલી;
	સંરચના passwd *pw;
	પૂર્ણાંક r, ચાવી_fd[અંક_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	અક્ષર *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	જો ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	જો (fd > 2)
		close(fd);

	જો (pledge("stdio rpath getpw dns id", ખાલી) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	માટે (i = 0; i < અંક_KEYTYPES; i++)
		ચાવી_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	ચાવી_fd[i++] = open(PATH_HOST_ECDSA_ચાવી_FILE, O_RDONLY);
	ચાવી_fd[i++] = open(PATH_HOST_ED25519_ચાવી_FILE, O_RDONLY);
	ચાવી_fd[i++] = open(PATH_HOST_RSA_ચાવી_FILE, O_RDONLY);
	ચાવી_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_ચાવી_FILE, O_RDONLY);

	જો ((pw = getpwuid(getuid())) == ખાલી)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(શૂન્ય)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, ખાલી);
	(શૂન્ય)fill_default_options(&options);
	જો (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	જો (pledge("stdio dns", ખાલી) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	માટે (i = found = 0; i < અંક_KEYTYPES; i++) {
		જો (ચાવી_fd[i] != -1)
			found = 1;
	}
	જો (found == 0)
		fatal("could not open any host key");

	found = 0;
	માટે (i = 0; i < અંક_KEYTYPES; i++) {
		ચાવીઓ[i] = ખાલી;
		જો (ચાવી_fd[i] == -1)
			ચાલુ;
		r = sshkey_load_private_type_fd(ચાવી_fd[i], ચાવી_UNSPEC,
		    ખાલી, &ચાવી, ખાલી);
		close(ચાવી_fd[i]);
		જો (r != 0)
			debug_r(r, "parse key %d", i);
		નહીંતર જો (ચાવી != ખાલી) {
			ચાવીઓ[i] = ચાવી;
			found = 1;
		}
	}
	જો (!found)
		fatal("no hostkey found");

	જો ((b = sshbuf_new()) == ખાલી)
		fatal("%s: sshbuf_new failed", __progname);
	જો (ssh_સંદેશ_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	જો ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	જો (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	જો ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	જો (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	જો ((host = get_local_name(fd)) == ખાલી)
		fatal("%s: cannot get local name for fd", __progname);

	જો ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	જો (valid_request(pw, host, &ચાવી, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	મુક્ત(host);

	found = 0;
	માટે (i = 0; i < અંક_KEYTYPES; i++) {
		જો (ચાવીઓ[i] != ખાલી &&
		    sshkey_equal_public(ચાવી, ચાવીઓ[i])) {
			found = 1;
			તોડો;
		}
	}
	જો (!found) {
		જો ((fp = sshkey_fingerprint(ચાવી, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ખાલી)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(ચાવી), fp ? fp : "");
	}

	જો ((r = sshkey_sign(ચાવીઓ[i], &signature, &slen, data, dlen,
	    pkalg, ખાલી, ખાલી, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	મુક્ત(data);

	/* send reply */
	sshbuf_reset(b);
	જો ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	જો (ssh_સંદેશ_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	પાછા (0);
}
