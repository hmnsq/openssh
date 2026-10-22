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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <errno.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <openssl/rand.h>
#அந்தர்பாவ <openssl/rsa.h>
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "readconf.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "ssherr.h"

வெளி எழுத்து *__progname;

நிலையான முழு
valid_request(கட்டமைப்பு passwd *pw, எழுத்து *host, கட்டமைப்பு sshkey **ret, எழுத்து **pkalgp,
    u_char *data, size_t datalen)
{
	கட்டமைப்பு sshbuf *b;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	u_char type, *pkblob;
	எழுத்து *p;
	size_t blen, len;
	எழுத்து *pkalg, *luser;
	முழு r, pktype, fail;

	எனில் (ret != வெற்று)
		*ret = வெற்று;
	எனில் (pkalgp != வெற்று)
		*pkalgp = வெற்று;
	fail = 0;

	எனில் ((b = sshbuf_from(data, datalen)) == வெற்று)
		fatal_f("sshbuf_from failed");

	/* session id */
	எனில் ((r = sshbuf_get_string(b, வெற்று, &len)) != 0)
		fatal_fr(r, "parse session ID");
	எனில் (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	எனில் ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	எனில் (type != SSH2_செய்தி_USERAUTH_REQUEST)
		fail++;

	/* server user */
	எனில் ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	எனில் ((r = sshbuf_get_cstring(b, &p, வெற்று)) != 0)
		fatal_fr(r, "parse service");
	எனில் (strcmp("ssh-connection", p) != 0)
		fail++;
	விடுவி(p);

	/* method */
	எனில் ((r = sshbuf_get_cstring(b, &p, வெற்று)) != 0)
		fatal_fr(r, "parse method");
	எனில் (strcmp("hostbased", p) != 0)
		fail++;
	விடுவி(p);

	/* pubkey */
	எனில் ((r = sshbuf_get_cstring(b, &pkalg, வெற்று)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	எனில் (pktype == சாவி_UNSPEC)
		fail++;
	இல்லையெனில் எனில் ((r = sshkey_from_blob(pkblob, blen, &சாவி)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} இல்லையெனில் எனில் (சாவி->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	எனில் ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	எனில் (len == 0)
		fail++;
	இல்லையெனில் எனில் (strlen(host) != len - 1)
		fail++;
	இல்லையெனில் எனில் (p[len - 1] != '.')
		fail++;
	இல்லையெனில் எனில் (strncasecmp(host, p, len - 1) != 0)
		fail++;
	விடுவி(p);

	/* local user */
	எனில் ((r = sshbuf_get_cstring(b, &luser, வெற்று)) != 0)
		fatal_fr(r, "parse luser");

	எனில் (strcmp(pw->pw_name, luser) != 0)
		fail++;
	விடுவி(luser);

	/* end of message */
	எனில் (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	எனில் (!fail) {
		எனில் (ret != வெற்று) {
			*ret = சாவி;
			சாவி = வெற்று;
		}
		எனில் (pkalgp != வெற்று) {
			*pkalgp = pkalg;
			pkalg = வெற்று;
		}
	}
	sshkey_free(சாவி);
	விடுவி(pkalg);
	விடுவி(pkblob);

	திரும்பு (fail ? -1 : 0);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	கட்டமைப்பு sshbuf *b;
	Options options;
#define இலக்கம்_KEYTYPES 5
	கட்டமைப்பு sshkey *சாவிகள்[இலக்கம்_KEYTYPES], *சாவி = வெற்று;
	கட்டமைப்பு passwd *pw;
	முழு r, சாவி_fd[இலக்கம்_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	எழுத்து *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	எனில் ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	எனில் (fd > 2)
		close(fd);

	எனில் (pledge("stdio rpath getpw dns id", வெற்று) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	க்கு (i = 0; i < இலக்கம்_KEYTYPES; i++)
		சாவி_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	சாவி_fd[i++] = open(PATH_HOST_ECDSA_சாவி_FILE, O_RDONLY);
	சாவி_fd[i++] = open(PATH_HOST_ED25519_சாவி_FILE, O_RDONLY);
	சாவி_fd[i++] = open(PATH_HOST_RSA_சாவி_FILE, O_RDONLY);
	சாவி_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_சாவி_FILE, O_RDONLY);

	எனில் ((pw = getpwuid(getuid())) == வெற்று)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(வெறுமை)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, வெற்று);
	(வெறுமை)fill_default_options(&options);
	எனில் (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	எனில் (pledge("stdio dns", வெற்று) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	க்கு (i = found = 0; i < இலக்கம்_KEYTYPES; i++) {
		எனில் (சாவி_fd[i] != -1)
			found = 1;
	}
	எனில் (found == 0)
		fatal("could not open any host key");

	found = 0;
	க்கு (i = 0; i < இலக்கம்_KEYTYPES; i++) {
		சாவிகள்[i] = வெற்று;
		எனில் (சாவி_fd[i] == -1)
			தொடர்;
		r = sshkey_load_private_type_fd(சாவி_fd[i], சாவி_UNSPEC,
		    வெற்று, &சாவி, வெற்று);
		close(சாவி_fd[i]);
		எனில் (r != 0)
			debug_r(r, "parse key %d", i);
		இல்லையெனில் எனில் (சாவி != வெற்று) {
			சாவிகள்[i] = சாவி;
			found = 1;
		}
	}
	எனில் (!found)
		fatal("no hostkey found");

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal("%s: sshbuf_new failed", __progname);
	எனில் (ssh_செய்தி_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	எனில் ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	எனில் (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	எனில் ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	எனில் (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	எனில் ((host = get_local_name(fd)) == வெற்று)
		fatal("%s: cannot get local name for fd", __progname);

	எனில் ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	எனில் (valid_request(pw, host, &சாவி, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	விடுவி(host);

	found = 0;
	க்கு (i = 0; i < இலக்கம்_KEYTYPES; i++) {
		எனில் (சாவிகள்[i] != வெற்று &&
		    sshkey_equal_public(சாவி, சாவிகள்[i])) {
			found = 1;
			நிறுத்து;
		}
	}
	எனில் (!found) {
		எனில் ((fp = sshkey_fingerprint(சாவி, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == வெற்று)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(சாவி), fp ? fp : "");
	}

	எனில் ((r = sshkey_sign(சாவிகள்[i], &signature, &slen, data, dlen,
	    pkalg, வெற்று, வெற்று, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	விடுவி(data);

	/* send reply */
	sshbuf_reset(b);
	எனில் ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	எனில் (ssh_செய்தி_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	திரும்பு (0);
}
