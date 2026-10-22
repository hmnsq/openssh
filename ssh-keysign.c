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

#ifdef WITH_OPENSSL
#ضمن <openssl/evp.h>
#ضمن <openssl/rand.h>
#ضمن <openssl/rsa.h>
#ضمن "openbsd-compat/openssl-compat.h"
#endif

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
    u_char *data, size_t datalen)
{
	بنية sshbuf *b;
	بنية sshkey *key = عدم;
	u_char type, *pkblob;
	حرف *p;
	size_t blen, len;
	حرف *pkalg, *luser;
	صحيح r, pktype, fail;

	𐡄𐡍 (ret != عدم)
		*ret = عدم;
	𐡄𐡍 (pkalgp != عدم)
		*pkalgp = عدم;
	fail = 0;

	𐡄𐡍 ((b = sshbuf_from(data, datalen)) == عدم)
		fatal_f("sshbuf_from failed");

	/* session id */
	𐡄𐡍 ((r = sshbuf_get_string(b, عدم, &len)) != 0)
		fatal_fr(r, "parse session ID");
	𐡄𐡍 (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	𐡄𐡍 ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	𐡄𐡍 (type != SSH2_MSG_USERAUTH_REQUEST)
		fail++;

	/* server user */
	𐡄𐡍 ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	𐡄𐡍 ((r = sshbuf_get_cstring(b, &p, عدم)) != 0)
		fatal_fr(r, "parse service");
	𐡄𐡍 (strcmp("ssh-connection", p) != 0)
		fail++;
	حرر(p);

	/* method */
	𐡄𐡍 ((r = sshbuf_get_cstring(b, &p, عدم)) != 0)
		fatal_fr(r, "parse method");
	𐡄𐡍 (strcmp("hostbased", p) != 0)
		fail++;
	حرر(p);

	/* pubkey */
	𐡄𐡍 ((r = sshbuf_get_cstring(b, &pkalg, عدم)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	𐡄𐡍 (pktype == KEY_UNSPEC)
		fail++;
	وإلا 𐡄𐡍 ((r = sshkey_from_blob(pkblob, blen, &key)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} وإلا 𐡄𐡍 (key->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	𐡄𐡍 ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	𐡄𐡍 (len == 0)
		fail++;
	وإلا 𐡄𐡍 (strlen(host) != len - 1)
		fail++;
	وإلا 𐡄𐡍 (p[len - 1] != '.')
		fail++;
	وإلا 𐡄𐡍 (strncasecmp(host, p, len - 1) != 0)
		fail++;
	حرر(p);

	/* local user */
	𐡄𐡍 ((r = sshbuf_get_cstring(b, &luser, عدم)) != 0)
		fatal_fr(r, "parse luser");

	𐡄𐡍 (strcmp(pw->pw_name, luser) != 0)
		fail++;
	حرر(luser);

	/* end of message */
	𐡄𐡍 (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	𐡄𐡍 (!fail) {
		𐡄𐡍 (ret != عدم) {
			*ret = key;
			key = عدم;
		}
		𐡄𐡍 (pkalgp != عدم) {
			*pkalgp = pkalg;
			pkalg = عدم;
		}
	}
	sshkey_free(key);
	حرر(pkalg);
	حرر(pkblob);

	أرجع (fail ? -1 : 0);
}

صحيح
main(صحيح argc, حرف **argv)
{
	بنية sshbuf *b;
	Options options;
#define NUM_KEYTYPES 5
	بنية sshkey *keys[NUM_KEYTYPES], *key = عدم;
	بنية passwd *pw;
	صحيح r, key_fd[NUM_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	حرف *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	𐡄𐡍 ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	𐡄𐡍 (fd > 2)
		close(fd);

	𐡄𐡍 (pledge("stdio rpath getpw dns id", عدم) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	لكل (i = 0; i < NUM_KEYTYPES; i++)
		key_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	key_fd[i++] = open(_PATH_HOST_ECDSA_KEY_FILE, O_RDONLY);
	key_fd[i++] = open(_PATH_HOST_ED25519_KEY_FILE, O_RDONLY);
	key_fd[i++] = open(_PATH_HOST_RSA_KEY_FILE, O_RDONLY);
	key_fd[i++] = open(_PATH_HOST_MLDSA44_ED25519_KEY_FILE, O_RDONLY);

	𐡄𐡍 ((pw = getpwuid(getuid())) == عدم)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(فراغ)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, عدم);
	(فراغ)fill_default_options(&options);
	𐡄𐡍 (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	𐡄𐡍 (pledge("stdio dns", عدم) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	لكل (i = found = 0; i < NUM_KEYTYPES; i++) {
		𐡄𐡍 (key_fd[i] != -1)
			found = 1;
	}
	𐡄𐡍 (found == 0)
		fatal("could not open any host key");

	found = 0;
	لكل (i = 0; i < NUM_KEYTYPES; i++) {
		keys[i] = عدم;
		𐡄𐡍 (key_fd[i] == -1)
			استمر;
		r = sshkey_load_private_type_fd(key_fd[i], KEY_UNSPEC,
		    عدم, &key, عدم);
		close(key_fd[i]);
		𐡄𐡍 (r != 0)
			debug_r(r, "parse key %d", i);
		وإلا 𐡄𐡍 (key != عدم) {
			keys[i] = key;
			found = 1;
		}
	}
	𐡄𐡍 (!found)
		fatal("no hostkey found");

	𐡄𐡍 ((b = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);
	𐡄𐡍 (ssh_msg_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	𐡄𐡍 ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	𐡄𐡍 (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	𐡄𐡍 ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	𐡄𐡍 (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	𐡄𐡍 ((host = get_local_name(fd)) == عدم)
		fatal("%s: cannot get local name for fd", __progname);

	𐡄𐡍 ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	𐡄𐡍 (valid_request(pw, host, &key, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	حرر(host);

	found = 0;
	لكل (i = 0; i < NUM_KEYTYPES; i++) {
		𐡄𐡍 (keys[i] != عدم &&
		    sshkey_equal_public(key, keys[i])) {
			found = 1;
			اكسر;
		}
	}
	𐡄𐡍 (!found) {
		𐡄𐡍 ((fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == عدم)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(key), fp ? fp : "");
	}

	𐡄𐡍 ((r = sshkey_sign(keys[i], &signature, &slen, data, dlen,
	    pkalg, عدم, عدم, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	حرر(data);

	/* send reply */
	sshbuf_reset(b);
	𐡄𐡍 ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	𐡄𐡍 (ssh_msg_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	أرجع (0);
}
