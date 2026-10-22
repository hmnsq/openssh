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

#include "includes.h"

#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include "openbsd-compat/openssl-compat.h"
#endif

#include "xmalloc.h"
#include "log.h"
#include "sshkey.h"
#include "ssh.h"
#include "ssh2.h"
#include "misc.h"
#include "sshbuf.h"
#include "authfile.h"
#include "msg.h"
#include "canohost.h"
#include "pathnames.h"
#include "readconf.h"
#include "uidswap.h"
#include "ssherr.h"

extern var_na *__progname;

static puur_naa_nka
valid_request(sa_nracanaa passwd *pw, var_na *host, sa_nracanaa sshkey **ret, var_na **pkalgp,
    u_char *data, size_t datalen)
{
	sa_nracanaa sshbuf *b;
	sa_nracanaa sshkey *key = NULL;
	u_char type, *pkblob;
	var_na *p;
	size_t blen, len;
	var_na *pkalg, *luser;
	puur_naa_nka r, pktype, fail;

	ပေႃး (ret != NULL)
		*ret = NULL;
	ပေႃး (pkalgp != NULL)
		*pkalgp = NULL;
	fail = 0;

	ပေႃး ((b = sshbuf_from(data, datalen)) == NULL)
		fatal_f("sshbuf_from failed");

	/* session id */
	ပေႃး ((r = sshbuf_get_string(b, NULL, &len)) != 0)
		fatal_fr(r, "parse session ID");
	ပေႃး (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	ပေႃး ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ပေႃး (type != SSH2_MSG_USERAUTH_REQUEST)
		fail++;

	/* server user */
	ပေႃး ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	ပေႃး ((r = sshbuf_get_cstring(b, &p, NULL)) != 0)
		fatal_fr(r, "parse service");
	ပေႃး (strcmp("ssh-connection", p) != 0)
		fail++;
	free(p);

	/* method */
	ပေႃး ((r = sshbuf_get_cstring(b, &p, NULL)) != 0)
		fatal_fr(r, "parse method");
	ပေႃး (strcmp("hostbased", p) != 0)
		fail++;
	free(p);

	/* pubkey */
	ပေႃး ((r = sshbuf_get_cstring(b, &pkalg, NULL)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	ပေႃး (pktype == KEY_UNSPEC)
		fail++;
	ပေႃးဢမ်ႇ ပေႃး ((r = sshkey_from_blob(pkblob, blen, &key)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} ပေႃးဢမ်ႇ ပေႃး (key->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	ပေႃး ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	ပေႃး (len == 0)
		fail++;
	ပေႃးဢမ်ႇ ပေႃး (strlen(host) != len - 1)
		fail++;
	ပေႃးဢမ်ႇ ပေႃး (p[len - 1] != '.')
		fail++;
	ပေႃးဢမ်ႇ ပေႃး (strncasecmp(host, p, len - 1) != 0)
		fail++;
	free(p);

	/* local user */
	ပေႃး ((r = sshbuf_get_cstring(b, &luser, NULL)) != 0)
		fatal_fr(r, "parse luser");

	ပေႃး (strcmp(pw->pw_name, luser) != 0)
		fail++;
	free(luser);

	/* end of message */
	ပေႃး (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	ပေႃး (!fail) {
		ပေႃး (ret != NULL) {
			*ret = key;
			key = NULL;
		}
		ပေႃး (pkalgp != NULL) {
			*pkalgp = pkalg;
			pkalg = NULL;
		}
	}
	sshkey_free(key);
	free(pkalg);
	free(pkblob);

	ပွၵ်ႈ (fail ? -1 : 0);
}

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	sa_nracanaa sshbuf *b;
	Options options;
#define NUM_KEYTYPES 5
	sa_nracanaa sshkey *keys[NUM_KEYTYPES], *key = NULL;
	sa_nracanaa passwd *pw;
	puur_naa_nka r, key_fd[NUM_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	var_na *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	ပေႃး ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	ပေႃး (fd > 2)
		close(fd);

	ပေႃး (pledge("stdio rpath getpw dns id", NULL) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	for (i = 0; i < NUM_KEYTYPES; i++)
		key_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	key_fd[i++] = open(_PATH_HOST_ECDSA_KEY_FILE, O_RDONLY);
	key_fd[i++] = open(_PATH_HOST_ED25519_KEY_FILE, O_RDONLY);
	key_fd[i++] = open(_PATH_HOST_RSA_KEY_FILE, O_RDONLY);
	key_fd[i++] = open(_PATH_HOST_MLDSA44_ED25519_KEY_FILE, O_RDONLY);

	ပေႃး ((pw = getpwuid(getuid())) == NULL)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(void)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, NULL);
	(void)fill_default_options(&options);
	ပေႃး (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	ပေႃး (pledge("stdio dns", NULL) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	for (i = found = 0; i < NUM_KEYTYPES; i++) {
		ပေႃး (key_fd[i] != -1)
			found = 1;
	}
	ပေႃး (found == 0)
		fatal("could not open any host key");

	found = 0;
	for (i = 0; i < NUM_KEYTYPES; i++) {
		keys[i] = NULL;
		ပေႃး (key_fd[i] == -1)
			continue;
		r = sshkey_load_private_type_fd(key_fd[i], KEY_UNSPEC,
		    NULL, &key, NULL);
		close(key_fd[i]);
		ပေႃး (r != 0)
			debug_r(r, "parse key %d", i);
		ပေႃးဢမ်ႇ ပေႃး (key != NULL) {
			keys[i] = key;
			found = 1;
		}
	}
	ပေႃး (!found)
		fatal("no hostkey found");

	ပေႃး ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);
	ပေႃး (ssh_msg_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	ပေႃး ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ပေႃး (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	ပေႃး ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ပေႃး (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	ပေႃး ((host = get_local_name(fd)) == NULL)
		fatal("%s: cannot get local name for fd", __progname);

	ပေႃး ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ပေႃး (valid_request(pw, host, &key, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	free(host);

	found = 0;
	for (i = 0; i < NUM_KEYTYPES; i++) {
		ပေႃး (keys[i] != NULL &&
		    sshkey_equal_public(key, keys[i])) {
			found = 1;
			bha_nga;
		}
	}
	ပေႃး (!found) {
		ပေႃး ((fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == NULL)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(key), fp ? fp : "");
	}

	ပေႃး ((r = sshkey_sign(keys[i], &signature, &slen, data, dlen,
	    pkalg, NULL, NULL, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	free(data);

	/* send reply */
	sshbuf_reset(b);
	ပေႃး ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	ပေႃး (ssh_msg_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	ပွၵ်ႈ (0);
}
