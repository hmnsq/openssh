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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <errno.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ <openssl/rand.h>
#അന്തര്ഭാവ <openssl/rsa.h>
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"
#endif

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "readconf.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "ssherr.h"

ബാഹ്യ അക്ഷരം *__progname;

സ്ഥിതം പൂർണ്ണസംഖ്യ
valid_request(ഘടന passwd *pw, അക്ഷരം *host, ഘടന sshkey **ret, അക്ഷരം **pkalgp,
    u_char *data, size_t datalen)
{
	ഘടന sshbuf *b;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	u_char type, *pkblob;
	അക്ഷരം *p;
	size_t blen, len;
	അക്ഷരം *pkalg, *luser;
	പൂർണ്ണസംഖ്യ r, pktype, fail;

	എങ്കിൽ (ret != ശൂന്യ)
		*ret = ശൂന്യ;
	എങ്കിൽ (pkalgp != ശൂന്യ)
		*pkalgp = ശൂന്യ;
	fail = 0;

	എങ്കിൽ ((b = sshbuf_from(data, datalen)) == ശൂന്യ)
		fatal_f("sshbuf_from failed");

	/* session id */
	എങ്കിൽ ((r = sshbuf_get_string(b, ശൂന്യ, &len)) != 0)
		fatal_fr(r, "parse session ID");
	എങ്കിൽ (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	എങ്കിൽ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	എങ്കിൽ (type != SSH2_സന്ദേശം_USERAUTH_REQUEST)
		fail++;

	/* server user */
	എങ്കിൽ ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &p, ശൂന്യ)) != 0)
		fatal_fr(r, "parse service");
	എങ്കിൽ (strcmp("ssh-connection", p) != 0)
		fail++;
	സ്വതന്ത്രം(p);

	/* method */
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &p, ശൂന്യ)) != 0)
		fatal_fr(r, "parse method");
	എങ്കിൽ (strcmp("hostbased", p) != 0)
		fail++;
	സ്വതന്ത്രം(p);

	/* pubkey */
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &pkalg, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	എങ്കിൽ (pktype == താക്കോൽ_UNSPEC)
		fail++;
	അല്ലെങ്കിൽ എങ്കിൽ ((r = sshkey_from_blob(pkblob, blen, &താക്കോൽ)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} അല്ലെങ്കിൽ എങ്കിൽ (താക്കോൽ->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	എങ്കിൽ (len == 0)
		fail++;
	അല്ലെങ്കിൽ എങ്കിൽ (strlen(host) != len - 1)
		fail++;
	അല്ലെങ്കിൽ എങ്കിൽ (p[len - 1] != '.')
		fail++;
	അല്ലെങ്കിൽ എങ്കിൽ (strncasecmp(host, p, len - 1) != 0)
		fail++;
	സ്വതന്ത്രം(p);

	/* local user */
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &luser, ശൂന്യ)) != 0)
		fatal_fr(r, "parse luser");

	എങ്കിൽ (strcmp(pw->pw_name, luser) != 0)
		fail++;
	സ്വതന്ത്രം(luser);

	/* end of message */
	എങ്കിൽ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	എങ്കിൽ (!fail) {
		എങ്കിൽ (ret != ശൂന്യ) {
			*ret = താക്കോൽ;
			താക്കോൽ = ശൂന്യ;
		}
		എങ്കിൽ (pkalgp != ശൂന്യ) {
			*pkalgp = pkalg;
			pkalg = ശൂന്യ;
		}
	}
	sshkey_free(താക്കോൽ);
	സ്വതന്ത്രം(pkalg);
	സ്വതന്ത്രം(pkblob);

	തിരികെ (fail ? -1 : 0);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	ഘടന sshbuf *b;
	Options options;
#define അക്കം_KEYTYPES 5
	ഘടന sshkey *താക്കോലുകൾ[അക്കം_KEYTYPES], *താക്കോൽ = ശൂന്യ;
	ഘടന passwd *pw;
	പൂർണ്ണസംഖ്യ r, താക്കോൽ_fd[അക്കം_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	അക്ഷരം *host, *fp, *pkalg;
	size_t slen, dlen;

	/* Ensure that stdin and stdout are connected */
	എങ്കിൽ ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	എങ്കിൽ (fd > 2)
		close(fd);

	എങ്കിൽ (pledge("stdio rpath getpw dns id", ശൂന്യ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	വേണ്ടി (i = 0; i < അക്കം_KEYTYPES; i++)
		താക്കോൽ_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	താക്കോൽ_fd[i++] = open(PATH_HOST_ECDSA_താക്കോൽ_FILE, O_RDONLY);
	താക്കോൽ_fd[i++] = open(PATH_HOST_ED25519_താക്കോൽ_FILE, O_RDONLY);
	താക്കോൽ_fd[i++] = open(PATH_HOST_RSA_താക്കോൽ_FILE, O_RDONLY);
	താക്കോൽ_fd[i++] = open(PATH_HOST_MLDSA44_ED25519_താക്കോൽ_FILE, O_RDONLY);

	എങ്കിൽ ((pw = getpwuid(getuid())) == ശൂന്യ)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(ശൂന്യം)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, ശൂന്യ);
	(ശൂന്യം)fill_default_options(&options);
	എങ്കിൽ (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	എങ്കിൽ (pledge("stdio dns", ശൂന്യ) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	വേണ്ടി (i = found = 0; i < അക്കം_KEYTYPES; i++) {
		എങ്കിൽ (താക്കോൽ_fd[i] != -1)
			found = 1;
	}
	എങ്കിൽ (found == 0)
		fatal("could not open any host key");

	found = 0;
	വേണ്ടി (i = 0; i < അക്കം_KEYTYPES; i++) {
		താക്കോലുകൾ[i] = ശൂന്യ;
		എങ്കിൽ (താക്കോൽ_fd[i] == -1)
			തുടരുക;
		r = sshkey_load_private_type_fd(താക്കോൽ_fd[i], താക്കോൽ_UNSPEC,
		    ശൂന്യ, &താക്കോൽ, ശൂന്യ);
		close(താക്കോൽ_fd[i]);
		എങ്കിൽ (r != 0)
			debug_r(r, "parse key %d", i);
		അല്ലെങ്കിൽ എങ്കിൽ (താക്കോൽ != ശൂന്യ) {
			താക്കോലുകൾ[i] = താക്കോൽ;
			found = 1;
		}
	}
	എങ്കിൽ (!found)
		fatal("no hostkey found");

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal("%s: sshbuf_new failed", __progname);
	എങ്കിൽ (ssh_സന്ദേശം_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	എങ്കിൽ ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	എങ്കിൽ (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	എങ്കിൽ ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	എങ്കിൽ (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	എങ്കിൽ ((host = get_local_name(fd)) == ശൂന്യ)
		fatal("%s: cannot get local name for fd", __progname);

	എങ്കിൽ ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	എങ്കിൽ (valid_request(pw, host, &താക്കോൽ, &pkalg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	സ്വതന്ത്രം(host);

	found = 0;
	വേണ്ടി (i = 0; i < അക്കം_KEYTYPES; i++) {
		എങ്കിൽ (താക്കോലുകൾ[i] != ശൂന്യ &&
		    sshkey_equal_public(താക്കോൽ, താക്കോലുകൾ[i])) {
			found = 1;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (!found) {
		എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(താക്കോൽ), fp ? fp : "");
	}

	എങ്കിൽ ((r = sshkey_sign(താക്കോലുകൾ[i], &signature, &slen, data, dlen,
	    pkalg, ശൂന്യ, ശൂന്യ, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	സ്വതന്ത്രം(data);

	/* send reply */
	sshbuf_reset(b);
	എങ്കിൽ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	എങ്കിൽ (ssh_സന്ദേശം_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	തിരികെ (0);
}
