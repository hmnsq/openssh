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

#समावेश "includes.h"

#समावेश <fcntl.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <errno.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/evp.h>
#समावेश <openssl/rand.h>
#समावेश <openssl/rsa.h>
#समावेश "openbsd-compat/openssl-compat.h"
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "log.h"
#समावेश "sshkey.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "misc.h"
#समावेश "sshbuf.h"
#समावेश "authfile.h"
#समावेश "msg.h"
#समावेश "canohost.h"
#समावेश "pathnames.h"
#समावेश "readconf.h"
#समावेश "uidswap.h"
#समावेश "ssherr.h"

बाह्य अक्षर *__progname;

अटल पूर्णांक
valid_request(काष्ठा passwd *pw, अक्षर *host, काष्ठा sshkey **ret, अक्षर **pkalgp,
    u_char *तथ्य, माप_प्रकार datalen)
{
	काष्ठा sshbuf *b;
	काष्ठा sshkey *कुंजी = शून्य;
	u_char type, *pkblob;
	अक्षर *p;
	माप_प्रकार blen, len;
	अक्षर *pkalg, *luser;
	पूर्णांक r, pktype, fail;

	अगर (ret != शून्य)
		*ret = शून्य;
	अगर (pkalgp != शून्य)
		*pkalgp = शून्य;
	fail = 0;

	अगर ((b = sshbuf_from(तथ्य, datalen)) == शून्य)
		fatal_f("sshbuf_from failed");

	/* session id */
	अगर ((r = sshbuf_get_string(b, शून्य, &len)) != 0)
		fatal_fr(r, "parse session ID");
	अगर (len != 20 && /* SHA1 */
	    len != 32 && /* SHA256 */
	    len != 48 && /* SHA384 */
	    len != 64)   /* SHA512 */
		fail++;

	अगर ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	अगर (type != SSH2_संदेश_USERAUTH_REQUEST)
		fail++;

	/* server user */
	अगर ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	अगर ((r = sshbuf_get_cstring(b, &p, शून्य)) != 0)
		fatal_fr(r, "parse service");
	अगर (म_भेद("ssh-connection", p) != 0)
		fail++;
	मुक्त(p);

	/* method */
	अगर ((r = sshbuf_get_cstring(b, &p, शून्य)) != 0)
		fatal_fr(r, "parse method");
	अगर (म_भेद("hostbased", p) != 0)
		fail++;
	मुक्त(p);

	/* pubkey */
	अगर ((r = sshbuf_get_cstring(b, &pkalg, शून्य)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	अगर (pktype == कुंजी_UNSPEC)
		fail++;
	अन्यथा अगर ((r = sshkey_from_blob(pkblob, blen, &कुंजी)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} अन्यथा अगर (कुंजी->type != pktype)
		fail++;

	/* client host name, handle trailing dot */
	अगर ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost \"%s\" got \"%s\"", host, p);
	अगर (len == 0)
		fail++;
	अन्यथा अगर (म_माप(host) != len - 1)
		fail++;
	अन्यथा अगर (p[len - 1] != '.')
		fail++;
	अन्यथा अगर (strncasecmp(host, p, len - 1) != 0)
		fail++;
	मुक्त(p);

	/* local user */
	अगर ((r = sshbuf_get_cstring(b, &luser, शून्य)) != 0)
		fatal_fr(r, "parse luser");

	अगर (म_भेद(pw->pw_name, luser) != 0)
		fail++;
	मुक्त(luser);

	/* end of message */
	अगर (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	अगर (!fail) {
		अगर (ret != शून्य) {
			*ret = कुंजी;
			कुंजी = शून्य;
		}
		अगर (pkalgp != शून्य) {
			*pkalgp = pkalg;
			pkalg = शून्य;
		}
	}
	sshkey_free(कुंजी);
	मुक्त(pkalg);
	मुक्त(pkblob);

	वापस (fail ? -1 : 0);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	काष्ठा sshbuf *b;
	Options options;
#घोषणा अंक_KEYTYPES 5
	काष्ठा sshkey *कुंजियाँ[अंक_KEYTYPES], *कुंजी = शून्य;
	काष्ठा passwd *pw;
	पूर्णांक r, कुंजी_fd[अंक_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *तथ्य, rver;
	अक्षर *host, *fp, *pkalg;
	माप_प्रकार slen, dlen;

	/* Ensure that stdin and stdout are connected */
	अगर ((fd = खोलो(_PATH_DEVNULL, O_RDWR)) < 2)
		निकास(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	अगर (fd > 2)
		बंद(fd);

	अगर (pledge("stdio rpath getpw dns id", शून्य) != 0)
		fatal("%s: pledge: %s", __progname, म_त्रुटि(त्रुटि_सं));

	क्रम (i = 0; i < अंक_KEYTYPES; i++)
		कुंजी_fd[i] = -1;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	कुंजी_fd[i++] = खोलो(PATH_HOST_ECDSA_कुंजी_FILE, O_RDONLY);
	कुंजी_fd[i++] = खोलो(PATH_HOST_ED25519_कुंजी_FILE, O_RDONLY);
	कुंजी_fd[i++] = खोलो(PATH_HOST_RSA_कुंजी_FILE, O_RDONLY);
	कुंजी_fd[i++] = खोलो(PATH_HOST_MLDSA44_ED25519_कुंजी_FILE, O_RDONLY);

	अगर ((pw = getpwuid(getuid())) == शून्य)
		fatal("getpwuid failed");
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#अगर_घोषित DEBUG_SSH_KEYSIGN
	log_init("ssh-keysign", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#पूर्ण_अगर

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(व्योम)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "", "",
	    &options, 0, शून्य);
	(व्योम)fill_default_options(&options);
	अगर (options.enable_ssh_keysign != 1)
		fatal("ssh-keysign not enabled in %s",
		    _PATH_HOST_CONFIG_FILE);

	अगर (pledge("stdio dns", शून्य) != 0)
		fatal("%s: pledge: %s", __progname, म_त्रुटि(त्रुटि_सं));

	क्रम (i = found = 0; i < अंक_KEYTYPES; i++) {
		अगर (कुंजी_fd[i] != -1)
			found = 1;
	}
	अगर (found == 0)
		fatal("could not open any host key");

	found = 0;
	क्रम (i = 0; i < अंक_KEYTYPES; i++) {
		कुंजियाँ[i] = शून्य;
		अगर (कुंजी_fd[i] == -1)
			जारी;
		r = sshkey_load_private_type_fd(कुंजी_fd[i], कुंजी_UNSPEC,
		    शून्य, &कुंजी, शून्य);
		बंद(कुंजी_fd[i]);
		अगर (r != 0)
			debug_r(r, "parse key %d", i);
		अन्यथा अगर (कुंजी != शून्य) {
			कुंजियाँ[i] = कुंजी;
			found = 1;
		}
	}
	अगर (!found)
		fatal("no hostkey found");

	अगर ((b = sshbuf_new()) == शून्य)
		fatal("%s: sshbuf_new failed", __progname);
	अगर (ssh_संदेश_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	अगर ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	अगर (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	अगर ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	अगर (fd <= STDERR_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	अगर ((host = get_local_name(fd)) == शून्य)
		fatal("%s: cannot get local name for fd", __progname);

	अगर ((r = sshbuf_get_string(b, &तथ्य, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	अगर (valid_request(pw, host, &कुंजी, &pkalg, तथ्य, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	मुक्त(host);

	found = 0;
	क्रम (i = 0; i < अंक_KEYTYPES; i++) {
		अगर (कुंजियाँ[i] != शून्य &&
		    sshkey_equal_public(कुंजी, कुंजियाँ[i])) {
			found = 1;
			अवरोध;
		}
	}
	अगर (!found) {
		अगर ((fp = sshkey_fingerprint(कुंजी, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == शून्य)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(कुंजी), fp ? fp : "");
	}

	अगर ((r = sshkey_sign(कुंजियाँ[i], &signature, &slen, तथ्य, dlen,
	    pkalg, शून्य, शून्य, 0)) != 0)
		fatal_r(r, "%s: sshkey_sign failed", __progname);
	मुक्त(तथ्य);

	/* send reply */
	sshbuf_reset(b);
	अगर ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	अगर (ssh_संदेश_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	वापस (0);
}
