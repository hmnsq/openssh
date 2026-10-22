/* $OpenBSD: hostfile.c,v 1.100 2025/11/25 00:57:04 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for manipulating the known hosts files.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 1999, 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
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

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <netinet/in.h>

#समावेश <errno.h>
#समावेश <resolv.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "match.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "pathnames.h"
#समावेश "ssherr.h"
#समावेश "digest.h"
#समावेश "hmac.h"
#समावेश "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

अटल पूर्णांक
extract_salt(स्थिर अक्षर *s, u_int l, u_char *salt, माप_प्रकार salt_len)
{
	अक्षर *p, *b64salt;
	u_int b64len;
	पूर्णांक ret;

	अगर (l < माप(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		वापस (-1);
	}
	अगर (म_भेदन(s, HASH_MAGIC, माप(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		वापस (-1);
	}
	s += माप(HASH_MAGIC) - 1;
	l -= माप(HASH_MAGIC) - 1;
	अगर ((p = स_प्रथम(s, HASH_DELIM, l)) == शून्य) {
		debug2("extract_salt: missing salt termination character");
		वापस (-1);
	}

	b64len = p - s;
	/* Sanity check */
	अगर (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		वापस (-1);
	}
	b64salt = xmalloc(1 + b64len);
	स_नकल(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	मुक्त(b64salt);
	अगर (ret == -1) {
		debug2("extract_salt: salt decode error");
		वापस (-1);
	}
	अगर (ret != (पूर्णांक)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		वापस (-1);
	}

	वापस (0);
}

अक्षर *
host_hash(स्थिर अक्षर *host, स्थिर अक्षर *name_from_hostfile, u_int src_len)
{
	काष्ठा ssh_hmac_ctx *ctx;
	u_char salt[256], परिणाम[256];
	अक्षर uu_salt[512], uu_परिणाम[512];
	अक्षर *encoded = शून्य;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	अगर (name_from_hostfile == शून्य) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} अन्यथा {
		/* Extract salt from known host entry */
		अगर (extract_salt(name_from_hostfile, src_len, salt,
		    माप(salt)) == -1)
			वापस (शून्य);
	}

	अगर ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == शून्य ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, म_माप(host)) < 0 ||
	    ssh_hmac_final(ctx, परिणाम, माप(परिणाम)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	अगर (__b64_ntop(salt, len, uu_salt, माप(uu_salt)) == -1 ||
	    __b64_ntop(परिणाम, len, uu_परिणाम, माप(uu_परिणाम)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_परिणाम);

	वापस (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

पूर्णांक
hostfile_read_कुंजी(अक्षर **cpp, u_int *bitsp, काष्ठा sshkey *ret)
{
	अक्षर *cp;

	/* Skip leading whitespace. */
	क्रम (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	अगर (sshkey_read(ret, &cp) != 0)
		वापस 0;

	/* Skip trailing whitespace. */
	क्रम (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	अगर (bitsp != शून्य)
		*bitsp = sshkey_आकार(ret);
	वापस 1;
}

अटल HostkeyMarker
check_markers(अक्षर **cpp)
{
	अक्षर marker[32], *sp, *cp = *cpp;
	पूर्णांक ret = MRK_NONE;

	जबतक (*cp == '@') {
		/* Only one marker is allowed */
		अगर (ret != MRK_NONE)
			वापस MRK_ERROR;
		/* Markers are terminated by whitespace */
		अगर ((sp = म_अक्षर(cp, ' ')) == शून्य &&
		    (sp = म_अक्षर(cp, '\t')) == शून्य)
			वापस MRK_ERROR;
		/* Extract marker for comparison */
		अगर (sp <= cp + 1 || sp >= cp + माप(marker))
			वापस MRK_ERROR;
		स_नकल(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		अगर (म_भेद(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		अन्यथा अगर (म_भेद(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		अन्यथा
			वापस MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		क्रम (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	वापस ret;
}

काष्ठा hostkeys *
init_hostkeys(व्योम)
{
	काष्ठा hostkeys *ret = xcalloc(1, माप(*ret));

	ret->entries = शून्य;
	वापस ret;
}

काष्ठा load_callback_ctx {
	स्थिर अक्षर *host;
	u_long अंक_loaded;
	काष्ठा hostkeys *hostkeys;
};

अटल पूर्णांक
record_hostkey(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *_ctx)
{
	काष्ठा load_callback_ctx *ctx = (काष्ठा load_callback_ctx *)_ctx;
	काष्ठा hostkeys *hostkeys = ctx->hostkeys;
	काष्ठा hostkey_entry *tmp;

	अगर (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		वापस 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->कुंजी), l->path, l->linenum);
	अगर ((tmp = recallocarray(hostkeys->entries, hostkeys->अंक_entries,
	    hostkeys->अंक_entries + 1, माप(*hostkeys->entries))) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->अंक_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->अंक_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->अंक_entries].पंक्ति = l->linenum;
	hostkeys->entries[hostkeys->अंक_entries].कुंजी = l->कुंजी;
	l->कुंजी = शून्य; /* steal it */
	hostkeys->entries[hostkeys->अंक_entries].marker = l->marker;
	hostkeys->entries[hostkeys->अंक_entries].note = l->note;
	hostkeys->अंक_entries++;
	ctx->अंक_loaded++;

	वापस 0;
}

व्योम
load_hostkeys_file(काष्ठा hostkeys *hostkeys, स्थिर अक्षर *host,
    स्थिर अक्षर *path, खाता *f, u_int note)
{
	पूर्णांक r;
	काष्ठा load_callback_ctx ctx;

	ctx.host = host;
	ctx.अंक_loaded = 0;
	ctx.hostkeys = hostkeys;

	अगर ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    शून्य, HKF_WANT_MATCH|HKF_WANT_PARSE_कुंजी, note)) != 0) {
		अगर (r != SSH_ERR_SYSTEM_ERROR && त्रुटि_सं != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	अगर (ctx.अंक_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.अंक_loaded, host);
}

व्योम
load_hostkeys(काष्ठा hostkeys *hostkeys, स्थिर अक्षर *host, स्थिर अक्षर *path,
    u_int note)
{
	खाता *f;

	अगर ((f = ख_खोलो(path, "r")) == शून्य) {
		debug_f("fopen %s: %s", path, म_त्रुटि(त्रुटि_सं));
		वापस;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	ख_बंद(f);
}

व्योम
free_hostkeys(काष्ठा hostkeys *hostkeys)
{
	u_int i;

	क्रम (i = 0; i < hostkeys->अंक_entries; i++) {
		मुक्त(hostkeys->entries[i].host);
		मुक्त(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].कुंजी);
		explicit_bzero(hostkeys->entries + i, माप(*hostkeys->entries));
	}
	मुक्त(hostkeys->entries);
	freezero(hostkeys, माप(*hostkeys));
}

अटल पूर्णांक
check_कुंजी_not_revoked(काष्ठा hostkeys *hostkeys, काष्ठा sshkey *k)
{
	पूर्णांक is_cert = sshkey_is_cert(k);
	u_int i;

	क्रम (i = 0; i < hostkeys->अंक_entries; i++) {
		अगर (hostkeys->entries[i].marker != MRK_REVOKE)
			जारी;
		अगर (sshkey_equal_public(k, hostkeys->entries[i].कुंजी))
			वापस -1;
		अगर (is_cert && k != शून्य &&
		    sshkey_equal_public(k->cert->signature_कुंजी,
		    hostkeys->entries[i].कुंजी))
			वापस -1;
	}
	वापस 0;
}

/*
 * Match keys against a specified key, or look one up by key type.
 *
 * If looking for a keytype (key == NULL) and one is found then return
 * HOST_FOUND, otherwise HOST_NEW.
 *
 * If looking for a key (key != NULL):
 *  1. If the key is a cert and a matching CA is found, return HOST_OK
 *  2. If the key is not a cert and a matching key is found, return HOST_OK
 *  3. If no key matches but a key with a different type is found, then
 *     return HOST_CHANGED
 *  4. If no matching keys are found, then return HOST_NEW.
 *
 * Finally, check any found key is not revoked.
 */
अटल HostStatus
check_hostkeys_by_कुंजी_or_type(काष्ठा hostkeys *hostkeys,
    काष्ठा sshkey *k, पूर्णांक keytype, पूर्णांक nid, स्थिर काष्ठा hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	पूर्णांक want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	अगर (found != शून्य)
		*found = शून्य;

	क्रम (i = 0; i < hostkeys->अंक_entries; i++) {
		अगर (hostkeys->entries[i].marker != want_marker)
			जारी;
		अगर (k == शून्य) {
			अगर (hostkeys->entries[i].कुंजी->type != keytype)
				जारी;
			अगर (nid != -1 &&
			    sshkey_type_plain(keytype) == कुंजी_ECDSA &&
			    hostkeys->entries[i].कुंजी->ecdsa_nid != nid)
				जारी;
			end_return = HOST_FOUND;
			अगर (found != शून्य)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].कुंजी;
			अवरोध;
		}
		अगर (want_cert) {
			अगर (sshkey_equal_public(k->cert->signature_कुंजी,
			    hostkeys->entries[i].कुंजी)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				अगर (found != शून्य)
					*found = hostkeys->entries + i;
				अवरोध;
			}
		} अन्यथा {
			अगर (sshkey_equal(k, hostkeys->entries[i].कुंजी)) {
				end_return = HOST_OK;
				अगर (found != शून्य)
					*found = hostkeys->entries + i;
				अवरोध;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			अगर (found != शून्य)
				*found = hostkeys->entries + i;
		}
	}
	अगर (check_कुंजी_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		अगर (found != शून्य)
			*found = शून्य;
	}
	वापस end_return;
}

HostStatus
check_कुंजी_in_hostkeys(काष्ठा hostkeys *hostkeys, काष्ठा sshkey *कुंजी,
    स्थिर काष्ठा hostkey_entry **found)
{
	अगर (कुंजी == शून्य)
		fatal("no key to look up");
	वापस check_hostkeys_by_कुंजी_or_type(hostkeys, कुंजी, 0, -1, found);
}

पूर्णांक
lookup_कुंजी_in_hostkeys_by_type(काष्ठा hostkeys *hostkeys, पूर्णांक keytype, पूर्णांक nid,
    स्थिर काष्ठा hostkey_entry **found)
{
	वापस (check_hostkeys_by_कुंजी_or_type(hostkeys, शून्य, keytype, nid,
	    found) == HOST_FOUND);
}

पूर्णांक
lookup_marker_in_hostkeys(काष्ठा hostkeys *hostkeys, पूर्णांक want_marker)
{
	u_int i;

	क्रम (i = 0; i < hostkeys->अंक_entries; i++) {
		अगर (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			वापस 1;
	}
	वापस 0;
}

अटल पूर्णांक
format_host_entry(काष्ठा sshbuf *entry, स्थिर अक्षर *host, स्थिर अक्षर *ip,
    स्थिर काष्ठा sshkey *कुंजी, पूर्णांक store_hash)
{
	पूर्णांक r, success = 0;
	अक्षर *hashed_host = शून्य, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	अगर (store_hash) {
		अगर ((hashed_host = host_hash(lhost, शून्य, 0)) == शून्य) {
			error_f("host_hash failed");
			मुक्त(lhost);
			वापस 0;
		}
		अगर ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} अन्यथा अगर (ip != शून्य) {
		अगर ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} अन्यथा {
		अगर ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	मुक्त(hashed_host);
	मुक्त(lhost);
	अगर ((r = sshkey_format_text(कुंजी, entry)) == 0)
		success = 1;
	अन्यथा
		error_fr(r, "sshkey_write");
	अगर ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	अगर (success && store_hash && ip != शून्य)
		success = format_host_entry(entry, ip, शून्य, कुंजी, 1);
	वापस success;
}

अटल पूर्णांक
write_host_entry(खाता *f, स्थिर अक्षर *host, स्थिर अक्षर *ip,
    स्थिर काष्ठा sshkey *कुंजी, पूर्णांक store_hash)
{
	पूर्णांक r, success = 0;
	काष्ठा sshbuf *entry = शून्य;

	अगर ((entry = sshbuf_new()) == शून्य)
		fatal_f("allocation failed");
	अगर ((r = format_host_entry(entry, host, ip, कुंजी, store_hash)) != 1) {
		debug_f("failed to format host entry");
		जाओ out;
	}
	अगर ((r = ख_डालो(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	वापस success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
व्योम
hostfile_create_user_ssh_dir(स्थिर अक्षर *filename, पूर्णांक notify)
{
	अक्षर *dotsshdir = शून्य, *p;
	माप_प्रकार len;
	काष्ठा stat st;

	अगर ((p = म_खोजप(filename, '/')) == शून्य)
		वापस;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	अगर (म_माप(dotsshdir) > len || म_भेदन(filename, dotsshdir, len) != 0)
		जाओ out; /* not ~/.ssh prefixed */
	अगर (stat(dotsshdir, &st) == 0)
		जाओ out; /* dir already exists */
	अन्यथा अगर (त्रुटि_सं != ENOENT)
		error("Could not stat %s: %s", dotsshdir, म_त्रुटि(त्रुटि_सं));
	अन्यथा {
#अगर_घोषित WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#पूर्ण_अगर
		अगर (सूची_गढ़ो(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, म_त्रुटि(त्रुटि_सं));
		अन्यथा अगर (notify)
			logit("Created directory '%s'.", dotsshdir);
#अगर_घोषित WITH_SELINUX
		ssh_selinux_setfscreatecon(शून्य);
#पूर्ण_अगर
	}
 out:
	मुक्त(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
पूर्णांक
add_host_to_hostfile(स्थिर अक्षर *filename, स्थिर अक्षर *host,
    स्थिर काष्ठा sshkey *कुंजी, पूर्णांक store_hash)
{
	खाता *f;
	पूर्णांक success, addnl = 0;

	अगर (कुंजी == शून्य)
		वापस 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	अगर ((f = ख_खोलो(filename, "a+")) == शून्य)
		वापस 0;
	रखो_भबफ(f, शून्य, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	अगर (ख_जाओ(f, -1L, अंत_से) == 0 && ख_अक्षर_लो(f) != '\n')
		addnl = 1;
	अगर (ख_जाओ(f, 0L, अंत_से) != 0 || (addnl && ख_अक्षर_दो('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, म_त्रुटि(त्रुटि_सं));
		ख_बंद(f);
		वापस 0;
	}
	success = write_host_entry(f, host, शून्य, कुंजी, store_hash);
	ख_बंद(f);
	वापस success;
}

काष्ठा host_delete_ctx {
	खाता *out;
	पूर्णांक quiet;
	स्थिर अक्षर *host, *ip;
	u_int *match_कुंजियाँ;	/* mask of HKF_MATCH_* for this key */
	काष्ठा sshkey * स्थिर *कुंजियाँ;
	माप_प्रकार nkeys;
	पूर्णांक modified;
};

अटल पूर्णांक
host_delete(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *_ctx)
{
	काष्ठा host_delete_ctx *ctx = (काष्ठा host_delete_ctx *)_ctx;
	पूर्णांक loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	माप_प्रकार i;

	/* Don't remove CA and revocation lines */
	अगर (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		क्रम (i = 0; i < ctx->nkeys; i++) {
			अगर (!sshkey_equal(ctx->कुंजियाँ[i], l->कुंजी))
				जारी;
			ctx->match_कुंजियाँ[i] |= l->match;
			ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->कुंजी), l->path, l->linenum);
			वापस 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->कुंजी), ctx->host);
		ctx->modified = 1;
		वापस 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	अगर (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
	वापस 0;
}

पूर्णांक
hostfile_replace_entries(स्थिर अक्षर *filename, स्थिर अक्षर *host, स्थिर अक्षर *ip,
    काष्ठा sshkey **कुंजियाँ, माप_प्रकार nkeys, पूर्णांक store_hash, पूर्णांक quiet, पूर्णांक hash_alg)
{
	पूर्णांक r, fd, oerrno = 0;
	पूर्णांक loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	काष्ठा host_delete_ctx ctx;
	अक्षर *fp = शून्य, *अस्थायी = शून्य, *back = शून्य;
	स्थिर अक्षर *what;
	mode_t omask;
	माप_प्रकार i;
	u_int want;

	omask = umask(077);

	स_रखो(&ctx, 0, माप(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	अगर ((ctx.match_कुंजियाँ = सुस्मृति(nkeys, माप(*ctx.match_कुंजियाँ))) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	ctx.कुंजियाँ = कुंजियाँ;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	अगर ((r = asprintf(&अस्थायी, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ fail;
	}

	अगर ((fd = mkstemp(अस्थायी)) == -1) {
		oerrno = त्रुटि_सं;
		error_f("mkstemp: %s", म_त्रुटि(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		जाओ fail;
	}
	अगर ((ctx.out = fdopen(fd, "w")) == शून्य) {
		oerrno = त्रुटि_सं;
		बंद(fd);
		error_f("fdopen: %s", म_त्रुटि(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		जाओ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	अगर ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_कुंजी, 0)) != 0) {
		oerrno = त्रुटि_सं;
		error_fr(r, "hostkeys_foreach");
		जाओ fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == शून्य ? 0 : HKF_MATCH_IP);
	क्रम (i = 0; i < nkeys; i++) {
		अगर (कुंजियाँ[i] == शून्य || (want & ctx.match_कुंजियाँ[i]) == want)
			जारी;
		अगर ((fp = sshkey_fingerprint(कुंजियाँ[i], hash_alg,
		    SSH_FP_DEFAULT)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ fail;
		}
		/* write host/ip */
		what = "";
		अगर (ctx.match_कुंजियाँ[i] == 0) {
			what = "Adding new key";
			अगर (!write_host_entry(ctx.out, host, ip,
			    कुंजियाँ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				जाओ fail;
			}
		} अन्यथा अगर ((want & ~ctx.match_कुंजियाँ[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			अगर (!write_host_entry(ctx.out, host, शून्य,
			    कुंजियाँ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				जाओ fail;
			}
		} अन्यथा अगर ((want & ~ctx.match_कुंजियाँ[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			अगर (!write_host_entry(ctx.out, ip, शून्य,
			    कुंजियाँ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				जाओ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == शून्य ? "" : ",", ip == शून्य ? "" : ip, filename,
		    sshkey_ssh_name(कुंजियाँ[i]), fp);
		मुक्त(fp);
		fp = शून्य;
		ctx.modified = 1;
	}
	ख_बंद(ctx.out);
	ctx.out = शून्य;

	अगर (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		अगर (unlink(back) == -1 && त्रुटि_सं != ENOENT) {
			oerrno = त्रुटि_सं;
			error_f("unlink %.100s: %s", back, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			जाओ fail;
		}
		अगर (link(filename, back) == -1) {
			oerrno = त्रुटि_सं;
			error_f("link %.100s to %.100s: %s", filename,
			    back, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			जाओ fail;
		}
		अगर (नाम(अस्थायी, filename) == -1) {
			oerrno = त्रुटि_सं;
			error_f("rename \"%s\" to \"%s\": %s", अस्थायी,
			    filename, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			जाओ fail;
		}
	} अन्यथा {
		/* No changes made; just delete the temporary file */
		अगर (unlink(अस्थायी) != 0)
			error_f("unlink \"%s\": %s", अस्थायी, म_त्रुटि(त्रुटि_सं));
	}

	/* success */
	r = 0;
 fail:
	अगर (अस्थायी != शून्य && r != 0)
		unlink(अस्थायी);
	मुक्त(अस्थायी);
	मुक्त(back);
	मुक्त(fp);
	अगर (ctx.out != शून्य)
		ख_बंद(ctx.out);
	मुक्त(ctx.match_कुंजियाँ);
	umask(omask);
	अगर (r == SSH_ERR_SYSTEM_ERROR)
		त्रुटि_सं = oerrno;
	वापस r;
}

अटल पूर्णांक
match_maybe_hashed(स्थिर अक्षर *host, स्थिर अक्षर *names, पूर्णांक *was_hashed)
{
	पूर्णांक hashed = *names == HASH_DELIM, ret;
	अक्षर *hashed_host = शून्य;
	माप_प्रकार nlen = म_माप(names);

	अगर (was_hashed != शून्य)
		*was_hashed = hashed;
	अगर (hashed) {
		अगर ((hashed_host = host_hash(host, names, nlen)) == शून्य)
			वापस -1;
		ret = (nlen == म_माप(hashed_host) &&
		    म_भेदन(hashed_host, names, nlen) == 0);
		मुक्त(hashed_host);
		वापस ret;
	}
	वापस match_hostname(host, names) == 1;
}

पूर्णांक
hostkeys_foreach_file(स्थिर अक्षर *path, खाता *f, hostkeys_foreach_fn *callback,
    व्योम *ctx, स्थिर अक्षर *host, स्थिर अक्षर *ip, u_int options, u_int note)
{
	अक्षर *पंक्ति = शून्य, ktype[128];
	u_long linenum = 0;
	अक्षर *cp, *cp2;
	u_int kbits;
	पूर्णांक hashed;
	पूर्णांक s, r = 0;
	काष्ठा hostkey_foreach_पंक्ति lineinfo;
	माप_प्रकार linesize = 0, l;

	स_रखो(&lineinfo, 0, माप(lineinfo));
	अगर (host == शून्य && (options & HKF_WANT_MATCH) != 0)
		वापस SSH_ERR_INVALID_ARGUMENT;

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		पंक्ति[म_खोज(पंक्ति, "\n")] = '\0';

		मुक्त(lineinfo.पंक्ति);
		sshkey_free(lineinfo.कुंजी);
		स_रखो(&lineinfo, 0, माप(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.पंक्ति = xstrdup(पंक्ति);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = कुंजी_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		क्रम (cp = पंक्ति; *cp == ' ' || *cp == '\t'; cp++)
			;
		अगर (!*cp || *cp == '#' || *cp == '\n') {
			अगर ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				अगर ((r = callback(&lineinfo, ctx)) != 0)
					अवरोध;
			}
			जारी;
		}

		अगर ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			अगर ((options & HKF_WANT_MATCH) == 0)
				जाओ bad;
			जारी;
		}

		/* Find the end of the host name portion. */
		क्रम (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		अगर (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			अगर ((options & HKF_WANT_MATCH) == 0)
				जाओ bad;
			जारी;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		अगर (host != शून्य) {
			अगर ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				जाओ bad;
			}
			अगर (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			अगर (ip != शून्य) {
				अगर ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					जाओ bad;
				}
				अगर (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			अगर ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				जारी;
		}

		/* Got a match.  Skip host name and any following whitespace */
		क्रम (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		अगर (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			जाओ bad;
		}
		lineinfo.rawkey = cp = cp2;

		अगर ((options & HKF_WANT_PARSE_कुंजी) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			अगर ((lineinfo.कुंजी = sshkey_new(कुंजी_UNSPEC)) == शून्य) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				अवरोध;
			}
			अगर (!hostfile_read_कुंजी(&cp, &kbits, lineinfo.कुंजी)) {
				जाओ bad;
			}
			lineinfo.keytype = lineinfo.कुंजी->type;
			lineinfo.comment = cp;
		} अन्यथा {
			/* Extract and parse key type */
			l = म_खोज(lineinfo.rawkey, " \t");
			अगर (l <= 1 || l >= माप(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				जाओ bad;
			स_नकल(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			अगर (lineinfo.keytype == कुंजी_UNSPEC && l < 8 &&
			    म_अखोज(ktype, "0123456789") == l)
				जाओ bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			क्रम (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			अगर (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = कुंजी_UNSPEC;
			}
			अगर (lineinfo.keytype == कुंजी_UNSPEC) {
 bad:
				sshkey_free(lineinfo.कुंजी);
				lineinfo.कुंजी = शून्य;
				lineinfo.status = HKF_STATUS_INVALID;
				अगर ((r = callback(&lineinfo, ctx)) != 0)
					अवरोध;
				जारी;
			}
		}
		अगर ((r = callback(&lineinfo, ctx)) != 0)
			अवरोध;
	}
	sshkey_free(lineinfo.कुंजी);
	मुक्त(lineinfo.पंक्ति);
	मुक्त(पंक्ति);
	वापस r;
}

पूर्णांक
hostkeys_foreach(स्थिर अक्षर *path, hostkeys_foreach_fn *callback, व्योम *ctx,
    स्थिर अक्षर *host, स्थिर अक्षर *ip, u_int options, u_int note)
{
	खाता *f;
	पूर्णांक r, oerrno;

	अगर ((f = ख_खोलो(path, "r")) == शून्य)
		वापस SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = त्रुटि_सं;
	ख_बंद(f);
	त्रुटि_सं = oerrno;
	वापस r;
}
