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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <netinet/in.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <resolv.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "hmac.h"
#അന്തര്ഭാവ "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

സ്ഥിതം പൂർണ്ണസംഖ്യ
extract_salt(സ്ഥിരം അക്ഷരം *s, u_int l, u_char *salt, size_t salt_len)
{
	അക്ഷരം *p, *b64salt;
	u_int b64len;
	പൂർണ്ണസംഖ്യ ret;

	എങ്കിൽ (l < വലുപ്പം(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		തിരികെ (-1);
	}
	എങ്കിൽ (strncmp(s, HASH_MAGIC, വലുപ്പം(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		തിരികെ (-1);
	}
	s += വലുപ്പം(HASH_MAGIC) - 1;
	l -= വലുപ്പം(HASH_MAGIC) - 1;
	എങ്കിൽ ((p = memchr(s, HASH_DELIM, l)) == ശൂന്യ) {
		debug2("extract_salt: missing salt termination character");
		തിരികെ (-1);
	}

	b64len = p - s;
	/* Sanity check */
	എങ്കിൽ (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		തിരികെ (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	സ്വതന്ത്രം(b64salt);
	എങ്കിൽ (ret == -1) {
		debug2("extract_salt: salt decode error");
		തിരികെ (-1);
	}
	എങ്കിൽ (ret != (പൂർണ്ണസംഖ്യ)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		തിരികെ (-1);
	}

	തിരികെ (0);
}

അക്ഷരം *
host_hash(സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *name_from_hostfile, u_int src_len)
{
	ഘടന ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	അക്ഷരം uu_salt[512], uu_result[512];
	അക്ഷരം *encoded = ശൂന്യ;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	എങ്കിൽ (name_from_hostfile == ശൂന്യ) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} അല്ലെങ്കിൽ {
		/* Extract salt from known host entry */
		എങ്കിൽ (extract_salt(name_from_hostfile, src_len, salt,
		    വലുപ്പം(salt)) == -1)
			തിരികെ (ശൂന്യ);
	}

	എങ്കിൽ ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == ശൂന്യ ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, വലുപ്പം(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	എങ്കിൽ (__b64_ntop(salt, len, uu_salt, വലുപ്പം(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, വലുപ്പം(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	തിരികെ (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

പൂർണ്ണസംഖ്യ
hostfile_read_താക്കോൽ(അക്ഷരം **cpp, u_int *bitsp, ഘടന sshkey *ret)
{
	അക്ഷരം *cp;

	/* Skip leading whitespace. */
	വേണ്ടി (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	എങ്കിൽ (sshkey_read(ret, &cp) != 0)
		തിരികെ 0;

	/* Skip trailing whitespace. */
	വേണ്ടി (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	എങ്കിൽ (bitsp != ശൂന്യ)
		*bitsp = sshkey_size(ret);
	തിരികെ 1;
}

സ്ഥിതം HostkeyMarker
check_markers(അക്ഷരം **cpp)
{
	അക്ഷരം marker[32], *sp, *cp = *cpp;
	പൂർണ്ണസംഖ്യ ret = MRK_NONE;

	ആകുമ്പോൾ (*cp == '@') {
		/* Only one marker is allowed */
		എങ്കിൽ (ret != MRK_NONE)
			തിരികെ MRK_ERROR;
		/* Markers are terminated by whitespace */
		എങ്കിൽ ((sp = strchr(cp, ' ')) == ശൂന്യ &&
		    (sp = strchr(cp, '\t')) == ശൂന്യ)
			തിരികെ MRK_ERROR;
		/* Extract marker for comparison */
		എങ്കിൽ (sp <= cp + 1 || sp >= cp + വലുപ്പം(marker))
			തിരികെ MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		എങ്കിൽ (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		അല്ലെങ്കിൽ എങ്കിൽ (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		അല്ലെങ്കിൽ
			തിരികെ MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		വേണ്ടി (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	തിരികെ ret;
}

ഘടന hostkeys *
init_hostkeys(ശൂന്യം)
{
	ഘടന hostkeys *ret = xcalloc(1, വലുപ്പം(*ret));

	ret->entries = ശൂന്യ;
	തിരികെ ret;
}

ഘടന load_callback_ctx {
	സ്ഥിരം അക്ഷരം *host;
	u_long അക്കം_loaded;
	ഘടന hostkeys *hostkeys;
};

സ്ഥിതം പൂർണ്ണസംഖ്യ
record_hostkey(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *_ctx)
{
	ഘടന load_callback_ctx *ctx = (ഘടന load_callback_ctx *)_ctx;
	ഘടന hostkeys *hostkeys = ctx->hostkeys;
	ഘടന hostkey_entry *tmp;

	എങ്കിൽ (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		തിരികെ 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->താക്കോൽ), l->path, l->linenum);
	എങ്കിൽ ((tmp = recallocarray(hostkeys->entries, hostkeys->അക്കം_entries,
	    hostkeys->അക്കം_entries + 1, വലുപ്പം(*hostkeys->entries))) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->അക്കം_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->അക്കം_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->അക്കം_entries].വരി = l->linenum;
	hostkeys->entries[hostkeys->അക്കം_entries].താക്കോൽ = l->താക്കോൽ;
	l->താക്കോൽ = ശൂന്യ; /* steal it */
	hostkeys->entries[hostkeys->അക്കം_entries].marker = l->marker;
	hostkeys->entries[hostkeys->അക്കം_entries].note = l->note;
	hostkeys->അക്കം_entries++;
	ctx->അക്കം_loaded++;

	തിരികെ 0;
}

ശൂന്യം
load_hostkeys_file(ഘടന hostkeys *hostkeys, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം അക്ഷരം *path, FILE *f, u_int note)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന load_callback_ctx ctx;

	ctx.host = host;
	ctx.അക്കം_loaded = 0;
	ctx.hostkeys = hostkeys;

	എങ്കിൽ ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    ശൂന്യ, HKF_WANT_MATCH|HKF_WANT_PARSE_താക്കോൽ, note)) != 0) {
		എങ്കിൽ (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	എങ്കിൽ (ctx.അക്കം_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.അക്കം_loaded, host);
}

ശൂന്യം
load_hostkeys(ഘടന hostkeys *hostkeys, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *path,
    u_int note)
{
	FILE *f;

	എങ്കിൽ ((f = fopen(path, "r")) == ശൂന്യ) {
		debug_f("fopen %s: %s", path, strerror(errno));
		തിരികെ;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

ശൂന്യം
free_hostkeys(ഘടന hostkeys *hostkeys)
{
	u_int i;

	വേണ്ടി (i = 0; i < hostkeys->അക്കം_entries; i++) {
		സ്വതന്ത്രം(hostkeys->entries[i].host);
		സ്വതന്ത്രം(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].താക്കോൽ);
		explicit_bzero(hostkeys->entries + i, വലുപ്പം(*hostkeys->entries));
	}
	സ്വതന്ത്രം(hostkeys->entries);
	freezero(hostkeys, വലുപ്പം(*hostkeys));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_താക്കോൽ_not_revoked(ഘടന hostkeys *hostkeys, ഘടന sshkey *k)
{
	പൂർണ്ണസംഖ്യ is_cert = sshkey_is_cert(k);
	u_int i;

	വേണ്ടി (i = 0; i < hostkeys->അക്കം_entries; i++) {
		എങ്കിൽ (hostkeys->entries[i].marker != MRK_REVOKE)
			തുടരുക;
		എങ്കിൽ (sshkey_equal_public(k, hostkeys->entries[i].താക്കോൽ))
			തിരികെ -1;
		എങ്കിൽ (is_cert && k != ശൂന്യ &&
		    sshkey_equal_public(k->cert->signature_താക്കോൽ,
		    hostkeys->entries[i].താക്കോൽ))
			തിരികെ -1;
	}
	തിരികെ 0;
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
സ്ഥിതം HostStatus
check_hostkeys_by_താക്കോൽ_or_type(ഘടന hostkeys *hostkeys,
    ഘടന sshkey *k, പൂർണ്ണസംഖ്യ keytype, പൂർണ്ണസംഖ്യ nid, സ്ഥിരം ഘടന hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	പൂർണ്ണസംഖ്യ want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	എങ്കിൽ (found != ശൂന്യ)
		*found = ശൂന്യ;

	വേണ്ടി (i = 0; i < hostkeys->അക്കം_entries; i++) {
		എങ്കിൽ (hostkeys->entries[i].marker != want_marker)
			തുടരുക;
		എങ്കിൽ (k == ശൂന്യ) {
			എങ്കിൽ (hostkeys->entries[i].താക്കോൽ->type != keytype)
				തുടരുക;
			എങ്കിൽ (nid != -1 &&
			    sshkey_type_plain(keytype) == താക്കോൽ_ECDSA &&
			    hostkeys->entries[i].താക്കോൽ->ecdsa_nid != nid)
				തുടരുക;
			end_return = HOST_FOUND;
			എങ്കിൽ (found != ശൂന്യ)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].താക്കോൽ;
			നിർത്തുക;
		}
		എങ്കിൽ (want_cert) {
			എങ്കിൽ (sshkey_equal_public(k->cert->signature_താക്കോൽ,
			    hostkeys->entries[i].താക്കോൽ)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				എങ്കിൽ (found != ശൂന്യ)
					*found = hostkeys->entries + i;
				നിർത്തുക;
			}
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (sshkey_equal(k, hostkeys->entries[i].താക്കോൽ)) {
				end_return = HOST_OK;
				എങ്കിൽ (found != ശൂന്യ)
					*found = hostkeys->entries + i;
				നിർത്തുക;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			എങ്കിൽ (found != ശൂന്യ)
				*found = hostkeys->entries + i;
		}
	}
	എങ്കിൽ (check_താക്കോൽ_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		എങ്കിൽ (found != ശൂന്യ)
			*found = ശൂന്യ;
	}
	തിരികെ end_return;
}

HostStatus
check_താക്കോൽ_in_hostkeys(ഘടന hostkeys *hostkeys, ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം ഘടന hostkey_entry **found)
{
	എങ്കിൽ (താക്കോൽ == ശൂന്യ)
		fatal("no key to look up");
	തിരികെ check_hostkeys_by_താക്കോൽ_or_type(hostkeys, താക്കോൽ, 0, -1, found);
}

പൂർണ്ണസംഖ്യ
lookup_താക്കോൽ_in_hostkeys_by_type(ഘടന hostkeys *hostkeys, പൂർണ്ണസംഖ്യ keytype, പൂർണ്ണസംഖ്യ nid,
    സ്ഥിരം ഘടന hostkey_entry **found)
{
	തിരികെ (check_hostkeys_by_താക്കോൽ_or_type(hostkeys, ശൂന്യ, keytype, nid,
	    found) == HOST_FOUND);
}

പൂർണ്ണസംഖ്യ
lookup_marker_in_hostkeys(ഘടന hostkeys *hostkeys, പൂർണ്ണസംഖ്യ want_marker)
{
	u_int i;

	വേണ്ടി (i = 0; i < hostkeys->അക്കം_entries; i++) {
		എങ്കിൽ (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			തിരികെ 1;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
format_host_entry(ഘടന sshbuf *entry, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip,
    സ്ഥിരം ഘടന sshkey *താക്കോൽ, പൂർണ്ണസംഖ്യ store_hash)
{
	പൂർണ്ണസംഖ്യ r, success = 0;
	അക്ഷരം *hashed_host = ശൂന്യ, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	എങ്കിൽ (store_hash) {
		എങ്കിൽ ((hashed_host = host_hash(lhost, ശൂന്യ, 0)) == ശൂന്യ) {
			error_f("host_hash failed");
			സ്വതന്ത്രം(lhost);
			തിരികെ 0;
		}
		എങ്കിൽ ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} അല്ലെങ്കിൽ എങ്കിൽ (ip != ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	സ്വതന്ത്രം(hashed_host);
	സ്വതന്ത്രം(lhost);
	എങ്കിൽ ((r = sshkey_format_text(താക്കോൽ, entry)) == 0)
		success = 1;
	അല്ലെങ്കിൽ
		error_fr(r, "sshkey_write");
	എങ്കിൽ ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	എങ്കിൽ (success && store_hash && ip != ശൂന്യ)
		success = format_host_entry(entry, ip, ശൂന്യ, താക്കോൽ, 1);
	തിരികെ success;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
write_host_entry(FILE *f, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip,
    സ്ഥിരം ഘടന sshkey *താക്കോൽ, പൂർണ്ണസംഖ്യ store_hash)
{
	പൂർണ്ണസംഖ്യ r, success = 0;
	ഘടന sshbuf *entry = ശൂന്യ;

	എങ്കിൽ ((entry = sshbuf_new()) == ശൂന്യ)
		fatal_f("allocation failed");
	എങ്കിൽ ((r = format_host_entry(entry, host, ip, താക്കോൽ, store_hash)) != 1) {
		debug_f("failed to format host entry");
		പോകുക out;
	}
	എങ്കിൽ ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		പോകുക out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	തിരികെ success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
ശൂന്യം
hostfile_create_user_ssh_dir(സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ notify)
{
	അക്ഷരം *dotsshdir = ശൂന്യ, *p;
	size_t len;
	ഘടന stat st;

	എങ്കിൽ ((p = strrchr(filename, '/')) == ശൂന്യ)
		തിരികെ;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	എങ്കിൽ (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		പോകുക out; /* not ~/.ssh prefixed */
	എങ്കിൽ (stat(dotsshdir, &st) == 0)
		പോകുക out; /* dir already exists */
	അല്ലെങ്കിൽ എങ്കിൽ (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	അല്ലെങ്കിൽ {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		എങ്കിൽ (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		അല്ലെങ്കിൽ എങ്കിൽ (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(ശൂന്യ);
#endif
	}
 out:
	സ്വതന്ത്രം(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
പൂർണ്ണസംഖ്യ
add_host_to_hostfile(സ്ഥിരം അക്ഷരം *filename, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം ഘടന sshkey *താക്കോൽ, പൂർണ്ണസംഖ്യ store_hash)
{
	FILE *f;
	പൂർണ്ണസംഖ്യ success, addnl = 0;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ)
		തിരികെ 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	എങ്കിൽ ((f = fopen(filename, "a+")) == ശൂന്യ)
		തിരികെ 0;
	setvbuf(f, ശൂന്യ, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	എങ്കിൽ (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	എങ്കിൽ (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		തിരികെ 0;
	}
	success = write_host_entry(f, host, ശൂന്യ, താക്കോൽ, store_hash);
	fclose(f);
	തിരികെ success;
}

ഘടന host_delete_ctx {
	FILE *out;
	പൂർണ്ണസംഖ്യ quiet;
	സ്ഥിരം അക്ഷരം *host, *ip;
	u_int *match_താക്കോലുകൾ;	/* mask of HKF_MATCH_* for this key */
	ഘടന sshkey * സ്ഥിരം *താക്കോലുകൾ;
	size_t nkeys;
	പൂർണ്ണസംഖ്യ modified;
};

സ്ഥിതം പൂർണ്ണസംഖ്യ
host_delete(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *_ctx)
{
	ഘടന host_delete_ctx *ctx = (ഘടന host_delete_ctx *)_ctx;
	പൂർണ്ണസംഖ്യ loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	എങ്കിൽ (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		വേണ്ടി (i = 0; i < ctx->nkeys; i++) {
			എങ്കിൽ (!sshkey_equal(ctx->താക്കോലുകൾ[i], l->താക്കോൽ))
				തുടരുക;
			ctx->match_താക്കോലുകൾ[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->വരി);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->താക്കോൽ), l->path, l->linenum);
			തിരികെ 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->താക്കോൽ), ctx->host);
		ctx->modified = 1;
		തിരികെ 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	എങ്കിൽ (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->വരി);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
hostfile_replace_entries(സ്ഥിരം അക്ഷരം *filename, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip,
    ഘടന sshkey **താക്കോലുകൾ, size_t nkeys, പൂർണ്ണസംഖ്യ store_hash, പൂർണ്ണസംഖ്യ quiet, പൂർണ്ണസംഖ്യ hash_alg)
{
	പൂർണ്ണസംഖ്യ r, fd, oerrno = 0;
	പൂർണ്ണസംഖ്യ loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ഘടന host_delete_ctx ctx;
	അക്ഷരം *fp = ശൂന്യ, *temp = ശൂന്യ, *back = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	എങ്കിൽ ((ctx.match_താക്കോലുകൾ = calloc(nkeys, വലുപ്പം(*ctx.match_താക്കോലുകൾ))) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	ctx.താക്കോലുകൾ = താക്കോലുകൾ;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	എങ്കിൽ ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക fail;
	}

	എങ്കിൽ ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		പോകുക fail;
	}
	എങ്കിൽ ((ctx.out = fdopen(fd, "w")) == ശൂന്യ) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		പോകുക fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	എങ്കിൽ ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_താക്കോൽ, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		പോകുക fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == ശൂന്യ ? 0 : HKF_MATCH_IP);
	വേണ്ടി (i = 0; i < nkeys; i++) {
		എങ്കിൽ (താക്കോലുകൾ[i] == ശൂന്യ || (want & ctx.match_താക്കോലുകൾ[i]) == want)
			തുടരുക;
		എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോലുകൾ[i], hash_alg,
		    SSH_FP_DEFAULT)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക fail;
		}
		/* write host/ip */
		what = "";
		എങ്കിൽ (ctx.match_താക്കോലുകൾ[i] == 0) {
			what = "Adding new key";
			എങ്കിൽ (!write_host_entry(ctx.out, host, ip,
			    താക്കോലുകൾ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				പോകുക fail;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ ((want & ~ctx.match_താക്കോലുകൾ[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			എങ്കിൽ (!write_host_entry(ctx.out, host, ശൂന്യ,
			    താക്കോലുകൾ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				പോകുക fail;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ ((want & ~ctx.match_താക്കോലുകൾ[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			എങ്കിൽ (!write_host_entry(ctx.out, ip, ശൂന്യ,
			    താക്കോലുകൾ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				പോകുക fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == ശൂന്യ ? "" : ",", ip == ശൂന്യ ? "" : ip, filename,
		    sshkey_ssh_name(താക്കോലുകൾ[i]), fp);
		സ്വതന്ത്രം(fp);
		fp = ശൂന്യ;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = ശൂന്യ;

	എങ്കിൽ (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		എങ്കിൽ (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			പോകുക fail;
		}
		എങ്കിൽ (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			പോകുക fail;
		}
		എങ്കിൽ (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			പോകുക fail;
		}
	} അല്ലെങ്കിൽ {
		/* No changes made; just delete the temporary file */
		എങ്കിൽ (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	എങ്കിൽ (temp != ശൂന്യ && r != 0)
		unlink(temp);
	സ്വതന്ത്രം(temp);
	സ്വതന്ത്രം(back);
	സ്വതന്ത്രം(fp);
	എങ്കിൽ (ctx.out != ശൂന്യ)
		fclose(ctx.out);
	സ്വതന്ത്രം(ctx.match_താക്കോലുകൾ);
	umask(omask);
	എങ്കിൽ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
match_maybe_hashed(സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *names, പൂർണ്ണസംഖ്യ *was_hashed)
{
	പൂർണ്ണസംഖ്യ hashed = *names == HASH_DELIM, ret;
	അക്ഷരം *hashed_host = ശൂന്യ;
	size_t nlen = strlen(names);

	എങ്കിൽ (was_hashed != ശൂന്യ)
		*was_hashed = hashed;
	എങ്കിൽ (hashed) {
		എങ്കിൽ ((hashed_host = host_hash(host, names, nlen)) == ശൂന്യ)
			തിരികെ -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		സ്വതന്ത്രം(hashed_host);
		തിരികെ ret;
	}
	തിരികെ match_hostname(host, names) == 1;
}

പൂർണ്ണസംഖ്യ
hostkeys_foreach_file(സ്ഥിരം അക്ഷരം *path, FILE *f, hostkeys_foreach_fn *callback,
    ശൂന്യം *ctx, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip, u_int options, u_int note)
{
	അക്ഷരം *വരി = ശൂന്യ, ktype[128];
	u_long linenum = 0;
	അക്ഷരം *cp, *cp2;
	u_int kbits;
	പൂർണ്ണസംഖ്യ hashed;
	പൂർണ്ണസംഖ്യ s, r = 0;
	ഘടന hostkey_foreach_വരി lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, വലുപ്പം(lineinfo));
	എങ്കിൽ (host == ശൂന്യ && (options & HKF_WANT_MATCH) != 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		linenum++;
		വരി[strcspn(വരി, "\n")] = '\0';

		സ്വതന്ത്രം(lineinfo.വരി);
		sshkey_free(lineinfo.താക്കോൽ);
		memset(&lineinfo, 0, വലുപ്പം(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.വരി = xstrdup(വരി);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = താക്കോൽ_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		വേണ്ടി (cp = വരി; *cp == ' ' || *cp == '\t'; cp++)
			;
		എങ്കിൽ (!*cp || *cp == '#' || *cp == '\n') {
			എങ്കിൽ ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				എങ്കിൽ ((r = callback(&lineinfo, ctx)) != 0)
					നിർത്തുക;
			}
			തുടരുക;
		}

		എങ്കിൽ ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			എങ്കിൽ ((options & HKF_WANT_MATCH) == 0)
				പോകുക bad;
			തുടരുക;
		}

		/* Find the end of the host name portion. */
		വേണ്ടി (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		എങ്കിൽ (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			എങ്കിൽ ((options & HKF_WANT_MATCH) == 0)
				പോകുക bad;
			തുടരുക;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		എങ്കിൽ (host != ശൂന്യ) {
			എങ്കിൽ ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				പോകുക bad;
			}
			എങ്കിൽ (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			എങ്കിൽ (ip != ശൂന്യ) {
				എങ്കിൽ ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					പോകുക bad;
				}
				എങ്കിൽ (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			എങ്കിൽ ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				തുടരുക;
		}

		/* Got a match.  Skip host name and any following whitespace */
		വേണ്ടി (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		എങ്കിൽ (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			പോകുക bad;
		}
		lineinfo.rawkey = cp = cp2;

		എങ്കിൽ ((options & HKF_WANT_PARSE_താക്കോൽ) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			എങ്കിൽ ((lineinfo.താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				നിർത്തുക;
			}
			എങ്കിൽ (!hostfile_read_താക്കോൽ(&cp, &kbits, lineinfo.താക്കോൽ)) {
				പോകുക bad;
			}
			lineinfo.keytype = lineinfo.താക്കോൽ->type;
			lineinfo.comment = cp;
		} അല്ലെങ്കിൽ {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			എങ്കിൽ (l <= 1 || l >= വലുപ്പം(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				പോകുക bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			എങ്കിൽ (lineinfo.keytype == താക്കോൽ_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				പോകുക bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			വേണ്ടി (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			എങ്കിൽ (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = താക്കോൽ_UNSPEC;
			}
			എങ്കിൽ (lineinfo.keytype == താക്കോൽ_UNSPEC) {
 bad:
				sshkey_free(lineinfo.താക്കോൽ);
				lineinfo.താക്കോൽ = ശൂന്യ;
				lineinfo.status = HKF_STATUS_INVALID;
				എങ്കിൽ ((r = callback(&lineinfo, ctx)) != 0)
					നിർത്തുക;
				തുടരുക;
			}
		}
		എങ്കിൽ ((r = callback(&lineinfo, ctx)) != 0)
			നിർത്തുക;
	}
	sshkey_free(lineinfo.താക്കോൽ);
	സ്വതന്ത്രം(lineinfo.വരി);
	സ്വതന്ത്രം(വരി);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
hostkeys_foreach(സ്ഥിരം അക്ഷരം *path, hostkeys_foreach_fn *callback, ശൂന്യം *ctx,
    സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip, u_int options, u_int note)
{
	FILE *f;
	പൂർണ്ണസംഖ്യ r, oerrno;

	എങ്കിൽ ((f = fopen(path, "r")) == ശൂന്യ)
		തിരികെ SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	തിരികെ r;
}
