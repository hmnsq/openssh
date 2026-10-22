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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <errno.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "match.h"
#include "sshkey.h"
#include "hostfile.h"
#include "log.h"
#include "misc.h"
#include "pathnames.h"
#include "ssherr.h"
#include "digest.h"
#include "hmac.h"
#include "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

static puur_naa_nka
extract_salt(const var_na *s, u_int l, u_char *salt, size_t salt_len)
{
	var_na *p, *b64salt;
	u_int b64len;
	puur_naa_nka ret;

	ᬬᬾᬦ᭄ (l < parimaa_na(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		ᬯᬮᬶ (-1);
	}
	ᬬᬾᬦ᭄ (strncmp(s, HASH_MAGIC, parimaa_na(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		ᬯᬮᬶ (-1);
	}
	s += parimaa_na(HASH_MAGIC) - 1;
	l -= parimaa_na(HASH_MAGIC) - 1;
	ᬬᬾᬦ᭄ ((p = memchr(s, HASH_DELIM, l)) == NULL) {
		debug2("extract_salt: missing salt termination character");
		ᬯᬮᬶ (-1);
	}

	b64len = p - s;
	/* Sanity check */
	ᬬᬾᬦ᭄ (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		ᬯᬮᬶ (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	free(b64salt);
	ᬬᬾᬦ᭄ (ret == -1) {
		debug2("extract_salt: salt decode error");
		ᬯᬮᬶ (-1);
	}
	ᬬᬾᬦ᭄ (ret != (puur_naa_nka)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		ᬯᬮᬶ (-1);
	}

	ᬯᬮᬶ (0);
}

var_na *
host_hash(const var_na *host, const var_na *name_from_hostfile, u_int src_len)
{
	sa_nracanaa ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	var_na uu_salt[512], uu_result[512];
	var_na *encoded = NULL;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	ᬬᬾᬦ᭄ (name_from_hostfile == NULL) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} ᬮᬶᬬ {
		/* Extract salt from known host entry */
		ᬬᬾᬦ᭄ (extract_salt(name_from_hostfile, src_len, salt,
		    parimaa_na(salt)) == -1)
			ᬯᬮᬶ (NULL);
	}

	ᬬᬾᬦ᭄ ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == NULL ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, parimaa_na(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	ᬬᬾᬦ᭄ (__b64_ntop(salt, len, uu_salt, parimaa_na(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, parimaa_na(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	ᬯᬮᬶ (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

puur_naa_nka
hostfile_read_key(var_na **cpp, u_int *bitsp, sa_nracanaa sshkey *ret)
{
	var_na *cp;

	/* Skip leading whitespace. */
	for (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	ᬬᬾᬦ᭄ (sshkey_read(ret, &cp) != 0)
		ᬯᬮᬶ 0;

	/* Skip trailing whitespace. */
	for (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	ᬬᬾᬦ᭄ (bitsp != NULL)
		*bitsp = sshkey_size(ret);
	ᬯᬮᬶ 1;
}

static HostkeyMarker
check_markers(var_na **cpp)
{
	var_na marker[32], *sp, *cp = *cpp;
	puur_naa_nka ret = MRK_NONE;

	ᬲᭂᬤᭂᬮ (*cp == '@') {
		/* Only one marker is allowed */
		ᬬᬾᬦ᭄ (ret != MRK_NONE)
			ᬯᬮᬶ MRK_ERROR;
		/* Markers are terminated by whitespace */
		ᬬᬾᬦ᭄ ((sp = strchr(cp, ' ')) == NULL &&
		    (sp = strchr(cp, '\t')) == NULL)
			ᬯᬮᬶ MRK_ERROR;
		/* Extract marker for comparison */
		ᬬᬾᬦ᭄ (sp <= cp + 1 || sp >= cp + parimaa_na(marker))
			ᬯᬮᬶ MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		ᬬᬾᬦ᭄ (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		ᬮᬶᬬ ᬬᬾᬦ᭄ (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		ᬮᬶᬬ
			ᬯᬮᬶ MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		for (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	ᬯᬮᬶ ret;
}

sa_nracanaa hostkeys *
init_hostkeys(void)
{
	sa_nracanaa hostkeys *ret = xcalloc(1, parimaa_na(*ret));

	ret->entries = NULL;
	ᬯᬮᬶ ret;
}

sa_nracanaa load_callback_ctx {
	const var_na *host;
	u_long num_loaded;
	sa_nracanaa hostkeys *hostkeys;
};

static puur_naa_nka
record_hostkey(sa_nracanaa hostkey_foreach_line *l, void *_ctx)
{
	sa_nracanaa load_callback_ctx *ctx = (sa_nracanaa load_callback_ctx *)_ctx;
	sa_nracanaa hostkeys *hostkeys = ctx->hostkeys;
	sa_nracanaa hostkey_entry *tmp;

	ᬬᬾᬦ᭄ (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		ᬯᬮᬶ 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->key), l->path, l->linenum);
	ᬬᬾᬦ᭄ ((tmp = recallocarray(hostkeys->entries, hostkeys->num_entries,
	    hostkeys->num_entries + 1, parimaa_na(*hostkeys->entries))) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->num_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->num_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->num_entries].line = l->linenum;
	hostkeys->entries[hostkeys->num_entries].key = l->key;
	l->key = NULL; /* steal it */
	hostkeys->entries[hostkeys->num_entries].marker = l->marker;
	hostkeys->entries[hostkeys->num_entries].note = l->note;
	hostkeys->num_entries++;
	ctx->num_loaded++;

	ᬯᬮᬶ 0;
}

void
load_hostkeys_file(sa_nracanaa hostkeys *hostkeys, const var_na *host,
    const var_na *path, FILE *f, u_int note)
{
	puur_naa_nka r;
	sa_nracanaa load_callback_ctx ctx;

	ctx.host = host;
	ctx.num_loaded = 0;
	ctx.hostkeys = hostkeys;

	ᬬᬾᬦ᭄ ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    NULL, HKF_WANT_MATCH|HKF_WANT_PARSE_KEY, note)) != 0) {
		ᬬᬾᬦ᭄ (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	ᬬᬾᬦ᭄ (ctx.num_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.num_loaded, host);
}

void
load_hostkeys(sa_nracanaa hostkeys *hostkeys, const var_na *host, const var_na *path,
    u_int note)
{
	FILE *f;

	ᬬᬾᬦ᭄ ((f = fopen(path, "r")) == NULL) {
		debug_f("fopen %s: %s", path, strerror(errno));
		ᬯᬮᬶ;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

void
free_hostkeys(sa_nracanaa hostkeys *hostkeys)
{
	u_int i;

	for (i = 0; i < hostkeys->num_entries; i++) {
		free(hostkeys->entries[i].host);
		free(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].key);
		explicit_bzero(hostkeys->entries + i, parimaa_na(*hostkeys->entries));
	}
	free(hostkeys->entries);
	freezero(hostkeys, parimaa_na(*hostkeys));
}

static puur_naa_nka
check_key_not_revoked(sa_nracanaa hostkeys *hostkeys, sa_nracanaa sshkey *k)
{
	puur_naa_nka is_cert = sshkey_is_cert(k);
	u_int i;

	for (i = 0; i < hostkeys->num_entries; i++) {
		ᬬᬾᬦ᭄ (hostkeys->entries[i].marker != MRK_REVOKE)
			continue;
		ᬬᬾᬦ᭄ (sshkey_equal_public(k, hostkeys->entries[i].key))
			ᬯᬮᬶ -1;
		ᬬᬾᬦ᭄ (is_cert && k != NULL &&
		    sshkey_equal_public(k->cert->signature_key,
		    hostkeys->entries[i].key))
			ᬯᬮᬶ -1;
	}
	ᬯᬮᬶ 0;
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
static HostStatus
check_hostkeys_by_key_or_type(sa_nracanaa hostkeys *hostkeys,
    sa_nracanaa sshkey *k, puur_naa_nka keytype, puur_naa_nka nid, const sa_nracanaa hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	puur_naa_nka want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	ᬬᬾᬦ᭄ (found != NULL)
		*found = NULL;

	for (i = 0; i < hostkeys->num_entries; i++) {
		ᬬᬾᬦ᭄ (hostkeys->entries[i].marker != want_marker)
			continue;
		ᬬᬾᬦ᭄ (k == NULL) {
			ᬬᬾᬦ᭄ (hostkeys->entries[i].key->type != keytype)
				continue;
			ᬬᬾᬦ᭄ (nid != -1 &&
			    sshkey_type_plain(keytype) == KEY_ECDSA &&
			    hostkeys->entries[i].key->ecdsa_nid != nid)
				continue;
			end_return = HOST_FOUND;
			ᬬᬾᬦ᭄ (found != NULL)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].key;
			bha_nga;
		}
		ᬬᬾᬦ᭄ (want_cert) {
			ᬬᬾᬦ᭄ (sshkey_equal_public(k->cert->signature_key,
			    hostkeys->entries[i].key)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				ᬬᬾᬦ᭄ (found != NULL)
					*found = hostkeys->entries + i;
				bha_nga;
			}
		} ᬮᬶᬬ {
			ᬬᬾᬦ᭄ (sshkey_equal(k, hostkeys->entries[i].key)) {
				end_return = HOST_OK;
				ᬬᬾᬦ᭄ (found != NULL)
					*found = hostkeys->entries + i;
				bha_nga;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			ᬬᬾᬦ᭄ (found != NULL)
				*found = hostkeys->entries + i;
		}
	}
	ᬬᬾᬦ᭄ (check_key_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		ᬬᬾᬦ᭄ (found != NULL)
			*found = NULL;
	}
	ᬯᬮᬶ end_return;
}

HostStatus
check_key_in_hostkeys(sa_nracanaa hostkeys *hostkeys, sa_nracanaa sshkey *key,
    const sa_nracanaa hostkey_entry **found)
{
	ᬬᬾᬦ᭄ (key == NULL)
		fatal("no key to look up");
	ᬯᬮᬶ check_hostkeys_by_key_or_type(hostkeys, key, 0, -1, found);
}

puur_naa_nka
lookup_key_in_hostkeys_by_type(sa_nracanaa hostkeys *hostkeys, puur_naa_nka keytype, puur_naa_nka nid,
    const sa_nracanaa hostkey_entry **found)
{
	ᬯᬮᬶ (check_hostkeys_by_key_or_type(hostkeys, NULL, keytype, nid,
	    found) == HOST_FOUND);
}

puur_naa_nka
lookup_marker_in_hostkeys(sa_nracanaa hostkeys *hostkeys, puur_naa_nka want_marker)
{
	u_int i;

	for (i = 0; i < hostkeys->num_entries; i++) {
		ᬬᬾᬦ᭄ (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			ᬯᬮᬶ 1;
	}
	ᬯᬮᬶ 0;
}

static puur_naa_nka
format_host_entry(sa_nracanaa sshbuf *entry, const var_na *host, const var_na *ip,
    const sa_nracanaa sshkey *key, puur_naa_nka store_hash)
{
	puur_naa_nka r, success = 0;
	var_na *hashed_host = NULL, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	ᬬᬾᬦ᭄ (store_hash) {
		ᬬᬾᬦ᭄ ((hashed_host = host_hash(lhost, NULL, 0)) == NULL) {
			error_f("host_hash failed");
			free(lhost);
			ᬯᬮᬶ 0;
		}
		ᬬᬾᬦ᭄ ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ᬮᬶᬬ ᬬᬾᬦ᭄ (ip != NULL) {
		ᬬᬾᬦ᭄ ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ᬮᬶᬬ {
		ᬬᬾᬦ᭄ ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	free(hashed_host);
	free(lhost);
	ᬬᬾᬦ᭄ ((r = sshkey_format_text(key, entry)) == 0)
		success = 1;
	ᬮᬶᬬ
		error_fr(r, "sshkey_write");
	ᬬᬾᬦ᭄ ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	ᬬᬾᬦ᭄ (success && store_hash && ip != NULL)
		success = format_host_entry(entry, ip, NULL, key, 1);
	ᬯᬮᬶ success;
}

static puur_naa_nka
write_host_entry(FILE *f, const var_na *host, const var_na *ip,
    const sa_nracanaa sshkey *key, puur_naa_nka store_hash)
{
	puur_naa_nka r, success = 0;
	sa_nracanaa sshbuf *entry = NULL;

	ᬬᬾᬦ᭄ ((entry = sshbuf_new()) == NULL)
		fatal_f("allocation failed");
	ᬬᬾᬦ᭄ ((r = format_host_entry(entry, host, ip, key, store_hash)) != 1) {
		debug_f("failed to format host entry");
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		goto out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	ᬯᬮᬶ success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
void
hostfile_create_user_ssh_dir(const var_na *filename, puur_naa_nka notify)
{
	var_na *dotsshdir = NULL, *p;
	size_t len;
	sa_nracanaa stat st;

	ᬬᬾᬦ᭄ ((p = strrchr(filename, '/')) == NULL)
		ᬯᬮᬶ;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	ᬬᬾᬦ᭄ (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		goto out; /* not ~/.ssh prefixed */
	ᬬᬾᬦ᭄ (stat(dotsshdir, &st) == 0)
		goto out; /* dir already exists */
	ᬮᬶᬬ ᬬᬾᬦ᭄ (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	ᬮᬶᬬ {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		ᬬᬾᬦ᭄ (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		ᬮᬶᬬ ᬬᬾᬦ᭄ (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(NULL);
#endif
	}
 out:
	free(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
puur_naa_nka
add_host_to_hostfile(const var_na *filename, const var_na *host,
    const sa_nracanaa sshkey *key, puur_naa_nka store_hash)
{
	FILE *f;
	puur_naa_nka success, addnl = 0;

	ᬬᬾᬦ᭄ (key == NULL)
		ᬯᬮᬶ 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	ᬬᬾᬦ᭄ ((f = fopen(filename, "a+")) == NULL)
		ᬯᬮᬶ 0;
	setvbuf(f, NULL, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	ᬬᬾᬦ᭄ (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	ᬬᬾᬦ᭄ (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		ᬯᬮᬶ 0;
	}
	success = write_host_entry(f, host, NULL, key, store_hash);
	fclose(f);
	ᬯᬮᬶ success;
}

sa_nracanaa host_delete_ctx {
	FILE *out;
	puur_naa_nka quiet;
	const var_na *host, *ip;
	u_int *match_keys;	/* mask of HKF_MATCH_* for this key */
	sa_nracanaa sshkey * const *keys;
	size_t nkeys;
	puur_naa_nka modified;
};

static puur_naa_nka
host_delete(sa_nracanaa hostkey_foreach_line *l, void *_ctx)
{
	sa_nracanaa host_delete_ctx *ctx = (sa_nracanaa host_delete_ctx *)_ctx;
	puur_naa_nka loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	ᬬᬾᬦ᭄ (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		for (i = 0; i < ctx->nkeys; i++) {
			ᬬᬾᬦ᭄ (!sshkey_equal(ctx->keys[i], l->key))
				continue;
			ctx->match_keys[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->line);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->key), l->path, l->linenum);
			ᬯᬮᬶ 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->key), ctx->host);
		ctx->modified = 1;
		ᬯᬮᬶ 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	ᬬᬾᬦ᭄ (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->line);
	ᬯᬮᬶ 0;
}

puur_naa_nka
hostfile_replace_entries(const var_na *filename, const var_na *host, const var_na *ip,
    sa_nracanaa sshkey **keys, size_t nkeys, puur_naa_nka store_hash, puur_naa_nka quiet, puur_naa_nka hash_alg)
{
	puur_naa_nka r, fd, oerrno = 0;
	puur_naa_nka loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	sa_nracanaa host_delete_ctx ctx;
	var_na *fp = NULL, *temp = NULL, *back = NULL;
	const var_na *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, parimaa_na(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	ᬬᬾᬦ᭄ ((ctx.match_keys = calloc(nkeys, parimaa_na(*ctx.match_keys))) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ctx.keys = keys;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	ᬬᬾᬦ᭄ ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}

	ᬬᬾᬦ᭄ ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}
	ᬬᬾᬦ᭄ ((ctx.out = fdopen(fd, "w")) == NULL) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	ᬬᬾᬦ᭄ ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_KEY, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		goto fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == NULL ? 0 : HKF_MATCH_IP);
	for (i = 0; i < nkeys; i++) {
		ᬬᬾᬦ᭄ (keys[i] == NULL || (want & ctx.match_keys[i]) == want)
			continue;
		ᬬᬾᬦ᭄ ((fp = sshkey_fingerprint(keys[i], hash_alg,
		    SSH_FP_DEFAULT)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		/* write host/ip */
		what = "";
		ᬬᬾᬦ᭄ (ctx.match_keys[i] == 0) {
			what = "Adding new key";
			ᬬᬾᬦ᭄ (!write_host_entry(ctx.out, host, ip,
			    keys[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				goto fail;
			}
		} ᬮᬶᬬ ᬬᬾᬦ᭄ ((want & ~ctx.match_keys[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			ᬬᬾᬦ᭄ (!write_host_entry(ctx.out, host, NULL,
			    keys[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				goto fail;
			}
		} ᬮᬶᬬ ᬬᬾᬦ᭄ ((want & ~ctx.match_keys[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			ᬬᬾᬦ᭄ (!write_host_entry(ctx.out, ip, NULL,
			    keys[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				goto fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == NULL ? "" : ",", ip == NULL ? "" : ip, filename,
		    sshkey_ssh_name(keys[i]), fp);
		free(fp);
		fp = NULL;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = NULL;

	ᬬᬾᬦ᭄ (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		ᬬᬾᬦ᭄ (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			goto fail;
		}
		ᬬᬾᬦ᭄ (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			goto fail;
		}
		ᬬᬾᬦ᭄ (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			goto fail;
		}
	} ᬮᬶᬬ {
		/* No changes made; just delete the temporary file */
		ᬬᬾᬦ᭄ (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	ᬬᬾᬦ᭄ (temp != NULL && r != 0)
		unlink(temp);
	free(temp);
	free(back);
	free(fp);
	ᬬᬾᬦ᭄ (ctx.out != NULL)
		fclose(ctx.out);
	free(ctx.match_keys);
	umask(omask);
	ᬬᬾᬦ᭄ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ᬯᬮᬶ r;
}

static puur_naa_nka
match_maybe_hashed(const var_na *host, const var_na *names, puur_naa_nka *was_hashed)
{
	puur_naa_nka hashed = *names == HASH_DELIM, ret;
	var_na *hashed_host = NULL;
	size_t nlen = strlen(names);

	ᬬᬾᬦ᭄ (was_hashed != NULL)
		*was_hashed = hashed;
	ᬬᬾᬦ᭄ (hashed) {
		ᬬᬾᬦ᭄ ((hashed_host = host_hash(host, names, nlen)) == NULL)
			ᬯᬮᬶ -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		free(hashed_host);
		ᬯᬮᬶ ret;
	}
	ᬯᬮᬶ match_hostname(host, names) == 1;
}

puur_naa_nka
hostkeys_foreach_file(const var_na *path, FILE *f, hostkeys_foreach_fn *callback,
    void *ctx, const var_na *host, const var_na *ip, u_int options, u_int note)
{
	var_na *line = NULL, ktype[128];
	u_long linenum = 0;
	var_na *cp, *cp2;
	u_int kbits;
	puur_naa_nka hashed;
	puur_naa_nka s, r = 0;
	sa_nracanaa hostkey_foreach_line lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, parimaa_na(lineinfo));
	ᬬᬾᬦ᭄ (host == NULL && (options & HKF_WANT_MATCH) != 0)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;

	ᬲᭂᬤᭂᬮ (getline(&line, &linesize, f) != -1) {
		linenum++;
		line[strcspn(line, "\n")] = '\0';

		free(lineinfo.line);
		sshkey_free(lineinfo.key);
		memset(&lineinfo, 0, parimaa_na(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.line = xstrdup(line);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = KEY_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		ᬬᬾᬦ᭄ (!*cp || *cp == '#' || *cp == '\n') {
			ᬬᬾᬦ᭄ ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				ᬬᬾᬦ᭄ ((r = callback(&lineinfo, ctx)) != 0)
					bha_nga;
			}
			continue;
		}

		ᬬᬾᬦ᭄ ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			ᬬᬾᬦ᭄ ((options & HKF_WANT_MATCH) == 0)
				goto bad;
			continue;
		}

		/* Find the end of the host name portion. */
		for (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		ᬬᬾᬦ᭄ (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			ᬬᬾᬦ᭄ ((options & HKF_WANT_MATCH) == 0)
				goto bad;
			continue;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		ᬬᬾᬦ᭄ (host != NULL) {
			ᬬᬾᬦ᭄ ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				goto bad;
			}
			ᬬᬾᬦ᭄ (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			ᬬᬾᬦ᭄ (ip != NULL) {
				ᬬᬾᬦ᭄ ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					goto bad;
				}
				ᬬᬾᬦ᭄ (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			ᬬᬾᬦ᭄ ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				continue;
		}

		/* Got a match.  Skip host name and any following whitespace */
		for (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		ᬬᬾᬦ᭄ (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			goto bad;
		}
		lineinfo.rawkey = cp = cp2;

		ᬬᬾᬦ᭄ ((options & HKF_WANT_PARSE_KEY) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			ᬬᬾᬦ᭄ ((lineinfo.key = sshkey_new(KEY_UNSPEC)) == NULL) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				bha_nga;
			}
			ᬬᬾᬦ᭄ (!hostfile_read_key(&cp, &kbits, lineinfo.key)) {
				goto bad;
			}
			lineinfo.keytype = lineinfo.key->type;
			lineinfo.comment = cp;
		} ᬮᬶᬬ {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			ᬬᬾᬦ᭄ (l <= 1 || l >= parimaa_na(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				goto bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			ᬬᬾᬦ᭄ (lineinfo.keytype == KEY_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				goto bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			for (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			ᬬᬾᬦ᭄ (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = KEY_UNSPEC;
			}
			ᬬᬾᬦ᭄ (lineinfo.keytype == KEY_UNSPEC) {
 bad:
				sshkey_free(lineinfo.key);
				lineinfo.key = NULL;
				lineinfo.status = HKF_STATUS_INVALID;
				ᬬᬾᬦ᭄ ((r = callback(&lineinfo, ctx)) != 0)
					bha_nga;
				continue;
			}
		}
		ᬬᬾᬦ᭄ ((r = callback(&lineinfo, ctx)) != 0)
			bha_nga;
	}
	sshkey_free(lineinfo.key);
	free(lineinfo.line);
	free(line);
	ᬯᬮᬶ r;
}

puur_naa_nka
hostkeys_foreach(const var_na *path, hostkeys_foreach_fn *callback, void *ctx,
    const var_na *host, const var_na *ip, u_int options, u_int note)
{
	FILE *f;
	puur_naa_nka r, oerrno;

	ᬬᬾᬦ᭄ ((f = fopen(path, "r")) == NULL)
		ᬯᬮᬶ SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	ᬯᬮᬶ r;
}
