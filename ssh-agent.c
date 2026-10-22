/* $OpenBSD: ssh-agent.c,v 1.333 2026/09/22 22:30:27 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/resource.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#ਜੇ_ਅੰਤ

/* Maximum accepted message length */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ {
	AUTH_ਅਣਵਰਤਿਆ = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

ਬਣਤਰ hostkey_sid {
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	ਬਣਤਰ sshbuf *sid;
	ਪੂਰਨ forwarded;
};

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ socket_ਇੰਦਰਾਜ {
	ਪੂਰਨ fd;
	sock_type type;
	ਬਣਤਰ sshbuf *ਨਿਵੇਸ਼;
	ਬਣਤਰ sshbuf *output;
	ਬਣਤਰ sshbuf *request;
	ਮਾਪ_t nsession_ids;
	ਬਣਤਰ hostkey_sid *session_ids;
	ਪੂਰਨ session_bind_attempted;
} Socket_ਇੰਦਰਾਜ;

u_int sockets_alloc = 0;
Socket_ਇੰਦਰਾਜ *sockets = ਨਿਰਾ;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 {
	TAILQ_ENTRY(ਪਛਾਣ_ਤੱਤ_2) ਅਗਲਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	ਅੱਖਰ *comment;
	ਅੱਖਰ *provider;
	time_t death;
	u_int confirm;
	ਅੱਖਰ *sk_provider;
	ਬਣਤਰ dest_constraint *dest_constraints;
	ਮਾਪ_t ndest_constraints;
} ਪਛਾਣ_ਤੱਤ;

ਬਣਤਰ idtable {
	ਪੂਰਨ nentries;
	TAILQ_HEAD(idqueue, ਪਛਾਣ_ਤੱਤ_2) idlist;
};

/* private key table */
ਬਣਤਰ idtable *idtab;

ਪੂਰਨ max_fd = 0;

/* pid of shell == parent of agent */
pid_t ਮਾਪਾ_pid = -1;
time_t ਮਾਪਾ_alive_interval = 0;

ਸਥਿਰ sig_atomic_t signalled_exit;
ਸਥਿਰ sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
ਸਥਿਰ ਅੱਖਰ *socket_name;
ਸਥਿਰ ਅੱਖਰ *socket_dir;
ਸਥਿਰ ਅੱਖਰ *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
ਸਥਿਰ ਅੱਖਰ *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
ਸਥਿਰ ਪੂਰਨ remote_ਜੋੜੋ_provider;

/* locking */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਤਾਲਾ_ਮਾਪ	32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਤਾਲਾ_SALT_ਮਾਪ	16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਤਾਲਾ_ਗੇੜ	1
ਪੂਰਨ locked = 0;
u_char ਤਾਲਾ_pwhash[ਤਾਲਾ_ਮਾਪ];
u_char ਤਾਲਾ_salt[ਤਾਲਾ_SALT_ਮਾਪ];

ਬਾਹਰੀ ਅੱਖਰ *__progname;

/* Default lifetime in seconds (0 == forever) */
ਸਥਿਰ ਪੂਰਨ lifetime = 0;

ਸਥਿਰ ਪੂਰਨ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
ਸਥਿਰ ਪੂਰਨ restrict_websafe = 1;
ਸਥਿਰ ਅੱਖਰ *websafe_allowlist;

ਸਥਿਰ ਖਾਲੀ
close_socket(Socket_ਇੰਦਰਾਜ *e)
{
	ਮਾਪ_t i;

	close(e->fd);
	sshbuf_free(e->ਨਿਵੇਸ਼);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	ਲਈ (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].ਕੁੰਜੀ);
		sshbuf_free(e->session_ids[i].sid);
	}
	ਮੁਕਤ(e->session_ids);
	memset(e, '\0', ਆਕਾਰ(*e));
	e->fd = -1;
	e->type = AUTH_ਅਣਵਰਤਿਆ;
}

ਸਥਿਰ ਖਾਲੀ
idtab_init(ਖਾਲੀ)
{
	idtab = xcalloc(1, ਆਕਾਰ(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

ਸਥਿਰ ਖਾਲੀ
free_dest_constraint_hop(ਬਣਤਰ dest_constraint_hop *dch)
{
	u_int i;

	ਜੇ (dch == ਨਿਰਾ)
		ਵਾਪਸ;
	ਮੁਕਤ(dch->user);
	ਮੁਕਤ(dch->hostname);
	ਲਈ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ਕੁੰਜੀਆਂ[i]);
	ਮੁਕਤ(dch->ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(dch->ਕੁੰਜੀ_is_ca);
}

ਸਥਿਰ ਖਾਲੀ
free_dest_constraints(ਬਣਤਰ dest_constraint *dcs, ਮਾਪ_t ndcs)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].ਮੰਜ਼ਿਲ);
	}
	ਮੁਕਤ(dcs);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
ਸਥਿਰ ਖਾਲੀ
dup_dest_constraint_hop(ਅਚਲ ਬਣਤਰ dest_constraint_hop *dch,
    ਬਣਤਰ dest_constraint_hop *ਬਾਹਰਲਾ)
{
	u_int i;
	ਪੂਰਨ r;

	ਬਾਹਰਲਾ->user = dch->user == ਨਿਰਾ ? ਨਿਰਾ : xstrdup(dch->user);
	ਬਾਹਰਲਾ->hostname = dch->hostname == ਨਿਰਾ ? ਨਿਰਾ : xstrdup(dch->hostname);
	ਬਾਹਰਲਾ->is_ca = dch->is_ca;
	ਬਾਹਰਲਾ->nkeys = dch->nkeys;
	ਬਾਹਰਲਾ->ਕੁੰਜੀਆਂ = ਬਾਹਰਲਾ->nkeys == 0 ? ਨਿਰਾ :
	    xcalloc(ਬਾਹਰਲਾ->nkeys, ਆਕਾਰ(*ਬਾਹਰਲਾ->ਕੁੰਜੀਆਂ));
	ਬਾਹਰਲਾ->ਕੁੰਜੀ_is_ca = ਬਾਹਰਲਾ->nkeys == 0 ? ਨਿਰਾ :
	    xcalloc(ਬਾਹਰਲਾ->nkeys, ਆਕਾਰ(*ਬਾਹਰਲਾ->ਕੁੰਜੀ_is_ca));
	ਲਈ (i = 0; i < dch->nkeys; i++) {
		ਜੇ (dch->ਕੁੰਜੀਆਂ[i] != ਨਿਰਾ &&
		    (r = sshkey_from_ਨਿੱਜੀ(dch->ਕੁੰਜੀਆਂ[i],
		    &(ਬਾਹਰਲਾ->ਕੁੰਜੀਆਂ[i]))) != 0)
			fatal_fr(r, "copy key");
		ਬਾਹਰਲਾ->ਕੁੰਜੀ_is_ca[i] = dch->ਕੁੰਜੀ_is_ca[i];
	}
}

ਸਥਿਰ ਬਣਤਰ dest_constraint *
dup_dest_constraints(ਅਚਲ ਬਣਤਰ dest_constraint *dcs, ਮਾਪ_t ndcs)
{
	ਮਾਪ_t i;
	ਬਣਤਰ dest_constraint *ret;

	ਜੇ (ndcs == 0)
		ਵਾਪਸ ਨਿਰਾ;
	ret = xcalloc(ndcs, ਆਕਾਰ(*ret));
	ਲਈ (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].ਮੰਜ਼ਿਲ, &ret[i].ਮੰਜ਼ਿਲ);
	}
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ /* ENABLE_PKCS11 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_CONSTRAINTS
ਸਥਿਰ ਖਾਲੀ
dump_dest_constraint_hop(ਅਚਲ ਬਣਤਰ dest_constraint_hop *dch)
{
	u_int i;
	ਅੱਖਰ *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == ਨਿਰਾ ? "(null)" : dch->user,
	    dch->hostname == ਨਿਰਾ ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	ਲਈ (i = 0; i < dch->nkeys; i++) {
		fp = ਨਿਰਾ;
		ਜੇ (dch->ਕੁੰਜੀਆਂ[i] != ਨਿਰਾ &&
		    (fp = sshkey_fingerprint(dch->ਕੁੰਜੀਆਂ[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->ਕੁੰਜੀਆਂ[i] == ਨਿਰਾ ? "" : sshkey_ssh_name(dch->ਕੁੰਜੀਆਂ[i]),
		    dch->ਕੁੰਜੀਆਂ[i] == ਨਿਰਾ ? "" : " ",
		    dch->ਕੁੰਜੀਆਂ[i] == ਨਿਰਾ ? "none" : fp,
		    dch->ਕੁੰਜੀ_is_ca[i]);
		ਮੁਕਤ(fp);
	}
}
#ਜੇ_ਅੰਤ /* DEBUG_CONSTRAINTS */

ਸਥਿਰ ਖਾਲੀ
dump_dest_constraints(ਅਚਲ ਅੱਖਰ *context,
    ਅਚਲ ਬਣਤਰ dest_constraint *dcs, ਮਾਪ_t ndcs)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_CONSTRAINTS
	ਮਾਪ_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	ਲਈ (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].ਮੰਜ਼ਿਲ);
	}
	debug_f("done for %s", context);
#ਜੇ_ਅੰਤ /* DEBUG_CONSTRAINTS */
}

ਸਥਿਰ ਖਾਲੀ
free_ਪਛਾਣ_ਤੱਤ(ਪਛਾਣ_ਤੱਤ *id)
{
	sshkey_free(id->ਕੁੰਜੀ);
	ਮੁਕਤ(id->provider);
	ਮੁਕਤ(id->comment);
	ਮੁਕਤ(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	ਮੁਕਤ(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_ਕੁੰਜੀ_hop(ਅਚਲ ਅੱਖਰ *ਟੈਗ, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਬਣਤਰ dest_constraint_hop *dch)
{
	ਅਚਲ ਅੱਖਰ *reason = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	ਅੱਖਰ *fp;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ -1;
	/* XXX logspam */
	ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    ਟੈਗ, hostname, sshkey_type(ਕੁੰਜੀ), fp, dch->nkeys);
	ਮੁਕਤ(fp);
	ਲਈ (i = 0; i < dch->nkeys; i++) {
		ਜੇ (dch->ਕੁੰਜੀਆਂ[i] == ਨਿਰਾ)
			ਵਾਪਸ -1;
		/* XXX logspam */
		ਜੇ ((fp = sshkey_fingerprint(dch->ਕੁੰਜੀਆਂ[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", ਟੈਗ, i,
		    dch->ਕੁੰਜੀ_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->ਕੁੰਜੀਆਂ[i]), fp);
		ਮੁਕਤ(fp);
		ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
			/* plain key */
			ਜੇ (dch->ਕੁੰਜੀ_is_ca[i] ||
			    !sshkey_equal(ਕੁੰਜੀ, dch->ਕੁੰਜੀਆਂ[i]))
				ਜਾਰੀ;
			ਵਾਪਸ 0;
		}
		/* certificate */
		ਜੇ (!dch->ਕੁੰਜੀ_is_ca[i])
			ਜਾਰੀ;
		ਜੇ (ਕੁੰਜੀ->cert == ਨਿਰਾ || ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ == ਨਿਰਾ)
			ਵਾਪਸ -1; /* shouldn't happen */
		ਜੇ (!sshkey_equal(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ, dch->ਕੁੰਜੀਆਂ[i]))
			ਜਾਰੀ;
		ਜੇ (sshkey_cert_check_host(ਕੁੰਜੀ, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id, hostname, reason);
			ਜਾਰੀ;
		}
		ਵਾਪਸ 0;
	}
	ਵਾਪਸ -1;
}

/* Check destination constraints on an identity against the hostkey/user */
ਸਥਿਰ ਪੂਰਨ
permitted_by_dest_constraints(ਅਚਲ ਬਣਤਰ sshkey *fromkey,
    ਅਚਲ ਬਣਤਰ sshkey *tokey, ਪਛਾਣ_ਤੱਤ *id, ਅਚਲ ਅੱਖਰ *user,
    ਅਚਲ ਅੱਖਰ **hostnamep)
{
	ਮਾਪ_t i;
	ਬਣਤਰ dest_constraint *d;

	ਜੇ (hostnamep != ਨਿਰਾ)
		*hostnamep = ਨਿਰਾ;
	ਲਈ (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->ਮੰਜ਼ਿਲ.user ? d->ਮੰਜ਼ਿਲ.user : "", d->ਮੰਜ਼ਿਲ.user ? "@" : "",
		    d->ਮੰਜ਼ਿਲ.hostname ? d->ਮੰਜ਼ਿਲ.hostname : "(ANY)", d->ਮੰਜ਼ਿਲ.nkeys);

		/* Match 'from' key */
		ਜੇ (fromkey == ਨਿਰਾ) {
			/* We are matching the first hop */
			ਜੇ (d->from.hostname != ਨਿਰਾ || d->from.nkeys != 0)
				ਜਾਰੀ;
		} ਨਹੀਂਤਾਂ ਜੇ (ਮੇਲ_ਕੁੰਜੀ_hop("from", fromkey, &d->from) != 0)
			ਜਾਰੀ;

		/* Match 'to' key */
		ਜੇ (tokey != ਨਿਰਾ && ਮੇਲ_ਕੁੰਜੀ_hop("to", tokey, &d->ਮੰਜ਼ਿਲ) != 0)
			ਜਾਰੀ;

		/* Match user if specified */
		ਜੇ (d->ਮੰਜ਼ਿਲ.user != ਨਿਰਾ && user != ਨਿਰਾ &&
		    !ਮੇਲ_ਨਮੂਨਾ(user, d->ਮੰਜ਼ਿਲ.user))
			ਜਾਰੀ;

		/* successfully matched this constraint */
		ਜੇ (hostnamep != ਨਿਰਾ)
			*hostnamep = d->ਮੰਜ਼ਿਲ.hostname;
		debug2_f("allowed for hostname %s",
		    d->ਮੰਜ਼ਿਲ.hostname == ਨਿਰਾ ? "*" : d->ਮੰਜ਼ਿਲ.hostname);
		ਵਾਪਸ 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->ਕੁੰਜੀ), id->comment);
	ਵਾਪਸ -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
ਪਛਾਣ_ਤੱਤ_permitted(ਪਛਾਣ_ਤੱਤ *id, Socket_ਇੰਦਰਾਜ *e, ਅੱਖਰ *user,
    ਅਚਲ ਅੱਖਰ **forward_hostnamep, ਅਚਲ ਅੱਖਰ **ਆਖਰੀ_hostnamep)
{
	ਮਾਪ_t i;
	ਅਚਲ ਅੱਖਰ **hp;
	ਬਣਤਰ hostkey_sid *hks;
	ਅਚਲ ਬਣਤਰ sshkey *fromkey = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *test_user;
	ਅੱਖਰ *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->ਕੁੰਜੀ), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	ਜੇ (id->ndest_constraints == 0)
		ਵਾਪਸ 0; /* unconstrained */
	ਜੇ (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		ਵਾਪਸ -1;
	}
	ਜੇ (e->nsession_ids == 0)
		ਵਾਪਸ 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	ਲਈ (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		ਜੇ (hks->ਕੁੰਜੀ == ਨਿਰਾ)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = ਨਿਰਾ;
		ਜੇ (fromkey != ਨਿਰਾ &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("fingerprint failed");
		ਜੇ ((fp2 = sshkey_fingerprint(hks->ਕੁੰਜੀ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->ਕੁੰਜੀ), fp2);
		ਮੁਕਤ(fp1);
		ਮੁਕਤ(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = ਨਿਰਾ;
		ਜੇ (i == e->nsession_ids - 1)
			hp = ਆਖਰੀ_hostnamep;
		ਨਹੀਂਤਾਂ ਜੇ (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = ਨਿਰਾ;
		ਜੇ (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			ਜੇ (hks->forwarded && user != ਨਿਰਾ) {
				error_f("tried to sign on forwarding hop");
				ਵਾਪਸ -1;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			ਵਾਪਸ -1;
		}
		ਜੇ (permitted_by_dest_constraints(fromkey, hks->ਕੁੰਜੀ, id,
		    test_user, hp) != 0)
			ਵਾਪਸ -1;
		fromkey = hks->ਕੁੰਜੀ;
	}
	/*
	 * Another special case: if the last bound session ID was for a
	 * forwarding, and this function is not being called to check a sign
	 * request (i.e. no 'user' supplied), then only permit the key if
	 * there is a permission that would allow it to be used at another
	 * destination. This hides keys that are allowed to be used to
	 * authenticate *to* a host but not permitted for *use* beyond it.
	 */
	hks = &e->session_ids[e->nsession_ids - 1];
	ਜੇ (hks->forwarded && user == ਨਿਰਾ &&
	    permitted_by_dest_constraints(hks->ਕੁੰਜੀ, ਨਿਰਾ, id,
	    ਨਿਰਾ, ਨਿਰਾ) != 0) {
		debug3_f("key permitted at host but not after");
		ਵਾਪਸ -1;
	}

	/* success */
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
socket_is_remote(Socket_ਇੰਦਰਾਜ *e)
{
	ਵਾਪਸ e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
ਸਥਿਰ ਪਛਾਣ_ਤੱਤ *
lookup_ਪਛਾਣ_ਤੱਤ(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪਛਾਣ_ਤੱਤ *id;

	TAILQ_FOREACH(id, &idtab->idlist, ਅਗਲਾ) {
		ਜੇ (sshkey_equal(ਕੁੰਜੀ, id->ਕੁੰਜੀ))
			ਵਾਪਸ (id);
	}
	ਵਾਪਸ (ਨਿਰਾ);
}

/* Check confirmation of keysign request */
ਸਥਿਰ ਪੂਰਨ
confirm_ਕੁੰਜੀ(ਪਛਾਣ_ਤੱਤ *id, ਅਚਲ ਅੱਖਰ *extra)
{
	ਅੱਖਰ *p;
	ਪੂਰਨ ret = -1;

	p = sshkey_fingerprint(id->ਕੁੰਜੀ, fingerprint_hash, SSH_FP_DEFAULT);
	ਜੇ (p != ਨਿਰਾ &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == ਨਿਰਾ ? "" : "\n", extra == ਨਿਰਾ ? "" : extra))
		ret = 0;
	ਮੁਕਤ(p);

	ਵਾਪਸ (ret);
}

ਸਥਿਰ ਖਾਲੀ
send_ਸਥਿਤੀ_generic(Socket_ਇੰਦਰਾਜ *e, u_int ਕੋਡ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, ਕੋਡ)) != 0)
		fatal_fr(r, "compose");
}

ਸਥਿਰ ਖਾਲੀ
send_ਸਥਿਤੀ(Socket_ਇੰਦਰਾਜ *e, ਪੂਰਨ success)
{
	send_ਸਥਿਤੀ_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
ਸਥਿਰ ਖਾਲੀ
process_request_identities(Socket_ਇੰਦਰਾਜ *e)
{
	ਪਛਾਣ_ਤੱਤ *id;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ, *ਕੁੰਜੀਆਂ;
	ਪੂਰਨ r;
	u_int i = 0, nentries = 0;
	ਅੱਖਰ *fp;

	debug2_f("entering");

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ || (ਕੁੰਜੀਆਂ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, ਅਗਲਾ) {
		ਜੇ ((fp = sshkey_fingerprint(id->ਕੁੰਜੀ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->ਕੁੰਜੀ), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		ਮੁਕਤ(fp);
		/* identity not visible, don't include in response */
		ਜੇ (ਪਛਾਣ_ਤੱਤ_permitted(id, e, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ) != 0)
			ਜਾਰੀ;
		ਜੇ ((r = sshkey_puts(id->ਕੁੰਜੀ, ਕੁੰਜੀਆਂ)) != 0 ||
		    (r = sshbuf_put_cstring(ਕੁੰਜੀਆਂ, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			ਜਾਰੀ;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, nentries)) != 0 ||
	    (r = sshbuf_putb(ਸੁਨੇਹਾ, ਕੁੰਜੀਆਂ)) != 0)
		fatal_fr(r, "compose");
	ਜੇ ((r = sshbuf_put_stringb(e->output, ਸੁਨੇਹਾ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ਸੁਨੇਹਾ);
	sshbuf_free(ਕੁੰਜੀਆਂ);
}


ਸਥਿਰ ਅੱਖਰ *
agent_decode_alg(ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_int flags)
{
	ਜੇ (ਕੁੰਜੀ->type == ਕੁੰਜੀ_RSA) {
		ਜੇ (flags & SSH_AGENT_RSA_SHA2_256)
			ਵਾਪਸ "rsa-sha2-256";
		ਨਹੀਂਤਾਂ ਜੇ (flags & SSH_AGENT_RSA_SHA2_512)
			ਵਾਪਸ "rsa-sha2-512";
	} ਨਹੀਂਤਾਂ ਜੇ (ਕੁੰਜੀ->type == ਕੁੰਜੀ_RSA_CERT) {
		ਜੇ (flags & SSH_AGENT_RSA_SHA2_256)
			ਵਾਪਸ "rsa-sha2-256-cert-v01@openssh.com";
		ਨਹੀਂਤਾਂ ਜੇ (flags & SSH_AGENT_RSA_SHA2_512)
			ਵਾਪਸ "rsa-sha2-512-cert-v01@openssh.com";
	}
	ਵਾਪਸ ਨਿਰਾ;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
ਸਥਿਰ ਪੂਰਨ
parse_userauth_request(ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ, ਅਚਲ ਬਣਤਰ sshkey *expected_ਕੁੰਜੀ,
    ਅੱਖਰ **userp, ਬਣਤਰ sshbuf **sess_idp, ਬਣਤਰ sshkey **hostkeyp)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ, *sess_id = ਨਿਰਾ;
	ਅੱਖਰ *user = ਨਿਰਾ, *service = ਨਿਰਾ, *ਵਿਧੀ = ਨਿਰਾ, *pkalg = ਨਿਰਾ;
	ਪੂਰਨ r;
	u_char t, sig_follows;
	ਬਣਤਰ sshkey *mkey = ਨਿਰਾ, *hostkey = ਨਿਰਾ;

	ਜੇ (userp != ਨਿਰਾ)
		*userp = ਨਿਰਾ;
	ਜੇ (sess_idp != ਨਿਰਾ)
		*sess_idp = ਨਿਰਾ;
	ਜੇ (hostkeyp != ਨਿਰਾ)
		*hostkeyp = ਨਿਰਾ;
	ਜੇ ((b = sshbuf_fromb(ਸੁਨੇਹਾ)) == ਨਿਰਾ)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	ਜੇ ((r = sshbuf_froms(b, &sess_id)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, ਨਿਰਾ)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, ਨਿਰਾ)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &ਵਿਧੀ, ਨਿਰਾ)) != 0 || /*ਵਿਧੀ*/
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, ਨਿਰਾ)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*ਕੁੰਜੀ*/
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (t != SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_ਕੁੰਜੀ, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_ਕੁੰਜੀ->type) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (strcmp(ਵਿਧੀ, "publickey-hostbound-v00@openssh.com") == 0) {
		ਜੇ ((r = sshkey_froms(b, &hostkey)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ਵਿਧੀ, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	ਜੇ (userp != ਨਿਰਾ) {
		*userp = user;
		user = ਨਿਰਾ;
	}
	ਜੇ (sess_idp != ਨਿਰਾ) {
		*sess_idp = sess_id;
		sess_id = ਨਿਰਾ;
	}
	ਜੇ (hostkeyp != ਨਿਰਾ) {
		*hostkeyp = hostkey;
		hostkey = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	ਮੁਕਤ(user);
	ਮੁਕਤ(service);
	ਮੁਕਤ(ਵਿਧੀ);
	ਮੁਕਤ(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	ਵਾਪਸ r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
ਸਥਿਰ ਪੂਰਨ
parse_sshsig_request(ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ)
{
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *b;

	ਜੇ ((b = sshbuf_fromb(ਸੁਨੇਹਾ)) == ਨਿਰਾ)
		fatal_f("sshbuf_fromb");

	ਜੇ ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, ਨਿਰਾ, ਨਿਰਾ)) != 0 || /* namespace */
	    (r = sshbuf_get_string_ਸਿੱਧਾ(b, ਨਿਰਾ, ਨਿਰਾ)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, ਨਿਰਾ, ਨਿਰਾ)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_ਸਿੱਧਾ(b, ਨਿਰਾ, ਨਿਰਾ)) != 0) /* H(msg) */
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
ਸਥਿਰ ਪੂਰਨ
check_websafe_ਸੁਨੇਹਾ_contents(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *ਅੰਕੜੇ)
{
	ਜੇ (parse_userauth_request(ਅੰਕੜੇ, ਕੁੰਜੀ, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ) == 0) {
		debug_f("signed data matches public key userauth request");
		ਵਾਪਸ 1;
	}
	ਜੇ (parse_sshsig_request(ਅੰਕੜੇ) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		ਵਾਪਸ 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
buf_equal(ਅਚਲ ਬਣਤਰ sshbuf *a, ਅਚਲ ਬਣਤਰ sshbuf *b)
{
	ਜੇ (sshbuf_ptr(a) == ਨਿਰਾ || sshbuf_ptr(b) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (sshbuf_len(a) != sshbuf_len(b))
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਵਾਪਸ 0;
}

/* ssh2 only */
ਸਥਿਰ ਖਾਲੀ
process_sign_request2(Socket_ਇੰਦਰਾਜ *e)
{
	u_char *signature = ਨਿਰਾ;
	ਮਾਪ_t slen = 0;
	u_int compat = 0, flags;
	ਪੂਰਨ r, ok = -1, retried = 0;
	ਅੱਖਰ *fp = ਨਿਰਾ, *pin = ਨਿਰਾ, *prompt = ਨਿਰਾ;
	ਅੱਖਰ *user = ਨਿਰਾ, *sig_dest = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *fwd_host = ਨਿਰਾ, *dest_host = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ = ਨਿਰਾ, *ਅੰਕੜੇ = ਨਿਰਾ, *sid = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ, *hostkey = ਨਿਰਾ;
	ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 *id;
	ਬਣਤਰ notifier_ctx *notifier = ਨਿਰਾ;

	debug_f("entering");

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ || (ਅੰਕੜੇ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_froms(e->request, &ਕੁੰਜੀ)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, ਅੰਕੜੇ)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		ਜਾਓ send;
	}

	ਜੇ ((id = lookup_ਪਛਾਣ_ਤੱਤ(ਕੁੰਜੀ)) == ਨਿਰਾ) {
		verbose_f("%s key not found", sshkey_type(ਕੁੰਜੀ));
		ਜਾਓ send;
	}
	ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ)
		fatal_f("fingerprint failed");

	ਜੇ (id->ndest_constraints != 0) {
		ਜੇ (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			ਜਾਓ send;
		}
		ਜੇ (parse_userauth_request(ਅੰਕੜੇ, ਕੁੰਜੀ, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			ਜਾਓ send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		ਜੇ (ਪਛਾਣ_ਤੱਤ_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			ਜਾਓ send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		ਜੇ (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->ਕੁੰਜੀ), fp);
			ਜਾਓ send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		ਜੇ (e->nsession_ids > 1 && hostkey == ਨਿਰਾ) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			ਜਾਓ send;
		}
		ਜੇ (hostkey != ਨਿਰਾ && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].ਕੁੰਜੀ)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			ਜਾਓ send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	ਜੇ (id->confirm && confirm_ਕੁੰਜੀ(id, sig_dest) != 0) {
		verbose_f("user refused key");
		ਜਾਓ send;
	}
	ਜੇ (sshkey_is_sk(id->ਕੁੰਜੀ)) {
		ਜੇ (restrict_websafe &&
		    ਮੇਲ_ਨਮੂਨਾ_list(id->ਕੁੰਜੀ->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_ਸੁਨੇਹਾ_contents(ਕੁੰਜੀ, ਅੰਕੜੇ)) {
			/* error already logged */
			ਜਾਓ send;
		}
		ਜੇ (id->ਕੁੰਜੀ->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_ਸ਼ੁਰੂ(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->ਕੁੰਜੀ), fp,
			    sig_dest == ਨਿਰਾ ? "" : "\n",
			    sig_dest == ਨਿਰਾ ? "" : sig_dest);
		}
	}
 retry_pin:
	ਜੇ ((r = sshkey_sign(id->ਕੁੰਜੀ, &signature, &slen,
	    sshbuf_ptr(ਅੰਕੜੇ), sshbuf_len(ਅੰਕੜੇ), agent_decode_alg(ਕੁੰਜੀ, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ਜੇ (pin == ਨਿਰਾ && !retried && sshkey_is_sk(id->ਕੁੰਜੀ) &&
		    r == SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE) {
			notify_complete(notifier, ਨਿਰਾ);
			notifier = ਨਿਰਾ;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->ਕੁੰਜੀ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->ਕੁੰਜੀ), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			ਜਾਓ retry_pin;
		}
		error_fr(r, "sshkey_sign");
		ਜਾਓ send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	ਜੇ (ok == 0) {
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(ਸੁਨੇਹਾ, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	ਜੇ ((r = sshbuf_put_stringb(e->output, ਸੁਨੇਹਾ)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(ਅੰਕੜੇ);
	sshbuf_free(ਸੁਨੇਹਾ);
	sshkey_free(ਕੁੰਜੀ);
	sshkey_free(hostkey);
	ਮੁਕਤ(fp);
	ਮੁਕਤ(signature);
	ਮੁਕਤ(sig_dest);
	ਮੁਕਤ(user);
	ਮੁਕਤ(prompt);
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));
}

/* shared */
ਸਥਿਰ ਖਾਲੀ
process_remove_ਪਛਾਣ_ਤੱਤ(Socket_ਇੰਦਰਾਜ *e)
{
	ਪੂਰਨ r, success = 0;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਪਛਾਣ_ਤੱਤ *id;

	debug2_f("entering");
	ਜੇ ((r = sshkey_froms(e->request, &ਕੁੰਜੀ)) != 0) {
		error_fr(r, "parse key");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((id = lookup_ਪਛਾਣ_ਤੱਤ(ਕੁੰਜੀ)) == ਨਿਰਾ) {
		debug_f("key not found");
		ਜਾਓ ਪੂਰਾ;
	}
	/* identity not visible, cannot be removed */
	ਜੇ (ਪਛਾਣ_ਤੱਤ_permitted(id, e, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ) != 0)
		ਜਾਓ ਪੂਰਾ; /* error already logged */
	/* We have this key, free it. */
	ਜੇ (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, ਅਗਲਾ);
	free_ਪਛਾਣ_ਤੱਤ(id);
	idtab->nentries--;
	success = 1;
 ਪੂਰਾ:
	sshkey_free(ਕੁੰਜੀ);
	send_ਸਥਿਤੀ(e, success);
}

ਸਥਿਰ ਖਾਲੀ
remove_all_identities(ਖਾਲੀ)
{
	ਪਛਾਣ_ਤੱਤ *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	ਲਈ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, ਅਗਲਾ);
		free_ਪਛਾਣ_ਤੱਤ(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

ਸਥਿਰ ਖਾਲੀ
process_remove_all_identities(Socket_ਇੰਦਰਾਜ *e)
{
	remove_all_identities();

	/* Send success. */
	send_ਸਥਿਤੀ(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
ਸਥਿਰ time_t
reaper(ਖਾਲੀ)
{
	time_t deadline = 0, now = monotime();
	ਪਛਾਣ_ਤੱਤ *id, *nxt;

	ਲਈ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, ਅਗਲਾ);
		ਜੇ (id->death == 0)
			ਜਾਰੀ;
		ਜੇ (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, ਅਗਲਾ);
			free_ਪਛਾਣ_ਤੱਤ(id);
			idtab->nentries--;
		} ਨਹੀਂਤਾਂ
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	ਜੇ (deadline == 0 || deadline <= now)
		ਵਾਪਸ 0;
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ (deadline - now);
}

ਸਥਿਰ ਪੂਰਨ
parse_dest_constraint_hop(ਬਣਤਰ sshbuf *b, ਬਣਤਰ dest_constraint_hop *dch)
{
	u_char ਕੁੰਜੀ_is_ca;
	ਮਾਪ_t elen = 0, userlen = 0;
	ਪੂਰਨ r;
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਅੱਖਰ *fp;

	memset(dch, '\0', ਆਕਾਰ(*dch));
	ਜੇ ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(b, ਨਿਰਾ, &elen)) != 0) {
		error_fr(r, "parse");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (*dch->hostname == '\0') {
		ਮੁਕਤ(dch->hostname);
		dch->hostname = ਨਿਰਾ;
	}
	ਜੇ (*dch->user == '\0') {
		ਮੁਕਤ(dch->user);
		dch->user = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜਦੋਂ (sshbuf_len(b) != 0) {
		dch->ਕੁੰਜੀਆਂ = xrecallocarray(dch->ਕੁੰਜੀਆਂ, dch->nkeys,
		    dch->nkeys + 1, ਆਕਾਰ(*dch->ਕੁੰਜੀਆਂ));
		dch->ਕੁੰਜੀ_is_ca = xrecallocarray(dch->ਕੁੰਜੀ_is_ca, dch->nkeys,
		    dch->nkeys + 1, ਆਕਾਰ(*dch->ਕੁੰਜੀ_is_ca));
		ਜੇ ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &ਕੁੰਜੀ_is_ca)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == ਨਿਰਾ ? "" : dch->user,
		    dch->user == ਨਿਰਾ ? "" : "@",
		    dch->hostname, ਕੁੰਜੀ_is_ca ? "CA " : "", sshkey_type(k), fp);
		ਮੁਕਤ(fp);
		dch->ਕੁੰਜੀਆਂ[dch->nkeys] = k;
		dch->ਕੁੰਜੀ_is_ca[dch->nkeys] = ਕੁੰਜੀ_is_ca != 0;
		dch->nkeys++;
		k = ਨਿਰਾ; /* transferred */
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshkey_free(k);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
parse_dest_constraint(ਬਣਤਰ sshbuf *m, ਬਣਤਰ dest_constraint *dc)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ, *frombuf = ਨਿਰਾ, *tobuf = ਨਿਰਾ;
	ਪੂਰਨ r;
	ਮਾਪ_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', ਆਕਾਰ(*dc));
	ਜੇ ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(b, ਨਿਰਾ, &elen)) != 0) {
		error_fr(r, "parse");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->ਮੰਜ਼ਿਲ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ; /* already logged */
	ਜੇ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->ਮੰਜ਼ਿਲ.user ? dc->ਮੰਜ਼ਿਲ.user : "", dc->ਮੰਜ਼ਿਲ.user ? "@" : "",
	    dc->ਮੰਜ਼ਿਲ.hostname ? dc->ਮੰਜ਼ਿਲ.hostname : "(ANY)", dc->ਮੰਜ਼ਿਲ.nkeys);
	/* check consistency */
	ਜੇ ((dc->from.hostname == ਨਿਰਾ) != (dc->from.nkeys == 0) ||
	    dc->from.user != ਨਿਰਾ) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (dc->ਮੰਜ਼ਿਲ.hostname == ਨਿਰਾ || dc->ਮੰਜ਼ਿਲ.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
parse_ਕੁੰਜੀ_constraint_extension(ਬਣਤਰ sshbuf *m, ਅੱਖਰ **sk_providerp,
    ਬਣਤਰ dest_constraint **dcsp, ਮਾਪ_t *ndcsp, ਪੂਰਨ *cert_onlyp,
    ਬਣਤਰ sshkey ***certs, ਮਾਪ_t *ncerts)
{
	ਅੱਖਰ *ext_name = ਨਿਰਾ;
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	u_char v;
	ਬਣਤਰ sshkey *k;

	ਜੇ ((r = sshbuf_get_cstring(m, &ext_name, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse constraint extension");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug_f("constraint ext %s", ext_name);
	ਜੇ (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		ਜੇ (sk_providerp == ਨਿਰਾ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*sk_providerp != ਨਿਰਾ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_get_cstring(m, sk_providerp, ਨਿਰਾ)) != 0) {
			error_fr(r, "parse %s", ext_name);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		ਜੇ (*dcsp != ਨਿਰਾ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜਦੋਂ (sshbuf_len(b) != 0) {
			ਜੇ (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    ਆਕਾਰ(**dcsp));
			ਜੇ ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
		}
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		ਜੇ (certs == ਨਿਰਾ || ncerts == ਨਿਰਾ || cert_onlyp == ਨਿਰਾ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*certs != ਨਿਰਾ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		*cert_onlyp = v != 0;
		ਜਦੋਂ (sshbuf_len(b) != 0) {
			ਜੇ (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    ਆਕਾਰ(**certs));
			ਜੇ ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} ਨਹੀਂਤਾਂ {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ext_name);
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
parse_ਕੁੰਜੀ_constraints(ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshkey *k, time_t *deathp,
    u_int *secondsp, ਪੂਰਨ *confirmp, ਅੱਖਰ **sk_providerp,
    ਬਣਤਰ dest_constraint **dcsp, ਮਾਪ_t *ndcsp,
    ਪੂਰਨ *cert_onlyp, ਮਾਪ_t *ncerts, ਬਣਤਰ sshkey ***certs)
{
	u_char ctype;
	ਪੂਰਨ r;
	u_int seconds;

	ਜਦੋਂ (sshbuf_len(m)) {
		ਜੇ ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਚੋਣ (ctype) {
		ਹਾਲਤ SSH_AGENT_CONSTRAIN_LIFETIME:
			ਜੇ (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			ਰੋਕੋ;
		ਹਾਲਤ SSH_AGENT_CONSTRAIN_CONFIRM:
			ਜੇ (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			*confirmp = 1;
			ਰੋਕੋ;
		ਹਾਲਤ SSH_AGENT_CONSTRAIN_EXTENSION:
			ਜੇ ((r = parse_ਕੁੰਜੀ_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
			ਰੋਕੋ;
		ਮੂਲ:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
process_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ(Socket_ਇੰਦਰਾਜ *e)
{
	ਪਛਾਣ_ਤੱਤ *id;
	ਪੂਰਨ success = 0, confirm = 0;
	ਅੱਖਰ *fp, *comment = ਨਿਰਾ, *sk_provider = ਨਿਰਾ;
	ਅੱਖਰ canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	ਬਣਤਰ dest_constraint *dest_constraints = ਨਿਰਾ;
	ਮਾਪ_t ndest_constraints = 0;
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	debug2_f("entering");
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_deserialize(e->request, &k)) != 0 ||
	    k == ਨਿਰਾ ||
	    (r = sshbuf_get_cstring(e->request, &comment, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (parse_ਕੁੰਜੀ_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	ਜੇ (sk_provider != ਨਿਰਾ) {
		ਜੇ (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} ਨਹੀਂਤਾਂ {
			ਜੇ (socket_is_remote(e) && !remote_ਜੋੜੋ_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (realpath(sk_provider, canonical_provider) == ਨਿਰਾ) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਮੁਕਤ(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
	}
	ਜੇ ((r = sshkey_shield_ਨਿੱਜੀ(k)) != 0) {
		error_fr(r, "shield private");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (lifetime && !death)
		death = monotime() + lifetime;
	ਜੇ ((id = lookup_ਪਛਾਣ_ਤੱਤ(k)) == ਨਿਰਾ) {
		id = xcalloc(1, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, ਅਗਲਾ);
		/* Increment the number of identities. */
		idtab->nentries++;
	} ਨਹੀਂਤਾਂ {
		/* identity not visible, do not update */
		ਜੇ (ਪਛਾਣ_ਤੱਤ_permitted(id, e, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ) != 0)
			ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->ਕੁੰਜੀ);
		ਮੁਕਤ(id->comment);
		ਮੁਕਤ(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->ਕੁੰਜੀ = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	ਜੇ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == ਨਿਰਾ ? "none" : sk_provider, ndest_constraints);
	ਮੁਕਤ(fp);
	/* transferred */
	k = ਨਿਰਾ;
	comment = ਨਿਰਾ;
	sk_provider = ਨਿਰਾ;
	dest_constraints = ਨਿਰਾ;
	ndest_constraints = 0;
	success = 1;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(sk_provider);
	ਮੁਕਤ(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_ਸਥਿਤੀ(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
ਸਥਿਰ ਖਾਲੀ
process_ਤਾਲਾ_agent(Socket_ਇੰਦਰਾਜ *e, ਪੂਰਨ ਤਾਲਾ)
{
	ਪੂਰਨ r, success = 0, delay;
	ਅੱਖਰ *passwd;
	u_char passwdhash[ਤਾਲਾ_ਮਾਪ];
	ਸਥਿਰ u_int fail_ਗਿਣਤੀ = 0;
	ਮਾਪ_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	ਜੇ ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (pwlen == 0) {
		debug("empty password not supported");
	} ਨਹੀਂਤਾਂ ਜੇ (locked && !ਤਾਲਾ) {
		ਜੇ (bcrypt_pbkdf(passwd, pwlen, ਤਾਲਾ_salt, ਆਕਾਰ(ਤਾਲਾ_salt),
		    passwdhash, ਆਕਾਰ(passwdhash), ਤਾਲਾ_ਗੇੜ) < 0)
			fatal("bcrypt_pbkdf");
		ਜੇ (timingsafe_bcmp(passwdhash, ਤਾਲਾ_pwhash, ਤਾਲਾ_ਮਾਪ) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_ਗਿਣਤੀ = 0;
			explicit_bzero(ਤਾਲਾ_pwhash, ਆਕਾਰ(ਤਾਲਾ_pwhash));
			success = 1;
		} ਨਹੀਂਤਾਂ {
			/* delay in 0.1s increments up to 10s */
			ਜੇ (fail_ਗਿਣਤੀ < 100)
				fail_ਗਿਣਤੀ++;
			delay = 100000 * fail_ਗਿਣਤੀ;
			debug("unlock failed, delaying %0.1lf seconds",
			    (ਦੁੱਗਣਾ)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, ਆਕਾਰ(passwdhash));
	} ਨਹੀਂਤਾਂ ਜੇ (!locked && ਤਾਲਾ) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(ਤਾਲਾ_salt, ਆਕਾਰ(ਤਾਲਾ_salt));
		ਜੇ (bcrypt_pbkdf(passwd, pwlen, ਤਾਲਾ_salt, ਆਕਾਰ(ਤਾਲਾ_salt),
		    ਤਾਲਾ_pwhash, ਆਕਾਰ(ਤਾਲਾ_pwhash), ਤਾਲਾ_ਗੇੜ) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_ਸਥਿਤੀ(e, success);
}

ਸਥਿਰ ਖਾਲੀ
no_identities(Socket_ਇੰਦਰਾਜ *e)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, ਸੁਨੇਹਾ)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(ਸੁਨੇਹਾ);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
ਸਥਿਰ ਖਾਲੀ
ਜੋੜੋ_p11_ਪਛਾਣ_ਤੱਤ(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅੱਖਰ *comment, ਅਚਲ ਅੱਖਰ *provider,
    time_t death, u_int confirm, ਬਣਤਰ dest_constraint *dest_constraints,
    ਮਾਪ_t ndest_constraints)
{
	ਪਛਾਣ_ਤੱਤ *id;

	ਜੇ (lookup_ਪਛਾਣ_ਤੱਤ(ਕੁੰਜੀ) != ਨਿਰਾ) {
		sshkey_free(ਕੁੰਜੀ);
		ਮੁਕਤ(comment);
		ਵਾਪਸ;
	}
	id = xcalloc(1, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ));
	id->ਕੁੰਜੀ = ਕੁੰਜੀ;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, ਅਗਲਾ);
	idtab->nentries++;
}

ਸਥਿਰ ਖਾਲੀ
process_ਜੋੜੋ_smartcard_ਕੁੰਜੀ(Socket_ਇੰਦਰਾਜ *e)
{
	ਅੱਖਰ *provider = ਨਿਰਾ, *pin = ਨਿਰਾ, canonical_provider[PATH_MAX];
	ਅੱਖਰ **comments = ਨਿਰਾ;
	ਪੂਰਨ r, i, ਗਿਣਤੀ_2 = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ = ਨਿਰਾ, *k;
	ਬਣਤਰ dest_constraint *dest_constraints = ਨਿਰਾ;
	ਮਾਪ_t j, ndest_constraints = 0, ncerts = 0;
	ਬਣਤਰ sshkey **certs = ਨਿਰਾ;
	ਪੂਰਨ cert_only = 0;

	debug2_f("entering");
	ਜੇ ((r = sshbuf_get_cstring(e->request, &provider, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse");
		ਜਾਓ send;
	}
	ਜੇ (parse_ਕੁੰਜੀ_constraints(e->request, ਨਿਰਾ, &death, &seconds, &confirm,
	    ਨਿਰਾ, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		ਜਾਓ send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	ਜੇ (socket_is_remote(e) && !remote_ਜੋੜੋ_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		ਜਾਓ send;
	}
	ਜੇ (realpath(provider, canonical_provider) == ਨਿਰਾ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		ਜਾਓ send;
	}
	ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		ਜਾਓ send;
	}
	debug_f("add %.100s", canonical_provider);
	ਜੇ (lifetime && !death)
		death = monotime() + lifetime;

	ਗਿਣਤੀ_2 = pkcs11_ਜੋੜੋ_provider(canonical_provider, pin, &ਕੁੰਜੀਆਂ, &comments);
	ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++) {
		ਜੇ (comments[i] == ਨਿਰਾ || comments[i][0] == '\0') {
			ਮੁਕਤ(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		ਲਈ (j = 0; j < ncerts; j++) {
			ਜੇ (!sshkey_is_cert(certs[j]))
				ਜਾਰੀ;
			ਜੇ (!sshkey_equal_ਜਨਤਕ(ਕੁੰਜੀਆਂ[i], certs[j]))
				ਜਾਰੀ;
			ਜੇ (pkcs11_make_cert(ਕੁੰਜੀਆਂ[i], certs[j], &k) != 0)
				ਜਾਰੀ;
			ਜੋੜੋ_p11_ਪਛਾਣ_ਤੱਤ(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		ਜੇ (!cert_only && lookup_ਪਛਾਣ_ਤੱਤ(ਕੁੰਜੀਆਂ[i]) == ਨਿਰਾ) {
			ਜੋੜੋ_p11_ਪਛਾਣ_ਤੱਤ(ਕੁੰਜੀਆਂ[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;		/* transferred */
			comments[i] = ਨਿਰਾ;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(ਕੁੰਜੀਆਂ[i]);
		ਮੁਕਤ(comments[i]);
	}
send:
	ਮੁਕਤ(pin);
	ਮੁਕਤ(provider);
	ਮੁਕਤ(ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ਲਈ (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	ਮੁਕਤ(certs);
	send_ਸਥਿਤੀ(e, success);
}

ਸਥਿਰ ਖਾਲੀ
process_remove_smartcard_ਕੁੰਜੀ(Socket_ਇੰਦਰਾਜ *e)
{
	ਅੱਖਰ *provider = ਨਿਰਾ, *pin = ਨਿਰਾ, canonical_provider[PATH_MAX];
	ਪੂਰਨ r, success = 0;
	ਪਛਾਣ_ਤੱਤ *id, *nxt;

	debug2_f("entering");
	ਜੇ ((r = sshbuf_get_cstring(e->request, &provider, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse");
		ਜਾਓ send;
	}
	ਮੁਕਤ(pin);

	ਜੇ (realpath(provider, canonical_provider) == ਨਿਰਾ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		ਜਾਓ send;
	}

	debug_f("remove %.100s", canonical_provider);
	ਲਈ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, ਅਗਲਾ);
		/* Skip file--based keys */
		ਜੇ (id->provider == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, ਅਗਲਾ);
			free_ਪਛਾਣ_ਤੱਤ(id);
			idtab->nentries--;
		}
	}
	ਜੇ (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	ਨਹੀਂਤਾਂ
		error_f("pkcs11_del_provider failed");
send:
	ਮੁਕਤ(provider);
	send_ਸਥਿਤੀ(e, success);
}
#ਜੇ_ਅੰਤ /* ENABLE_PKCS11 */

ਸਥਿਰ ਪੂਰਨ
process_ext_session_bind(Socket_ਇੰਦਰਾਜ *e)
{
	ਪੂਰਨ r, sid_ਮੇਲ, ਕੁੰਜੀ_ਮੇਲ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *sid = ਨਿਰਾ, *sig = ਨਿਰਾ;
	ਅੱਖਰ *fp = ਨਿਰਾ;
	ਮਾਪ_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	ਜੇ ((r = sshkey_froms(e->request, &ਕੁੰਜੀ)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	ਜੇ ((r = sshkey_verify(ਕੁੰਜੀ, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), ਨਿਰਾ, 0, ਨਿਰਾ)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(ਕੁੰਜੀ), fp);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* check whether sid/key already recorded */
	ਲਈ (i = 0; i < e->nsession_ids; i++) {
		ਜੇ (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		sid_ਮੇਲ = buf_equal(sid, e->session_ids[i].sid) == 0;
		ਕੁੰਜੀ_ਮੇਲ = sshkey_equal(ਕੁੰਜੀ, e->session_ids[i].ਕੁੰਜੀ);
		ਜੇ (sid_ਮੇਲ && ਕੁੰਜੀ_ਮੇਲ) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(ਕੁੰਜੀ), fp);
			r = 0;
			ਜਾਓ ਬਾਹਰਲਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (sid_ਮੇਲ) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(ਕੁੰਜੀ), fp);
			r = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	ਜੇ (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, ਆਕਾਰ(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(ਕੁੰਜੀ), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].ਕੁੰਜੀ = ਕੁੰਜੀ;
	e->session_ids[i].forwarded = fwd != 0;
	ਕੁੰਜੀ = ਨਿਰਾ; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	ਜੇ ((e->session_ids[i].sid = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(fp);
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(sid);
	sshbuf_free(sig);
	ਵਾਪਸ r == 0 ? 1 : 0;
}

ਸਥਿਰ ਪੂਰਨ
process_ext_query(Socket_ਇੰਦਰਾਜ *e)
{
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ = ਨਿਰਾ;

	debug2_f("entering");
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	ਜੇ ((r = sshbuf_put_stringb(e->output, ਸੁਨੇਹਾ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
process_extension(Socket_ਇੰਦਰਾਜ *e)
{
	ਪੂਰਨ r, replied = 0, success = 0;
	ਅੱਖਰ *name;

	debug2_f("entering");
	ਜੇ ((r = sshbuf_get_cstring(e->request, &name, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse");
		send_ਸਥਿਤੀ(e, 0);
		ਵਾਪਸ;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	ਜੇ (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} ਨਹੀਂਤਾਂ ਜੇ (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		ਜਾਓ generic_fail;
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} ਨਹੀਂਤਾਂ {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		ਮੁਕਤ(name);
		send_ਸਥਿਤੀ(e, 0);
		ਵਾਪਸ;
	}
	ਮੁਕਤ(name);
	/* Agent failures are signalled with a different error code */
	ਜੇ (!replied) {
		send_ਸਥਿਤੀ_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
ਸਥਿਰ ਪੂਰਨ
process_ਸੁਨੇਹਾ(u_int socknum)
{
	u_int ਸੁਨੇਹਾ_len;
	u_char type;
	ਅਚਲ u_char *cp;
	ਪੂਰਨ r;
	Socket_ਇੰਦਰਾਜ *e;

	ਜੇ (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	ਜੇ (sshbuf_len(e->ਨਿਵੇਸ਼) < 5)
		ਵਾਪਸ 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->ਨਿਵੇਸ਼);
	ਸੁਨੇਹਾ_len = PEEK_U32(cp);
	ਜੇ (ਸੁਨੇਹਾ_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, ਸੁਨੇਹਾ_len, AGENT_MAX_LEN);
		ਵਾਪਸ -1;
	}
	ਜੇ (sshbuf_len(e->ਨਿਵੇਸ਼) < ਸੁਨੇਹਾ_len + 4)
		ਵਾਪਸ 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	ਜੇ ((r = sshbuf_get_stringb(e->ਨਿਵੇਸ਼, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		ਜੇ (r == SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			ਵਾਪਸ -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	ਜੇ (locked && type != SSH_AGENTC_UNLOCK) {
		ਚੋਣ (type) {
		ਹਾਲਤ SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			ਰੋਕੋ;
		ਹਾਲਤ SSH_AGENTC_EXTENSION:
			process_extension(e);
			ਰੋਕੋ;
		ਮੂਲ:
			/* send a fail message for all other request types */
			send_ਸਥਿਤੀ(e, 0);
		}
		sshbuf_reset(e->request);
		ਵਾਪਸ 1;
	}

	ਚੋਣ (type) {
	ਹਾਲਤ SSH_AGENTC_ਤਾਲਾ:
	ਹਾਲਤ SSH_AGENTC_UNLOCK:
		process_ਤਾਲਾ_agent(e, type == SSH_AGENTC_ਤਾਲਾ);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		ਰੋਕੋ;
	/* ssh2 */
	ਹਾਲਤ SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_AGENTC_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ:
	ਹਾਲਤ SSH2_AGENTC_ਜੋੜੋ_ID_CONSTRAINED:
		process_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ(e);
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_AGENTC_REMOVE_ਪਛਾਣ_ਤੱਤ:
		process_remove_ਪਛਾਣ_ਤੱਤ(e);
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		ਰੋਕੋ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	ਹਾਲਤ SSH_AGENTC_ਜੋੜੋ_SMARTCARD_ਕੁੰਜੀ:
	ਹਾਲਤ SSH_AGENTC_ਜੋੜੋ_SMARTCARD_ਕੁੰਜੀ_CONSTRAINED:
		process_ਜੋੜੋ_smartcard_ਕੁੰਜੀ(e);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_AGENTC_REMOVE_SMARTCARD_ਕੁੰਜੀ:
		process_remove_smartcard_ਕੁੰਜੀ(e);
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* ENABLE_PKCS11 */
	ਹਾਲਤ SSH_AGENTC_EXTENSION:
		process_extension(e);
		ਰੋਕੋ;
	ਮੂਲ:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_ਸਥਿਤੀ(e, 0);
		ਰੋਕੋ;
	}
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
new_socket(sock_type type, ਪੂਰਨ fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	ਸੈੱਟ_nonblock(fd);

	ਜੇ (fd > max_fd)
		max_fd = fd;

	ਲਈ (i = 0; i < sockets_alloc; i++)
		ਜੇ (sockets[i].type == AUTH_ਅਣਵਰਤਿਆ) {
			sockets[i].fd = fd;
			ਜੇ ((sockets[i].ਨਿਵੇਸ਼ = sshbuf_new()) == ਨਿਰਾ ||
			    (sockets[i].output = sshbuf_new()) == ਨਿਰਾ ||
			    (sockets[i].request = sshbuf_new()) == ਨਿਰਾ)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			ਵਾਪਸ;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    ਆਕਾਰ(sockets[0]));
	ਲਈ (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_ਅਣਵਰਤਿਆ;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	ਜੇ ((sockets[old_alloc].ਨਿਵੇਸ਼ = sshbuf_new()) == ਨਿਰਾ ||
	    (sockets[old_alloc].output = sshbuf_new()) == ਨਿਰਾ ||
	    (sockets[old_alloc].request = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

ਸਥਿਰ ਪੂਰਨ
handle_socket_read(u_int socknum)
{
	ਬਣਤਰ sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	ਪੂਰਨ fd;

	slen = ਆਕਾਰ(sunaddr);
	fd = accept(sockets[socknum].fd, (ਬਣਤਰ sockaddr *)&sunaddr, &slen);
	ਜੇ (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		ਵਾਪਸ -1;
	}
	ਜੇ ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		ਵਾਪਸ -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
handle_conn_read(u_int socknum)
{
	ਅੱਖਰ buf[AGENT_RBUF_LEN];
	ssize_t len;
	ਪੂਰਨ r;

	ਜੇ ((len = ਪਠ(sockets[socknum].fd, buf, ਆਕਾਰ(buf))) <= 0) {
		ਜੇ (len == -1) {
			ਜੇ (errno == EAGAIN || errno == EINTR)
				ਵਾਪਸ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ਵਾਪਸ -1;
	}
	ਜੇ ((r = sshbuf_put(sockets[socknum].ਨਿਵੇਸ਼, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, ਆਕਾਰ(buf));
	ਲਈ (;;) {
		ਜੇ ((r = process_ਸੁਨੇਹਾ(socknum)) == -1)
			ਵਾਪਸ -1;
		ਨਹੀਂਤਾਂ ਜੇ (r == 0)
			ਰੋਕੋ;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
handle_conn_write(u_int socknum)
{
	ssize_t len;
	ਪੂਰਨ r;

	ਜੇ (sshbuf_len(sockets[socknum].output) == 0)
		ਵਾਪਸ 0; /* shouldn't happen */
	ਜੇ ((len = ਲਿਖ(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		ਜੇ (len == -1) {
			ਜੇ (errno == EAGAIN || errno == EINTR)
				ਵਾਪਸ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ਵਾਪਸ -1;
	}
	ਜੇ ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
after_poll(ਬਣਤਰ pollfd *pfd, ਮਾਪ_t npfd, u_int maxfds)
{
	ਮਾਪ_t i;
	u_int socknum, activefds = npfd;

	ਲਈ (i = 0; i < npfd; i++) {
		ਜੇ (pfd[i].revents == 0)
			ਜਾਰੀ;
		/* Find sockets entry */
		ਲਈ (socknum = 0; socknum < sockets_alloc; socknum++) {
			ਜੇ (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				ਜਾਰੀ;
			ਜੇ (pfd[i].fd == sockets[socknum].fd)
				ਰੋਕੋ;
		}
		ਜੇ (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			ਜਾਰੀ;
		}
		/* Process events */
		ਚੋਣ (sockets[socknum].type) {
		ਹਾਲਤ AUTH_SOCKET:
			ਜੇ ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				ਰੋਕੋ;
			ਜੇ (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				ਰੋਕੋ;
			}
			ਜੇ (handle_socket_read(socknum) == 0)
				activefds++;
			ਰੋਕੋ;
		ਹਾਲਤ AUTH_CONNECTION:
			ਜੇ ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				ਜਾਓ close_sock;
			ਜੇ ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				ਜੇ (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				ਰੋਕੋ;
			}
			ਰੋਕੋ;
		ਮੂਲ:
			ਰੋਕੋ;
		}
	}
}

ਸਥਿਰ ਪੂਰਨ
prepare_poll(ਬਣਤਰ pollfd **pfdp, ਮਾਪ_t *npfdp, ਬਣਤਰ timespec *timeoutp, u_int maxfds)
{
	ਬਣਤਰ pollfd *pfd = *pfdp;
	ਮਾਪ_t i, j, npfd = 0;
	time_t deadline;
	ਪੂਰਨ r;

	/* Count active sockets */
	ਲਈ (i = 0; i < sockets_alloc; i++) {
		ਚੋਣ (sockets[i].type) {
		ਹਾਲਤ AUTH_SOCKET:
		ਹਾਲਤ AUTH_CONNECTION:
			npfd++;
			ਰੋਕੋ;
		ਹਾਲਤ AUTH_ਅਣਵਰਤਿਆ:
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("Unknown socket type %d", sockets[i].type);
			ਰੋਕੋ;
		}
	}
	ਜੇ (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, ਆਕਾਰ(*pfd))) == ਨਿਰਾ)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	ਲਈ (i = j = 0; i < sockets_alloc; i++) {
		ਚੋਣ (sockets[i].type) {
		ਹਾਲਤ AUTH_SOCKET:
			ਜੇ (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				ਰੋਕੋ;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			ਰੋਕੋ;
		ਹਾਲਤ AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			ਜੇ ((r = sshbuf_check_reserve(sockets[i].ਨਿਵੇਸ਼,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			ਨਹੀਂਤਾਂ ਜੇ (r != SSH_ERR_NO_ਬਫਰ_SPACE)
				fatal_fr(r, "reserve");
			ਜੇ (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			ਰੋਕੋ;
		ਮੂਲ:
			ਰੋਕੋ;
		}
	}
	deadline = reaper();
	ਜੇ (ਮਾਪਾ_alive_interval != 0)
		deadline = (deadline == 0) ? ਮਾਪਾ_alive_interval :
		    MINIMUM(deadline, ਮਾਪਾ_alive_interval);
	ਜੇ (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	ਵਾਪਸ (1);
}

ਸਥਿਰ ਖਾਲੀ
cleanup_socket(ਖਾਲੀ)
{
	ਜੇ (cleanup_pid != 0 && getpid() != cleanup_pid)
		ਵਾਪਸ;
	debug_f("cleanup");
	ਜੇ (socket_name != ਨਿਰਾ) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		ਮੁਕਤ(socket_name);
		socket_name = ਨਿਰਾ;
		ਮੁਕਤ(socket_dir);
		socket_dir = ਨਿਰਾ;
	}
}

ਖਾਲੀ
cleanup_exit(ਪੂਰਨ i)
{
	cleanup_socket();
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	pkcs11_terminate();
#ਜੇ_ਅੰਤ
	_exit(i);
}

ਸਥਿਰ ਖਾਲੀ
cleanup_handler(ਪੂਰਨ sig)
{
	signalled_exit = sig;
}

ਸਥਿਰ ਖਾਲੀ
keydrop_handler(ਪੂਰਨ sig)
{
	signalled_keydrop = sig;
}

ਸਥਿਰ ਖਾਲੀ
check_ਮਾਪਾ_exists(ਖਾਲੀ)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	ਜੇ (ਮਾਪਾ_pid != -1 && getppid() != ਮਾਪਾ_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr,
	    "usage: ssh-agent [-c | -s] [-DdU] [-T | -A directory | -a bind_address]\n"
	    "                 [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life]\n"
	    "       ssh-agent [-U] [-T | -A directory | -a bind_address]\n"
	    "                 [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life] command [arg ...]\n"
	    "       ssh-agent [-c | -s] -k\n"
	    "       ssh-agent -u\n"
	    "       ssh-agent -V\n");
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ ac, ਅੱਖਰ **av)
{
	ਪੂਰਨ c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	ਪੂਰਨ s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	ਪੂਰਨ sock = -1, ch, ਨਤੀਜਾ, saved_errno;
	pid_t pid;
 	ਅੱਖਰ *homedir = ਨਿਰਾ, *shell, *format, *pidstr, *agentsocket = ਨਿਰਾ;
	ਅੱਖਰ *cp, pidstrbuf[1 + 3 * ਆਕਾਰ pid];
	ਅੱਖਰ *fdstr;
	ਅਚਲ ਅੱਖਰ *errstr = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *ccp;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SETRLIMIT
	ਬਣਤਰ rlimit rlim;
#ਜੇ_ਅੰਤ
	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਮਾਪ_t len;
	ਬਹੁਲਕ_t prev_ਨਕਾਬ;
	ਬਣਤਰ timespec timeout;
	ਬਣਤਰ pollfd *pfd = ਨਿਰਾ;
	ਮਾਪ_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	ਪੂਰਨ socket_activated = 0;
	ਬਣਤਰ passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(ਖਾਲੀ)setegid(getgid());
	(ਖਾਲੀ)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	ਜੇ ((pw = getpwuid(getuid())) == ਨਿਰਾ)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ RLIMIT_NOFILE
	ਜੇ (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#ਜੇ_ਅੰਤ

	__progname = ssh_get_progname(av[0]);
	ਬੀਜ_rng();

	ਜਦੋਂ ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ਜੇ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'c':
			ਜੇ (s_flag)
				usage();
			c_flag++;
			ਰੋਕੋ;
		ਹਾਲਤ 'k':
			k_flag++;
			ਰੋਕੋ;
		ਹਾਲਤ 'O':
			ਜੇ (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_ਜੋੜੋ_provider = 1;
			ਨਹੀਂਤਾਂ ਜੇ ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != ਨਿਰਾ) {
				ਜੇ (websafe_allowlist != ਨਿਰਾ)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} ਨਹੀਂਤਾਂ
				fatal("Unknown -O option");
			ਰੋਕੋ;
		ਹਾਲਤ 'P':
			ਜੇ (allowed_providers != ਨਿਰਾ)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 's':
			ਜੇ (c_flag)
				usage();
			s_flag++;
			ਰੋਕੋ;
		ਹਾਲਤ 'd':
			ਜੇ (d_flag || D_flag)
				usage();
			d_flag++;
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
			ਜੇ (d_flag || D_flag)
				usage();
			D_flag++;
			ਰੋਕੋ;
		ਹਾਲਤ 'a':
			agentsocket = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'A':
			socket_dirspec = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 't':
			ਜੇ ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'T':
			T_flag++;
			ਰੋਕੋ;
		ਹਾਲਤ 'u':
			u_flag++;
			ਰੋਕੋ;
		ਹਾਲਤ 'U':
			U_flag++;
			ਰੋਕੋ;
		ਹਾਲਤ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_ਸੰਸਕਰਣ, SSH_OPENSSL_ਸੰਸਕਰਣ);
			ਬਾਹਰ_ਨਿਕਲੋ(0);
		ਮੂਲ:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	ਜੇ (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	ਜੇ (((socket_dirspec != ਨਿਰਾ) + (agentsocket != ਨਿਰਾ) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	ਜੇ (allowed_providers == ਨਿਰਾ)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	ਜੇ (websafe_allowlist == ਨਿਰਾ)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	ਜੇ (T_flag)
		socket_dirspec = xstrdup(ਰਸਤਾ_SSH_AGENT_SOCKET_TMPDIR);
	ਨਹੀਂਤਾਂ ਜੇ (socket_dirspec == ਨਿਰਾ && agentsocket == ਨਿਰਾ)
		socket_dirspec = xstrdup(ਰਸਤਾ_SSH_AGENT_SOCKET_DIR);

	ਜੇ (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		ਜੇ (shell != ਨਿਰਾ && (len = ਲੜੀ_ਲੰਬਾਈ(shell)) > 2 &&
		    ਲੜੀ_ਤੁਲਨਾ(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	ਜੇ (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		ਜੇ (pidstr == ਨਿਰਾ) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		pid = (ਪੂਰਨ)strtonum(pidstr, 2, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &errstr);
		ਜੇ (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		ਜੇ (kill(pid, SIGTERM) == -1) {
			perror("kill");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		ਲਿਖੋ(format, SSH_AUTHSOCKET_ENV_NAME);
		ਲਿਖੋ(format, SSH_AGENTPID_ENV_NAME);
		ਲਿਖੋ("echo Agent pid %ld killed;\n", (ਲੰਮਾ)pid);
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	}
	ਜੇ (u_flag) {
		ਜੇ ((homedir = get_homedir()) == ਨਿਰਾ)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		ਲਿਖੋ("Deleted stale agent sockets in ~/%s\n",
		    ਰਸਤਾ_SSH_AGENT_SOCKET_DIR);
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENT_MIN_FDS (3+1+1+1+4)
	ਜੇ (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (ਲੰਮਾ ਲੰਮਾ)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	ਮਾਪਾ_pid = getpid();

	/* Has the socket been provided via socket activation? */
	ਜੇ (agentsocket == ਨਿਰਾ && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != ਨਿਰਾ &&
	    (fdstr = getenv("LISTEN_FDS")) != ਨਿਰਾ) {
		ਜੇ (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		ਜੇ (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (ਪੂਰਨ)strtonum(pidstr, 1, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &errstr);
		ਜੇ (errstr != ਨਿਰਾ)
			fatal("invalid LISTEN_PID: %s", errstr);
		ਜੇ (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	ਜੇ (sock == -1 && agentsocket == ਨਿਰਾ) {
		/* Listen on a socket in/under a given directory */
		ਜੇ ((homedir = get_homedir()) == ਨਿਰਾ)
			fatal("Couldn't determine home directory");
		ਜੇ (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		ਜੇ (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		ਮੁਕਤ(homedir);
	} ਨਹੀਂਤਾਂ ਜੇ (sock == -1) {
		/* Listen on explicit socket path */
		prev_ਨਕਾਬ = umask(0177);
		socket_name = xstrdup(agentsocket);
		ਜੇ ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			ਮੁਕਤ(socket_name);
			socket_name = ਨਿਰਾ; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_ਨਕਾਬ);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	ਜੇ (sock == -1) {
		prev_ਨਕਾਬ = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		ਜੇ (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_ਨਕਾਬ);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	ਜੇ (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		ਜੇ (socket_name != ਨਿਰਾ) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			ਲਿਖੋ(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			ਮੁਕਤ(cp);
			ਲਿਖੋ("echo Agent pid %ld;\n", (ਲੰਮਾ)ਮਾਪਾ_pid);
			fflush(stdout);
		}
		ਜਾਓ skip;
	}
	pid = fork();
	ਜੇ (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	ਜੇ (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, ਆਕਾਰ pidstrbuf, "%ld", (ਲੰਮਾ)pid);
		ਜੇ (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			ਲਿਖੋ(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			ਲਿਖੋ(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			ਮੁਕਤ(cp);
			ਲਿਖੋ("echo Agent pid %ld;\n", (ਲੰਮਾ)pid);
			ਬਾਹਰ_ਨਿਕਲੋ(0);
		}
		ਜੇ (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	/*ਬੱਚਾ*/
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	ਜੇ (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(ਖਾਲੀ)chdir("/");
	ਜੇ (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	ਜੇ (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#ਜੇ_ਅੰਤ

skip:

	cleanup_pid = getpid();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	pkcs11_init(0);
#ਜੇ_ਅੰਤ
	new_socket(AUTH_SOCKET, sock);
	ਜੇ (ac > 0)
		ਮਾਪਾ_alive_interval = 10;
	idtab_init();
	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
	ssh_signal(SIGHUP, cleanup_handler);
	ssh_signal(SIGTERM, cleanup_handler);
	ssh_signal(SIGUSR1, keydrop_handler);

	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGINT);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGUSR1);

	ਜੇ (socket_name != ਨਿਰਾ && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	ਜੇ (socket_dir != ਨਿਰਾ && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	ਜੇ (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	ਜੇ ((ccp = getenv("SSH_SK_HELPER")) == ਨਿਰਾ || *ccp == '\0')
		ccp = ਰਸਤਾ_SSH_SK_HELPER;
	ਜੇ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ਜੇ ((ccp = getenv("SSH_PKCS11_HELPER")) == ਨਿਰਾ || *ccp == '\0')
		ccp = ਰਸਤਾ_SSH_PKCS11_HELPER;
	ਜੇ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ਜੇ ((ccp = getenv("SSH_ASKPASS")) == ਨਿਰਾ || *ccp == '\0')
		ccp = ਰਸਤਾ_SSH_ASKPASS_DEFAULT;
	ਜੇ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ਜੇ (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	ਜੇ (pledge("stdio rpath cpath wpath unix id proc exec", ਨਿਰਾ) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	ਜਦੋਂ (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ਜੇ (signalled_exit != 0) {
			logit("exiting on signal %d", (ਪੂਰਨ)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		ਜੇ (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (ਪੂਰਨ)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		ਨਤੀਜਾ = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, ਨਿਰਾ);
		saved_errno = errno;
		ਜੇ (ਮਾਪਾ_alive_interval != 0)
			check_ਮਾਪਾ_exists();
		(ਖਾਲੀ) reaper();	/* remove expired keys */
		ਜੇ (ਨਤੀਜਾ == -1) {
			ਜੇ (saved_errno == EINTR)
				ਜਾਰੀ;
			fatal("poll: %s", strerror(saved_errno));
		} ਨਹੀਂਤਾਂ ਜੇ (ਨਤੀਜਾ > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
