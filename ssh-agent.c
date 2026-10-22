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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <sys/resource.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/un.h>
#അന്തര്ഭാവ <sys/wait.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"
#endif

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <util.h>
#അന്തര്ഭാവ <pwd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "ssh-pkcs11.h"
#അന്തര്ഭാവ "sk-api.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "version.h"

#ifndef DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#endif
#ifndef DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#endif

/* Maximum accepted message length */
#define AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#define AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#define AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#define AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#define AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#define AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#define AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

തരനിർവചനം എണ്ണൽ {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

ഘടന hostkey_sid {
	ഘടന sshkey *താക്കോൽ;
	ഘടന sshbuf *sid;
	പൂർണ്ണസംഖ്യ forwarded;
};

തരനിർവചനം ഘടന socket_entry {
	പൂർണ്ണസംഖ്യ fd;
	sock_type type;
	ഘടന sshbuf *നിവേശം;
	ഘടന sshbuf *output;
	ഘടന sshbuf *request;
	size_t nsession_ids;
	ഘടന hostkey_sid *session_ids;
	പൂർണ്ണസംഖ്യ session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = ശൂന്യ;

തരനിർവചനം ഘടന identity {
	TAILQ_ENTRY(identity) next;
	ഘടന sshkey *താക്കോൽ;
	അക്ഷരം *comment;
	അക്ഷരം *provider;
	time_t death;
	u_int confirm;
	അക്ഷരം *sk_provider;
	ഘടന dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

ഘടന idtable {
	പൂർണ്ണസംഖ്യ nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
ഘടന idtable *idtab;

പൂർണ്ണസംഖ്യ max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

സ്ഥിതം sig_atomic_t signalled_exit;
സ്ഥിതം sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
സ്ഥിതം അക്ഷരം *socket_name;
സ്ഥിതം അക്ഷരം *socket_dir;
സ്ഥിതം അക്ഷരം *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
സ്ഥിതം അക്ഷരം *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
പൂർണ്ണസംഖ്യ locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

ബാഹ്യ അക്ഷരം *__progname;

/* Default lifetime in seconds (0 == forever) */
സ്ഥിതം പൂർണ്ണസംഖ്യ lifetime = 0;

സ്ഥിതം പൂർണ്ണസംഖ്യ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
സ്ഥിതം പൂർണ്ണസംഖ്യ restrict_websafe = 1;
സ്ഥിതം അക്ഷരം *websafe_allowlist;

സ്ഥിതം ശൂന്യം
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->നിവേശം);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	വേണ്ടി (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].താക്കോൽ);
		sshbuf_free(e->session_ids[i].sid);
	}
	സ്വതന്ത്രം(e->session_ids);
	memset(e, '\0', വലുപ്പം(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

സ്ഥിതം ശൂന്യം
idtab_init(ശൂന്യം)
{
	idtab = xcalloc(1, വലുപ്പം(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

സ്ഥിതം ശൂന്യം
free_dest_constraint_hop(ഘടന dest_constraint_hop *dch)
{
	u_int i;

	എങ്കിൽ (dch == ശൂന്യ)
		തിരികെ;
	സ്വതന്ത്രം(dch->user);
	സ്വതന്ത്രം(dch->hostname);
	വേണ്ടി (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->താക്കോലുകൾ[i]);
	സ്വതന്ത്രം(dch->താക്കോലുകൾ);
	സ്വതന്ത്രം(dch->താക്കോൽ_is_ca);
}

സ്ഥിതം ശൂന്യം
free_dest_constraints(ഘടന dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	വേണ്ടി (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	സ്വതന്ത്രം(dcs);
}

#ifdef ENABLE_PKCS11
സ്ഥിതം ശൂന്യം
dup_dest_constraint_hop(സ്ഥിരം ഘടന dest_constraint_hop *dch,
    ഘടന dest_constraint_hop *out)
{
	u_int i;
	പൂർണ്ണസംഖ്യ r;

	out->user = dch->user == ശൂന്യ ? ശൂന്യ : xstrdup(dch->user);
	out->hostname = dch->hostname == ശൂന്യ ? ശൂന്യ : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->താക്കോലുകൾ = out->nkeys == 0 ? ശൂന്യ :
	    xcalloc(out->nkeys, വലുപ്പം(*out->താക്കോലുകൾ));
	out->താക്കോൽ_is_ca = out->nkeys == 0 ? ശൂന്യ :
	    xcalloc(out->nkeys, വലുപ്പം(*out->താക്കോൽ_is_ca));
	വേണ്ടി (i = 0; i < dch->nkeys; i++) {
		എങ്കിൽ (dch->താക്കോലുകൾ[i] != ശൂന്യ &&
		    (r = sshkey_from_private(dch->താക്കോലുകൾ[i],
		    &(out->താക്കോലുകൾ[i]))) != 0)
			fatal_fr(r, "copy key");
		out->താക്കോൽ_is_ca[i] = dch->താക്കോൽ_is_ca[i];
	}
}

സ്ഥിതം ഘടന dest_constraint *
dup_dest_constraints(സ്ഥിരം ഘടന dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	ഘടന dest_constraint *ret;

	എങ്കിൽ (ndcs == 0)
		തിരികെ ശൂന്യ;
	ret = xcalloc(ndcs, വലുപ്പം(*ret));
	വേണ്ടി (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	തിരികെ ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
സ്ഥിതം ശൂന്യം
dump_dest_constraint_hop(സ്ഥിരം ഘടന dest_constraint_hop *dch)
{
	u_int i;
	അക്ഷരം *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == ശൂന്യ ? "(null)" : dch->user,
	    dch->hostname == ശൂന്യ ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	വേണ്ടി (i = 0; i < dch->nkeys; i++) {
		fp = ശൂന്യ;
		എങ്കിൽ (dch->താക്കോലുകൾ[i] != ശൂന്യ &&
		    (fp = sshkey_fingerprint(dch->താക്കോലുകൾ[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->താക്കോലുകൾ[i] == ശൂന്യ ? "" : sshkey_ssh_name(dch->താക്കോലുകൾ[i]),
		    dch->താക്കോലുകൾ[i] == ശൂന്യ ? "" : " ",
		    dch->താക്കോലുകൾ[i] == ശൂന്യ ? "none" : fp,
		    dch->താക്കോൽ_is_ca[i]);
		സ്വതന്ത്രം(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

സ്ഥിതം ശൂന്യം
dump_dest_constraints(സ്ഥിരം അക്ഷരം *context,
    സ്ഥിരം ഘടന dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	വേണ്ടി (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

സ്ഥിതം ശൂന്യം
free_identity(Identity *id)
{
	sshkey_free(id->താക്കോൽ);
	സ്വതന്ത്രം(id->provider);
	സ്വതന്ത്രം(id->comment);
	സ്വതന്ത്രം(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	സ്വതന്ത്രം(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
match_താക്കോൽ_hop(സ്ഥിരം അക്ഷരം *tag, സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം ഘടന dest_constraint_hop *dch)
{
	സ്ഥിരം അക്ഷരം *reason = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	അക്ഷരം *fp;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ)
		തിരികെ -1;
	/* XXX logspam */
	എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ശൂന്യ)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(താക്കോൽ), fp, dch->nkeys);
	സ്വതന്ത്രം(fp);
	വേണ്ടി (i = 0; i < dch->nkeys; i++) {
		എങ്കിൽ (dch->താക്കോലുകൾ[i] == ശൂന്യ)
			തിരികെ -1;
		/* XXX logspam */
		എങ്കിൽ ((fp = sshkey_fingerprint(dch->താക്കോലുകൾ[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->താക്കോൽ_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->താക്കോലുകൾ[i]), fp);
		സ്വതന്ത്രം(fp);
		എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
			/* plain key */
			എങ്കിൽ (dch->താക്കോൽ_is_ca[i] ||
			    !sshkey_equal(താക്കോൽ, dch->താക്കോലുകൾ[i]))
				തുടരുക;
			തിരികെ 0;
		}
		/* certificate */
		എങ്കിൽ (!dch->താക്കോൽ_is_ca[i])
			തുടരുക;
		എങ്കിൽ (താക്കോൽ->cert == ശൂന്യ || താക്കോൽ->cert->signature_താക്കോൽ == ശൂന്യ)
			തിരികെ -1; /* shouldn't happen */
		എങ്കിൽ (!sshkey_equal(താക്കോൽ->cert->signature_താക്കോൽ, dch->താക്കോലുകൾ[i]))
			തുടരുക;
		എങ്കിൽ (sshkey_cert_check_host(താക്കോൽ, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    താക്കോൽ->cert->താക്കോൽ_id, hostname, reason);
			തുടരുക;
		}
		തിരികെ 0;
	}
	തിരികെ -1;
}

/* Check destination constraints on an identity against the hostkey/user */
സ്ഥിതം പൂർണ്ണസംഖ്യ
permitted_by_dest_constraints(സ്ഥിരം ഘടന sshkey *fromkey,
    സ്ഥിരം ഘടന sshkey *tokey, Identity *id, സ്ഥിരം അക്ഷരം *user,
    സ്ഥിരം അക്ഷരം **hostnamep)
{
	size_t i;
	ഘടന dest_constraint *d;

	എങ്കിൽ (hostnamep != ശൂന്യ)
		*hostnamep = ശൂന്യ;
	വേണ്ടി (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->to.user ? d->to.user : "", d->to.user ? "@" : "",
		    d->to.hostname ? d->to.hostname : "(ANY)", d->to.nkeys);

		/* Match 'from' key */
		എങ്കിൽ (fromkey == ശൂന്യ) {
			/* We are matching the first hop */
			എങ്കിൽ (d->from.hostname != ശൂന്യ || d->from.nkeys != 0)
				തുടരുക;
		} അല്ലെങ്കിൽ എങ്കിൽ (match_താക്കോൽ_hop("from", fromkey, &d->from) != 0)
			തുടരുക;

		/* Match 'to' key */
		എങ്കിൽ (tokey != ശൂന്യ && match_താക്കോൽ_hop("to", tokey, &d->to) != 0)
			തുടരുക;

		/* Match user if specified */
		എങ്കിൽ (d->to.user != ശൂന്യ && user != ശൂന്യ &&
		    !match_pattern(user, d->to.user))
			തുടരുക;

		/* successfully matched this constraint */
		എങ്കിൽ (hostnamep != ശൂന്യ)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == ശൂന്യ ? "*" : d->to.hostname);
		തിരികെ 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->താക്കോൽ), id->comment);
	തിരികെ -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
identity_permitted(Identity *id, SocketEntry *e, അക്ഷരം *user,
    സ്ഥിരം അക്ഷരം **forward_hostnamep, സ്ഥിരം അക്ഷരം **last_hostnamep)
{
	size_t i;
	സ്ഥിരം അക്ഷരം **hp;
	ഘടന hostkey_sid *hks;
	സ്ഥിരം ഘടന sshkey *fromkey = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *test_user;
	അക്ഷരം *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->താക്കോൽ), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	എങ്കിൽ (id->ndest_constraints == 0)
		തിരികെ 0; /* unconstrained */
	എങ്കിൽ (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		തിരികെ -1;
	}
	എങ്കിൽ (e->nsession_ids == 0)
		തിരികെ 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	വേണ്ടി (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		എങ്കിൽ (hks->താക്കോൽ == ശൂന്യ)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = ശൂന്യ;
		എങ്കിൽ (fromkey != ശൂന്യ &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("fingerprint failed");
		എങ്കിൽ ((fp2 = sshkey_fingerprint(hks->താക്കോൽ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->താക്കോൽ), fp2);
		സ്വതന്ത്രം(fp1);
		സ്വതന്ത്രം(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = ശൂന്യ;
		എങ്കിൽ (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		അല്ലെങ്കിൽ എങ്കിൽ (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = ശൂന്യ;
		എങ്കിൽ (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			എങ്കിൽ (hks->forwarded && user != ശൂന്യ) {
				error_f("tried to sign on forwarding hop");
				തിരികെ -1;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			തിരികെ -1;
		}
		എങ്കിൽ (permitted_by_dest_constraints(fromkey, hks->താക്കോൽ, id,
		    test_user, hp) != 0)
			തിരികെ -1;
		fromkey = hks->താക്കോൽ;
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
	എങ്കിൽ (hks->forwarded && user == ശൂന്യ &&
	    permitted_by_dest_constraints(hks->താക്കോൽ, ശൂന്യ, id,
	    ശൂന്യ, ശൂന്യ) != 0) {
		debug3_f("key permitted at host but not after");
		തിരികെ -1;
	}

	/* success */
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
socket_is_remote(SocketEntry *e)
{
	തിരികെ e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
സ്ഥിതം Identity *
lookup_identity(ഘടന sshkey *താക്കോൽ)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		എങ്കിൽ (sshkey_equal(താക്കോൽ, id->താക്കോൽ))
			തിരികെ (id);
	}
	തിരികെ (ശൂന്യ);
}

/* Check confirmation of keysign request */
സ്ഥിതം പൂർണ്ണസംഖ്യ
confirm_താക്കോൽ(Identity *id, സ്ഥിരം അക്ഷരം *extra)
{
	അക്ഷരം *p;
	പൂർണ്ണസംഖ്യ ret = -1;

	p = sshkey_fingerprint(id->താക്കോൽ, fingerprint_hash, SSH_FP_DEFAULT);
	എങ്കിൽ (p != ശൂന്യ &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == ശൂന്യ ? "" : "\n", extra == ശൂന്യ ? "" : extra))
		ret = 0;
	സ്വതന്ത്രം(p);

	തിരികെ (ret);
}

സ്ഥിതം ശൂന്യം
send_status_generic(SocketEntry *e, u_int code)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

സ്ഥിതം ശൂന്യം
send_status(SocketEntry *e, പൂർണ്ണസംഖ്യ success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
സ്ഥിതം ശൂന്യം
process_request_identities(SocketEntry *e)
{
	Identity *id;
	ഘടന sshbuf *സന്ദേശം, *താക്കോലുകൾ;
	പൂർണ്ണസംഖ്യ r;
	u_int i = 0, nentries = 0;
	അക്ഷരം *fp;

	debug2_f("entering");

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ || (താക്കോലുകൾ = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		എങ്കിൽ ((fp = sshkey_fingerprint(id->താക്കോൽ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->താക്കോൽ), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		സ്വതന്ത്രം(fp);
		/* identity not visible, don't include in response */
		എങ്കിൽ (identity_permitted(id, e, ശൂന്യ, ശൂന്യ, ശൂന്യ) != 0)
			തുടരുക;
		എങ്കിൽ ((r = sshkey_puts(id->താക്കോൽ, താക്കോലുകൾ)) != 0 ||
		    (r = sshbuf_put_cstring(താക്കോലുകൾ, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			തുടരുക;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, nentries)) != 0 ||
	    (r = sshbuf_putb(സന്ദേശം, താക്കോലുകൾ)) != 0)
		fatal_fr(r, "compose");
	എങ്കിൽ ((r = sshbuf_put_stringb(e->output, സന്ദേശം)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(സന്ദേശം);
	sshbuf_free(താക്കോലുകൾ);
}


സ്ഥിതം അക്ഷരം *
agent_decode_alg(ഘടന sshkey *താക്കോൽ, u_int flags)
{
	എങ്കിൽ (താക്കോൽ->type == താക്കോൽ_RSA) {
		എങ്കിൽ (flags & SSH_AGENT_RSA_SHA2_256)
			തിരികെ "rsa-sha2-256";
		അല്ലെങ്കിൽ എങ്കിൽ (flags & SSH_AGENT_RSA_SHA2_512)
			തിരികെ "rsa-sha2-512";
	} അല്ലെങ്കിൽ എങ്കിൽ (താക്കോൽ->type == താക്കോൽ_RSA_CERT) {
		എങ്കിൽ (flags & SSH_AGENT_RSA_SHA2_256)
			തിരികെ "rsa-sha2-256-cert-v01@openssh.com";
		അല്ലെങ്കിൽ എങ്കിൽ (flags & SSH_AGENT_RSA_SHA2_512)
			തിരികെ "rsa-sha2-512-cert-v01@openssh.com";
	}
	തിരികെ ശൂന്യ;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_userauth_request(ഘടന sshbuf *സന്ദേശം, സ്ഥിരം ഘടന sshkey *expected_താക്കോൽ,
    അക്ഷരം **userp, ഘടന sshbuf **sess_idp, ഘടന sshkey **hostkeyp)
{
	ഘടന sshbuf *b = ശൂന്യ, *sess_id = ശൂന്യ;
	അക്ഷരം *user = ശൂന്യ, *service = ശൂന്യ, *method = ശൂന്യ, *pkalg = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	u_char t, sig_follows;
	ഘടന sshkey *mkey = ശൂന്യ, *hostkey = ശൂന്യ;

	എങ്കിൽ (userp != ശൂന്യ)
		*userp = ശൂന്യ;
	എങ്കിൽ (sess_idp != ശൂന്യ)
		*sess_idp = ശൂന്യ;
	എങ്കിൽ (hostkeyp != ശൂന്യ)
		*hostkeyp = ശൂന്യ;
	എങ്കിൽ ((b = sshbuf_fromb(സന്ദേശം)) == ശൂന്യ)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	എങ്കിൽ ((r = sshbuf_froms(b, &sess_id)) != 0)
		പോകുക out;
	എങ്കിൽ (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, ശൂന്യ)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, ശൂന്യ)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, ശൂന്യ)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, ശൂന്യ)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*താക്കോൽ*/
		പോകുക out;
	എങ്കിൽ (t != SSH2_സന്ദേശം_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_താക്കോൽ, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_താക്കോൽ->type) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		എങ്കിൽ ((r = sshkey_froms(b, &hostkey)) != 0)
			പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	എങ്കിൽ (userp != ശൂന്യ) {
		*userp = user;
		user = ശൂന്യ;
	}
	എങ്കിൽ (sess_idp != ശൂന്യ) {
		*sess_idp = sess_id;
		sess_id = ശൂന്യ;
	}
	എങ്കിൽ (hostkeyp != ശൂന്യ) {
		*hostkeyp = hostkey;
		hostkey = ശൂന്യ;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(service);
	സ്വതന്ത്രം(method);
	സ്വതന്ത്രം(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	തിരികെ r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_sshsig_request(ഘടന sshbuf *സന്ദേശം)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *b;

	എങ്കിൽ ((b = sshbuf_fromb(സന്ദേശം)) == ശൂന്യ)
		fatal_f("sshbuf_fromb");

	എങ്കിൽ ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, ശൂന്യ, ശൂന്യ)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, ശൂന്യ, ശൂന്യ)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, ശൂന്യ, ശൂന്യ)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, ശൂന്യ, ശൂന്യ)) != 0) /* H(msg) */
		പോകുക out;
	എങ്കിൽ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
check_websafe_message_contents(ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *data)
{
	എങ്കിൽ (parse_userauth_request(data, താക്കോൽ, ശൂന്യ, ശൂന്യ, ശൂന്യ) == 0) {
		debug_f("signed data matches public key userauth request");
		തിരികെ 1;
	}
	എങ്കിൽ (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		തിരികെ 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
buf_equal(സ്ഥിരം ഘടന sshbuf *a, സ്ഥിരം ഘടന sshbuf *b)
{
	എങ്കിൽ (sshbuf_ptr(a) == ശൂന്യ || sshbuf_ptr(b) == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (sshbuf_len(a) != sshbuf_len(b))
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	തിരികെ 0;
}

/* ssh2 only */
സ്ഥിതം ശൂന്യം
process_sign_request2(SocketEntry *e)
{
	u_char *signature = ശൂന്യ;
	size_t slen = 0;
	u_int compat = 0, flags;
	പൂർണ്ണസംഖ്യ r, ok = -1, retried = 0;
	അക്ഷരം *fp = ശൂന്യ, *pin = ശൂന്യ, *prompt = ശൂന്യ;
	അക്ഷരം *user = ശൂന്യ, *sig_dest = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *fwd_host = ശൂന്യ, *dest_host = ശൂന്യ;
	ഘടന sshbuf *സന്ദേശം = ശൂന്യ, *data = ശൂന്യ, *sid = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ, *hostkey = ശൂന്യ;
	ഘടന identity *id;
	ഘടന notifier_ctx *notifier = ശൂന്യ;

	debug_f("entering");

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ || (data = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_froms(e->request, &താക്കോൽ)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		പോകുക send;
	}

	എങ്കിൽ ((id = lookup_identity(താക്കോൽ)) == ശൂന്യ) {
		verbose_f("%s key not found", sshkey_type(താക്കോൽ));
		പോകുക send;
	}
	എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ശൂന്യ)
		fatal_f("fingerprint failed");

	എങ്കിൽ (id->ndest_constraints != 0) {
		എങ്കിൽ (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			പോകുക send;
		}
		എങ്കിൽ (parse_userauth_request(data, താക്കോൽ, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			പോകുക send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		എങ്കിൽ (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			പോകുക send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		എങ്കിൽ (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->താക്കോൽ), fp);
			പോകുക send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		എങ്കിൽ (e->nsession_ids > 1 && hostkey == ശൂന്യ) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			പോകുക send;
		}
		എങ്കിൽ (hostkey != ശൂന്യ && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].താക്കോൽ)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			പോകുക send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	എങ്കിൽ (id->confirm && confirm_താക്കോൽ(id, sig_dest) != 0) {
		verbose_f("user refused key");
		പോകുക send;
	}
	എങ്കിൽ (sshkey_is_sk(id->താക്കോൽ)) {
		എങ്കിൽ (restrict_websafe &&
		    match_pattern_list(id->താക്കോൽ->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(താക്കോൽ, data)) {
			/* error already logged */
			പോകുക send;
		}
		എങ്കിൽ (id->താക്കോൽ->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->താക്കോൽ), fp,
			    sig_dest == ശൂന്യ ? "" : "\n",
			    sig_dest == ശൂന്യ ? "" : sig_dest);
		}
	}
 retry_pin:
	എങ്കിൽ ((r = sshkey_sign(id->താക്കോൽ, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(താക്കോൽ, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		എങ്കിൽ (pin == ശൂന്യ && !retried && sshkey_is_sk(id->താക്കോൽ) &&
		    r == SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE) {
			notify_complete(notifier, ശൂന്യ);
			notifier = ശൂന്യ;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->താക്കോൽ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->താക്കോൽ), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			പോകുക retry_pin;
		}
		error_fr(r, "sshkey_sign");
		പോകുക send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	എങ്കിൽ (ok == 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(സന്ദേശം, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	എങ്കിൽ ((r = sshbuf_put_stringb(e->output, സന്ദേശം)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(സന്ദേശം);
	sshkey_free(താക്കോൽ);
	sshkey_free(hostkey);
	സ്വതന്ത്രം(fp);
	സ്വതന്ത്രം(signature);
	സ്വതന്ത്രം(sig_dest);
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(prompt);
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));
}

/* shared */
സ്ഥിതം ശൂന്യം
process_remove_identity(SocketEntry *e)
{
	പൂർണ്ണസംഖ്യ r, success = 0;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	Identity *id;

	debug2_f("entering");
	എങ്കിൽ ((r = sshkey_froms(e->request, &താക്കോൽ)) != 0) {
		error_fr(r, "parse key");
		പോകുക done;
	}
	എങ്കിൽ ((id = lookup_identity(താക്കോൽ)) == ശൂന്യ) {
		debug_f("key not found");
		പോകുക done;
	}
	/* identity not visible, cannot be removed */
	എങ്കിൽ (identity_permitted(id, e, ശൂന്യ, ശൂന്യ, ശൂന്യ) != 0)
		പോകുക done; /* error already logged */
	/* We have this key, free it. */
	എങ്കിൽ (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(താക്കോൽ);
	send_status(e, success);
}

സ്ഥിതം ശൂന്യം
remove_all_identities(ശൂന്യം)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	വേണ്ടി (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

സ്ഥിതം ശൂന്യം
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
സ്ഥിതം time_t
reaper(ശൂന്യം)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	വേണ്ടി (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		എങ്കിൽ (id->death == 0)
			തുടരുക;
		എങ്കിൽ (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} അല്ലെങ്കിൽ
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	എങ്കിൽ (deadline == 0 || deadline <= now)
		തിരികെ 0;
	അല്ലെങ്കിൽ
		തിരികെ (deadline - now);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_dest_constraint_hop(ഘടന sshbuf *b, ഘടന dest_constraint_hop *dch)
{
	u_char താക്കോൽ_is_ca;
	size_t elen = 0, userlen = 0;
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshkey *k = ശൂന്യ;
	അക്ഷരം *fp;

	memset(dch, '\0', വലുപ്പം(*dch));
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ശൂന്യ, &elen)) != 0) {
		error_fr(r, "parse");
		പോകുക out;
	}
	എങ്കിൽ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		പോകുക out;
	}
	എങ്കിൽ (*dch->hostname == '\0') {
		സ്വതന്ത്രം(dch->hostname);
		dch->hostname = ശൂന്യ;
	}
	എങ്കിൽ (*dch->user == '\0') {
		സ്വതന്ത്രം(dch->user);
		dch->user = ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	ആകുമ്പോൾ (sshbuf_len(b) != 0) {
		dch->താക്കോലുകൾ = xrecallocarray(dch->താക്കോലുകൾ, dch->nkeys,
		    dch->nkeys + 1, വലുപ്പം(*dch->താക്കോലുകൾ));
		dch->താക്കോൽ_is_ca = xrecallocarray(dch->താക്കോൽ_is_ca, dch->nkeys,
		    dch->nkeys + 1, വലുപ്പം(*dch->താക്കോൽ_is_ca));
		എങ്കിൽ ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &താക്കോൽ_is_ca)) != 0)
			പോകുക out;
		എങ്കിൽ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == ശൂന്യ ? "" : dch->user,
		    dch->user == ശൂന്യ ? "" : "@",
		    dch->hostname, താക്കോൽ_is_ca ? "CA " : "", sshkey_type(k), fp);
		സ്വതന്ത്രം(fp);
		dch->താക്കോലുകൾ[dch->nkeys] = k;
		dch->താക്കോൽ_is_ca[dch->nkeys] = താക്കോൽ_is_ca != 0;
		dch->nkeys++;
		k = ശൂന്യ; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_dest_constraint(ഘടന sshbuf *m, ഘടന dest_constraint *dc)
{
	ഘടന sshbuf *b = ശൂന്യ, *frombuf = ശൂന്യ, *tobuf = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', വലുപ്പം(*dc));
	എങ്കിൽ ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ശൂന്യ, &elen)) != 0) {
		error_fr(r, "parse");
		പോകുക out;
	}
	എങ്കിൽ ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		പോകുക out; /* already logged */
	എങ്കിൽ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		പോകുക out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	എങ്കിൽ ((dc->from.hostname == ശൂന്യ) != (dc->from.nkeys == 0) ||
	    dc->from.user != ശൂന്യ) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (dc->to.hostname == ശൂന്യ || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_താക്കോൽ_constraint_extension(ഘടന sshbuf *m, അക്ഷരം **sk_providerp,
    ഘടന dest_constraint **dcsp, size_t *ndcsp, പൂർണ്ണസംഖ്യ *cert_onlyp,
    ഘടന sshkey ***certs, size_t *ncerts)
{
	അക്ഷരം *ext_name = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *b = ശൂന്യ;
	u_char v;
	ഘടന sshkey *k;

	എങ്കിൽ ((r = sshbuf_get_cstring(m, &ext_name, ശൂന്യ)) != 0) {
		error_fr(r, "parse constraint extension");
		പോകുക out;
	}
	debug_f("constraint ext %s", ext_name);
	എങ്കിൽ (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		എങ്കിൽ (sk_providerp == ശൂന്യ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ (*sk_providerp != ശൂന്യ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_get_cstring(m, sk_providerp, ശൂന്യ)) != 0) {
			error_fr(r, "parse %s", ext_name);
			പോകുക out;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		എങ്കിൽ (*dcsp != ശൂന്യ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			പോകുക out;
		}
		ആകുമ്പോൾ (sshbuf_len(b) != 0) {
			എങ്കിൽ (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				പോകുക out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    വലുപ്പം(**dcsp));
			എങ്കിൽ ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				പോകുക out; /* error already logged */
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		എങ്കിൽ (certs == ശൂന്യ || ncerts == ശൂന്യ || cert_onlyp == ശൂന്യ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ (*certs != ശൂന്യ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			പോകുക out;
		}
		*cert_onlyp = v != 0;
		ആകുമ്പോൾ (sshbuf_len(b) != 0) {
			എങ്കിൽ (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				പോകുക out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    വലുപ്പം(**certs));
			എങ്കിൽ ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				പോകുക out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} അല്ലെങ്കിൽ {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	സ്വതന്ത്രം(ext_name);
	sshbuf_free(b);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_താക്കോൽ_constraints(ഘടന sshbuf *m, ഘടന sshkey *k, time_t *deathp,
    u_int *secondsp, പൂർണ്ണസംഖ്യ *confirmp, അക്ഷരം **sk_providerp,
    ഘടന dest_constraint **dcsp, size_t *ndcsp,
    പൂർണ്ണസംഖ്യ *cert_onlyp, size_t *ncerts, ഘടന sshkey ***certs)
{
	u_char ctype;
	പൂർണ്ണസംഖ്യ r;
	u_int seconds;

	ആകുമ്പോൾ (sshbuf_len(m)) {
		എങ്കിൽ ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			പോകുക out;
		}
		തിരഞ്ഞെടുപ്പ് (ctype) {
		അവസ്ഥ SSH_AGENT_CONSTRAIN_LIFETIME:
			എങ്കിൽ (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				പോകുക out;
			}
			എങ്കിൽ ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				പോകുക out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			നിർത്തുക;
		അവസ്ഥ SSH_AGENT_CONSTRAIN_CONFIRM:
			എങ്കിൽ (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				പോകുക out;
			}
			*confirmp = 1;
			നിർത്തുക;
		അവസ്ഥ SSH_AGENT_CONSTRAIN_EXTENSION:
			എങ്കിൽ ((r = parse_താക്കോൽ_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				പോകുക out; /* error already logged */
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			പോകുക out;
		}
	}
	/* success */
	r = 0;
 out:
	തിരികെ r;
}

സ്ഥിതം ശൂന്യം
process_add_identity(SocketEntry *e)
{
	Identity *id;
	പൂർണ്ണസംഖ്യ success = 0, confirm = 0;
	അക്ഷരം *fp, *comment = ശൂന്യ, *sk_provider = ശൂന്യ;
	അക്ഷരം canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	ഘടന dest_constraint *dest_constraints = ശൂന്യ;
	size_t ndest_constraints = 0;
	ഘടന sshkey *k = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	എങ്കിൽ ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == ശൂന്യ ||
	    (r = sshbuf_get_cstring(e->request, &comment, ശൂന്യ)) != 0) {
		error_fr(r, "parse");
		പോകുക out;
	}
	എങ്കിൽ (parse_താക്കോൽ_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    ശൂന്യ, ശൂന്യ, ശൂന്യ) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		പോകുക out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	എങ്കിൽ (sk_provider != ശൂന്യ) {
		എങ്കിൽ (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			പോകുക out;
		}
		എങ്കിൽ (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				പോകുക out;
			}
			എങ്കിൽ (realpath(sk_provider, canonical_provider) == ശൂന്യ) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				പോകുക out;
			}
			സ്വതന്ത്രം(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			എങ്കിൽ (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				പോകുക out;
			}
		}
	}
	എങ്കിൽ ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		പോകുക out;
	}
	എങ്കിൽ (lifetime && !death)
		death = monotime() + lifetime;
	എങ്കിൽ ((id = lookup_identity(k)) == ശൂന്യ) {
		id = xcalloc(1, വലുപ്പം(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} അല്ലെങ്കിൽ {
		/* identity not visible, do not update */
		എങ്കിൽ (identity_permitted(id, e, ശൂന്യ, ശൂന്യ, ശൂന്യ) != 0)
			പോകുക out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->താക്കോൽ);
		സ്വതന്ത്രം(id->comment);
		സ്വതന്ത്രം(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->താക്കോൽ = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	എങ്കിൽ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ശൂന്യ)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == ശൂന്യ ? "none" : sk_provider, ndest_constraints);
	സ്വതന്ത്രം(fp);
	/* transferred */
	k = ശൂന്യ;
	comment = ശൂന്യ;
	sk_provider = ശൂന്യ;
	dest_constraints = ശൂന്യ;
	ndest_constraints = 0;
	success = 1;
 out:
	സ്വതന്ത്രം(sk_provider);
	സ്വതന്ത്രം(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
സ്ഥിതം ശൂന്യം
process_lock_agent(SocketEntry *e, പൂർണ്ണസംഖ്യ lock)
{
	പൂർണ്ണസംഖ്യ r, success = 0, delay;
	അക്ഷരം *passwd;
	u_char passwdhash[LOCK_SIZE];
	സ്ഥിതം u_int fail_എണ്ണം = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	എങ്കിൽ ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (pwlen == 0) {
		debug("empty password not supported");
	} അല്ലെങ്കിൽ എങ്കിൽ (locked && !lock) {
		എങ്കിൽ (bcrypt_pbkdf(passwd, pwlen, lock_salt, വലുപ്പം(lock_salt),
		    passwdhash, വലുപ്പം(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		എങ്കിൽ (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_എണ്ണം = 0;
			explicit_bzero(lock_pwhash, വലുപ്പം(lock_pwhash));
			success = 1;
		} അല്ലെങ്കിൽ {
			/* delay in 0.1s increments up to 10s */
			എങ്കിൽ (fail_എണ്ണം < 100)
				fail_എണ്ണം++;
			delay = 100000 * fail_എണ്ണം;
			debug("unlock failed, delaying %0.1lf seconds",
			    (ഇരട്ട)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, വലുപ്പം(passwdhash));
	} അല്ലെങ്കിൽ എങ്കിൽ (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, വലുപ്പം(lock_salt));
		എങ്കിൽ (bcrypt_pbkdf(passwd, pwlen, lock_salt, വലുപ്പം(lock_salt),
		    lock_pwhash, വലുപ്പം(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

സ്ഥിതം ശൂന്യം
no_identities(SocketEntry *e)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, സന്ദേശം)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(സന്ദേശം);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
സ്ഥിതം ശൂന്യം
add_p11_identity(ഘടന sshkey *താക്കോൽ, അക്ഷരം *comment, സ്ഥിരം അക്ഷരം *provider,
    time_t death, u_int confirm, ഘടന dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	എങ്കിൽ (lookup_identity(താക്കോൽ) != ശൂന്യ) {
		sshkey_free(താക്കോൽ);
		സ്വതന്ത്രം(comment);
		തിരികെ;
	}
	id = xcalloc(1, വലുപ്പം(Identity));
	id->താക്കോൽ = താക്കോൽ;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
}

സ്ഥിതം ശൂന്യം
process_add_smartcard_താക്കോൽ(SocketEntry *e)
{
	അക്ഷരം *provider = ശൂന്യ, *pin = ശൂന്യ, canonical_provider[PATH_MAX];
	അക്ഷരം **comments = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, i, എണ്ണം = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	ഘടന sshkey **താക്കോലുകൾ = ശൂന്യ, *k;
	ഘടന dest_constraint *dest_constraints = ശൂന്യ;
	size_t j, ndest_constraints = 0, ncerts = 0;
	ഘടന sshkey **certs = ശൂന്യ;
	പൂർണ്ണസംഖ്യ cert_only = 0;

	debug2_f("entering");
	എങ്കിൽ ((r = sshbuf_get_cstring(e->request, &provider, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ശൂന്യ)) != 0) {
		error_fr(r, "parse");
		പോകുക send;
	}
	എങ്കിൽ (parse_താക്കോൽ_constraints(e->request, ശൂന്യ, &death, &seconds, &confirm,
	    ശൂന്യ, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		പോകുക send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	എങ്കിൽ (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		പോകുക send;
	}
	എങ്കിൽ (realpath(provider, canonical_provider) == ശൂന്യ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		പോകുക send;
	}
	എങ്കിൽ (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		പോകുക send;
	}
	debug_f("add %.100s", canonical_provider);
	എങ്കിൽ (lifetime && !death)
		death = monotime() + lifetime;

	എണ്ണം = pkcs11_add_provider(canonical_provider, pin, &താക്കോലുകൾ, &comments);
	വേണ്ടി (i = 0; i < എണ്ണം; i++) {
		എങ്കിൽ (comments[i] == ശൂന്യ || comments[i][0] == '\0') {
			സ്വതന്ത്രം(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		വേണ്ടി (j = 0; j < ncerts; j++) {
			എങ്കിൽ (!sshkey_is_cert(certs[j]))
				തുടരുക;
			എങ്കിൽ (!sshkey_equal_public(താക്കോലുകൾ[i], certs[j]))
				തുടരുക;
			എങ്കിൽ (pkcs11_make_cert(താക്കോലുകൾ[i], certs[j], &k) != 0)
				തുടരുക;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		എങ്കിൽ (!cert_only && lookup_identity(താക്കോലുകൾ[i]) == ശൂന്യ) {
			add_p11_identity(താക്കോലുകൾ[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			താക്കോലുകൾ[i] = ശൂന്യ;		/* transferred */
			comments[i] = ശൂന്യ;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(താക്കോലുകൾ[i]);
		സ്വതന്ത്രം(comments[i]);
	}
send:
	സ്വതന്ത്രം(pin);
	സ്വതന്ത്രം(provider);
	സ്വതന്ത്രം(താക്കോലുകൾ);
	സ്വതന്ത്രം(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	വേണ്ടി (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	സ്വതന്ത്രം(certs);
	send_status(e, success);
}

സ്ഥിതം ശൂന്യം
process_remove_smartcard_താക്കോൽ(SocketEntry *e)
{
	അക്ഷരം *provider = ശൂന്യ, *pin = ശൂന്യ, canonical_provider[PATH_MAX];
	പൂർണ്ണസംഖ്യ r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	എങ്കിൽ ((r = sshbuf_get_cstring(e->request, &provider, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ശൂന്യ)) != 0) {
		error_fr(r, "parse");
		പോകുക send;
	}
	സ്വതന്ത്രം(pin);

	എങ്കിൽ (realpath(provider, canonical_provider) == ശൂന്യ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		പോകുക send;
	}

	debug_f("remove %.100s", canonical_provider);
	വേണ്ടി (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		എങ്കിൽ (id->provider == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	എങ്കിൽ (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	അല്ലെങ്കിൽ
		error_f("pkcs11_del_provider failed");
send:
	സ്വതന്ത്രം(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

സ്ഥിതം പൂർണ്ണസംഖ്യ
process_ext_session_bind(SocketEntry *e)
{
	പൂർണ്ണസംഖ്യ r, sid_match, താക്കോൽ_match;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *sid = ശൂന്യ, *sig = ശൂന്യ;
	അക്ഷരം *fp = ശൂന്യ;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	എങ്കിൽ ((r = sshkey_froms(e->request, &താക്കോൽ)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		പോകുക out;
	}
	എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ശൂന്യ)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	എങ്കിൽ ((r = sshkey_verify(താക്കോൽ, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), ശൂന്യ, 0, ശൂന്യ)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(താക്കോൽ), fp);
		പോകുക out;
	}
	/* check whether sid/key already recorded */
	വേണ്ടി (i = 0; i < e->nsession_ids; i++) {
		എങ്കിൽ (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			പോകുക out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		താക്കോൽ_match = sshkey_equal(താക്കോൽ, e->session_ids[i].താക്കോൽ);
		എങ്കിൽ (sid_match && താക്കോൽ_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(താക്കോൽ), fp);
			r = 0;
			പോകുക out;
		} അല്ലെങ്കിൽ എങ്കിൽ (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(താക്കോൽ), fp);
			r = -1;
			പോകുക out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	എങ്കിൽ (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		പോകുക out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, വലുപ്പം(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(താക്കോൽ), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].താക്കോൽ = താക്കോൽ;
	e->session_ids[i].forwarded = fwd != 0;
	താക്കോൽ = ശൂന്യ; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	എങ്കിൽ ((e->session_ids[i].sid = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	സ്വതന്ത്രം(fp);
	sshkey_free(താക്കോൽ);
	sshbuf_free(sid);
	sshbuf_free(sig);
	തിരികെ r == 0 ? 1 : 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
process_ext_query(SocketEntry *e)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *സന്ദേശം = ശൂന്യ;

	debug2_f("entering");
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(സന്ദേശം, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	എങ്കിൽ ((r = sshbuf_put_stringb(e->output, സന്ദേശം)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(സന്ദേശം);
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
process_extension(SocketEntry *e)
{
	പൂർണ്ണസംഖ്യ r, replied = 0, success = 0;
	അക്ഷരം *name;

	debug2_f("entering");
	എങ്കിൽ ((r = sshbuf_get_cstring(e->request, &name, ശൂന്യ)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		തിരികെ;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	എങ്കിൽ (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} അല്ലെങ്കിൽ എങ്കിൽ (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		പോകുക generic_fail;
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} അല്ലെങ്കിൽ {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		സ്വതന്ത്രം(name);
		send_status(e, 0);
		തിരികെ;
	}
	സ്വതന്ത്രം(name);
	/* Agent failures are signalled with a different error code */
	എങ്കിൽ (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
process_message(u_int socknum)
{
	u_int സന്ദേശം_len;
	u_char type;
	സ്ഥിരം u_char *cp;
	പൂർണ്ണസംഖ്യ r;
	SocketEntry *e;

	എങ്കിൽ (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	എങ്കിൽ (sshbuf_len(e->നിവേശം) < 5)
		തിരികെ 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->നിവേശം);
	സന്ദേശം_len = PEEK_U32(cp);
	എങ്കിൽ (സന്ദേശം_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, സന്ദേശം_len, AGENT_MAX_LEN);
		തിരികെ -1;
	}
	എങ്കിൽ (sshbuf_len(e->നിവേശം) < സന്ദേശം_len + 4)
		തിരികെ 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	എങ്കിൽ ((r = sshbuf_get_stringb(e->നിവേശം, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		എങ്കിൽ (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			തിരികെ -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	എങ്കിൽ (locked && type != SSH_AGENTC_UNLOCK) {
		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			നിർത്തുക;
		അവസ്ഥ SSH_AGENTC_EXTENSION:
			process_extension(e);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		തിരികെ 1;
	}

	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ SSH_AGENTC_LOCK:
	അവസ്ഥ SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		നിർത്തുക;
	അവസ്ഥ SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		നിർത്തുക;
	/* ssh2 */
	അവസ്ഥ SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		നിർത്തുക;
	അവസ്ഥ SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		നിർത്തുക;
	അവസ്ഥ SSH2_AGENTC_ADD_IDENTITY:
	അവസ്ഥ SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		നിർത്തുക;
	അവസ്ഥ SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		നിർത്തുക;
	അവസ്ഥ SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		നിർത്തുക;
#ifdef ENABLE_PKCS11
	അവസ്ഥ SSH_AGENTC_ADD_SMARTCARD_താക്കോൽ:
	അവസ്ഥ SSH_AGENTC_ADD_SMARTCARD_താക്കോൽ_CONSTRAINED:
		process_add_smartcard_താക്കോൽ(e);
		നിർത്തുക;
	അവസ്ഥ SSH_AGENTC_REMOVE_SMARTCARD_താക്കോൽ:
		process_remove_smartcard_താക്കോൽ(e);
		നിർത്തുക;
#endif /* ENABLE_PKCS11 */
	അവസ്ഥ SSH_AGENTC_EXTENSION:
		process_extension(e);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		നിർത്തുക;
	}
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
new_socket(sock_type type, പൂർണ്ണസംഖ്യ fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	എങ്കിൽ (fd > max_fd)
		max_fd = fd;

	വേണ്ടി (i = 0; i < sockets_alloc; i++)
		എങ്കിൽ (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			എങ്കിൽ ((sockets[i].നിവേശം = sshbuf_new()) == ശൂന്യ ||
			    (sockets[i].output = sshbuf_new()) == ശൂന്യ ||
			    (sockets[i].request = sshbuf_new()) == ശൂന്യ)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			തിരികെ;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    വലുപ്പം(sockets[0]));
	വേണ്ടി (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	എങ്കിൽ ((sockets[old_alloc].നിവേശം = sshbuf_new()) == ശൂന്യ ||
	    (sockets[old_alloc].output = sshbuf_new()) == ശൂന്യ ||
	    (sockets[old_alloc].request = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_socket_read(u_int socknum)
{
	ഘടന sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	പൂർണ്ണസംഖ്യ fd;

	slen = വലുപ്പം(sunaddr);
	fd = accept(sockets[socknum].fd, (ഘടന sockaddr *)&sunaddr, &slen);
	എങ്കിൽ (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		തിരികെ -1;
	}
	എങ്കിൽ ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		തിരികെ -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_conn_read(u_int socknum)
{
	അക്ഷരം buf[AGENT_RBUF_LEN];
	ssize_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((len = പഠ(sockets[socknum].fd, buf, വലുപ്പം(buf))) <= 0) {
		എങ്കിൽ (len == -1) {
			എങ്കിൽ (errno == EAGAIN || errno == EINTR)
				തിരികെ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		തിരികെ -1;
	}
	എങ്കിൽ ((r = sshbuf_put(sockets[socknum].നിവേശം, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, വലുപ്പം(buf));
	വേണ്ടി (;;) {
		എങ്കിൽ ((r = process_message(socknum)) == -1)
			തിരികെ -1;
		അല്ലെങ്കിൽ എങ്കിൽ (r == 0)
			നിർത്തുക;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_conn_write(u_int socknum)
{
	ssize_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (sshbuf_len(sockets[socknum].output) == 0)
		തിരികെ 0; /* shouldn't happen */
	എങ്കിൽ ((len = ലിഖ(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		എങ്കിൽ (len == -1) {
			എങ്കിൽ (errno == EAGAIN || errno == EINTR)
				തിരികെ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		തിരികെ -1;
	}
	എങ്കിൽ ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
after_poll(ഘടന pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	വേണ്ടി (i = 0; i < npfd; i++) {
		എങ്കിൽ (pfd[i].revents == 0)
			തുടരുക;
		/* Find sockets entry */
		വേണ്ടി (socknum = 0; socknum < sockets_alloc; socknum++) {
			എങ്കിൽ (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				തുടരുക;
			എങ്കിൽ (pfd[i].fd == sockets[socknum].fd)
				നിർത്തുക;
		}
		എങ്കിൽ (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			തുടരുക;
		}
		/* Process events */
		തിരഞ്ഞെടുപ്പ് (sockets[socknum].type) {
		അവസ്ഥ AUTH_SOCKET:
			എങ്കിൽ ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				നിർത്തുക;
			എങ്കിൽ (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				നിർത്തുക;
			}
			എങ്കിൽ (handle_socket_read(socknum) == 0)
				activefds++;
			നിർത്തുക;
		അവസ്ഥ AUTH_CONNECTION:
			എങ്കിൽ ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				പോകുക close_sock;
			എങ്കിൽ ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				എങ്കിൽ (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				നിർത്തുക;
			}
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			നിർത്തുക;
		}
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
prepare_poll(ഘടന pollfd **pfdp, size_t *npfdp, ഘടന timespec *timeoutp, u_int maxfds)
{
	ഘടന pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	പൂർണ്ണസംഖ്യ r;

	/* Count active sockets */
	വേണ്ടി (i = 0; i < sockets_alloc; i++) {
		തിരഞ്ഞെടുപ്പ് (sockets[i].type) {
		അവസ്ഥ AUTH_SOCKET:
		അവസ്ഥ AUTH_CONNECTION:
			npfd++;
			നിർത്തുക;
		അവസ്ഥ AUTH_UNUSED:
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("Unknown socket type %d", sockets[i].type);
			നിർത്തുക;
		}
	}
	എങ്കിൽ (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, വലുപ്പം(*pfd))) == ശൂന്യ)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	വേണ്ടി (i = j = 0; i < sockets_alloc; i++) {
		തിരഞ്ഞെടുപ്പ് (sockets[i].type) {
		അവസ്ഥ AUTH_SOCKET:
			എങ്കിൽ (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				നിർത്തുക;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			നിർത്തുക;
		അവസ്ഥ AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			എങ്കിൽ ((r = sshbuf_check_reserve(sockets[i].നിവേശം,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			അല്ലെങ്കിൽ എങ്കിൽ (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			എങ്കിൽ (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			നിർത്തുക;
		}
	}
	deadline = reaper();
	എങ്കിൽ (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	എങ്കിൽ (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	തിരികെ (1);
}

സ്ഥിതം ശൂന്യം
cleanup_socket(ശൂന്യം)
{
	എങ്കിൽ (cleanup_pid != 0 && getpid() != cleanup_pid)
		തിരികെ;
	debug_f("cleanup");
	എങ്കിൽ (socket_name != ശൂന്യ) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		സ്വതന്ത്രം(socket_name);
		socket_name = ശൂന്യ;
		സ്വതന്ത്രം(socket_dir);
		socket_dir = ശൂന്യ;
	}
}

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

സ്ഥിതം ശൂന്യം
cleanup_handler(പൂർണ്ണസംഖ്യ sig)
{
	signalled_exit = sig;
}

സ്ഥിതം ശൂന്യം
keydrop_handler(പൂർണ്ണസംഖ്യ sig)
{
	signalled_keydrop = sig;
}

സ്ഥിതം ശൂന്യം
check_parent_exists(ശൂന്യം)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	എങ്കിൽ (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
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
	exit(1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ ac, അക്ഷരം **av)
{
	പൂർണ്ണസംഖ്യ c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	പൂർണ്ണസംഖ്യ s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	പൂർണ്ണസംഖ്യ sock = -1, ch, result, saved_errno;
	pid_t pid;
 	അക്ഷരം *homedir = ശൂന്യ, *shell, *format, *pidstr, *agentsocket = ശൂന്യ;
	അക്ഷരം *cp, pidstrbuf[1 + 3 * വലുപ്പം pid];
	അക്ഷരം *fdstr;
	സ്ഥിരം അക്ഷരം *errstr = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *ccp;
#ifdef HAVE_SETRLIMIT
	ഘടന rlimit rlim;
#endif
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	ബാഹ്യ അക്ഷരം *optarg;
	size_t len;
	mode_t prev_mask;
	ഘടന timespec timeout;
	ഘടന pollfd *pfd = ശൂന്യ;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	പൂർണ്ണസംഖ്യ socket_activated = 0;
	ഘടന passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(ശൂന്യം)setegid(getgid());
	(ശൂന്യം)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	എങ്കിൽ ((pw = getpwuid(getuid())) == ശൂന്യ)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	എങ്കിൽ (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	ആകുമ്പോൾ ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			എങ്കിൽ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			നിർത്തുക;
		അവസ്ഥ 'c':
			എങ്കിൽ (s_flag)
				usage();
			c_flag++;
			നിർത്തുക;
		അവസ്ഥ 'k':
			k_flag++;
			നിർത്തുക;
		അവസ്ഥ 'O':
			എങ്കിൽ (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			അല്ലെങ്കിൽ എങ്കിൽ ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != ശൂന്യ) {
				എങ്കിൽ (websafe_allowlist != ശൂന്യ)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} അല്ലെങ്കിൽ
				fatal("Unknown -O option");
			നിർത്തുക;
		അവസ്ഥ 'P':
			എങ്കിൽ (allowed_providers != ശൂന്യ)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 's':
			എങ്കിൽ (c_flag)
				usage();
			s_flag++;
			നിർത്തുക;
		അവസ്ഥ 'd':
			എങ്കിൽ (d_flag || D_flag)
				usage();
			d_flag++;
			നിർത്തുക;
		അവസ്ഥ 'D':
			എങ്കിൽ (d_flag || D_flag)
				usage();
			D_flag++;
			നിർത്തുക;
		അവസ്ഥ 'a':
			agentsocket = optarg;
			നിർത്തുക;
		അവസ്ഥ 'A':
			socket_dirspec = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 't':
			എങ്കിൽ ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			നിർത്തുക;
		അവസ്ഥ 'T':
			T_flag++;
			നിർത്തുക;
		അവസ്ഥ 'u':
			u_flag++;
			നിർത്തുക;
		അവസ്ഥ 'U':
			U_flag++;
			നിർത്തുക;
		അവസ്ഥ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		സ്ഥിരസ്ഥിതി:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	എങ്കിൽ (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	എങ്കിൽ (((socket_dirspec != ശൂന്യ) + (agentsocket != ശൂന്യ) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	എങ്കിൽ (allowed_providers == ശൂന്യ)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	എങ്കിൽ (websafe_allowlist == ശൂന്യ)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	എങ്കിൽ (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	അല്ലെങ്കിൽ എങ്കിൽ (socket_dirspec == ശൂന്യ && agentsocket == ശൂന്യ)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	എങ്കിൽ (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		എങ്കിൽ (shell != ശൂന്യ && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	എങ്കിൽ (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		എങ്കിൽ (pidstr == ശൂന്യ) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (പൂർണ്ണസംഖ്യ)strtonum(pidstr, 2, INT_MAX, &errstr);
		എങ്കിൽ (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		എങ്കിൽ (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	എങ്കിൽ (u_flag) {
		എങ്കിൽ ((homedir = get_homedir()) == ശൂന്യ)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		printf("Deleted stale agent sockets in ~/%s\n",
		    _PATH_SSH_AGENT_SOCKET_DIR);
		exit(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#define SSH_AGENT_MIN_FDS (3+1+1+1+4)
	എങ്കിൽ (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	എങ്കിൽ (agentsocket == ശൂന്യ && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != ശൂന്യ &&
	    (fdstr = getenv("LISTEN_FDS")) != ശൂന്യ) {
		എങ്കിൽ (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		എങ്കിൽ (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (പൂർണ്ണസംഖ്യ)strtonum(pidstr, 1, INT_MAX, &errstr);
		എങ്കിൽ (errstr != ശൂന്യ)
			fatal("invalid LISTEN_PID: %s", errstr);
		എങ്കിൽ (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	എങ്കിൽ (sock == -1 && agentsocket == ശൂന്യ) {
		/* Listen on a socket in/under a given directory */
		എങ്കിൽ ((homedir = get_homedir()) == ശൂന്യ)
			fatal("Couldn't determine home directory");
		എങ്കിൽ (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		എങ്കിൽ (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		സ്വതന്ത്രം(homedir);
	} അല്ലെങ്കിൽ എങ്കിൽ (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		എങ്കിൽ ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			സ്വതന്ത്രം(socket_name);
			socket_name = ശൂന്യ; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	എങ്കിൽ (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		എങ്കിൽ (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	എങ്കിൽ (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		എങ്കിൽ (socket_name != ശൂന്യ) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			സ്വതന്ത്രം(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		പോകുക skip;
	}
	pid = fork();
	എങ്കിൽ (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	എങ്കിൽ (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, വലുപ്പം pidstrbuf, "%ld", (long)pid);
		എങ്കിൽ (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			സ്വതന്ത്രം(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		എങ്കിൽ (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
	/* child */
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	എങ്കിൽ (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(ശൂന്യം)chdir("/");
	എങ്കിൽ (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	എങ്കിൽ (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#endif

skip:

	cleanup_pid = getpid();

#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	എങ്കിൽ (ac > 0)
		parent_alive_interval = 10;
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

	എങ്കിൽ (socket_name != ശൂന്യ && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	എങ്കിൽ (socket_dir != ശൂന്യ && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	എങ്കിൽ (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	എങ്കിൽ ((ccp = getenv("SSH_SK_HELPER")) == ശൂന്യ || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	എങ്കിൽ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	എങ്കിൽ ((ccp = getenv("SSH_PKCS11_HELPER")) == ശൂന്യ || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	എങ്കിൽ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	എങ്കിൽ ((ccp = getenv("SSH_ASKPASS")) == ശൂന്യ || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	എങ്കിൽ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	എങ്കിൽ (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	എങ്കിൽ (pledge("stdio rpath cpath wpath unix id proc exec", ശൂന്യ) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	ആകുമ്പോൾ (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		എങ്കിൽ (signalled_exit != 0) {
			logit("exiting on signal %d", (പൂർണ്ണസംഖ്യ)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		എങ്കിൽ (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (പൂർണ്ണസംഖ്യ)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, ശൂന്യ);
		saved_errno = errno;
		എങ്കിൽ (parent_alive_interval != 0)
			check_parent_exists();
		(ശൂന്യം) reaper();	/* remove expired keys */
		എങ്കിൽ (result == -1) {
			എങ്കിൽ (saved_errno == EINTR)
				തുടരുക;
			fatal("poll: %s", strerror(saved_errno));
		} അല്ലെങ്കിൽ എങ്കിൽ (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
