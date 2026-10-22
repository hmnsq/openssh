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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/resource.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"
#endif

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <util.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "version.h"

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

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଗଣନା {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

ସଂରଚନା hostkey_sid {
	ସଂରଚନା sshkey *ଚାବି;
	ସଂରଚନା sshbuf *sid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା forwarded;
};

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା socket_entry {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;
	sock_type type;
	ସଂରଚନା sshbuf *ନିବେଶ;
	ସଂରଚନା sshbuf *output;
	ସଂରଚନା sshbuf *request;
	size_t nsession_ids;
	ସଂରଚନା hostkey_sid *session_ids;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = ଖାଲି;

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା identity {
	TAILQ_ENTRY(identity) next;
	ସଂରଚନା sshkey *ଚାବି;
	ଅକ୍ଷର *comment;
	ଅକ୍ଷର *provider;
	time_t death;
	u_int confirm;
	ଅକ୍ଷର *sk_provider;
	ସଂରଚନା dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

ସଂରଚନା idtable {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
ସଂରଚନା idtable *idtab;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

ସ୍ଥିର sig_atomic_t signalled_exit;
ସ୍ଥିର sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
ସ୍ଥିର ଅକ୍ଷର *socket_name;
ସ୍ଥିର ଅକ୍ଷର *socket_dir;
ସ୍ଥିର ଅକ୍ଷର *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
ସ୍ଥିର ଅକ୍ଷର *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
ପୂର୍ଣ୍ଣସଂଖ୍ୟା locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

ବାହ୍ୟ ଅକ୍ଷର *__progname;

/* Default lifetime in seconds (0 == forever) */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା lifetime = 0;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା restrict_websafe = 1;
ସ୍ଥିର ଅକ୍ଷର *websafe_allowlist;

ସ୍ଥିର ଶୂନ୍ୟ
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->ନିବେଶ);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	ପାଇଁ (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].ଚାବି);
		sshbuf_free(e->session_ids[i].sid);
	}
	ମୁକ୍ତ(e->session_ids);
	memset(e, '\0', ଆକାର(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

ସ୍ଥିର ଶୂନ୍ୟ
idtab_init(ଶୂନ୍ୟ)
{
	idtab = xcalloc(1, ଆକାର(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
free_dest_constraint_hop(ସଂରଚନା dest_constraint_hop *dch)
{
	u_int i;

	ଯଦି (dch == ଖାଲି)
		ଫେରନ୍ତୁ;
	ମୁକ୍ତ(dch->user);
	ମୁକ୍ତ(dch->hostname);
	ପାଇଁ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ଚାବିଗୁଡ଼ିକ[i]);
	ମୁକ୍ତ(dch->ଚାବିଗୁଡ଼ିକ);
	ମୁକ୍ତ(dch->ଚାବି_is_ca);
}

ସ୍ଥିର ଶୂନ୍ୟ
free_dest_constraints(ସଂରଚନା dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	ପାଇଁ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	ମୁକ୍ତ(dcs);
}

#ifdef ENABLE_PKCS11
ସ୍ଥିର ଶୂନ୍ୟ
dup_dest_constraint_hop(ଅଚଳ ସଂରଚନା dest_constraint_hop *dch,
    ସଂରଚନା dest_constraint_hop *out)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	out->user = dch->user == ଖାଲି ? ଖାଲି : xstrdup(dch->user);
	out->hostname = dch->hostname == ଖାଲି ? ଖାଲି : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->ଚାବିଗୁଡ଼ିକ = out->nkeys == 0 ? ଖାଲି :
	    xcalloc(out->nkeys, ଆକାର(*out->ଚାବିଗୁଡ଼ିକ));
	out->ଚାବି_is_ca = out->nkeys == 0 ? ଖାଲି :
	    xcalloc(out->nkeys, ଆକାର(*out->ଚାବି_is_ca));
	ପାଇଁ (i = 0; i < dch->nkeys; i++) {
		ଯଦି (dch->ଚାବିଗୁଡ଼ିକ[i] != ଖାଲି &&
		    (r = sshkey_from_private(dch->ଚାବିଗୁଡ଼ିକ[i],
		    &(out->ଚାବିଗୁଡ଼ିକ[i]))) != 0)
			fatal_fr(r, "copy key");
		out->ଚାବି_is_ca[i] = dch->ଚାବି_is_ca[i];
	}
}

ସ୍ଥିର ସଂରଚନା dest_constraint *
dup_dest_constraints(ଅଚଳ ସଂରଚନା dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	ସଂରଚନା dest_constraint *ret;

	ଯଦି (ndcs == 0)
		ଫେରନ୍ତୁ ଖାଲି;
	ret = xcalloc(ndcs, ଆକାର(*ret));
	ପାଇଁ (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	ଫେରନ୍ତୁ ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
ସ୍ଥିର ଶୂନ୍ୟ
dump_dest_constraint_hop(ଅଚଳ ସଂରଚନା dest_constraint_hop *dch)
{
	u_int i;
	ଅକ୍ଷର *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == ଖାଲି ? "(null)" : dch->user,
	    dch->hostname == ଖାଲି ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	ପାଇଁ (i = 0; i < dch->nkeys; i++) {
		fp = ଖାଲି;
		ଯଦି (dch->ଚାବିଗୁଡ଼ିକ[i] != ଖାଲି &&
		    (fp = sshkey_fingerprint(dch->ଚାବିଗୁଡ଼ିକ[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->ଚାବିଗୁଡ଼ିକ[i] == ଖାଲି ? "" : sshkey_ssh_name(dch->ଚାବିଗୁଡ଼ିକ[i]),
		    dch->ଚାବିଗୁଡ଼ିକ[i] == ଖାଲି ? "" : " ",
		    dch->ଚାବିଗୁଡ଼ିକ[i] == ଖାଲି ? "none" : fp,
		    dch->ଚାବି_is_ca[i]);
		ମୁକ୍ତ(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

ସ୍ଥିର ଶୂନ୍ୟ
dump_dest_constraints(ଅଚଳ ଅକ୍ଷର *context,
    ଅଚଳ ସଂରଚନା dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	ପାଇଁ (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

ସ୍ଥିର ଶୂନ୍ୟ
free_identity(Identity *id)
{
	sshkey_free(id->ଚାବି);
	ମୁକ୍ତ(id->provider);
	ମୁକ୍ତ(id->comment);
	ମୁକ୍ତ(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	ମୁକ୍ତ(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_ଚାବି_hop(ଅଚଳ ଅକ୍ଷର *tag, ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ସଂରଚନା dest_constraint_hop *dch)
{
	ଅଚଳ ଅକ୍ଷର *reason = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	ଅକ୍ଷର *fp;

	ଯଦି (ଚାବି == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	/* XXX logspam */
	ଯଦି ((fp = sshkey_fingerprint(ଚାବି, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ଖାଲି)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(ଚାବି), fp, dch->nkeys);
	ମୁକ୍ତ(fp);
	ପାଇଁ (i = 0; i < dch->nkeys; i++) {
		ଯଦି (dch->ଚାବିଗୁଡ଼ିକ[i] == ଖାଲି)
			ଫେରନ୍ତୁ -1;
		/* XXX logspam */
		ଯଦି ((fp = sshkey_fingerprint(dch->ଚାବିଗୁଡ଼ିକ[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->ଚାବି_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->ଚାବିଗୁଡ଼ିକ[i]), fp);
		ମୁକ୍ତ(fp);
		ଯଦି (!sshkey_is_cert(ଚାବି)) {
			/* plain key */
			ଯଦି (dch->ଚାବି_is_ca[i] ||
			    !sshkey_equal(ଚାବି, dch->ଚାବିଗୁଡ଼ିକ[i]))
				ଜାରି;
			ଫେରନ୍ତୁ 0;
		}
		/* certificate */
		ଯଦି (!dch->ଚାବି_is_ca[i])
			ଜାରି;
		ଯଦି (ଚାବି->cert == ଖାଲି || ଚାବି->cert->signature_ଚାବି == ଖାଲି)
			ଫେରନ୍ତୁ -1; /* shouldn't happen */
		ଯଦି (!sshkey_equal(ଚାବି->cert->signature_ଚାବି, dch->ଚାବିଗୁଡ଼ିକ[i]))
			ଜାରି;
		ଯଦି (sshkey_cert_check_host(ଚାବି, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    ଚାବି->cert->ଚାବି_id, hostname, reason);
			ଜାରି;
		}
		ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ -1;
}

/* Check destination constraints on an identity against the hostkey/user */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
permitted_by_dest_constraints(ଅଚଳ ସଂରଚନା sshkey *fromkey,
    ଅଚଳ ସଂରଚନା sshkey *tokey, Identity *id, ଅଚଳ ଅକ୍ଷର *user,
    ଅଚଳ ଅକ୍ଷର **hostnamep)
{
	size_t i;
	ସଂରଚନା dest_constraint *d;

	ଯଦି (hostnamep != ଖାଲି)
		*hostnamep = ଖାଲି;
	ପାଇଁ (i = 0; i < id->ndest_constraints; i++) {
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
		ଯଦି (fromkey == ଖାଲି) {
			/* We are matching the first hop */
			ଯଦି (d->from.hostname != ଖାଲି || d->from.nkeys != 0)
				ଜାରି;
		} ଅନ୍ୟଥା ଯଦି (match_ଚାବି_hop("from", fromkey, &d->from) != 0)
			ଜାରି;

		/* Match 'to' key */
		ଯଦି (tokey != ଖାଲି && match_ଚାବି_hop("to", tokey, &d->to) != 0)
			ଜାରି;

		/* Match user if specified */
		ଯଦି (d->to.user != ଖାଲି && user != ଖାଲି &&
		    !match_pattern(user, d->to.user))
			ଜାରି;

		/* successfully matched this constraint */
		ଯଦି (hostnamep != ଖାଲି)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == ଖାଲି ? "*" : d->to.hostname);
		ଫେରନ୍ତୁ 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->ଚାବି), id->comment);
	ଫେରନ୍ତୁ -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
identity_permitted(Identity *id, SocketEntry *e, ଅକ୍ଷର *user,
    ଅଚଳ ଅକ୍ଷର **forward_hostnamep, ଅଚଳ ଅକ୍ଷର **last_hostnamep)
{
	size_t i;
	ଅଚଳ ଅକ୍ଷର **hp;
	ସଂରଚନା hostkey_sid *hks;
	ଅଚଳ ସଂରଚନା sshkey *fromkey = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *test_user;
	ଅକ୍ଷର *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->ଚାବି), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	ଯଦି (id->ndest_constraints == 0)
		ଫେରନ୍ତୁ 0; /* unconstrained */
	ଯଦି (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (e->nsession_ids == 0)
		ଫେରନ୍ତୁ 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	ପାଇଁ (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		ଯଦି (hks->ଚାବି == ଖାଲି)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = ଖାଲି;
		ଯଦି (fromkey != ଖାଲି &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("fingerprint failed");
		ଯଦି ((fp2 = sshkey_fingerprint(hks->ଚାବି, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->ଚାବି), fp2);
		ମୁକ୍ତ(fp1);
		ମୁକ୍ତ(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = ଖାଲି;
		ଯଦି (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		ଅନ୍ୟଥା ଯଦି (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = ଖାଲି;
		ଯଦି (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			ଯଦି (hks->forwarded && user != ଖାଲି) {
				error_f("tried to sign on forwarding hop");
				ଫେରନ୍ତୁ -1;
			}
		} ଅନ୍ୟଥା ଯଦି (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			ଫେରନ୍ତୁ -1;
		}
		ଯଦି (permitted_by_dest_constraints(fromkey, hks->ଚାବି, id,
		    test_user, hp) != 0)
			ଫେରନ୍ତୁ -1;
		fromkey = hks->ଚାବି;
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
	ଯଦି (hks->forwarded && user == ଖାଲି &&
	    permitted_by_dest_constraints(hks->ଚାବି, ଖାଲି, id,
	    ଖାଲି, ଖାଲି) != 0) {
		debug3_f("key permitted at host but not after");
		ଫେରନ୍ତୁ -1;
	}

	/* success */
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
socket_is_remote(SocketEntry *e)
{
	ଫେରନ୍ତୁ e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
ସ୍ଥିର Identity *
lookup_identity(ସଂରଚନା sshkey *ଚାବି)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		ଯଦି (sshkey_equal(ଚାବି, id->ଚାବି))
			ଫେରନ୍ତୁ (id);
	}
	ଫେରନ୍ତୁ (ଖାଲି);
}

/* Check confirmation of keysign request */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
confirm_ଚାବି(Identity *id, ଅଚଳ ଅକ୍ଷର *extra)
{
	ଅକ୍ଷର *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	p = sshkey_fingerprint(id->ଚାବି, fingerprint_hash, SSH_FP_DEFAULT);
	ଯଦି (p != ଖାଲି &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == ଖାଲି ? "" : "\n", extra == ଖାଲି ? "" : extra))
		ret = 0;
	ମୁକ୍ତ(p);

	ଫେରନ୍ତୁ (ret);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_status_generic(SocketEntry *e, u_int code)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

ସ୍ଥିର ଶୂନ୍ୟ
send_status(SocketEntry *e, ପୂର୍ଣ୍ଣସଂଖ୍ୟା success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
ସ୍ଥିର ଶୂନ୍ୟ
process_request_identities(SocketEntry *e)
{
	Identity *id;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ, *ଚାବିଗୁଡ଼ିକ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i = 0, nentries = 0;
	ଅକ୍ଷର *fp;

	debug2_f("entering");

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି || (ଚାବିଗୁଡ଼ିକ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		ଯଦି ((fp = sshkey_fingerprint(id->ଚାବି, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->ଚାବି), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		ମୁକ୍ତ(fp);
		/* identity not visible, don't include in response */
		ଯଦି (identity_permitted(id, e, ଖାଲି, ଖାଲି, ଖାଲି) != 0)
			ଜାରି;
		ଯଦି ((r = sshkey_puts(id->ଚାବି, ଚାବିଗୁଡ଼ିକ)) != 0 ||
		    (r = sshbuf_put_cstring(ଚାବିଗୁଡ଼ିକ, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			ଜାରି;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, nentries)) != 0 ||
	    (r = sshbuf_putb(ସନ୍ଦେଶ, ଚାବିଗୁଡ଼ିକ)) != 0)
		fatal_fr(r, "compose");
	ଯଦି ((r = sshbuf_put_stringb(e->output, ସନ୍ଦେଶ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ସନ୍ଦେଶ);
	sshbuf_free(ଚାବିଗୁଡ଼ିକ);
}


ସ୍ଥିର ଅକ୍ଷର *
agent_decode_alg(ସଂରଚନା sshkey *ଚାବି, u_int flags)
{
	ଯଦି (ଚାବି->type == ଚାବି_RSA) {
		ଯଦି (flags & SSH_AGENT_RSA_SHA2_256)
			ଫେରନ୍ତୁ "rsa-sha2-256";
		ଅନ୍ୟଥା ଯଦି (flags & SSH_AGENT_RSA_SHA2_512)
			ଫେରନ୍ତୁ "rsa-sha2-512";
	} ଅନ୍ୟଥା ଯଦି (ଚାବି->type == ଚାବି_RSA_CERT) {
		ଯଦି (flags & SSH_AGENT_RSA_SHA2_256)
			ଫେରନ୍ତୁ "rsa-sha2-256-cert-v01@openssh.com";
		ଅନ୍ୟଥା ଯଦି (flags & SSH_AGENT_RSA_SHA2_512)
			ଫେରନ୍ତୁ "rsa-sha2-512-cert-v01@openssh.com";
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_userauth_request(ସଂରଚନା sshbuf *ସନ୍ଦେଶ, ଅଚଳ ସଂରଚନା sshkey *expected_ଚାବି,
    ଅକ୍ଷର **userp, ସଂରଚନା sshbuf **sess_idp, ସଂରଚନା sshkey **hostkeyp)
{
	ସଂରଚନା sshbuf *b = ଖାଲି, *sess_id = ଖାଲି;
	ଅକ୍ଷର *user = ଖାଲି, *service = ଖାଲି, *method = ଖାଲି, *pkalg = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char t, sig_follows;
	ସଂରଚନା sshkey *mkey = ଖାଲି, *hostkey = ଖାଲି;

	ଯଦି (userp != ଖାଲି)
		*userp = ଖାଲି;
	ଯଦି (sess_idp != ଖାଲି)
		*sess_idp = ଖାଲି;
	ଯଦି (hostkeyp != ଖାଲି)
		*hostkeyp = ଖାଲି;
	ଯଦି ((b = sshbuf_fromb(ସନ୍ଦେଶ)) == ଖାଲି)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	ଯଦି ((r = sshbuf_froms(b, &sess_id)) != 0)
		ଯାଅ out;
	ଯଦି (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, ଖାଲି)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, ଖାଲି)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, ଖାଲି)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, ଖାଲି)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*ଚାବି*/
		ଯାଅ out;
	ଯଦି (t != SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_ଚାବି, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_ଚାବି->type) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		ଯଦି ((r = sshkey_froms(b, &hostkey)) != 0)
			ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	ଯଦି (userp != ଖାଲି) {
		*userp = user;
		user = ଖାଲି;
	}
	ଯଦି (sess_idp != ଖାଲି) {
		*sess_idp = sess_id;
		sess_id = ଖାଲି;
	}
	ଯଦି (hostkeyp != ଖାଲି) {
		*hostkeyp = hostkey;
		hostkey = ଖାଲି;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(service);
	ମୁକ୍ତ(method);
	ମୁକ୍ତ(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	ଫେରନ୍ତୁ r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_sshsig_request(ସଂରଚନା sshbuf *ସନ୍ଦେଶ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *b;

	ଯଦି ((b = sshbuf_fromb(ସନ୍ଦେଶ)) == ଖାଲି)
		fatal_f("sshbuf_fromb");

	ଯଦି ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, ଖାଲି, ଖାଲି)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, ଖାଲି, ଖାଲି)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, ଖାଲି, ଖାଲି)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, ଖାଲି, ଖାଲି)) != 0) /* H(msg) */
		ଯାଅ out;
	ଯଦି (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_websafe_message_contents(ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *data)
{
	ଯଦି (parse_userauth_request(data, ଚାବି, ଖାଲି, ଖାଲି, ଖାଲି) == 0) {
		debug_f("signed data matches public key userauth request");
		ଫେରନ୍ତୁ 1;
	}
	ଯଦି (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		ଫେରନ୍ତୁ 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
buf_equal(ଅଚଳ ସଂରଚନା sshbuf *a, ଅଚଳ ସଂରଚନା sshbuf *b)
{
	ଯଦି (sshbuf_ptr(a) == ଖାଲି || sshbuf_ptr(b) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (sshbuf_len(a) != sshbuf_len(b))
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଫେରନ୍ତୁ 0;
}

/* ssh2 only */
ସ୍ଥିର ଶୂନ୍ୟ
process_sign_request2(SocketEntry *e)
{
	u_char *signature = ଖାଲି;
	size_t slen = 0;
	u_int compat = 0, flags;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ok = -1, retried = 0;
	ଅକ୍ଷର *fp = ଖାଲି, *pin = ଖାଲି, *prompt = ଖାଲି;
	ଅକ୍ଷର *user = ଖାଲି, *sig_dest = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *fwd_host = ଖାଲି, *dest_host = ଖାଲି;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ = ଖାଲି, *data = ଖାଲି, *sid = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି, *hostkey = ଖାଲି;
	ସଂରଚନା identity *id;
	ସଂରଚନା notifier_ctx *notifier = ଖାଲି;

	debug_f("entering");

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି || (data = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_froms(e->request, &ଚାବି)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		ଯାଅ send;
	}

	ଯଦି ((id = lookup_identity(ଚାବି)) == ଖାଲି) {
		verbose_f("%s key not found", sshkey_type(ଚାବି));
		ଯାଅ send;
	}
	ଯଦି ((fp = sshkey_fingerprint(ଚାବି, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ଖାଲି)
		fatal_f("fingerprint failed");

	ଯଦି (id->ndest_constraints != 0) {
		ଯଦି (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			ଯାଅ send;
		}
		ଯଦି (parse_userauth_request(data, ଚାବି, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			ଯାଅ send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		ଯଦି (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			ଯାଅ send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		ଯଦି (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->ଚାବି), fp);
			ଯାଅ send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		ଯଦି (e->nsession_ids > 1 && hostkey == ଖାଲି) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			ଯାଅ send;
		}
		ଯଦି (hostkey != ଖାଲି && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].ଚାବି)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			ଯାଅ send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	ଯଦି (id->confirm && confirm_ଚାବି(id, sig_dest) != 0) {
		verbose_f("user refused key");
		ଯାଅ send;
	}
	ଯଦି (sshkey_is_sk(id->ଚାବି)) {
		ଯଦି (restrict_websafe &&
		    match_pattern_list(id->ଚାବି->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(ଚାବି, data)) {
			/* error already logged */
			ଯାଅ send;
		}
		ଯଦି (id->ଚାବି->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->ଚାବି), fp,
			    sig_dest == ଖାଲି ? "" : "\n",
			    sig_dest == ଖାଲି ? "" : sig_dest);
		}
	}
 retry_pin:
	ଯଦି ((r = sshkey_sign(id->ଚାବି, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(ଚାବି, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ଯଦି (pin == ଖାଲି && !retried && sshkey_is_sk(id->ଚାବି) &&
		    r == SSH_ERR_ଚାବି_WRONG_PASSPHRASE) {
			notify_complete(notifier, ଖାଲି);
			notifier = ଖାଲି;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->ଚାବି->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->ଚାବି), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			ଯାଅ retry_pin;
		}
		error_fr(r, "sshkey_sign");
		ଯାଅ send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	ଯଦି (ok == 0) {
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(ସନ୍ଦେଶ, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	ଯଦି ((r = sshbuf_put_stringb(e->output, ସନ୍ଦେଶ)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(ସନ୍ଦେଶ);
	sshkey_free(ଚାବି);
	sshkey_free(hostkey);
	ମୁକ୍ତ(fp);
	ମୁକ୍ତ(signature);
	ମୁକ୍ତ(sig_dest);
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(prompt);
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));
}

/* shared */
ସ୍ଥିର ଶୂନ୍ୟ
process_remove_identity(SocketEntry *e)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	Identity *id;

	debug2_f("entering");
	ଯଦି ((r = sshkey_froms(e->request, &ଚାବି)) != 0) {
		error_fr(r, "parse key");
		ଯାଅ done;
	}
	ଯଦି ((id = lookup_identity(ଚାବି)) == ଖାଲି) {
		debug_f("key not found");
		ଯାଅ done;
	}
	/* identity not visible, cannot be removed */
	ଯଦି (identity_permitted(id, e, ଖାଲି, ଖାଲି, ଖାଲି) != 0)
		ଯାଅ done; /* error already logged */
	/* We have this key, free it. */
	ଯଦି (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(ଚାବି);
	send_status(e, success);
}

ସ୍ଥିର ଶୂନ୍ୟ
remove_all_identities(ଶୂନ୍ୟ)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	ପାଇଁ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
ସ୍ଥିର time_t
reaper(ଶୂନ୍ୟ)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	ପାଇଁ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		ଯଦି (id->death == 0)
			ଜାରି;
		ଯଦି (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} ଅନ୍ୟଥା
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	ଯଦି (deadline == 0 || deadline <= now)
		ଫେରନ୍ତୁ 0;
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ (deadline - now);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_dest_constraint_hop(ସଂରଚନା sshbuf *b, ସଂରଚନା dest_constraint_hop *dch)
{
	u_char ଚାବି_is_ca;
	size_t elen = 0, userlen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshkey *k = ଖାଲି;
	ଅକ୍ଷର *fp;

	memset(dch, '\0', ଆକାର(*dch));
	ଯଦି ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ଖାଲି, &elen)) != 0) {
		error_fr(r, "parse");
		ଯାଅ out;
	}
	ଯଦି (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ଯାଅ out;
	}
	ଯଦି (*dch->hostname == '\0') {
		ମୁକ୍ତ(dch->hostname);
		dch->hostname = ଖାଲି;
	}
	ଯଦି (*dch->user == '\0') {
		ମୁକ୍ତ(dch->user);
		dch->user = ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯେତେବେଳେ (sshbuf_len(b) != 0) {
		dch->ଚାବିଗୁଡ଼ିକ = xrecallocarray(dch->ଚାବିଗୁଡ଼ିକ, dch->nkeys,
		    dch->nkeys + 1, ଆକାର(*dch->ଚାବିଗୁଡ଼ିକ));
		dch->ଚାବି_is_ca = xrecallocarray(dch->ଚାବି_is_ca, dch->nkeys,
		    dch->nkeys + 1, ଆକାର(*dch->ଚାବି_is_ca));
		ଯଦି ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &ଚାବି_is_ca)) != 0)
			ଯାଅ out;
		ଯଦି ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == ଖାଲି ? "" : dch->user,
		    dch->user == ଖାଲି ? "" : "@",
		    dch->hostname, ଚାବି_is_ca ? "CA " : "", sshkey_type(k), fp);
		ମୁକ୍ତ(fp);
		dch->ଚାବିଗୁଡ଼ିକ[dch->nkeys] = k;
		dch->ଚାବି_is_ca[dch->nkeys] = ଚାବି_is_ca != 0;
		dch->nkeys++;
		k = ଖାଲି; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_dest_constraint(ସଂରଚନା sshbuf *m, ସଂରଚନା dest_constraint *dc)
{
	ସଂରଚନା sshbuf *b = ଖାଲି, *frombuf = ଖାଲି, *tobuf = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', ଆକାର(*dc));
	ଯଦି ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ଖାଲି, &elen)) != 0) {
		error_fr(r, "parse");
		ଯାଅ out;
	}
	ଯଦି ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		ଯାଅ out; /* already logged */
	ଯଦି (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ଯାଅ out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	ଯଦି ((dc->from.hostname == ଖାଲି) != (dc->from.nkeys == 0) ||
	    dc->from.user != ଖାଲି) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (dc->to.hostname == ଖାଲି || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_ଚାବି_constraint_extension(ସଂରଚନା sshbuf *m, ଅକ୍ଷର **sk_providerp,
    ସଂରଚନା dest_constraint **dcsp, size_t *ndcsp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *cert_onlyp,
    ସଂରଚନା sshkey ***certs, size_t *ncerts)
{
	ଅକ୍ଷର *ext_name = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	u_char v;
	ସଂରଚନା sshkey *k;

	ଯଦି ((r = sshbuf_get_cstring(m, &ext_name, ଖାଲି)) != 0) {
		error_fr(r, "parse constraint extension");
		ଯାଅ out;
	}
	debug_f("constraint ext %s", ext_name);
	ଯଦି (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		ଯଦି (sk_providerp == ଖାଲି) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି (*sk_providerp != ଖାଲି) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_get_cstring(m, sk_providerp, ଖାଲି)) != 0) {
			error_fr(r, "parse %s", ext_name);
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା ଯଦି (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		ଯଦି (*dcsp != ଖାଲି) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			ଯାଅ out;
		}
		ଯେତେବେଳେ (sshbuf_len(b) != 0) {
			ଯଦି (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				ଯାଅ out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    ଆକାର(**dcsp));
			ଯଦି ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				ଯାଅ out; /* error already logged */
		}
	} ଅନ୍ୟଥା ଯଦି (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		ଯଦି (certs == ଖାଲି || ncerts == ଖାଲି || cert_onlyp == ଖାଲି) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି (*certs != ଖାଲି) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			ଯାଅ out;
		}
		*cert_onlyp = v != 0;
		ଯେତେବେଳେ (sshbuf_len(b) != 0) {
			ଯଦି (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				ଯାଅ out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    ଆକାର(**certs));
			ଯଦି ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				ଯାଅ out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} ଅନ୍ୟଥା {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	ମୁକ୍ତ(ext_name);
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_ଚାବି_constraints(ସଂରଚନା sshbuf *m, ସଂରଚନା sshkey *k, time_t *deathp,
    u_int *secondsp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *confirmp, ଅକ୍ଷର **sk_providerp,
    ସଂରଚନା dest_constraint **dcsp, size_t *ndcsp,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *cert_onlyp, size_t *ncerts, ସଂରଚନା sshkey ***certs)
{
	u_char ctype;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int seconds;

	ଯେତେବେଳେ (sshbuf_len(m)) {
		ଯଦି ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			ଯାଅ out;
		}
		ବାଛ (ctype) {
		ସ୍ଥିତି SSH_AGENT_CONSTRAIN_LIFETIME:
			ଯଦି (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				ଯାଅ out;
			}
			ଯଦି ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				ଯାଅ out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH_AGENT_CONSTRAIN_CONFIRM:
			ଯଦି (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				ଯାଅ out;
			}
			*confirmp = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH_AGENT_CONSTRAIN_EXTENSION:
			ଯଦି ((r = parse_ଚାବି_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				ଯାଅ out; /* error already logged */
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			ଯାଅ out;
		}
	}
	/* success */
	r = 0;
 out:
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଶୂନ୍ୟ
process_add_identity(SocketEntry *e)
{
	Identity *id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success = 0, confirm = 0;
	ଅକ୍ଷର *fp, *comment = ଖାଲି, *sk_provider = ଖାଲି;
	ଅକ୍ଷର canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	ସଂରଚନା dest_constraint *dest_constraints = ଖାଲି;
	size_t ndest_constraints = 0;
	ସଂରଚନା sshkey *k = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	ଯଦି ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == ଖାଲି ||
	    (r = sshbuf_get_cstring(e->request, &comment, ଖାଲି)) != 0) {
		error_fr(r, "parse");
		ଯାଅ out;
	}
	ଯଦି (parse_ଚାବି_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    ଖାଲି, ଖାଲି, ଖାଲି) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		ଯାଅ out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	ଯଦି (sk_provider != ଖାଲି) {
		ଯଦି (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			ଯାଅ out;
		}
		ଯଦି (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} ଅନ୍ୟଥା {
			ଯଦି (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				ଯାଅ out;
			}
			ଯଦି (realpath(sk_provider, canonical_provider) == ଖାଲି) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				ଯାଅ out;
			}
			ମୁକ୍ତ(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			ଯଦି (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				ଯାଅ out;
			}
		}
	}
	ଯଦି ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		ଯାଅ out;
	}
	ଯଦି (lifetime && !death)
		death = monotime() + lifetime;
	ଯଦି ((id = lookup_identity(k)) == ଖାଲି) {
		id = xcalloc(1, ଆକାର(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} ଅନ୍ୟଥା {
		/* identity not visible, do not update */
		ଯଦି (identity_permitted(id, e, ଖାଲି, ଖାଲି, ଖାଲି) != 0)
			ଯାଅ out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->ଚାବି);
		ମୁକ୍ତ(id->comment);
		ମୁକ୍ତ(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->ଚାବି = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	ଯଦି ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ଖାଲି)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == ଖାଲି ? "none" : sk_provider, ndest_constraints);
	ମୁକ୍ତ(fp);
	/* transferred */
	k = ଖାଲି;
	comment = ଖାଲି;
	sk_provider = ଖାଲି;
	dest_constraints = ଖାଲି;
	ndest_constraints = 0;
	success = 1;
 out:
	ମୁକ୍ତ(sk_provider);
	ମୁକ୍ତ(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
ସ୍ଥିର ଶୂନ୍ୟ
process_lock_agent(SocketEntry *e, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lock)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0, delay;
	ଅକ୍ଷର *passwd;
	u_char passwdhash[LOCK_SIZE];
	ସ୍ଥିର u_int fail_ଗଣନା = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	ଯଦି ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (pwlen == 0) {
		debug("empty password not supported");
	} ଅନ୍ୟଥା ଯଦି (locked && !lock) {
		ଯଦି (bcrypt_pbkdf(passwd, pwlen, lock_salt, ଆକାର(lock_salt),
		    passwdhash, ଆକାର(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		ଯଦି (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_ଗଣନା = 0;
			explicit_bzero(lock_pwhash, ଆକାର(lock_pwhash));
			success = 1;
		} ଅନ୍ୟଥା {
			/* delay in 0.1s increments up to 10s */
			ଯଦି (fail_ଗଣନା < 100)
				fail_ଗଣନା++;
			delay = 100000 * fail_ଗଣନା;
			debug("unlock failed, delaying %0.1lf seconds",
			    (ଦ୍ୱିଗୁଣ)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, ଆକାର(passwdhash));
	} ଅନ୍ୟଥା ଯଦି (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, ଆକାର(lock_salt));
		ଯଦି (bcrypt_pbkdf(passwd, pwlen, lock_salt, ଆକାର(lock_salt),
		    lock_pwhash, ଆକାର(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

ସ୍ଥିର ଶୂନ୍ୟ
no_identities(SocketEntry *e)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, ସନ୍ଦେଶ)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(ସନ୍ଦେଶ);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
ସ୍ଥିର ଶୂନ୍ୟ
add_p11_identity(ସଂରଚନା sshkey *ଚାବି, ଅକ୍ଷର *comment, ଅଚଳ ଅକ୍ଷର *provider,
    time_t death, u_int confirm, ସଂରଚନା dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	ଯଦି (lookup_identity(ଚାବି) != ଖାଲି) {
		sshkey_free(ଚାବି);
		ମୁକ୍ତ(comment);
		ଫେରନ୍ତୁ;
	}
	id = xcalloc(1, ଆକାର(Identity));
	id->ଚାବି = ଚାବି;
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

ସ୍ଥିର ଶୂନ୍ୟ
process_add_smartcard_ଚାବି(SocketEntry *e)
{
	ଅକ୍ଷର *provider = ଖାଲି, *pin = ଖାଲି, canonical_provider[PATH_MAX];
	ଅକ୍ଷର **comments = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i, ଗଣନା_2 = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ = ଖାଲି, *k;
	ସଂରଚନା dest_constraint *dest_constraints = ଖାଲି;
	size_t j, ndest_constraints = 0, ncerts = 0;
	ସଂରଚନା sshkey **certs = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only = 0;

	debug2_f("entering");
	ଯଦି ((r = sshbuf_get_cstring(e->request, &provider, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ଖାଲି)) != 0) {
		error_fr(r, "parse");
		ଯାଅ send;
	}
	ଯଦି (parse_ଚାବି_constraints(e->request, ଖାଲି, &death, &seconds, &confirm,
	    ଖାଲି, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		ଯାଅ send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	ଯଦି (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		ଯାଅ send;
	}
	ଯଦି (realpath(provider, canonical_provider) == ଖାଲି) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		ଯାଅ send;
	}
	ଯଦି (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		ଯାଅ send;
	}
	debug_f("add %.100s", canonical_provider);
	ଯଦି (lifetime && !death)
		death = monotime() + lifetime;

	ଗଣନା_2 = pkcs11_add_provider(canonical_provider, pin, &ଚାବିଗୁଡ଼ିକ, &comments);
	ପାଇଁ (i = 0; i < ଗଣନା_2; i++) {
		ଯଦି (comments[i] == ଖାଲି || comments[i][0] == '\0') {
			ମୁକ୍ତ(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		ପାଇଁ (j = 0; j < ncerts; j++) {
			ଯଦି (!sshkey_is_cert(certs[j]))
				ଜାରି;
			ଯଦି (!sshkey_equal_public(ଚାବିଗୁଡ଼ିକ[i], certs[j]))
				ଜାରି;
			ଯଦି (pkcs11_make_cert(ଚାବିଗୁଡ଼ିକ[i], certs[j], &k) != 0)
				ଜାରି;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		ଯଦି (!cert_only && lookup_identity(ଚାବିଗୁଡ଼ିକ[i]) == ଖାଲି) {
			add_p11_identity(ଚାବିଗୁଡ଼ିକ[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			ଚାବିଗୁଡ଼ିକ[i] = ଖାଲି;		/* transferred */
			comments[i] = ଖାଲି;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(ଚାବିଗୁଡ଼ିକ[i]);
		ମୁକ୍ତ(comments[i]);
	}
send:
	ମୁକ୍ତ(pin);
	ମୁକ୍ତ(provider);
	ମୁକ୍ତ(ଚାବିଗୁଡ଼ିକ);
	ମୁକ୍ତ(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ପାଇଁ (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	ମୁକ୍ତ(certs);
	send_status(e, success);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_remove_smartcard_ଚାବି(SocketEntry *e)
{
	ଅକ୍ଷର *provider = ଖାଲି, *pin = ଖାଲି, canonical_provider[PATH_MAX];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	ଯଦି ((r = sshbuf_get_cstring(e->request, &provider, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ଖାଲି)) != 0) {
		error_fr(r, "parse");
		ଯାଅ send;
	}
	ମୁକ୍ତ(pin);

	ଯଦି (realpath(provider, canonical_provider) == ଖାଲି) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		ଯାଅ send;
	}

	debug_f("remove %.100s", canonical_provider);
	ପାଇଁ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		ଯଦି (id->provider == ଖାଲି)
			ଜାରି;
		ଯଦି (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	ଯଦି (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	ଅନ୍ୟଥା
		error_f("pkcs11_del_provider failed");
send:
	ମୁକ୍ତ(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_ext_session_bind(SocketEntry *e)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, sid_match, ଚାବି_match;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *sid = ଖାଲି, *sig = ଖାଲି;
	ଅକ୍ଷର *fp = ଖାଲି;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	ଯଦି ((r = sshkey_froms(e->request, &ଚାବି)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		ଯାଅ out;
	}
	ଯଦି ((fp = sshkey_fingerprint(ଚାବି, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ଖାଲି)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	ଯଦି ((r = sshkey_verify(ଚାବି, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), ଖାଲି, 0, ଖାଲି)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(ଚାବି), fp);
		ଯାଅ out;
	}
	/* check whether sid/key already recorded */
	ପାଇଁ (i = 0; i < e->nsession_ids; i++) {
		ଯଦି (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			ଯାଅ out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		ଚାବି_match = sshkey_equal(ଚାବି, e->session_ids[i].ଚାବି);
		ଯଦି (sid_match && ଚାବି_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(ଚାବି), fp);
			r = 0;
			ଯାଅ out;
		} ଅନ୍ୟଥା ଯଦି (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(ଚାବି), fp);
			r = -1;
			ଯାଅ out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	ଯଦି (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		ଯାଅ out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, ଆକାର(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(ଚାବି), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].ଚାବି = ଚାବି;
	e->session_ids[i].forwarded = fwd != 0;
	ଚାବି = ଖାଲି; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	ଯଦି ((e->session_ids[i].sid = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	ମୁକ୍ତ(fp);
	sshkey_free(ଚାବି);
	sshbuf_free(sid);
	sshbuf_free(sig);
	ଫେରନ୍ତୁ r == 0 ? 1 : 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_ext_query(SocketEntry *e)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ = ଖାଲି;

	debug2_f("entering");
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	ଯଦି ((r = sshbuf_put_stringb(e->output, ସନ୍ଦେଶ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extension(SocketEntry *e)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, replied = 0, success = 0;
	ଅକ୍ଷର *name;

	debug2_f("entering");
	ଯଦି ((r = sshbuf_get_cstring(e->request, &name, ଖାଲି)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		ଫେରନ୍ତୁ;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	ଯଦି (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} ଅନ୍ୟଥା ଯଦି (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		ଯାଅ generic_fail;
	} ଅନ୍ୟଥା ଯଦି (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} ଅନ୍ୟଥା {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		ମୁକ୍ତ(name);
		send_status(e, 0);
		ଫେରନ୍ତୁ;
	}
	ମୁକ୍ତ(name);
	/* Agent failures are signalled with a different error code */
	ଯଦି (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_message(u_int socknum)
{
	u_int ସନ୍ଦେଶ_len;
	u_char type;
	ଅଚଳ u_char *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	SocketEntry *e;

	ଯଦି (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	ଯଦି (sshbuf_len(e->ନିବେଶ) < 5)
		ଫେରନ୍ତୁ 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->ନିବେଶ);
	ସନ୍ଦେଶ_len = PEEK_U32(cp);
	ଯଦି (ସନ୍ଦେଶ_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, ସନ୍ଦେଶ_len, AGENT_MAX_LEN);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (sshbuf_len(e->ନିବେଶ) < ସନ୍ଦେଶ_len + 4)
		ଫେରନ୍ତୁ 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	ଯଦି ((r = sshbuf_get_stringb(e->ନିବେଶ, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		ଯଦି (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			ଫେରନ୍ତୁ -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	ଯଦି (locked && type != SSH_AGENTC_UNLOCK) {
		ବାଛ (type) {
		ସ୍ଥିତି SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH_AGENTC_EXTENSION:
			process_extension(e);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		ଫେରନ୍ତୁ 1;
	}

	ବାଛ (type) {
	ସ୍ଥିତି SSH_AGENTC_LOCK:
	ସ୍ଥିତି SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		ଭାଙ୍ଗ;
	/* ssh2 */
	ସ୍ଥିତି SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_AGENTC_ADD_IDENTITY:
	ସ୍ଥିତି SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		ଭାଙ୍ଗ;
#ifdef ENABLE_PKCS11
	ସ୍ଥିତି SSH_AGENTC_ADD_SMARTCARD_ଚାବି:
	ସ୍ଥିତି SSH_AGENTC_ADD_SMARTCARD_ଚାବି_CONSTRAINED:
		process_add_smartcard_ଚାବି(e);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_AGENTC_REMOVE_SMARTCARD_ଚାବି:
		process_remove_smartcard_ଚାବି(e);
		ଭାଙ୍ଗ;
#endif /* ENABLE_PKCS11 */
	ସ୍ଥିତି SSH_AGENTC_EXTENSION:
		process_extension(e);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
new_socket(sock_type type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	ଯଦି (fd > max_fd)
		max_fd = fd;

	ପାଇଁ (i = 0; i < sockets_alloc; i++)
		ଯଦି (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			ଯଦି ((sockets[i].ନିବେଶ = sshbuf_new()) == ଖାଲି ||
			    (sockets[i].output = sshbuf_new()) == ଖାଲି ||
			    (sockets[i].request = sshbuf_new()) == ଖାଲି)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			ଫେରନ୍ତୁ;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    ଆକାର(sockets[0]));
	ପାଇଁ (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	ଯଦି ((sockets[old_alloc].ନିବେଶ = sshbuf_new()) == ଖାଲି ||
	    (sockets[old_alloc].output = sshbuf_new()) == ଖାଲି ||
	    (sockets[old_alloc].request = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_socket_read(u_int socknum)
{
	ସଂରଚନା sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	slen = ଆକାର(sunaddr);
	fd = accept(sockets[socknum].fd, (ସଂରଚନା sockaddr *)&sunaddr, &slen);
	ଯଦି (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		ଫେରନ୍ତୁ -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_conn_read(u_int socknum)
{
	ଅକ୍ଷର buf[AGENT_RBUF_LEN];
	ssize_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((len = ପଠ(sockets[socknum].fd, buf, ଆକାର(buf))) <= 0) {
		ଯଦି (len == -1) {
			ଯଦି (errno == EAGAIN || errno == EINTR)
				ଫେରନ୍ତୁ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((r = sshbuf_put(sockets[socknum].ନିବେଶ, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, ଆକାର(buf));
	ପାଇଁ (;;) {
		ଯଦି ((r = process_message(socknum)) == -1)
			ଫେରନ୍ତୁ -1;
		ଅନ୍ୟଥା ଯଦି (r == 0)
			ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_conn_write(u_int socknum)
{
	ssize_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (sshbuf_len(sockets[socknum].output) == 0)
		ଫେରନ୍ତୁ 0; /* shouldn't happen */
	ଯଦି ((len = ଲିଖ(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		ଯଦି (len == -1) {
			ଯଦି (errno == EAGAIN || errno == EINTR)
				ଫେରନ୍ତୁ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
after_poll(ସଂରଚନା pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	ପାଇଁ (i = 0; i < npfd; i++) {
		ଯଦି (pfd[i].revents == 0)
			ଜାରି;
		/* Find sockets entry */
		ପାଇଁ (socknum = 0; socknum < sockets_alloc; socknum++) {
			ଯଦି (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				ଜାରି;
			ଯଦି (pfd[i].fd == sockets[socknum].fd)
				ଭାଙ୍ଗ;
		}
		ଯଦି (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			ଜାରି;
		}
		/* Process events */
		ବାଛ (sockets[socknum].type) {
		ସ୍ଥିତି AUTH_SOCKET:
			ଯଦି ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				ଭାଙ୍ଗ;
			ଯଦି (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				ଭାଙ୍ଗ;
			}
			ଯଦି (handle_socket_read(socknum) == 0)
				activefds++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AUTH_CONNECTION:
			ଯଦି ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				ଯାଅ close_sock;
			ଯଦି ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				ଯଦି (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				ଭାଙ୍ଗ;
			}
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଭାଙ୍ଗ;
		}
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
prepare_poll(ସଂରଚନା pollfd **pfdp, size_t *npfdp, ସଂରଚନା timespec *timeoutp, u_int maxfds)
{
	ସଂରଚନା pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* Count active sockets */
	ପାଇଁ (i = 0; i < sockets_alloc; i++) {
		ବାଛ (sockets[i].type) {
		ସ୍ଥିତି AUTH_SOCKET:
		ସ୍ଥିତି AUTH_CONNECTION:
			npfd++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AUTH_UNUSED:
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("Unknown socket type %d", sockets[i].type);
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, ଆକାର(*pfd))) == ଖାଲି)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	ପାଇଁ (i = j = 0; i < sockets_alloc; i++) {
		ବାଛ (sockets[i].type) {
		ସ୍ଥିତି AUTH_SOCKET:
			ଯଦି (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				ଭାଙ୍ଗ;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			ଯଦି ((r = sshbuf_check_reserve(sockets[i].ନିବେଶ,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			ଅନ୍ୟଥା ଯଦି (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			ଯଦି (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଭାଙ୍ଗ;
		}
	}
	deadline = reaper();
	ଯଦି (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	ଯଦି (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	ଫେରନ୍ତୁ (1);
}

ସ୍ଥିର ଶୂନ୍ୟ
cleanup_socket(ଶୂନ୍ୟ)
{
	ଯଦି (cleanup_pid != 0 && getpid() != cleanup_pid)
		ଫେରନ୍ତୁ;
	debug_f("cleanup");
	ଯଦି (socket_name != ଖାଲି) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		ମୁକ୍ତ(socket_name);
		socket_name = ଖାଲି;
		ମୁକ୍ତ(socket_dir);
		socket_dir = ଖାଲି;
	}
}

ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

ସ୍ଥିର ଶୂନ୍ୟ
cleanup_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	signalled_exit = sig;
}

ସ୍ଥିର ଶୂନ୍ୟ
keydrop_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	signalled_keydrop = sig;
}

ସ୍ଥିର ଶୂନ୍ୟ
check_parent_exists(ଶୂନ୍ୟ)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	ଯଦି (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
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

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ac, ଅକ୍ଷର **av)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock = -1, ch, result, saved_errno;
	pid_t pid;
 	ଅକ୍ଷର *homedir = ଖାଲି, *shell, *format, *pidstr, *agentsocket = ଖାଲି;
	ଅକ୍ଷର *cp, pidstrbuf[1 + 3 * ଆକାର pid];
	ଅକ୍ଷର *fdstr;
	ଅଚଳ ଅକ୍ଷର *errstr = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *ccp;
#ifdef HAVE_SETRLIMIT
	ସଂରଚନା rlimit rlim;
#endif
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	size_t len;
	mode_t prev_mask;
	ସଂରଚନା timespec timeout;
	ସଂରଚନା pollfd *pfd = ଖାଲି;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା socket_activated = 0;
	ସଂରଚନା passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(ଶୂନ୍ୟ)setegid(getgid());
	(ଶୂନ୍ୟ)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	ଯଦି ((pw = getpwuid(getuid())) == ଖାଲି)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	ଯଦି (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	ଯେତେବେଳେ ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ଯଦି (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'c':
			ଯଦି (s_flag)
				usage();
			c_flag++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'k':
			k_flag++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'O':
			ଯଦି (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			ଅନ୍ୟଥା ଯଦି ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != ଖାଲି) {
				ଯଦି (websafe_allowlist != ଖାଲି)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} ଅନ୍ୟଥା
				fatal("Unknown -O option");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'P':
			ଯଦି (allowed_providers != ଖାଲି)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 's':
			ଯଦି (c_flag)
				usage();
			s_flag++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'd':
			ଯଦି (d_flag || D_flag)
				usage();
			d_flag++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'D':
			ଯଦି (d_flag || D_flag)
				usage();
			D_flag++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'a':
			agentsocket = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'A':
			socket_dirspec = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':
			ଯଦି ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'T':
			T_flag++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'u':
			u_flag++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'U':
			U_flag++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	ଯଦି (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	ଯଦି (((socket_dirspec != ଖାଲି) + (agentsocket != ଖାଲି) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	ଯଦି (allowed_providers == ଖାଲି)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	ଯଦି (websafe_allowlist == ଖାଲି)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	ଯଦି (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	ଅନ୍ୟଥା ଯଦି (socket_dirspec == ଖାଲି && agentsocket == ଖାଲି)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	ଯଦି (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		ଯଦି (shell != ଖାଲି && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	ଯଦି (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		ଯଦି (pidstr == ଖାଲି) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(pidstr, 2, INT_MAX, &errstr);
		ଯଦି (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		ଯଦି (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	ଯଦି (u_flag) {
		ଯଦି ((homedir = get_homedir()) == ଖାଲି)
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
	ଯଦି (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	ଯଦି (agentsocket == ଖାଲି && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != ଖାଲି &&
	    (fdstr = getenv("LISTEN_FDS")) != ଖାଲି) {
		ଯଦି (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		ଯଦି (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(pidstr, 1, INT_MAX, &errstr);
		ଯଦି (errstr != ଖାଲି)
			fatal("invalid LISTEN_PID: %s", errstr);
		ଯଦି (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	ଯଦି (sock == -1 && agentsocket == ଖାଲି) {
		/* Listen on a socket in/under a given directory */
		ଯଦି ((homedir = get_homedir()) == ଖାଲି)
			fatal("Couldn't determine home directory");
		ଯଦି (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		ଯଦି (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		ମୁକ୍ତ(homedir);
	} ଅନ୍ୟଥା ଯଦି (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		ଯଦି ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			ମୁକ୍ତ(socket_name);
			socket_name = ଖାଲି; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	ଯଦି (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		ଯଦି (sock < 0) {
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
	ଯଦି (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		ଯଦି (socket_name != ଖାଲି) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			ମୁକ୍ତ(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		ଯାଅ skip;
	}
	pid = fork();
	ଯଦି (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	ଯଦି (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, ଆକାର pidstrbuf, "%ld", (long)pid);
		ଯଦି (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			ମୁକ୍ତ(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		ଯଦି (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
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

	ଯଦି (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(ଶୂନ୍ୟ)chdir("/");
	ଯଦି (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	ଯଦି (setrlimit(RLIMIT_CORE, &rlim) == -1) {
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
	ଯଦି (ac > 0)
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

	ଯଦି (socket_name != ଖାଲି && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	ଯଦି (socket_dir != ଖାଲି && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	ଯଦି (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	ଯଦି ((ccp = getenv("SSH_SK_HELPER")) == ଖାଲି || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	ଯଦି (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ଯଦି ((ccp = getenv("SSH_PKCS11_HELPER")) == ଖାଲି || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	ଯଦି (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ଯଦି ((ccp = getenv("SSH_ASKPASS")) == ଖାଲି || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	ଯଦି (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ଯଦି (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	ଯଦି (pledge("stdio rpath cpath wpath unix id proc exec", ଖାଲି) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	ଯେତେବେଳେ (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ଯଦି (signalled_exit != 0) {
			logit("exiting on signal %d", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		ଯଦି (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, ଖାଲି);
		saved_errno = errno;
		ଯଦି (parent_alive_interval != 0)
			check_parent_exists();
		(ଶୂନ୍ୟ) reaper();	/* remove expired keys */
		ଯଦି (result == -1) {
			ଯଦି (saved_errno == EINTR)
				ଜାରି;
			fatal("poll: %s", strerror(saved_errno));
		} ଅନ୍ୟଥା ଯଦି (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
