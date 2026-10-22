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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/resource.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/un.h>
#అన్తర్భావ <sys/wait.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#అయితే_ముగింపు

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <util.h>
#అన్తర్భావ <pwd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "ssh-pkcs11.h"
#అన్తర్భావ "sk-api.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "version.h"

#నిర్వచితం_కాకపోతే DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#అయితే_ముగింపు

/* Maximum accepted message length */
#నిర్వచించు AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#నిర్వచించు AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#నిర్వచించు AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#నిర్వచించు AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#నిర్వచించు AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#నిర్వచించు AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#నిర్వచించు AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

రకనిర్వచనం గణన {
	AUTH_వాడని = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

నిర్మాణం hostkey_sid {
	నిర్మాణం sshkey *కీలకం;
	నిర్మాణం sshbuf *sid;
	పూర్ణాంకం forwarded;
};

రకనిర్వచనం నిర్మాణం socket_నమోదు {
	పూర్ణాంకం fd;
	sock_type type;
	నిర్మాణం sshbuf *ఆదానం;
	నిర్మాణం sshbuf *output;
	నిర్మాణం sshbuf *request;
	కొలత_t nsession_ids;
	నిర్మాణం hostkey_sid *session_ids;
	పూర్ణాంకం session_bind_attempted;
} Socket_నమోదు;

u_int sockets_alloc = 0;
Socket_నమోదు *sockets = ఖాళీ;

రకనిర్వచనం నిర్మాణం తటస్థం_2 {
	TAILQ_ENTRY(తటస్థం_2) తదుపరి;
	నిర్మాణం sshkey *కీలకం;
	అక్షరం *comment;
	అక్షరం *provider;
	time_t death;
	u_int confirm;
	అక్షరం *sk_provider;
	నిర్మాణం dest_constraint *dest_constraints;
	కొలత_t ndest_constraints;
} తటస్థం;

నిర్మాణం idtable {
	పూర్ణాంకం nentries;
	TAILQ_HEAD(idqueue, తటస్థం_2) idlist;
};

/* private key table */
నిర్మాణం idtable *idtab;

పూర్ణాంకం max_fd = 0;

/* pid of shell == parent of agent */
pid_t మాతృ_pid = -1;
time_t మాతృ_alive_interval = 0;

స్థిర sig_atomic_t signalled_exit;
స్థిర sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
స్థిర అక్షరం *socket_name;
స్థిర అక్షరం *socket_dir;
స్థిర అక్షరం *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
స్థిర అక్షరం *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
స్థిర పూర్ణాంకం remote_కూడు_provider;

/* locking */
#నిర్వచించు తాళం_కొలత	32
#నిర్వచించు తాళం_SALT_కొలత	16
#నిర్వచించు తాళం_విడతలు	1
పూర్ణాంకం locked = 0;
u_char తాళం_pwhash[తాళం_కొలత];
u_char తాళం_salt[తాళం_SALT_కొలత];

బాహ్య అక్షరం *__progname;

/* Default lifetime in seconds (0 == forever) */
స్థిర పూర్ణాంకం lifetime = 0;

స్థిర పూర్ణాంకం fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
స్థిర పూర్ణాంకం restrict_websafe = 1;
స్థిర అక్షరం *websafe_allowlist;

స్థిర శూన్య
close_socket(Socket_నమోదు *e)
{
	కొలత_t i;

	close(e->fd);
	sshbuf_free(e->ఆదానం);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	కొరకు (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].కీలకం);
		sshbuf_free(e->session_ids[i].sid);
	}
	విడుదల(e->session_ids);
	memset(e, '\0', పరిమాణం(*e));
	e->fd = -1;
	e->type = AUTH_వాడని;
}

స్థిర శూన్య
idtab_init(శూన్య)
{
	idtab = xcalloc(1, పరిమాణం(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

స్థిర శూన్య
free_dest_constraint_hop(నిర్మాణం dest_constraint_hop *dch)
{
	u_int i;

	ఒకవేళ (dch == ఖాళీ)
		తిరిగి;
	విడుదల(dch->user);
	విడుదల(dch->hostname);
	కొరకు (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->కీలకాలు[i]);
	విడుదల(dch->కీలకాలు);
	విడుదల(dch->కీలకం_is_ca);
}

స్థిర శూన్య
free_dest_constraints(నిర్మాణం dest_constraint *dcs, కొలత_t ndcs)
{
	కొలత_t i;

	కొరకు (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].గమ్యం);
	}
	విడుదల(dcs);
}

#నిర్వచితమైతే ENABLE_PKCS11
స్థిర శూన్య
dup_dest_constraint_hop(స్థిరరాశి నిర్మాణం dest_constraint_hop *dch,
    నిర్మాణం dest_constraint_hop *బహిర్గతం)
{
	u_int i;
	పూర్ణాంకం r;

	బహిర్గతం->user = dch->user == ఖాళీ ? ఖాళీ : xstrdup(dch->user);
	బహిర్గతం->hostname = dch->hostname == ఖాళీ ? ఖాళీ : xstrdup(dch->hostname);
	బహిర్గతం->is_ca = dch->is_ca;
	బహిర్గతం->nkeys = dch->nkeys;
	బహిర్గతం->కీలకాలు = బహిర్గతం->nkeys == 0 ? ఖాళీ :
	    xcalloc(బహిర్గతం->nkeys, పరిమాణం(*బహిర్గతం->కీలకాలు));
	బహిర్గతం->కీలకం_is_ca = బహిర్గతం->nkeys == 0 ? ఖాళీ :
	    xcalloc(బహిర్గతం->nkeys, పరిమాణం(*బహిర్గతం->కీలకం_is_ca));
	కొరకు (i = 0; i < dch->nkeys; i++) {
		ఒకవేళ (dch->కీలకాలు[i] != ఖాళీ &&
		    (r = sshkey_from_వ్యక్తిగత(dch->కీలకాలు[i],
		    &(బహిర్గతం->కీలకాలు[i]))) != 0)
			fatal_fr(r, "copy key");
		బహిర్గతం->కీలకం_is_ca[i] = dch->కీలకం_is_ca[i];
	}
}

స్థిర నిర్మాణం dest_constraint *
dup_dest_constraints(స్థిరరాశి నిర్మాణం dest_constraint *dcs, కొలత_t ndcs)
{
	కొలత_t i;
	నిర్మాణం dest_constraint *ret;

	ఒకవేళ (ndcs == 0)
		తిరిగి ఖాళీ;
	ret = xcalloc(ndcs, పరిమాణం(*ret));
	కొరకు (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].గమ్యం, &ret[i].గమ్యం);
	}
	తిరిగి ret;
}
#అయితే_ముగింపు /* ENABLE_PKCS11 */

#నిర్వచితమైతే DEBUG_CONSTRAINTS
స్థిర శూన్య
dump_dest_constraint_hop(స్థిరరాశి నిర్మాణం dest_constraint_hop *dch)
{
	u_int i;
	అక్షరం *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == ఖాళీ ? "(null)" : dch->user,
	    dch->hostname == ఖాళీ ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	కొరకు (i = 0; i < dch->nkeys; i++) {
		fp = ఖాళీ;
		ఒకవేళ (dch->కీలకాలు[i] != ఖాళీ &&
		    (fp = sshkey_fingerprint(dch->కీలకాలు[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->కీలకాలు[i] == ఖాళీ ? "" : sshkey_ssh_name(dch->కీలకాలు[i]),
		    dch->కీలకాలు[i] == ఖాళీ ? "" : " ",
		    dch->కీలకాలు[i] == ఖాళీ ? "none" : fp,
		    dch->కీలకం_is_ca[i]);
		విడుదల(fp);
	}
}
#అయితే_ముగింపు /* DEBUG_CONSTRAINTS */

స్థిర శూన్య
dump_dest_constraints(స్థిరరాశి అక్షరం *context,
    స్థిరరాశి నిర్మాణం dest_constraint *dcs, కొలత_t ndcs)
{
#నిర్వచితమైతే DEBUG_CONSTRAINTS
	కొలత_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	కొరకు (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].గమ్యం);
	}
	debug_f("done for %s", context);
#అయితే_ముగింపు /* DEBUG_CONSTRAINTS */
}

స్థిర శూన్య
free_తటస్థం(తటస్థం *id)
{
	sshkey_free(id->కీలకం);
	విడుదల(id->provider);
	విడుదల(id->comment);
	విడుదల(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	విడుదల(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
స్థిర పూర్ణాంకం
సరిపోలిక_కీలకం_hop(స్థిరరాశి అక్షరం *ట్యాగ్, స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి నిర్మాణం dest_constraint_hop *dch)
{
	స్థిరరాశి అక్షరం *reason = ఖాళీ;
	స్థిరరాశి అక్షరం *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	అక్షరం *fp;

	ఒకవేళ (కీలకం == ఖాళీ)
		తిరిగి -1;
	/* XXX logspam */
	ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ఖాళీ)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    ట్యాగ్, hostname, sshkey_type(కీలకం), fp, dch->nkeys);
	విడుదల(fp);
	కొరకు (i = 0; i < dch->nkeys; i++) {
		ఒకవేళ (dch->కీలకాలు[i] == ఖాళీ)
			తిరిగి -1;
		/* XXX logspam */
		ఒకవేళ ((fp = sshkey_fingerprint(dch->కీలకాలు[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", ట్యాగ్, i,
		    dch->కీలకం_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->కీలకాలు[i]), fp);
		విడుదల(fp);
		ఒకవేళ (!sshkey_is_cert(కీలకం)) {
			/* plain key */
			ఒకవేళ (dch->కీలకం_is_ca[i] ||
			    !sshkey_equal(కీలకం, dch->కీలకాలు[i]))
				కొనసాగు;
			తిరిగి 0;
		}
		/* certificate */
		ఒకవేళ (!dch->కీలకం_is_ca[i])
			కొనసాగు;
		ఒకవేళ (కీలకం->cert == ఖాళీ || కీలకం->cert->signature_కీలకం == ఖాళీ)
			తిరిగి -1; /* shouldn't happen */
		ఒకవేళ (!sshkey_equal(కీలకం->cert->signature_కీలకం, dch->కీలకాలు[i]))
			కొనసాగు;
		ఒకవేళ (sshkey_cert_check_host(కీలకం, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    కీలకం->cert->కీలకం_id, hostname, reason);
			కొనసాగు;
		}
		తిరిగి 0;
	}
	తిరిగి -1;
}

/* Check destination constraints on an identity against the hostkey/user */
స్థిర పూర్ణాంకం
permitted_by_dest_constraints(స్థిరరాశి నిర్మాణం sshkey *fromkey,
    స్థిరరాశి నిర్మాణం sshkey *tokey, తటస్థం *id, స్థిరరాశి అక్షరం *user,
    స్థిరరాశి అక్షరం **hostnamep)
{
	కొలత_t i;
	నిర్మాణం dest_constraint *d;

	ఒకవేళ (hostnamep != ఖాళీ)
		*hostnamep = ఖాళీ;
	కొరకు (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->గమ్యం.user ? d->గమ్యం.user : "", d->గమ్యం.user ? "@" : "",
		    d->గమ్యం.hostname ? d->గమ్యం.hostname : "(ANY)", d->గమ్యం.nkeys);

		/* Match 'from' key */
		ఒకవేళ (fromkey == ఖాళీ) {
			/* We are matching the first hop */
			ఒకవేళ (d->from.hostname != ఖాళీ || d->from.nkeys != 0)
				కొనసాగు;
		} లేకపోతే ఒకవేళ (సరిపోలిక_కీలకం_hop("from", fromkey, &d->from) != 0)
			కొనసాగు;

		/* Match 'to' key */
		ఒకవేళ (tokey != ఖాళీ && సరిపోలిక_కీలకం_hop("to", tokey, &d->గమ్యం) != 0)
			కొనసాగు;

		/* Match user if specified */
		ఒకవేళ (d->గమ్యం.user != ఖాళీ && user != ఖాళీ &&
		    !సరిపోలిక_నమూనా(user, d->గమ్యం.user))
			కొనసాగు;

		/* successfully matched this constraint */
		ఒకవేళ (hostnamep != ఖాళీ)
			*hostnamep = d->గమ్యం.hostname;
		debug2_f("allowed for hostname %s",
		    d->గమ్యం.hostname == ఖాళీ ? "*" : d->గమ్యం.hostname);
		తిరిగి 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->కీలకం), id->comment);
	తిరిగి -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
స్థిర పూర్ణాంకం
తటస్థం_permitted(తటస్థం *id, Socket_నమోదు *e, అక్షరం *user,
    స్థిరరాశి అక్షరం **forward_hostnamep, స్థిరరాశి అక్షరం **చివరి_hostnamep)
{
	కొలత_t i;
	స్థిరరాశి అక్షరం **hp;
	నిర్మాణం hostkey_sid *hks;
	స్థిరరాశి నిర్మాణం sshkey *fromkey = ఖాళీ;
	స్థిరరాశి అక్షరం *test_user;
	అక్షరం *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->కీలకం), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	ఒకవేళ (id->ndest_constraints == 0)
		తిరిగి 0; /* unconstrained */
	ఒకవేళ (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		తిరిగి -1;
	}
	ఒకవేళ (e->nsession_ids == 0)
		తిరిగి 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	కొరకు (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		ఒకవేళ (hks->కీలకం == ఖాళీ)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = ఖాళీ;
		ఒకవేళ (fromkey != ఖాళీ &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("fingerprint failed");
		ఒకవేళ ((fp2 = sshkey_fingerprint(hks->కీలకం, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->కీలకం), fp2);
		విడుదల(fp1);
		విడుదల(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = ఖాళీ;
		ఒకవేళ (i == e->nsession_ids - 1)
			hp = చివరి_hostnamep;
		లేకపోతే ఒకవేళ (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = ఖాళీ;
		ఒకవేళ (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			ఒకవేళ (hks->forwarded && user != ఖాళీ) {
				error_f("tried to sign on forwarding hop");
				తిరిగి -1;
			}
		} లేకపోతే ఒకవేళ (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			తిరిగి -1;
		}
		ఒకవేళ (permitted_by_dest_constraints(fromkey, hks->కీలకం, id,
		    test_user, hp) != 0)
			తిరిగి -1;
		fromkey = hks->కీలకం;
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
	ఒకవేళ (hks->forwarded && user == ఖాళీ &&
	    permitted_by_dest_constraints(hks->కీలకం, ఖాళీ, id,
	    ఖాళీ, ఖాళీ) != 0) {
		debug3_f("key permitted at host but not after");
		తిరిగి -1;
	}

	/* success */
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
socket_is_remote(Socket_నమోదు *e)
{
	తిరిగి e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
స్థిర తటస్థం *
lookup_తటస్థం(నిర్మాణం sshkey *కీలకం)
{
	తటస్థం *id;

	TAILQ_FOREACH(id, &idtab->idlist, తదుపరి) {
		ఒకవేళ (sshkey_equal(కీలకం, id->కీలకం))
			తిరిగి (id);
	}
	తిరిగి (ఖాళీ);
}

/* Check confirmation of keysign request */
స్థిర పూర్ణాంకం
confirm_కీలకం(తటస్థం *id, స్థిరరాశి అక్షరం *extra)
{
	అక్షరం *p;
	పూర్ణాంకం ret = -1;

	p = sshkey_fingerprint(id->కీలకం, fingerprint_hash, SSH_FP_DEFAULT);
	ఒకవేళ (p != ఖాళీ &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == ఖాళీ ? "" : "\n", extra == ఖాళీ ? "" : extra))
		ret = 0;
	విడుదల(p);

	తిరిగి (ret);
}

స్థిర శూన్య
send_స్థితి_generic(Socket_నమోదు *e, u_int సంకేతం_2)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, సంకేతం_2)) != 0)
		fatal_fr(r, "compose");
}

స్థిర శూన్య
send_స్థితి(Socket_నమోదు *e, పూర్ణాంకం success)
{
	send_స్థితి_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
స్థిర శూన్య
process_request_identities(Socket_నమోదు *e)
{
	తటస్థం *id;
	నిర్మాణం sshbuf *సందేశం, *కీలకాలు;
	పూర్ణాంకం r;
	u_int i = 0, nentries = 0;
	అక్షరం *fp;

	debug2_f("entering");

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ || (కీలకాలు = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, తదుపరి) {
		ఒకవేళ ((fp = sshkey_fingerprint(id->కీలకం, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->కీలకం), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		విడుదల(fp);
		/* identity not visible, don't include in response */
		ఒకవేళ (తటస్థం_permitted(id, e, ఖాళీ, ఖాళీ, ఖాళీ) != 0)
			కొనసాగు;
		ఒకవేళ ((r = sshkey_puts(id->కీలకం, కీలకాలు)) != 0 ||
		    (r = sshbuf_put_cstring(కీలకాలు, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			కొనసాగు;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, nentries)) != 0 ||
	    (r = sshbuf_putb(సందేశం, కీలకాలు)) != 0)
		fatal_fr(r, "compose");
	ఒకవేళ ((r = sshbuf_put_stringb(e->output, సందేశం)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(సందేశం);
	sshbuf_free(కీలకాలు);
}


స్థిర అక్షరం *
agent_decode_alg(నిర్మాణం sshkey *కీలకం, u_int flags)
{
	ఒకవేళ (కీలకం->type == కీలకం_RSA) {
		ఒకవేళ (flags & SSH_AGENT_RSA_SHA2_256)
			తిరిగి "rsa-sha2-256";
		లేకపోతే ఒకవేళ (flags & SSH_AGENT_RSA_SHA2_512)
			తిరిగి "rsa-sha2-512";
	} లేకపోతే ఒకవేళ (కీలకం->type == కీలకం_RSA_CERT) {
		ఒకవేళ (flags & SSH_AGENT_RSA_SHA2_256)
			తిరిగి "rsa-sha2-256-cert-v01@openssh.com";
		లేకపోతే ఒకవేళ (flags & SSH_AGENT_RSA_SHA2_512)
			తిరిగి "rsa-sha2-512-cert-v01@openssh.com";
	}
	తిరిగి ఖాళీ;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
స్థిర పూర్ణాంకం
parse_userauth_request(నిర్మాణం sshbuf *సందేశం, స్థిరరాశి నిర్మాణం sshkey *expected_కీలకం,
    అక్షరం **userp, నిర్మాణం sshbuf **sess_idp, నిర్మాణం sshkey **hostkeyp)
{
	నిర్మాణం sshbuf *b = ఖాళీ, *sess_id = ఖాళీ;
	అక్షరం *user = ఖాళీ, *service = ఖాళీ, *పద్ధతి = ఖాళీ, *pkalg = ఖాళీ;
	పూర్ణాంకం r;
	u_char t, sig_follows;
	నిర్మాణం sshkey *mkey = ఖాళీ, *hostkey = ఖాళీ;

	ఒకవేళ (userp != ఖాళీ)
		*userp = ఖాళీ;
	ఒకవేళ (sess_idp != ఖాళీ)
		*sess_idp = ఖాళీ;
	ఒకవేళ (hostkeyp != ఖాళీ)
		*hostkeyp = ఖాళీ;
	ఒకవేళ ((b = sshbuf_fromb(సందేశం)) == ఖాళీ)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	ఒకవేళ ((r = sshbuf_froms(b, &sess_id)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, ఖాళీ)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, ఖాళీ)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &పద్ధతి, ఖాళీ)) != 0 || /*పద్ధతి*/
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, ఖాళీ)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*కీలకం*/
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (t != SSH2_సందేశం_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_కీలకం, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_కీలకం->type) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (strcmp(పద్ధతి, "publickey-hostbound-v00@openssh.com") == 0) {
		ఒకవేళ ((r = sshkey_froms(b, &hostkey)) != 0)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ (strcmp(పద్ధతి, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	ఒకవేళ (userp != ఖాళీ) {
		*userp = user;
		user = ఖాళీ;
	}
	ఒకవేళ (sess_idp != ఖాళీ) {
		*sess_idp = sess_id;
		sess_id = ఖాళీ;
	}
	ఒకవేళ (hostkeyp != ఖాళీ) {
		*hostkeyp = hostkey;
		hostkey = ఖాళీ;
	}
 బహిర్గతం:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	విడుదల(user);
	విడుదల(service);
	విడుదల(పద్ధతి);
	విడుదల(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	తిరిగి r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
స్థిర పూర్ణాంకం
parse_sshsig_request(నిర్మాణం sshbuf *సందేశం)
{
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *b;

	ఒకవేళ ((b = sshbuf_fromb(సందేశం)) == ఖాళీ)
		fatal_f("sshbuf_fromb");

	ఒకవేళ ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, ఖాళీ, ఖాళీ)) != 0 || /* namespace */
	    (r = sshbuf_get_string_ప్రత్యక్ష(b, ఖాళీ, ఖాళీ)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, ఖాళీ, ఖాళీ)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_ప్రత్యక్ష(b, ఖాళీ, ఖాళీ)) != 0) /* H(msg) */
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
స్థిర పూర్ణాంకం
check_websafe_సందేశం_contents(నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *దత్తాంశం)
{
	ఒకవేళ (parse_userauth_request(దత్తాంశం, కీలకం, ఖాళీ, ఖాళీ, ఖాళీ) == 0) {
		debug_f("signed data matches public key userauth request");
		తిరిగి 1;
	}
	ఒకవేళ (parse_sshsig_request(దత్తాంశం) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		తిరిగి 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
buf_equal(స్థిరరాశి నిర్మాణం sshbuf *a, స్థిరరాశి నిర్మాణం sshbuf *b)
{
	ఒకవేళ (sshbuf_ptr(a) == ఖాళీ || sshbuf_ptr(b) == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (sshbuf_len(a) != sshbuf_len(b))
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	తిరిగి 0;
}

/* ssh2 only */
స్థిర శూన్య
process_sign_request2(Socket_నమోదు *e)
{
	u_char *signature = ఖాళీ;
	కొలత_t slen = 0;
	u_int compat = 0, flags;
	పూర్ణాంకం r, ok = -1, retried = 0;
	అక్షరం *fp = ఖాళీ, *pin = ఖాళీ, *prompt = ఖాళీ;
	అక్షరం *user = ఖాళీ, *sig_dest = ఖాళీ;
	స్థిరరాశి అక్షరం *fwd_host = ఖాళీ, *dest_host = ఖాళీ;
	నిర్మాణం sshbuf *సందేశం = ఖాళీ, *దత్తాంశం = ఖాళీ, *sid = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ, *hostkey = ఖాళీ;
	నిర్మాణం తటస్థం_2 *id;
	నిర్మాణం notifier_ctx *notifier = ఖాళీ;

	debug_f("entering");

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ || (దత్తాంశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_froms(e->request, &కీలకం)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, దత్తాంశం)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		వెళ్ళు send;
	}

	ఒకవేళ ((id = lookup_తటస్థం(కీలకం)) == ఖాళీ) {
		verbose_f("%s key not found", sshkey_type(కీలకం));
		వెళ్ళు send;
	}
	ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ఖాళీ)
		fatal_f("fingerprint failed");

	ఒకవేళ (id->ndest_constraints != 0) {
		ఒకవేళ (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			వెళ్ళు send;
		}
		ఒకవేళ (parse_userauth_request(దత్తాంశం, కీలకం, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			వెళ్ళు send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		ఒకవేళ (తటస్థం_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			వెళ్ళు send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		ఒకవేళ (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->కీలకం), fp);
			వెళ్ళు send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		ఒకవేళ (e->nsession_ids > 1 && hostkey == ఖాళీ) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			వెళ్ళు send;
		}
		ఒకవేళ (hostkey != ఖాళీ && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].కీలకం)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			వెళ్ళు send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	ఒకవేళ (id->confirm && confirm_కీలకం(id, sig_dest) != 0) {
		verbose_f("user refused key");
		వెళ్ళు send;
	}
	ఒకవేళ (sshkey_is_sk(id->కీలకం)) {
		ఒకవేళ (restrict_websafe &&
		    సరిపోలిక_నమూనా_list(id->కీలకం->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_సందేశం_contents(కీలకం, దత్తాంశం)) {
			/* error already logged */
			వెళ్ళు send;
		}
		ఒకవేళ (id->కీలకం->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_ప్రారంభం(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->కీలకం), fp,
			    sig_dest == ఖాళీ ? "" : "\n",
			    sig_dest == ఖాళీ ? "" : sig_dest);
		}
	}
 retry_pin:
	ఒకవేళ ((r = sshkey_sign(id->కీలకం, &signature, &slen,
	    sshbuf_ptr(దత్తాంశం), sshbuf_len(దత్తాంశం), agent_decode_alg(కీలకం, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ఒకవేళ (pin == ఖాళీ && !retried && sshkey_is_sk(id->కీలకం) &&
		    r == SSH_ERR_కీలకం_WRONG_PASSPHRASE) {
			notify_complete(notifier, ఖాళీ);
			notifier = ఖాళీ;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->కీలకం->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->కీలకం), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			వెళ్ళు retry_pin;
		}
		error_fr(r, "sshkey_sign");
		వెళ్ళు send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	ఒకవేళ (ok == 0) {
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(సందేశం, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} లేకపోతే ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	ఒకవేళ ((r = sshbuf_put_stringb(e->output, సందేశం)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(దత్తాంశం);
	sshbuf_free(సందేశం);
	sshkey_free(కీలకం);
	sshkey_free(hostkey);
	విడుదల(fp);
	విడుదల(signature);
	విడుదల(sig_dest);
	విడుదల(user);
	విడుదల(prompt);
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));
}

/* shared */
స్థిర శూన్య
process_remove_తటస్థం(Socket_నమోదు *e)
{
	పూర్ణాంకం r, success = 0;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	తటస్థం *id;

	debug2_f("entering");
	ఒకవేళ ((r = sshkey_froms(e->request, &కీలకం)) != 0) {
		error_fr(r, "parse key");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((id = lookup_తటస్థం(కీలకం)) == ఖాళీ) {
		debug_f("key not found");
		వెళ్ళు పూర్తి;
	}
	/* identity not visible, cannot be removed */
	ఒకవేళ (తటస్థం_permitted(id, e, ఖాళీ, ఖాళీ, ఖాళీ) != 0)
		వెళ్ళు పూర్తి; /* error already logged */
	/* We have this key, free it. */
	ఒకవేళ (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, తదుపరి);
	free_తటస్థం(id);
	idtab->nentries--;
	success = 1;
 పూర్తి:
	sshkey_free(కీలకం);
	send_స్థితి(e, success);
}

స్థిర శూన్య
remove_all_identities(శూన్య)
{
	తటస్థం *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	కొరకు (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, తదుపరి);
		free_తటస్థం(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

స్థిర శూన్య
process_remove_all_identities(Socket_నమోదు *e)
{
	remove_all_identities();

	/* Send success. */
	send_స్థితి(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
స్థిర time_t
reaper(శూన్య)
{
	time_t deadline = 0, now = monotime();
	తటస్థం *id, *nxt;

	కొరకు (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, తదుపరి);
		ఒకవేళ (id->death == 0)
			కొనసాగు;
		ఒకవేళ (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, తదుపరి);
			free_తటస్థం(id);
			idtab->nentries--;
		} లేకపోతే
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	ఒకవేళ (deadline == 0 || deadline <= now)
		తిరిగి 0;
	లేకపోతే
		తిరిగి (deadline - now);
}

స్థిర పూర్ణాంకం
parse_dest_constraint_hop(నిర్మాణం sshbuf *b, నిర్మాణం dest_constraint_hop *dch)
{
	u_char కీలకం_is_ca;
	కొలత_t elen = 0, userlen = 0;
	పూర్ణాంకం r;
	నిర్మాణం sshkey *k = ఖాళీ;
	అక్షరం *fp;

	memset(dch, '\0', పరిమాణం(*dch));
	ఒకవేళ ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(b, ఖాళీ, &elen)) != 0) {
		error_fr(r, "parse");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (*dch->hostname == '\0') {
		విడుదల(dch->hostname);
		dch->hostname = ఖాళీ;
	}
	ఒకవేళ (*dch->user == '\0') {
		విడుదల(dch->user);
		dch->user = ఖాళీ;
	} లేకపోతే ఒకవేళ (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	అయితే (sshbuf_len(b) != 0) {
		dch->కీలకాలు = xrecallocarray(dch->కీలకాలు, dch->nkeys,
		    dch->nkeys + 1, పరిమాణం(*dch->కీలకాలు));
		dch->కీలకం_is_ca = xrecallocarray(dch->కీలకం_is_ca, dch->nkeys,
		    dch->nkeys + 1, పరిమాణం(*dch->కీలకం_is_ca));
		ఒకవేళ ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &కీలకం_is_ca)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == ఖాళీ ? "" : dch->user,
		    dch->user == ఖాళీ ? "" : "@",
		    dch->hostname, కీలకం_is_ca ? "CA " : "", sshkey_type(k), fp);
		విడుదల(fp);
		dch->కీలకాలు[dch->nkeys] = k;
		dch->కీలకం_is_ca[dch->nkeys] = కీలకం_is_ca != 0;
		dch->nkeys++;
		k = ఖాళీ; /* transferred */
	}
	/* success */
	r = 0;
 బహిర్గతం:
	sshkey_free(k);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
parse_dest_constraint(నిర్మాణం sshbuf *m, నిర్మాణం dest_constraint *dc)
{
	నిర్మాణం sshbuf *b = ఖాళీ, *frombuf = ఖాళీ, *tobuf = ఖాళీ;
	పూర్ణాంకం r;
	కొలత_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', పరిమాణం(*dc));
	ఒకవేళ ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(b, ఖాళీ, &elen)) != 0) {
		error_fr(r, "parse");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->గమ్యం)) != 0)
		వెళ్ళు బహిర్గతం; /* already logged */
	ఒకవేళ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->గమ్యం.user ? dc->గమ్యం.user : "", dc->గమ్యం.user ? "@" : "",
	    dc->గమ్యం.hostname ? dc->గమ్యం.hostname : "(ANY)", dc->గమ్యం.nkeys);
	/* check consistency */
	ఒకవేళ ((dc->from.hostname == ఖాళీ) != (dc->from.nkeys == 0) ||
	    dc->from.user != ఖాళీ) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (dc->గమ్యం.hostname == ఖాళీ || dc->గమ్యం.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
parse_కీలకం_constraint_extension(నిర్మాణం sshbuf *m, అక్షరం **sk_providerp,
    నిర్మాణం dest_constraint **dcsp, కొలత_t *ndcsp, పూర్ణాంకం *cert_onlyp,
    నిర్మాణం sshkey ***certs, కొలత_t *ncerts)
{
	అక్షరం *ext_name = ఖాళీ;
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *b = ఖాళీ;
	u_char v;
	నిర్మాణం sshkey *k;

	ఒకవేళ ((r = sshbuf_get_cstring(m, &ext_name, ఖాళీ)) != 0) {
		error_fr(r, "parse constraint extension");
		వెళ్ళు బహిర్గతం;
	}
	debug_f("constraint ext %s", ext_name);
	ఒకవేళ (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		ఒకవేళ (sk_providerp == ఖాళీ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*sk_providerp != ఖాళీ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_get_cstring(m, sk_providerp, ఖాళీ)) != 0) {
			error_fr(r, "parse %s", ext_name);
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే ఒకవేళ (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		ఒకవేళ (*dcsp != ఖాళీ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			వెళ్ళు బహిర్గతం;
		}
		అయితే (sshbuf_len(b) != 0) {
			ఒకవేళ (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				వెళ్ళు బహిర్గతం;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    పరిమాణం(**dcsp));
			ఒకవేళ ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				వెళ్ళు బహిర్గతం; /* error already logged */
		}
	} లేకపోతే ఒకవేళ (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		ఒకవేళ (certs == ఖాళీ || ncerts == ఖాళీ || cert_onlyp == ఖాళీ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*certs != ఖాళీ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			వెళ్ళు బహిర్గతం;
		}
		*cert_onlyp = v != 0;
		అయితే (sshbuf_len(b) != 0) {
			ఒకవేళ (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				వెళ్ళు బహిర్గతం;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    పరిమాణం(**certs));
			ఒకవేళ ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				వెళ్ళు బహిర్గతం;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} లేకపోతే {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	విడుదల(ext_name);
	sshbuf_free(b);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
parse_కీలకం_constraints(నిర్మాణం sshbuf *m, నిర్మాణం sshkey *k, time_t *deathp,
    u_int *secondsp, పూర్ణాంకం *confirmp, అక్షరం **sk_providerp,
    నిర్మాణం dest_constraint **dcsp, కొలత_t *ndcsp,
    పూర్ణాంకం *cert_onlyp, కొలత_t *ncerts, నిర్మాణం sshkey ***certs)
{
	u_char ctype;
	పూర్ణాంకం r;
	u_int seconds;

	అయితే (sshbuf_len(m)) {
		ఒకవేళ ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			వెళ్ళు బహిర్గతం;
		}
		ఎంపిక (ctype) {
		స్థితి SSH_AGENT_CONSTRAIN_LIFETIME:
			ఒకవేళ (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				వెళ్ళు బహిర్గతం;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			ఆపు;
		స్థితి SSH_AGENT_CONSTRAIN_CONFIRM:
			ఒకవేళ (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				వెళ్ళు బహిర్గతం;
			}
			*confirmp = 1;
			ఆపు;
		స్థితి SSH_AGENT_CONSTRAIN_EXTENSION:
			ఒకవేళ ((r = parse_కీలకం_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				వెళ్ళు బహిర్గతం; /* error already logged */
			ఆపు;
		అప్రమేయ:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			వెళ్ళు బహిర్గతం;
		}
	}
	/* success */
	r = 0;
 బహిర్గతం:
	తిరిగి r;
}

స్థిర శూన్య
process_కూడు_తటస్థం(Socket_నమోదు *e)
{
	తటస్థం *id;
	పూర్ణాంకం success = 0, confirm = 0;
	అక్షరం *fp, *comment = ఖాళీ, *sk_provider = ఖాళీ;
	అక్షరం canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	నిర్మాణం dest_constraint *dest_constraints = ఖాళీ;
	కొలత_t ndest_constraints = 0;
	నిర్మాణం sshkey *k = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	debug2_f("entering");
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_deserialize(e->request, &k)) != 0 ||
	    k == ఖాళీ ||
	    (r = sshbuf_get_cstring(e->request, &comment, ఖాళీ)) != 0) {
		error_fr(r, "parse");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (parse_కీలకం_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    ఖాళీ, ఖాళీ, ఖాళీ) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		వెళ్ళు బహిర్గతం;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	ఒకవేళ (sk_provider != ఖాళీ) {
		ఒకవేళ (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} లేకపోతే {
			ఒకవేళ (socket_is_remote(e) && !remote_కూడు_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (realpath(sk_provider, canonical_provider) == ఖాళీ) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				వెళ్ళు బహిర్గతం;
			}
			విడుదల(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			ఒకవేళ (సరిపోలిక_నమూనా_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				వెళ్ళు బహిర్గతం;
			}
		}
	}
	ఒకవేళ ((r = sshkey_shield_వ్యక్తిగత(k)) != 0) {
		error_fr(r, "shield private");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (lifetime && !death)
		death = monotime() + lifetime;
	ఒకవేళ ((id = lookup_తటస్థం(k)) == ఖాళీ) {
		id = xcalloc(1, పరిమాణం(తటస్థం));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, తదుపరి);
		/* Increment the number of identities. */
		idtab->nentries++;
	} లేకపోతే {
		/* identity not visible, do not update */
		ఒకవేళ (తటస్థం_permitted(id, e, ఖాళీ, ఖాళీ, ఖాళీ) != 0)
			వెళ్ళు బహిర్గతం; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->కీలకం);
		విడుదల(id->comment);
		విడుదల(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->కీలకం = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	ఒకవేళ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ఖాళీ)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == ఖాళీ ? "none" : sk_provider, ndest_constraints);
	విడుదల(fp);
	/* transferred */
	k = ఖాళీ;
	comment = ఖాళీ;
	sk_provider = ఖాళీ;
	dest_constraints = ఖాళీ;
	ndest_constraints = 0;
	success = 1;
 బహిర్గతం:
	విడుదల(sk_provider);
	విడుదల(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_స్థితి(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
స్థిర శూన్య
process_తాళం_agent(Socket_నమోదు *e, పూర్ణాంకం తాళం)
{
	పూర్ణాంకం r, success = 0, delay;
	అక్షరం *passwd;
	u_char passwdhash[తాళం_కొలత];
	స్థిర u_int fail_లెక్క = 0;
	కొలత_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	ఒకవేళ ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (pwlen == 0) {
		debug("empty password not supported");
	} లేకపోతే ఒకవేళ (locked && !తాళం) {
		ఒకవేళ (bcrypt_pbkdf(passwd, pwlen, తాళం_salt, పరిమాణం(తాళం_salt),
		    passwdhash, పరిమాణం(passwdhash), తాళం_విడతలు) < 0)
			fatal("bcrypt_pbkdf");
		ఒకవేళ (timingsafe_bcmp(passwdhash, తాళం_pwhash, తాళం_కొలత) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_లెక్క = 0;
			explicit_bzero(తాళం_pwhash, పరిమాణం(తాళం_pwhash));
			success = 1;
		} లేకపోతే {
			/* delay in 0.1s increments up to 10s */
			ఒకవేళ (fail_లెక్క < 100)
				fail_లెక్క++;
			delay = 100000 * fail_లెక్క;
			debug("unlock failed, delaying %0.1lf seconds",
			    (ద్విగుణ)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, పరిమాణం(passwdhash));
	} లేకపోతే ఒకవేళ (!locked && తాళం) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(తాళం_salt, పరిమాణం(తాళం_salt));
		ఒకవేళ (bcrypt_pbkdf(passwd, pwlen, తాళం_salt, పరిమాణం(తాళం_salt),
		    తాళం_pwhash, పరిమాణం(తాళం_pwhash), తాళం_విడతలు) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_స్థితి(e, success);
}

స్థిర శూన్య
no_identities(Socket_నమోదు *e)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, సందేశం)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(సందేశం);
}

#నిర్వచితమైతే ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
స్థిర శూన్య
కూడు_p11_తటస్థం(నిర్మాణం sshkey *కీలకం, అక్షరం *comment, స్థిరరాశి అక్షరం *provider,
    time_t death, u_int confirm, నిర్మాణం dest_constraint *dest_constraints,
    కొలత_t ndest_constraints)
{
	తటస్థం *id;

	ఒకవేళ (lookup_తటస్థం(కీలకం) != ఖాళీ) {
		sshkey_free(కీలకం);
		విడుదల(comment);
		తిరిగి;
	}
	id = xcalloc(1, పరిమాణం(తటస్థం));
	id->కీలకం = కీలకం;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, తదుపరి);
	idtab->nentries++;
}

స్థిర శూన్య
process_కూడు_smartcard_కీలకం(Socket_నమోదు *e)
{
	అక్షరం *provider = ఖాళీ, *pin = ఖాళీ, canonical_provider[PATH_MAX];
	అక్షరం **comments = ఖాళీ;
	పూర్ణాంకం r, i, లెక్క = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	నిర్మాణం sshkey **కీలకాలు = ఖాళీ, *k;
	నిర్మాణం dest_constraint *dest_constraints = ఖాళీ;
	కొలత_t j, ndest_constraints = 0, ncerts = 0;
	నిర్మాణం sshkey **certs = ఖాళీ;
	పూర్ణాంకం cert_only = 0;

	debug2_f("entering");
	ఒకవేళ ((r = sshbuf_get_cstring(e->request, &provider, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ఖాళీ)) != 0) {
		error_fr(r, "parse");
		వెళ్ళు send;
	}
	ఒకవేళ (parse_కీలకం_constraints(e->request, ఖాళీ, &death, &seconds, &confirm,
	    ఖాళీ, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		వెళ్ళు send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	ఒకవేళ (socket_is_remote(e) && !remote_కూడు_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		వెళ్ళు send;
	}
	ఒకవేళ (realpath(provider, canonical_provider) == ఖాళీ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		వెళ్ళు send;
	}
	ఒకవేళ (సరిపోలిక_నమూనా_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		వెళ్ళు send;
	}
	debug_f("add %.100s", canonical_provider);
	ఒకవేళ (lifetime && !death)
		death = monotime() + lifetime;

	లెక్క = pkcs11_కూడు_provider(canonical_provider, pin, &కీలకాలు, &comments);
	కొరకు (i = 0; i < లెక్క; i++) {
		ఒకవేళ (comments[i] == ఖాళీ || comments[i][0] == '\0') {
			విడుదల(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		కొరకు (j = 0; j < ncerts; j++) {
			ఒకవేళ (!sshkey_is_cert(certs[j]))
				కొనసాగు;
			ఒకవేళ (!sshkey_equal_ప్రజా(కీలకాలు[i], certs[j]))
				కొనసాగు;
			ఒకవేళ (pkcs11_make_cert(కీలకాలు[i], certs[j], &k) != 0)
				కొనసాగు;
			కూడు_p11_తటస్థం(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		ఒకవేళ (!cert_only && lookup_తటస్థం(కీలకాలు[i]) == ఖాళీ) {
			కూడు_p11_తటస్థం(కీలకాలు[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			కీలకాలు[i] = ఖాళీ;		/* transferred */
			comments[i] = ఖాళీ;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(కీలకాలు[i]);
		విడుదల(comments[i]);
	}
send:
	విడుదల(pin);
	విడుదల(provider);
	విడుదల(కీలకాలు);
	విడుదల(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	కొరకు (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	విడుదల(certs);
	send_స్థితి(e, success);
}

స్థిర శూన్య
process_remove_smartcard_కీలకం(Socket_నమోదు *e)
{
	అక్షరం *provider = ఖాళీ, *pin = ఖాళీ, canonical_provider[PATH_MAX];
	పూర్ణాంకం r, success = 0;
	తటస్థం *id, *nxt;

	debug2_f("entering");
	ఒకవేళ ((r = sshbuf_get_cstring(e->request, &provider, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ఖాళీ)) != 0) {
		error_fr(r, "parse");
		వెళ్ళు send;
	}
	విడుదల(pin);

	ఒకవేళ (realpath(provider, canonical_provider) == ఖాళీ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		వెళ్ళు send;
	}

	debug_f("remove %.100s", canonical_provider);
	కొరకు (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, తదుపరి);
		/* Skip file--based keys */
		ఒకవేళ (id->provider == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, తదుపరి);
			free_తటస్థం(id);
			idtab->nentries--;
		}
	}
	ఒకవేళ (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	లేకపోతే
		error_f("pkcs11_del_provider failed");
send:
	విడుదల(provider);
	send_స్థితి(e, success);
}
#అయితే_ముగింపు /* ENABLE_PKCS11 */

స్థిర పూర్ణాంకం
process_ext_session_bind(Socket_నమోదు *e)
{
	పూర్ణాంకం r, sid_సరిపోలిక, కీలకం_సరిపోలిక;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *sid = ఖాళీ, *sig = ఖాళీ;
	అక్షరం *fp = ఖాళీ;
	కొలత_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	ఒకవేళ ((r = sshkey_froms(e->request, &కీలకం)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ఖాళీ)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	ఒకవేళ ((r = sshkey_verify(కీలకం, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), ఖాళీ, 0, ఖాళీ)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(కీలకం), fp);
		వెళ్ళు బహిర్గతం;
	}
	/* check whether sid/key already recorded */
	కొరకు (i = 0; i < e->nsession_ids; i++) {
		ఒకవేళ (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			వెళ్ళు బహిర్గతం;
		}
		sid_సరిపోలిక = buf_equal(sid, e->session_ids[i].sid) == 0;
		కీలకం_సరిపోలిక = sshkey_equal(కీలకం, e->session_ids[i].కీలకం);
		ఒకవేళ (sid_సరిపోలిక && కీలకం_సరిపోలిక) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(కీలకం), fp);
			r = 0;
			వెళ్ళు బహిర్గతం;
		} లేకపోతే ఒకవేళ (sid_సరిపోలిక) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(కీలకం), fp);
			r = -1;
			వెళ్ళు బహిర్గతం;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	ఒకవేళ (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		వెళ్ళు బహిర్గతం;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, పరిమాణం(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(కీలకం), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].కీలకం = కీలకం;
	e->session_ids[i].forwarded = fwd != 0;
	కీలకం = ఖాళీ; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	ఒకవేళ ((e->session_ids[i].sid = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 బహిర్గతం:
	విడుదల(fp);
	sshkey_free(కీలకం);
	sshbuf_free(sid);
	sshbuf_free(sig);
	తిరిగి r == 0 ? 1 : 0;
}

స్థిర పూర్ణాంకం
process_ext_query(Socket_నమోదు *e)
{
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *సందేశం = ఖాళీ;

	debug2_f("entering");
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(సందేశం, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	ఒకవేళ ((r = sshbuf_put_stringb(e->output, సందేశం)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(సందేశం);
	తిరిగి 1;
}

స్థిర శూన్య
process_extension(Socket_నమోదు *e)
{
	పూర్ణాంకం r, replied = 0, success = 0;
	అక్షరం *name;

	debug2_f("entering");
	ఒకవేళ ((r = sshbuf_get_cstring(e->request, &name, ఖాళీ)) != 0) {
		error_fr(r, "parse");
		send_స్థితి(e, 0);
		తిరిగి;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	ఒకవేళ (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} లేకపోతే ఒకవేళ (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		వెళ్ళు generic_fail;
	} లేకపోతే ఒకవేళ (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} లేకపోతే {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		విడుదల(name);
		send_స్థితి(e, 0);
		తిరిగి;
	}
	విడుదల(name);
	/* Agent failures are signalled with a different error code */
	ఒకవేళ (!replied) {
		send_స్థితి_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
స్థిర పూర్ణాంకం
process_సందేశం(u_int socknum)
{
	u_int సందేశం_len;
	u_char type;
	స్థిరరాశి u_char *cp;
	పూర్ణాంకం r;
	Socket_నమోదు *e;

	ఒకవేళ (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	ఒకవేళ (sshbuf_len(e->ఆదానం) < 5)
		తిరిగి 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->ఆదానం);
	సందేశం_len = PEEK_U32(cp);
	ఒకవేళ (సందేశం_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, సందేశం_len, AGENT_MAX_LEN);
		తిరిగి -1;
	}
	ఒకవేళ (sshbuf_len(e->ఆదానం) < సందేశం_len + 4)
		తిరిగి 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	ఒకవేళ ((r = sshbuf_get_stringb(e->ఆదానం, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		ఒకవేళ (r == SSH_ERR_సందేశం_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			తిరిగి -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	ఒకవేళ (locked && type != SSH_AGENTC_UNLOCK) {
		ఎంపిక (type) {
		స్థితి SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			ఆపు;
		స్థితి SSH_AGENTC_EXTENSION:
			process_extension(e);
			ఆపు;
		అప్రమేయ:
			/* send a fail message for all other request types */
			send_స్థితి(e, 0);
		}
		sshbuf_reset(e->request);
		తిరిగి 1;
	}

	ఎంపిక (type) {
	స్థితి SSH_AGENTC_తాళం:
	స్థితి SSH_AGENTC_UNLOCK:
		process_తాళం_agent(e, type == SSH_AGENTC_తాళం);
		ఆపు;
	స్థితి SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		ఆపు;
	/* ssh2 */
	స్థితి SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		ఆపు;
	స్థితి SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		ఆపు;
	స్థితి SSH2_AGENTC_కూడు_తటస్థం:
	స్థితి SSH2_AGENTC_కూడు_ID_CONSTRAINED:
		process_కూడు_తటస్థం(e);
		ఆపు;
	స్థితి SSH2_AGENTC_REMOVE_తటస్థం:
		process_remove_తటస్థం(e);
		ఆపు;
	స్థితి SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		ఆపు;
#నిర్వచితమైతే ENABLE_PKCS11
	స్థితి SSH_AGENTC_కూడు_SMARTCARD_కీలకం:
	స్థితి SSH_AGENTC_కూడు_SMARTCARD_కీలకం_CONSTRAINED:
		process_కూడు_smartcard_కీలకం(e);
		ఆపు;
	స్థితి SSH_AGENTC_REMOVE_SMARTCARD_కీలకం:
		process_remove_smartcard_కీలకం(e);
		ఆపు;
#అయితే_ముగింపు /* ENABLE_PKCS11 */
	స్థితి SSH_AGENTC_EXTENSION:
		process_extension(e);
		ఆపు;
	అప్రమేయ:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_స్థితి(e, 0);
		ఆపు;
	}
	తిరిగి 1;
}

స్థిర శూన్య
new_socket(sock_type type, పూర్ణాంకం fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	సమితి_nonblock(fd);

	ఒకవేళ (fd > max_fd)
		max_fd = fd;

	కొరకు (i = 0; i < sockets_alloc; i++)
		ఒకవేళ (sockets[i].type == AUTH_వాడని) {
			sockets[i].fd = fd;
			ఒకవేళ ((sockets[i].ఆదానం = sshbuf_new()) == ఖాళీ ||
			    (sockets[i].output = sshbuf_new()) == ఖాళీ ||
			    (sockets[i].request = sshbuf_new()) == ఖాళీ)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			తిరిగి;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    పరిమాణం(sockets[0]));
	కొరకు (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_వాడని;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	ఒకవేళ ((sockets[old_alloc].ఆదానం = sshbuf_new()) == ఖాళీ ||
	    (sockets[old_alloc].output = sshbuf_new()) == ఖాళీ ||
	    (sockets[old_alloc].request = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

స్థిర పూర్ణాంకం
handle_socket_read(u_int socknum)
{
	నిర్మాణం sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	పూర్ణాంకం fd;

	slen = పరిమాణం(sunaddr);
	fd = accept(sockets[socknum].fd, (నిర్మాణం sockaddr *)&sunaddr, &slen);
	ఒకవేళ (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		తిరిగి -1;
	}
	ఒకవేళ ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		తిరిగి -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
handle_conn_read(u_int socknum)
{
	అక్షరం buf[AGENT_RBUF_LEN];
	ssize_t len;
	పూర్ణాంకం r;

	ఒకవేళ ((len = పఠ(sockets[socknum].fd, buf, పరిమాణం(buf))) <= 0) {
		ఒకవేళ (len == -1) {
			ఒకవేళ (errno == EAGAIN || errno == EINTR)
				తిరిగి 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		తిరిగి -1;
	}
	ఒకవేళ ((r = sshbuf_put(sockets[socknum].ఆదానం, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, పరిమాణం(buf));
	కొరకు (;;) {
		ఒకవేళ ((r = process_సందేశం(socknum)) == -1)
			తిరిగి -1;
		లేకపోతే ఒకవేళ (r == 0)
			ఆపు;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
handle_conn_write(u_int socknum)
{
	ssize_t len;
	పూర్ణాంకం r;

	ఒకవేళ (sshbuf_len(sockets[socknum].output) == 0)
		తిరిగి 0; /* shouldn't happen */
	ఒకవేళ ((len = లిఖ(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		ఒకవేళ (len == -1) {
			ఒకవేళ (errno == EAGAIN || errno == EINTR)
				తిరిగి 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		తిరిగి -1;
	}
	ఒకవేళ ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	తిరిగి 0;
}

స్థిర శూన్య
after_poll(నిర్మాణం pollfd *pfd, కొలత_t npfd, u_int maxfds)
{
	కొలత_t i;
	u_int socknum, activefds = npfd;

	కొరకు (i = 0; i < npfd; i++) {
		ఒకవేళ (pfd[i].revents == 0)
			కొనసాగు;
		/* Find sockets entry */
		కొరకు (socknum = 0; socknum < sockets_alloc; socknum++) {
			ఒకవేళ (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				కొనసాగు;
			ఒకవేళ (pfd[i].fd == sockets[socknum].fd)
				ఆపు;
		}
		ఒకవేళ (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			కొనసాగు;
		}
		/* Process events */
		ఎంపిక (sockets[socknum].type) {
		స్థితి AUTH_SOCKET:
			ఒకవేళ ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				ఆపు;
			ఒకవేళ (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				ఆపు;
			}
			ఒకవేళ (handle_socket_read(socknum) == 0)
				activefds++;
			ఆపు;
		స్థితి AUTH_CONNECTION:
			ఒకవేళ ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				వెళ్ళు close_sock;
			ఒకవేళ ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				ఒకవేళ (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				ఆపు;
			}
			ఆపు;
		అప్రమేయ:
			ఆపు;
		}
	}
}

స్థిర పూర్ణాంకం
prepare_poll(నిర్మాణం pollfd **pfdp, కొలత_t *npfdp, నిర్మాణం timespec *timeoutp, u_int maxfds)
{
	నిర్మాణం pollfd *pfd = *pfdp;
	కొలత_t i, j, npfd = 0;
	time_t deadline;
	పూర్ణాంకం r;

	/* Count active sockets */
	కొరకు (i = 0; i < sockets_alloc; i++) {
		ఎంపిక (sockets[i].type) {
		స్థితి AUTH_SOCKET:
		స్థితి AUTH_CONNECTION:
			npfd++;
			ఆపు;
		స్థితి AUTH_వాడని:
			ఆపు;
		అప్రమేయ:
			fatal("Unknown socket type %d", sockets[i].type);
			ఆపు;
		}
	}
	ఒకవేళ (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, పరిమాణం(*pfd))) == ఖాళీ)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	కొరకు (i = j = 0; i < sockets_alloc; i++) {
		ఎంపిక (sockets[i].type) {
		స్థితి AUTH_SOCKET:
			ఒకవేళ (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				ఆపు;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			ఆపు;
		స్థితి AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			ఒకవేళ ((r = sshbuf_check_reserve(sockets[i].ఆదానం,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			లేకపోతే ఒకవేళ (r != SSH_ERR_NO_బఫరు_SPACE)
				fatal_fr(r, "reserve");
			ఒకవేళ (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			ఆపు;
		అప్రమేయ:
			ఆపు;
		}
	}
	deadline = reaper();
	ఒకవేళ (మాతృ_alive_interval != 0)
		deadline = (deadline == 0) ? మాతృ_alive_interval :
		    MINIMUM(deadline, మాతృ_alive_interval);
	ఒకవేళ (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	తిరిగి (1);
}

స్థిర శూన్య
cleanup_socket(శూన్య)
{
	ఒకవేళ (cleanup_pid != 0 && getpid() != cleanup_pid)
		తిరిగి;
	debug_f("cleanup");
	ఒకవేళ (socket_name != ఖాళీ) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		విడుదల(socket_name);
		socket_name = ఖాళీ;
		విడుదల(socket_dir);
		socket_dir = ఖాళీ;
	}
}

శూన్య
cleanup_exit(పూర్ణాంకం i)
{
	cleanup_socket();
#నిర్వచితమైతే ENABLE_PKCS11
	pkcs11_terminate();
#అయితే_ముగింపు
	_exit(i);
}

స్థిర శూన్య
cleanup_handler(పూర్ణాంకం sig)
{
	signalled_exit = sig;
}

స్థిర శూన్య
keydrop_handler(పూర్ణాంకం sig)
{
	signalled_keydrop = sig;
}

స్థిర శూన్య
check_మాతృ_exists(శూన్య)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	ఒకవేళ (మాతృ_pid != -1 && getppid() != మాతృ_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

స్థిర శూన్య
usage(శూన్య)
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
	నిష్క్రమించు(1);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం ac, అక్షరం **av)
{
	పూర్ణాంకం c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	పూర్ణాంకం s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	పూర్ణాంకం sock = -1, ch, ఫలితం, saved_errno;
	pid_t pid;
 	అక్షరం *homedir = ఖాళీ, *shell, *format, *pidstr, *agentsocket = ఖాళీ;
	అక్షరం *cp, pidstrbuf[1 + 3 * పరిమాణం pid];
	అక్షరం *fdstr;
	స్థిరరాశి అక్షరం *errstr = ఖాళీ;
	స్థిరరాశి అక్షరం *ccp;
#నిర్వచితమైతే HAVE_SETRLIMIT
	నిర్మాణం rlimit rlim;
#అయితే_ముగింపు
	బాహ్య పూర్ణాంకం optind;
	బాహ్య అక్షరం *optarg;
	కొలత_t len;
	బహుళకం_t prev_ముసుగు;
	నిర్మాణం timespec timeout;
	నిర్మాణం pollfd *pfd = ఖాళీ;
	కొలత_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	పూర్ణాంకం socket_activated = 0;
	నిర్మాణం passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(శూన్య)setegid(getgid());
	(శూన్య)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	ఒకవేళ ((pw = getpwuid(getuid())) == ఖాళీ)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#నిర్వచితమైతే RLIMIT_NOFILE
	ఒకవేళ (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#అయితే_ముగింపు

	__progname = ssh_get_progname(av[0]);
	విత్తనం_rng();

	అయితే ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ఒకవేళ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ఆపు;
		స్థితి 'c':
			ఒకవేళ (s_flag)
				usage();
			c_flag++;
			ఆపు;
		స్థితి 'k':
			k_flag++;
			ఆపు;
		స్థితి 'O':
			ఒకవేళ (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			లేకపోతే ఒకవేళ (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_కూడు_provider = 1;
			లేకపోతే ఒకవేళ ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != ఖాళీ) {
				ఒకవేళ (websafe_allowlist != ఖాళీ)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} లేకపోతే
				fatal("Unknown -O option");
			ఆపు;
		స్థితి 'P':
			ఒకవేళ (allowed_providers != ఖాళీ)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			ఆపు;
		స్థితి 's':
			ఒకవేళ (c_flag)
				usage();
			s_flag++;
			ఆపు;
		స్థితి 'd':
			ఒకవేళ (d_flag || D_flag)
				usage();
			d_flag++;
			ఆపు;
		స్థితి 'D':
			ఒకవేళ (d_flag || D_flag)
				usage();
			D_flag++;
			ఆపు;
		స్థితి 'a':
			agentsocket = optarg;
			ఆపు;
		స్థితి 'A':
			socket_dirspec = xstrdup(optarg);
			ఆపు;
		స్థితి 't':
			ఒకవేళ ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			ఆపు;
		స్థితి 'T':
			T_flag++;
			ఆపు;
		స్థితి 'u':
			u_flag++;
			ఆపు;
		స్థితి 'U':
			U_flag++;
			ఆపు;
		స్థితి 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_సంస్కరణ, SSH_OPENSSL_సంస్కరణ);
			నిష్క్రమించు(0);
		అప్రమేయ:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	ఒకవేళ (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	ఒకవేళ (((socket_dirspec != ఖాళీ) + (agentsocket != ఖాళీ) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	ఒకవేళ (allowed_providers == ఖాళీ)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	ఒకవేళ (websafe_allowlist == ఖాళీ)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	ఒకవేళ (T_flag)
		socket_dirspec = xstrdup(మార్గం_SSH_AGENT_SOCKET_TMPDIR);
	లేకపోతే ఒకవేళ (socket_dirspec == ఖాళీ && agentsocket == ఖాళీ)
		socket_dirspec = xstrdup(మార్గం_SSH_AGENT_SOCKET_DIR);

	ఒకవేళ (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		ఒకవేళ (shell != ఖాళీ && (len = అక్షరశ్రేణి_పొడవు(shell)) > 2 &&
		    అక్షరశ్రేణి_పోలిక(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	ఒకవేళ (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		ఒకవేళ (pidstr == ఖాళీ) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			నిష్క్రమించు(1);
		}
		pid = (పూర్ణాంకం)strtonum(pidstr, 2, గరిష్ఠ_పూర్ణాంకం, &errstr);
		ఒకవేళ (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			నిష్క్రమించు(1);
		}
		ఒకవేళ (kill(pid, SIGTERM) == -1) {
			perror("kill");
			నిష్క్రమించు(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		రాయి(format, SSH_AUTHSOCKET_ENV_NAME);
		రాయి(format, SSH_AGENTPID_ENV_NAME);
		రాయి("echo Agent pid %ld killed;\n", (దీర్ఘ)pid);
		నిష్క్రమించు(0);
	}
	ఒకవేళ (u_flag) {
		ఒకవేళ ((homedir = get_homedir()) == ఖాళీ)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		రాయి("Deleted stale agent sockets in ~/%s\n",
		    మార్గం_SSH_AGENT_SOCKET_DIR);
		నిష్క్రమించు(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#నిర్వచించు SSH_AGENT_MIN_FDS (3+1+1+1+4)
	ఒకవేళ (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (దీర్ఘ దీర్ఘ)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	మాతృ_pid = getpid();

	/* Has the socket been provided via socket activation? */
	ఒకవేళ (agentsocket == ఖాళీ && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != ఖాళీ &&
	    (fdstr = getenv("LISTEN_FDS")) != ఖాళీ) {
		ఒకవేళ (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		ఒకవేళ (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (పూర్ణాంకం)strtonum(pidstr, 1, గరిష్ఠ_పూర్ణాంకం, &errstr);
		ఒకవేళ (errstr != ఖాళీ)
			fatal("invalid LISTEN_PID: %s", errstr);
		ఒకవేళ (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	ఒకవేళ (sock == -1 && agentsocket == ఖాళీ) {
		/* Listen on a socket in/under a given directory */
		ఒకవేళ ((homedir = get_homedir()) == ఖాళీ)
			fatal("Couldn't determine home directory");
		ఒకవేళ (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		ఒకవేళ (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		విడుదల(homedir);
	} లేకపోతే ఒకవేళ (sock == -1) {
		/* Listen on explicit socket path */
		prev_ముసుగు = umask(0177);
		socket_name = xstrdup(agentsocket);
		ఒకవేళ ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			విడుదల(socket_name);
			socket_name = ఖాళీ; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_ముసుగు);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	ఒకవేళ (sock == -1) {
		prev_ముసుగు = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		ఒకవేళ (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_ముసుగు);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	ఒకవేళ (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		ఒకవేళ (socket_name != ఖాళీ) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			రాయి(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			విడుదల(cp);
			రాయి("echo Agent pid %ld;\n", (దీర్ఘ)మాతృ_pid);
			fflush(stdout);
		}
		వెళ్ళు skip;
	}
	pid = fork();
	ఒకవేళ (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	ఒకవేళ (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, పరిమాణం pidstrbuf, "%ld", (దీర్ఘ)pid);
		ఒకవేళ (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			రాయి(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			రాయి(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			విడుదల(cp);
			రాయి("echo Agent pid %ld;\n", (దీర్ఘ)pid);
			నిష్క్రమించు(0);
		}
		ఒకవేళ (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			నిష్క్రమించు(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		నిష్క్రమించు(1);
	}
	/*బిడ్డ*/
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	ఒకవేళ (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(శూన్య)chdir("/");
	ఒకవేళ (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#నిర్వచితమైతే HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	ఒకవేళ (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#అయితే_ముగింపు

skip:

	cleanup_pid = getpid();

#నిర్వచితమైతే ENABLE_PKCS11
	pkcs11_init(0);
#అయితే_ముగింపు
	new_socket(AUTH_SOCKET, sock);
	ఒకవేళ (ac > 0)
		మాతృ_alive_interval = 10;
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

	ఒకవేళ (socket_name != ఖాళీ && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	ఒకవేళ (socket_dir != ఖాళీ && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	ఒకవేళ (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	ఒకవేళ ((ccp = getenv("SSH_SK_HELPER")) == ఖాళీ || *ccp == '\0')
		ccp = మార్గం_SSH_SK_HELPER;
	ఒకవేళ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ఒకవేళ ((ccp = getenv("SSH_PKCS11_HELPER")) == ఖాళీ || *ccp == '\0')
		ccp = మార్గం_SSH_PKCS11_HELPER;
	ఒకవేళ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ఒకవేళ ((ccp = getenv("SSH_ASKPASS")) == ఖాళీ || *ccp == '\0')
		ccp = మార్గం_SSH_ASKPASS_DEFAULT;
	ఒకవేళ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ఒకవేళ (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	ఒకవేళ (pledge("stdio rpath cpath wpath unix id proc exec", ఖాళీ) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	అయితే (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ఒకవేళ (signalled_exit != 0) {
			logit("exiting on signal %d", (పూర్ణాంకం)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		ఒకవేళ (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (పూర్ణాంకం)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		ఫలితం = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, ఖాళీ);
		saved_errno = errno;
		ఒకవేళ (మాతృ_alive_interval != 0)
			check_మాతృ_exists();
		(శూన్య) reaper();	/* remove expired keys */
		ఒకవేళ (ఫలితం == -1) {
			ఒకవేళ (saved_errno == EINTR)
				కొనసాగు;
			fatal("poll: %s", strerror(saved_errno));
		} లేకపోతే ఒకవేళ (ఫలితం > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
