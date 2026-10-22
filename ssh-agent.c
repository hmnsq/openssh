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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/time.h>
#شامل <sys/queue.h>
#شامل <sys/resource.h>
#شامل <sys/socket.h>
#شامل <sys/stat.h>
#شامل <sys/un.h>
#شامل <sys/wait.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/evp.h>
#شامل "openbsd-compat/openssl-compat.h"
#اگر_ختم

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <paths.h>
#شامل <poll.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <limits.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <util.h>
#شامل <pwd.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "authfd.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "digest.h"
#شامل "ssherr.h"
#شامل "match.h"
#شامل "msg.h"
#شامل "pathnames.h"
#شامل "ssh-pkcs11.h"
#شامل "sk-api.h"
#شامل "myproposal.h"
#شامل "version.h"

#اگر_غیر_تعریف_شدہ DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#اگر_ختم
#اگر_غیر_تعریف_شدہ DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#اگر_ختم

/* Maximum accepted message length */
#تعریف_کرو AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#تعریف_کرو AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#تعریف_کرو AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#تعریف_کرو AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#تعریف_کرو AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#تعریف_کرو AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#تعریف_کرو AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

قسمتعریف شمار {
	AUTH_غیر_مستعمل = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

ساخت hostkey_sid {
	ساخت sshkey *کلید;
	ساخت sshbuf *sid;
	صحیح forwarded;
};

قسمتعریف ساخت socket_اندراج {
	صحیح fd;
	sock_type type;
	ساخت sshbuf *داخلہ;
	ساخت sshbuf *output;
	ساخت sshbuf *request;
	سائز_t nsession_ids;
	ساخت hostkey_sid *session_ids;
	صحیح session_bind_attempted;
} Socket_اندراج;

u_int sockets_alloc = 0;
Socket_اندراج *sockets = تہی;

قسمتعریف ساخت شناختی_عنصر_2 {
	TAILQ_ENTRY(شناختی_عنصر_2) اگلا;
	ساخت sshkey *کلید;
	حرف *comment;
	حرف *provider;
	time_t death;
	u_int confirm;
	حرف *sk_provider;
	ساخت dest_constraint *dest_constraints;
	سائز_t ndest_constraints;
} شناختی_عنصر;

ساخت idtable {
	صحیح nentries;
	TAILQ_HEAD(idqueue, شناختی_عنصر_2) idlist;
};

/* private key table */
ساخت idtable *idtab;

صحیح max_fd = 0;

/* pid of shell == parent of agent */
pid_t والد_pid = -1;
time_t والد_alive_interval = 0;

ساکن sig_atomic_t signalled_exit;
ساکن sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
ساکن حرف *socket_name;
ساکن حرف *socket_dir;
ساکن حرف *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
ساکن حرف *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
ساکن صحیح remote_جوڑو_provider;

/* locking */
#تعریف_کرو تالا_سائز	32
#تعریف_کرو تالا_SALT_سائز	16
#تعریف_کرو تالا_دور	1
صحیح locked = 0;
u_char تالا_pwhash[تالا_سائز];
u_char تالا_salt[تالا_SALT_سائز];

خارجی حرف *__progname;

/* Default lifetime in seconds (0 == forever) */
ساکن صحیح lifetime = 0;

ساکن صحیح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
ساکن صحیح restrict_websafe = 1;
ساکن حرف *websafe_allowlist;

ساکن خالی
close_socket(Socket_اندراج *e)
{
	سائز_t i;

	close(e->fd);
	sshbuf_free(e->داخلہ);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	برائے (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].کلید);
		sshbuf_free(e->session_ids[i].sid);
	}
	آزاد(e->session_ids);
	memset(e, '\0', حجم(*e));
	e->fd = -1;
	e->type = AUTH_غیر_مستعمل;
}

ساکن خالی
idtab_init(خالی)
{
	idtab = xcalloc(1, حجم(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

ساکن خالی
free_dest_constraint_hop(ساخت dest_constraint_hop *dch)
{
	u_int i;

	اگر (dch == تہی)
		واپس;
	آزاد(dch->user);
	آزاد(dch->hostname);
	برائے (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->کلیدیں[i]);
	آزاد(dch->کلیدیں);
	آزاد(dch->کلید_is_ca);
}

ساکن خالی
free_dest_constraints(ساخت dest_constraint *dcs, سائز_t ndcs)
{
	سائز_t i;

	برائے (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].مقصد);
	}
	آزاد(dcs);
}

#اگر_تعریف_شدہ ENABLE_PKCS11
ساکن خالی
dup_dest_constraint_hop(ثابت ساخت dest_constraint_hop *dch,
    ساخت dest_constraint_hop *برآمد)
{
	u_int i;
	صحیح r;

	برآمد->user = dch->user == تہی ? تہی : xstrdup(dch->user);
	برآمد->hostname = dch->hostname == تہی ? تہی : xstrdup(dch->hostname);
	برآمد->is_ca = dch->is_ca;
	برآمد->nkeys = dch->nkeys;
	برآمد->کلیدیں = برآمد->nkeys == 0 ? تہی :
	    xcalloc(برآمد->nkeys, حجم(*برآمد->کلیدیں));
	برآمد->کلید_is_ca = برآمد->nkeys == 0 ? تہی :
	    xcalloc(برآمد->nkeys, حجم(*برآمد->کلید_is_ca));
	برائے (i = 0; i < dch->nkeys; i++) {
		اگر (dch->کلیدیں[i] != تہی &&
		    (r = sshkey_from_نجی(dch->کلیدیں[i],
		    &(برآمد->کلیدیں[i]))) != 0)
			fatal_fr(r, "copy key");
		برآمد->کلید_is_ca[i] = dch->کلید_is_ca[i];
	}
}

ساکن ساخت dest_constraint *
dup_dest_constraints(ثابت ساخت dest_constraint *dcs, سائز_t ndcs)
{
	سائز_t i;
	ساخت dest_constraint *ret;

	اگر (ndcs == 0)
		واپس تہی;
	ret = xcalloc(ndcs, حجم(*ret));
	برائے (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].مقصد, &ret[i].مقصد);
	}
	واپس ret;
}
#اگر_ختم /* ENABLE_PKCS11 */

#اگر_تعریف_شدہ DEBUG_CONSTRAINTS
ساکن خالی
dump_dest_constraint_hop(ثابت ساخت dest_constraint_hop *dch)
{
	u_int i;
	حرف *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == تہی ? "(null)" : dch->user,
	    dch->hostname == تہی ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	برائے (i = 0; i < dch->nkeys; i++) {
		fp = تہی;
		اگر (dch->کلیدیں[i] != تہی &&
		    (fp = sshkey_fingerprint(dch->کلیدیں[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == تہی)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->کلیدیں[i] == تہی ? "" : sshkey_ssh_name(dch->کلیدیں[i]),
		    dch->کلیدیں[i] == تہی ? "" : " ",
		    dch->کلیدیں[i] == تہی ? "none" : fp,
		    dch->کلید_is_ca[i]);
		آزاد(fp);
	}
}
#اگر_ختم /* DEBUG_CONSTRAINTS */

ساکن خالی
dump_dest_constraints(ثابت حرف *context,
    ثابت ساخت dest_constraint *dcs, سائز_t ndcs)
{
#اگر_تعریف_شدہ DEBUG_CONSTRAINTS
	سائز_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	برائے (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].مقصد);
	}
	debug_f("done for %s", context);
#اگر_ختم /* DEBUG_CONSTRAINTS */
}

ساکن خالی
free_شناختی_عنصر(شناختی_عنصر *id)
{
	sshkey_free(id->کلید);
	آزاد(id->provider);
	آزاد(id->comment);
	آزاد(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	آزاد(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
ساکن صحیح
مطابقت_کلید_hop(ثابت حرف *لیبل, ثابت ساخت sshkey *کلید,
    ثابت ساخت dest_constraint_hop *dch)
{
	ثابت حرف *reason = تہی;
	ثابت حرف *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	حرف *fp;

	اگر (کلید == تہی)
		واپس -1;
	/* XXX logspam */
	اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == تہی)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    لیبل, hostname, sshkey_type(کلید), fp, dch->nkeys);
	آزاد(fp);
	برائے (i = 0; i < dch->nkeys; i++) {
		اگر (dch->کلیدیں[i] == تہی)
			واپس -1;
		/* XXX logspam */
		اگر ((fp = sshkey_fingerprint(dch->کلیدیں[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == تہی)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", لیبل, i,
		    dch->کلید_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->کلیدیں[i]), fp);
		آزاد(fp);
		اگر (!sshkey_is_cert(کلید)) {
			/* plain key */
			اگر (dch->کلید_is_ca[i] ||
			    !sshkey_equal(کلید, dch->کلیدیں[i]))
				جاری;
			واپس 0;
		}
		/* certificate */
		اگر (!dch->کلید_is_ca[i])
			جاری;
		اگر (کلید->cert == تہی || کلید->cert->signature_کلید == تہی)
			واپس -1; /* shouldn't happen */
		اگر (!sshkey_equal(کلید->cert->signature_کلید, dch->کلیدیں[i]))
			جاری;
		اگر (sshkey_cert_check_host(کلید, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    کلید->cert->کلید_id, hostname, reason);
			جاری;
		}
		واپس 0;
	}
	واپس -1;
}

/* Check destination constraints on an identity against the hostkey/user */
ساکن صحیح
permitted_by_dest_constraints(ثابت ساخت sshkey *fromkey,
    ثابت ساخت sshkey *tokey, شناختی_عنصر *id, ثابت حرف *user,
    ثابت حرف **hostnamep)
{
	سائز_t i;
	ساخت dest_constraint *d;

	اگر (hostnamep != تہی)
		*hostnamep = تہی;
	برائے (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->مقصد.user ? d->مقصد.user : "", d->مقصد.user ? "@" : "",
		    d->مقصد.hostname ? d->مقصد.hostname : "(ANY)", d->مقصد.nkeys);

		/* Match 'from' key */
		اگر (fromkey == تہی) {
			/* We are matching the first hop */
			اگر (d->from.hostname != تہی || d->from.nkeys != 0)
				جاری;
		} ورنہ اگر (مطابقت_کلید_hop("from", fromkey, &d->from) != 0)
			جاری;

		/* Match 'to' key */
		اگر (tokey != تہی && مطابقت_کلید_hop("to", tokey, &d->مقصد) != 0)
			جاری;

		/* Match user if specified */
		اگر (d->مقصد.user != تہی && user != تہی &&
		    !مطابقت_نمونہ(user, d->مقصد.user))
			جاری;

		/* successfully matched this constraint */
		اگر (hostnamep != تہی)
			*hostnamep = d->مقصد.hostname;
		debug2_f("allowed for hostname %s",
		    d->مقصد.hostname == تہی ? "*" : d->مقصد.hostname);
		واپس 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->کلید), id->comment);
	واپس -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
ساکن صحیح
شناختی_عنصر_permitted(شناختی_عنصر *id, Socket_اندراج *e, حرف *user,
    ثابت حرف **forward_hostnamep, ثابت حرف **آخری_hostnamep)
{
	سائز_t i;
	ثابت حرف **hp;
	ساخت hostkey_sid *hks;
	ثابت ساخت sshkey *fromkey = تہی;
	ثابت حرف *test_user;
	حرف *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->کلید), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	اگر (id->ndest_constraints == 0)
		واپس 0; /* unconstrained */
	اگر (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		واپس -1;
	}
	اگر (e->nsession_ids == 0)
		واپس 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	برائے (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		اگر (hks->کلید == تہی)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = تہی;
		اگر (fromkey != تہی &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == تہی)
			fatal_f("fingerprint failed");
		اگر ((fp2 = sshkey_fingerprint(hks->کلید, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == تہی)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->کلید), fp2);
		آزاد(fp1);
		آزاد(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = تہی;
		اگر (i == e->nsession_ids - 1)
			hp = آخری_hostnamep;
		ورنہ اگر (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = تہی;
		اگر (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			اگر (hks->forwarded && user != تہی) {
				error_f("tried to sign on forwarding hop");
				واپس -1;
			}
		} ورنہ اگر (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			واپس -1;
		}
		اگر (permitted_by_dest_constraints(fromkey, hks->کلید, id,
		    test_user, hp) != 0)
			واپس -1;
		fromkey = hks->کلید;
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
	اگر (hks->forwarded && user == تہی &&
	    permitted_by_dest_constraints(hks->کلید, تہی, id,
	    تہی, تہی) != 0) {
		debug3_f("key permitted at host but not after");
		واپس -1;
	}

	/* success */
	واپس 0;
}

ساکن صحیح
socket_is_remote(Socket_اندراج *e)
{
	واپس e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
ساکن شناختی_عنصر *
lookup_شناختی_عنصر(ساخت sshkey *کلید)
{
	شناختی_عنصر *id;

	TAILQ_FOREACH(id, &idtab->idlist, اگلا) {
		اگر (sshkey_equal(کلید, id->کلید))
			واپس (id);
	}
	واپس (تہی);
}

/* Check confirmation of keysign request */
ساکن صحیح
confirm_کلید(شناختی_عنصر *id, ثابت حرف *extra)
{
	حرف *p;
	صحیح ret = -1;

	p = sshkey_fingerprint(id->کلید, fingerprint_hash, SSH_FP_DEFAULT);
	اگر (p != تہی &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == تہی ? "" : "\n", extra == تہی ? "" : extra))
		ret = 0;
	آزاد(p);

	واپس (ret);
}

ساکن خالی
send_حالت_generic(Socket_اندراج *e, u_int رمز)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, رمز)) != 0)
		fatal_fr(r, "compose");
}

ساکن خالی
send_حالت(Socket_اندراج *e, صحیح success)
{
	send_حالت_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
ساکن خالی
process_request_identities(Socket_اندراج *e)
{
	شناختی_عنصر *id;
	ساخت sshbuf *پیغام, *کلیدیں;
	صحیح r;
	u_int i = 0, nentries = 0;
	حرف *fp;

	debug2_f("entering");

	اگر ((پیغام = sshbuf_new()) == تہی || (کلیدیں = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, اگلا) {
		اگر ((fp = sshkey_fingerprint(id->کلید, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == تہی)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->کلید), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		آزاد(fp);
		/* identity not visible, don't include in response */
		اگر (شناختی_عنصر_permitted(id, e, تہی, تہی, تہی) != 0)
			جاری;
		اگر ((r = sshkey_puts(id->کلید, کلیدیں)) != 0 ||
		    (r = sshbuf_put_cstring(کلیدیں, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			جاری;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, nentries)) != 0 ||
	    (r = sshbuf_putb(پیغام, کلیدیں)) != 0)
		fatal_fr(r, "compose");
	اگر ((r = sshbuf_put_stringb(e->output, پیغام)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(پیغام);
	sshbuf_free(کلیدیں);
}


ساکن حرف *
agent_decode_alg(ساخت sshkey *کلید, u_int flags)
{
	اگر (کلید->type == کلید_RSA) {
		اگر (flags & SSH_AGENT_RSA_SHA2_256)
			واپس "rsa-sha2-256";
		ورنہ اگر (flags & SSH_AGENT_RSA_SHA2_512)
			واپس "rsa-sha2-512";
	} ورنہ اگر (کلید->type == کلید_RSA_CERT) {
		اگر (flags & SSH_AGENT_RSA_SHA2_256)
			واپس "rsa-sha2-256-cert-v01@openssh.com";
		ورنہ اگر (flags & SSH_AGENT_RSA_SHA2_512)
			واپس "rsa-sha2-512-cert-v01@openssh.com";
	}
	واپس تہی;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
ساکن صحیح
parse_userauth_request(ساخت sshbuf *پیغام, ثابت ساخت sshkey *expected_کلید,
    حرف **userp, ساخت sshbuf **sess_idp, ساخت sshkey **hostkeyp)
{
	ساخت sshbuf *b = تہی, *sess_id = تہی;
	حرف *user = تہی, *service = تہی, *طریقہ = تہی, *pkalg = تہی;
	صحیح r;
	u_char t, sig_follows;
	ساخت sshkey *mkey = تہی, *hostkey = تہی;

	اگر (userp != تہی)
		*userp = تہی;
	اگر (sess_idp != تہی)
		*sess_idp = تہی;
	اگر (hostkeyp != تہی)
		*hostkeyp = تہی;
	اگر ((b = sshbuf_fromb(پیغام)) == تہی)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	اگر ((r = sshbuf_froms(b, &sess_id)) != 0)
		جاؤ برآمد;
	اگر (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, تہی)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, تہی)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &طریقہ, تہی)) != 0 || /*طریقہ*/
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, تہی)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*کلید*/
		جاؤ برآمد;
	اگر (t != SSH2_پیغام_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_کلید, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_کلید->type) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (strcmp(طریقہ, "publickey-hostbound-v00@openssh.com") == 0) {
		اگر ((r = sshkey_froms(b, &hostkey)) != 0)
			جاؤ برآمد;
	} ورنہ اگر (strcmp(طریقہ, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	اگر (userp != تہی) {
		*userp = user;
		user = تہی;
	}
	اگر (sess_idp != تہی) {
		*sess_idp = sess_id;
		sess_id = تہی;
	}
	اگر (hostkeyp != تہی) {
		*hostkeyp = hostkey;
		hostkey = تہی;
	}
 برآمد:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	آزاد(user);
	آزاد(service);
	آزاد(طریقہ);
	آزاد(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	واپس r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
ساکن صحیح
parse_sshsig_request(ساخت sshbuf *پیغام)
{
	صحیح r;
	ساخت sshbuf *b;

	اگر ((b = sshbuf_fromb(پیغام)) == تہی)
		fatal_f("sshbuf_fromb");

	اگر ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, تہی, تہی)) != 0 || /* namespace */
	    (r = sshbuf_get_string_براہ_راست(b, تہی, تہی)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, تہی, تہی)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_براہ_راست(b, تہی, تہی)) != 0) /* H(msg) */
		جاؤ برآمد;
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	واپس r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
ساکن صحیح
check_websafe_پیغام_contents(ساخت sshkey *کلید, ساخت sshbuf *ڈیٹا)
{
	اگر (parse_userauth_request(ڈیٹا, کلید, تہی, تہی, تہی) == 0) {
		debug_f("signed data matches public key userauth request");
		واپس 1;
	}
	اگر (parse_sshsig_request(ڈیٹا) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		واپس 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	واپس 0;
}

ساکن صحیح
buf_equal(ثابت ساخت sshbuf *a, ثابت ساخت sshbuf *b)
{
	اگر (sshbuf_ptr(a) == تہی || sshbuf_ptr(b) == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (sshbuf_len(a) != sshbuf_len(b))
		واپس SSH_ERR_INVALID_FORMAT;
	اگر (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		واپس SSH_ERR_INVALID_FORMAT;
	واپس 0;
}

/* ssh2 only */
ساکن خالی
process_sign_request2(Socket_اندراج *e)
{
	u_char *signature = تہی;
	سائز_t slen = 0;
	u_int compat = 0, flags;
	صحیح r, ok = -1, retried = 0;
	حرف *fp = تہی, *pin = تہی, *prompt = تہی;
	حرف *user = تہی, *sig_dest = تہی;
	ثابت حرف *fwd_host = تہی, *dest_host = تہی;
	ساخت sshbuf *پیغام = تہی, *ڈیٹا = تہی, *sid = تہی;
	ساخت sshkey *کلید = تہی, *hostkey = تہی;
	ساخت شناختی_عنصر_2 *id;
	ساخت notifier_ctx *notifier = تہی;

	debug_f("entering");

	اگر ((پیغام = sshbuf_new()) == تہی || (ڈیٹا = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_froms(e->request, &کلید)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, ڈیٹا)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		جاؤ send;
	}

	اگر ((id = lookup_شناختی_عنصر(کلید)) == تہی) {
		verbose_f("%s key not found", sshkey_type(کلید));
		جاؤ send;
	}
	اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == تہی)
		fatal_f("fingerprint failed");

	اگر (id->ndest_constraints != 0) {
		اگر (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			جاؤ send;
		}
		اگر (parse_userauth_request(ڈیٹا, کلید, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			جاؤ send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		اگر (شناختی_عنصر_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			جاؤ send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		اگر (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->کلید), fp);
			جاؤ send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		اگر (e->nsession_ids > 1 && hostkey == تہی) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			جاؤ send;
		}
		اگر (hostkey != تہی && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].کلید)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			جاؤ send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	اگر (id->confirm && confirm_کلید(id, sig_dest) != 0) {
		verbose_f("user refused key");
		جاؤ send;
	}
	اگر (sshkey_is_sk(id->کلید)) {
		اگر (restrict_websafe &&
		    مطابقت_نمونہ_list(id->کلید->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_پیغام_contents(کلید, ڈیٹا)) {
			/* error already logged */
			جاؤ send;
		}
		اگر (id->کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_آغاز(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->کلید), fp,
			    sig_dest == تہی ? "" : "\n",
			    sig_dest == تہی ? "" : sig_dest);
		}
	}
 retry_pin:
	اگر ((r = sshkey_sign(id->کلید, &signature, &slen,
	    sshbuf_ptr(ڈیٹا), sshbuf_len(ڈیٹا), agent_decode_alg(کلید, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		اگر (pin == تہی && !retried && sshkey_is_sk(id->کلید) &&
		    r == SSH_ERR_کلید_WRONG_PASSPHRASE) {
			notify_complete(notifier, تہی);
			notifier = تہی;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->کلید), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			جاؤ retry_pin;
		}
		error_fr(r, "sshkey_sign");
		جاؤ send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	اگر (ok == 0) {
		اگر ((r = sshbuf_put_u8(پیغام, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(پیغام, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} ورنہ اگر ((r = sshbuf_put_u8(پیغام, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	اگر ((r = sshbuf_put_stringb(e->output, پیغام)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(ڈیٹا);
	sshbuf_free(پیغام);
	sshkey_free(کلید);
	sshkey_free(hostkey);
	آزاد(fp);
	آزاد(signature);
	آزاد(sig_dest);
	آزاد(user);
	آزاد(prompt);
	اگر (pin != تہی)
		freezero(pin, لڑی_لمبائی(pin));
}

/* shared */
ساکن خالی
process_remove_شناختی_عنصر(Socket_اندراج *e)
{
	صحیح r, success = 0;
	ساخت sshkey *کلید = تہی;
	شناختی_عنصر *id;

	debug2_f("entering");
	اگر ((r = sshkey_froms(e->request, &کلید)) != 0) {
		error_fr(r, "parse key");
		جاؤ مکمل;
	}
	اگر ((id = lookup_شناختی_عنصر(کلید)) == تہی) {
		debug_f("key not found");
		جاؤ مکمل;
	}
	/* identity not visible, cannot be removed */
	اگر (شناختی_عنصر_permitted(id, e, تہی, تہی, تہی) != 0)
		جاؤ مکمل; /* error already logged */
	/* We have this key, free it. */
	اگر (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, اگلا);
	free_شناختی_عنصر(id);
	idtab->nentries--;
	success = 1;
 مکمل:
	sshkey_free(کلید);
	send_حالت(e, success);
}

ساکن خالی
remove_all_identities(خالی)
{
	شناختی_عنصر *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	برائے (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, اگلا);
		free_شناختی_عنصر(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

ساکن خالی
process_remove_all_identities(Socket_اندراج *e)
{
	remove_all_identities();

	/* Send success. */
	send_حالت(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
ساکن time_t
reaper(خالی)
{
	time_t deadline = 0, now = monotime();
	شناختی_عنصر *id, *nxt;

	برائے (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, اگلا);
		اگر (id->death == 0)
			جاری;
		اگر (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, اگلا);
			free_شناختی_عنصر(id);
			idtab->nentries--;
		} ورنہ
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	اگر (deadline == 0 || deadline <= now)
		واپس 0;
	ورنہ
		واپس (deadline - now);
}

ساکن صحیح
parse_dest_constraint_hop(ساخت sshbuf *b, ساخت dest_constraint_hop *dch)
{
	u_char کلید_is_ca;
	سائز_t elen = 0, userlen = 0;
	صحیح r;
	ساخت sshkey *k = تہی;
	حرف *fp;

	memset(dch, '\0', حجم(*dch));
	اگر ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, تہی)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(b, تہی, &elen)) != 0) {
		error_fr(r, "parse");
		جاؤ برآمد;
	}
	اگر (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		جاؤ برآمد;
	}
	اگر (*dch->hostname == '\0') {
		آزاد(dch->hostname);
		dch->hostname = تہی;
	}
	اگر (*dch->user == '\0') {
		آزاد(dch->user);
		dch->user = تہی;
	} ورنہ اگر (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	جب (sshbuf_len(b) != 0) {
		dch->کلیدیں = xrecallocarray(dch->کلیدیں, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->کلیدیں));
		dch->کلید_is_ca = xrecallocarray(dch->کلید_is_ca, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->کلید_is_ca));
		اگر ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &کلید_is_ca)) != 0)
			جاؤ برآمد;
		اگر ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == تہی)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == تہی ? "" : dch->user,
		    dch->user == تہی ? "" : "@",
		    dch->hostname, کلید_is_ca ? "CA " : "", sshkey_type(k), fp);
		آزاد(fp);
		dch->کلیدیں[dch->nkeys] = k;
		dch->کلید_is_ca[dch->nkeys] = کلید_is_ca != 0;
		dch->nkeys++;
		k = تہی; /* transferred */
	}
	/* success */
	r = 0;
 برآمد:
	sshkey_free(k);
	واپس r;
}

ساکن صحیح
parse_dest_constraint(ساخت sshbuf *m, ساخت dest_constraint *dc)
{
	ساخت sshbuf *b = تہی, *frombuf = تہی, *tobuf = تہی;
	صحیح r;
	سائز_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', حجم(*dc));
	اگر ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(b, تہی, &elen)) != 0) {
		error_fr(r, "parse");
		جاؤ برآمد;
	}
	اگر ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->مقصد)) != 0)
		جاؤ برآمد; /* already logged */
	اگر (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		جاؤ برآمد;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->مقصد.user ? dc->مقصد.user : "", dc->مقصد.user ? "@" : "",
	    dc->مقصد.hostname ? dc->مقصد.hostname : "(ANY)", dc->مقصد.nkeys);
	/* check consistency */
	اگر ((dc->from.hostname == تہی) != (dc->from.nkeys == 0) ||
	    dc->from.user != تہی) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (dc->مقصد.hostname == تہی || dc->مقصد.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	واپس r;
}

ساکن صحیح
parse_کلید_constraint_extension(ساخت sshbuf *m, حرف **sk_providerp,
    ساخت dest_constraint **dcsp, سائز_t *ndcsp, صحیح *cert_onlyp,
    ساخت sshkey ***certs, سائز_t *ncerts)
{
	حرف *ext_name = تہی;
	صحیح r;
	ساخت sshbuf *b = تہی;
	u_char v;
	ساخت sshkey *k;

	اگر ((r = sshbuf_get_cstring(m, &ext_name, تہی)) != 0) {
		error_fr(r, "parse constraint extension");
		جاؤ برآمد;
	}
	debug_f("constraint ext %s", ext_name);
	اگر (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		اگر (sk_providerp == تہی) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر (*sk_providerp != تہی) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_get_cstring(m, sk_providerp, تہی)) != 0) {
			error_fr(r, "parse %s", ext_name);
			جاؤ برآمد;
		}
	} ورنہ اگر (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		اگر (*dcsp != تہی) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			جاؤ برآمد;
		}
		جب (sshbuf_len(b) != 0) {
			اگر (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				جاؤ برآمد;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    حجم(**dcsp));
			اگر ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				جاؤ برآمد; /* error already logged */
		}
	} ورنہ اگر (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		اگر (certs == تہی || ncerts == تہی || cert_onlyp == تہی) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر (*certs != تہی) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			جاؤ برآمد;
		}
		*cert_onlyp = v != 0;
		جب (sshbuf_len(b) != 0) {
			اگر (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				جاؤ برآمد;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    حجم(**certs));
			اگر ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				جاؤ برآمد;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} ورنہ {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	آزاد(ext_name);
	sshbuf_free(b);
	واپس r;
}

ساکن صحیح
parse_کلید_constraints(ساخت sshbuf *m, ساخت sshkey *k, time_t *deathp,
    u_int *secondsp, صحیح *confirmp, حرف **sk_providerp,
    ساخت dest_constraint **dcsp, سائز_t *ndcsp,
    صحیح *cert_onlyp, سائز_t *ncerts, ساخت sshkey ***certs)
{
	u_char ctype;
	صحیح r;
	u_int seconds;

	جب (sshbuf_len(m)) {
		اگر ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			جاؤ برآمد;
		}
		انتخاب (ctype) {
		حالت SSH_AGENT_CONSTRAIN_LIFETIME:
			اگر (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				جاؤ برآمد;
			}
			اگر ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				جاؤ برآمد;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			توڑو;
		حالت SSH_AGENT_CONSTRAIN_CONFIRM:
			اگر (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				جاؤ برآمد;
			}
			*confirmp = 1;
			توڑو;
		حالت SSH_AGENT_CONSTRAIN_EXTENSION:
			اگر ((r = parse_کلید_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				جاؤ برآمد; /* error already logged */
			توڑو;
		طےشدہ:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			جاؤ برآمد;
		}
	}
	/* success */
	r = 0;
 برآمد:
	واپس r;
}

ساکن خالی
process_جوڑو_شناختی_عنصر(Socket_اندراج *e)
{
	شناختی_عنصر *id;
	صحیح success = 0, confirm = 0;
	حرف *fp, *comment = تہی, *sk_provider = تہی;
	حرف canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	ساخت dest_constraint *dest_constraints = تہی;
	سائز_t ndest_constraints = 0;
	ساخت sshkey *k = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	debug2_f("entering");
	اگر ((r = sshkey_نجی_deserialize(e->request, &k)) != 0 ||
	    k == تہی ||
	    (r = sshbuf_get_cstring(e->request, &comment, تہی)) != 0) {
		error_fr(r, "parse");
		جاؤ برآمد;
	}
	اگر (parse_کلید_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    تہی, تہی, تہی) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		جاؤ برآمد;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	اگر (sk_provider != تہی) {
		اگر (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			جاؤ برآمد;
		}
		اگر (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} ورنہ {
			اگر (socket_is_remote(e) && !remote_جوڑو_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				جاؤ برآمد;
			}
			اگر (realpath(sk_provider, canonical_provider) == تہی) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				جاؤ برآمد;
			}
			آزاد(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			اگر (مطابقت_نمونہ_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				جاؤ برآمد;
			}
		}
	}
	اگر ((r = sshkey_shield_نجی(k)) != 0) {
		error_fr(r, "shield private");
		جاؤ برآمد;
	}
	اگر (lifetime && !death)
		death = monotime() + lifetime;
	اگر ((id = lookup_شناختی_عنصر(k)) == تہی) {
		id = xcalloc(1, حجم(شناختی_عنصر));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, اگلا);
		/* Increment the number of identities. */
		idtab->nentries++;
	} ورنہ {
		/* identity not visible, do not update */
		اگر (شناختی_عنصر_permitted(id, e, تہی, تہی, تہی) != 0)
			جاؤ برآمد; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->کلید);
		آزاد(id->comment);
		آزاد(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->کلید = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	اگر ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == تہی)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == تہی ? "none" : sk_provider, ndest_constraints);
	آزاد(fp);
	/* transferred */
	k = تہی;
	comment = تہی;
	sk_provider = تہی;
	dest_constraints = تہی;
	ndest_constraints = 0;
	success = 1;
 برآمد:
	آزاد(sk_provider);
	آزاد(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_حالت(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
ساکن خالی
process_تالا_agent(Socket_اندراج *e, صحیح تالا)
{
	صحیح r, success = 0, delay;
	حرف *passwd;
	u_char passwdhash[تالا_سائز];
	ساکن u_int fail_گنتی = 0;
	سائز_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	اگر ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	اگر (pwlen == 0) {
		debug("empty password not supported");
	} ورنہ اگر (locked && !تالا) {
		اگر (bcrypt_pbkdf(passwd, pwlen, تالا_salt, حجم(تالا_salt),
		    passwdhash, حجم(passwdhash), تالا_دور) < 0)
			fatal("bcrypt_pbkdf");
		اگر (timingsafe_bcmp(passwdhash, تالا_pwhash, تالا_سائز) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_گنتی = 0;
			explicit_bzero(تالا_pwhash, حجم(تالا_pwhash));
			success = 1;
		} ورنہ {
			/* delay in 0.1s increments up to 10s */
			اگر (fail_گنتی < 100)
				fail_گنتی++;
			delay = 100000 * fail_گنتی;
			debug("unlock failed, delaying %0.1lf seconds",
			    (دوہرا)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, حجم(passwdhash));
	} ورنہ اگر (!locked && تالا) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(تالا_salt, حجم(تالا_salt));
		اگر (bcrypt_pbkdf(passwd, pwlen, تالا_salt, حجم(تالا_salt),
		    تالا_pwhash, حجم(تالا_pwhash), تالا_دور) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_حالت(e, success);
}

ساکن خالی
no_identities(Socket_اندراج *e)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, پیغام)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(پیغام);
}

#اگر_تعریف_شدہ ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
ساکن خالی
جوڑو_p11_شناختی_عنصر(ساخت sshkey *کلید, حرف *comment, ثابت حرف *provider,
    time_t death, u_int confirm, ساخت dest_constraint *dest_constraints,
    سائز_t ndest_constraints)
{
	شناختی_عنصر *id;

	اگر (lookup_شناختی_عنصر(کلید) != تہی) {
		sshkey_free(کلید);
		آزاد(comment);
		واپس;
	}
	id = xcalloc(1, حجم(شناختی_عنصر));
	id->کلید = کلید;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, اگلا);
	idtab->nentries++;
}

ساکن خالی
process_جوڑو_smartcard_کلید(Socket_اندراج *e)
{
	حرف *provider = تہی, *pin = تہی, canonical_provider[PATH_MAX];
	حرف **comments = تہی;
	صحیح r, i, گنتی = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	ساخت sshkey **کلیدیں = تہی, *k;
	ساخت dest_constraint *dest_constraints = تہی;
	سائز_t j, ndest_constraints = 0, ncerts = 0;
	ساخت sshkey **certs = تہی;
	صحیح cert_only = 0;

	debug2_f("entering");
	اگر ((r = sshbuf_get_cstring(e->request, &provider, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, تہی)) != 0) {
		error_fr(r, "parse");
		جاؤ send;
	}
	اگر (parse_کلید_constraints(e->request, تہی, &death, &seconds, &confirm,
	    تہی, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		جاؤ send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	اگر (socket_is_remote(e) && !remote_جوڑو_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		جاؤ send;
	}
	اگر (realpath(provider, canonical_provider) == تہی) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		جاؤ send;
	}
	اگر (مطابقت_نمونہ_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		جاؤ send;
	}
	debug_f("add %.100s", canonical_provider);
	اگر (lifetime && !death)
		death = monotime() + lifetime;

	گنتی = pkcs11_جوڑو_provider(canonical_provider, pin, &کلیدیں, &comments);
	برائے (i = 0; i < گنتی; i++) {
		اگر (comments[i] == تہی || comments[i][0] == '\0') {
			آزاد(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		برائے (j = 0; j < ncerts; j++) {
			اگر (!sshkey_is_cert(certs[j]))
				جاری;
			اگر (!sshkey_equal_عوامی(کلیدیں[i], certs[j]))
				جاری;
			اگر (pkcs11_make_cert(کلیدیں[i], certs[j], &k) != 0)
				جاری;
			جوڑو_p11_شناختی_عنصر(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		اگر (!cert_only && lookup_شناختی_عنصر(کلیدیں[i]) == تہی) {
			جوڑو_p11_شناختی_عنصر(کلیدیں[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			کلیدیں[i] = تہی;		/* transferred */
			comments[i] = تہی;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(کلیدیں[i]);
		آزاد(comments[i]);
	}
send:
	آزاد(pin);
	آزاد(provider);
	آزاد(کلیدیں);
	آزاد(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	برائے (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	آزاد(certs);
	send_حالت(e, success);
}

ساکن خالی
process_remove_smartcard_کلید(Socket_اندراج *e)
{
	حرف *provider = تہی, *pin = تہی, canonical_provider[PATH_MAX];
	صحیح r, success = 0;
	شناختی_عنصر *id, *nxt;

	debug2_f("entering");
	اگر ((r = sshbuf_get_cstring(e->request, &provider, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, تہی)) != 0) {
		error_fr(r, "parse");
		جاؤ send;
	}
	آزاد(pin);

	اگر (realpath(provider, canonical_provider) == تہی) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		جاؤ send;
	}

	debug_f("remove %.100s", canonical_provider);
	برائے (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, اگلا);
		/* Skip file--based keys */
		اگر (id->provider == تہی)
			جاری;
		اگر (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, اگلا);
			free_شناختی_عنصر(id);
			idtab->nentries--;
		}
	}
	اگر (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	ورنہ
		error_f("pkcs11_del_provider failed");
send:
	آزاد(provider);
	send_حالت(e, success);
}
#اگر_ختم /* ENABLE_PKCS11 */

ساکن صحیح
process_ext_session_bind(Socket_اندراج *e)
{
	صحیح r, sid_مطابقت, کلید_مطابقت;
	ساخت sshkey *کلید = تہی;
	ساخت sshbuf *sid = تہی, *sig = تہی;
	حرف *fp = تہی;
	سائز_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	اگر ((r = sshkey_froms(e->request, &کلید)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		جاؤ برآمد;
	}
	اگر (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		جاؤ برآمد;
	}
	اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == تہی)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	اگر ((r = sshkey_verify(کلید, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), تہی, 0, تہی)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(کلید), fp);
		جاؤ برآمد;
	}
	/* check whether sid/key already recorded */
	برائے (i = 0; i < e->nsession_ids; i++) {
		اگر (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			جاؤ برآمد;
		}
		sid_مطابقت = buf_equal(sid, e->session_ids[i].sid) == 0;
		کلید_مطابقت = sshkey_equal(کلید, e->session_ids[i].کلید);
		اگر (sid_مطابقت && کلید_مطابقت) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(کلید), fp);
			r = 0;
			جاؤ برآمد;
		} ورنہ اگر (sid_مطابقت) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(کلید), fp);
			r = -1;
			جاؤ برآمد;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	اگر (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		جاؤ برآمد;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, حجم(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(کلید), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].کلید = کلید;
	e->session_ids[i].forwarded = fwd != 0;
	کلید = تہی; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	اگر ((e->session_ids[i].sid = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 برآمد:
	آزاد(fp);
	sshkey_free(کلید);
	sshbuf_free(sid);
	sshbuf_free(sig);
	واپس r == 0 ? 1 : 0;
}

ساکن صحیح
process_ext_query(Socket_اندراج *e)
{
	صحیح r;
	ساخت sshbuf *پیغام = تہی;

	debug2_f("entering");
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(پیغام, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	اگر ((r = sshbuf_put_stringb(e->output, پیغام)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(پیغام);
	واپس 1;
}

ساکن خالی
process_extension(Socket_اندراج *e)
{
	صحیح r, replied = 0, success = 0;
	حرف *name;

	debug2_f("entering");
	اگر ((r = sshbuf_get_cstring(e->request, &name, تہی)) != 0) {
		error_fr(r, "parse");
		send_حالت(e, 0);
		واپس;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	اگر (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} ورنہ اگر (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		جاؤ generic_fail;
	} ورنہ اگر (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} ورنہ {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		آزاد(name);
		send_حالت(e, 0);
		واپس;
	}
	آزاد(name);
	/* Agent failures are signalled with a different error code */
	اگر (!replied) {
		send_حالت_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
ساکن صحیح
process_پیغام(u_int socknum)
{
	u_int پیغام_len;
	u_char type;
	ثابت u_char *cp;
	صحیح r;
	Socket_اندراج *e;

	اگر (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	اگر (sshbuf_len(e->داخلہ) < 5)
		واپس 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->داخلہ);
	پیغام_len = PEEK_U32(cp);
	اگر (پیغام_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, پیغام_len, AGENT_MAX_LEN);
		واپس -1;
	}
	اگر (sshbuf_len(e->داخلہ) < پیغام_len + 4)
		واپس 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	اگر ((r = sshbuf_get_stringb(e->داخلہ, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		اگر (r == SSH_ERR_پیغام_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			واپس -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	اگر (locked && type != SSH_AGENTC_UNLOCK) {
		انتخاب (type) {
		حالت SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			توڑو;
		حالت SSH_AGENTC_EXTENSION:
			process_extension(e);
			توڑو;
		طےشدہ:
			/* send a fail message for all other request types */
			send_حالت(e, 0);
		}
		sshbuf_reset(e->request);
		واپس 1;
	}

	انتخاب (type) {
	حالت SSH_AGENTC_تالا:
	حالت SSH_AGENTC_UNLOCK:
		process_تالا_agent(e, type == SSH_AGENTC_تالا);
		توڑو;
	حالت SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		توڑو;
	/* ssh2 */
	حالت SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		توڑو;
	حالت SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		توڑو;
	حالت SSH2_AGENTC_جوڑو_شناختی_عنصر:
	حالت SSH2_AGENTC_جوڑو_ID_CONSTRAINED:
		process_جوڑو_شناختی_عنصر(e);
		توڑو;
	حالت SSH2_AGENTC_REMOVE_شناختی_عنصر:
		process_remove_شناختی_عنصر(e);
		توڑو;
	حالت SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		توڑو;
#اگر_تعریف_شدہ ENABLE_PKCS11
	حالت SSH_AGENTC_جوڑو_SMARTCARD_کلید:
	حالت SSH_AGENTC_جوڑو_SMARTCARD_کلید_CONSTRAINED:
		process_جوڑو_smartcard_کلید(e);
		توڑو;
	حالت SSH_AGENTC_REMOVE_SMARTCARD_کلید:
		process_remove_smartcard_کلید(e);
		توڑو;
#اگر_ختم /* ENABLE_PKCS11 */
	حالت SSH_AGENTC_EXTENSION:
		process_extension(e);
		توڑو;
	طےشدہ:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_حالت(e, 0);
		توڑو;
	}
	واپس 1;
}

ساکن خالی
new_socket(sock_type type, صحیح fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	سیٹ_nonblock(fd);

	اگر (fd > max_fd)
		max_fd = fd;

	برائے (i = 0; i < sockets_alloc; i++)
		اگر (sockets[i].type == AUTH_غیر_مستعمل) {
			sockets[i].fd = fd;
			اگر ((sockets[i].داخلہ = sshbuf_new()) == تہی ||
			    (sockets[i].output = sshbuf_new()) == تہی ||
			    (sockets[i].request = sshbuf_new()) == تہی)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			واپس;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    حجم(sockets[0]));
	برائے (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_غیر_مستعمل;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	اگر ((sockets[old_alloc].داخلہ = sshbuf_new()) == تہی ||
	    (sockets[old_alloc].output = sshbuf_new()) == تہی ||
	    (sockets[old_alloc].request = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

ساکن صحیح
handle_socket_read(u_int socknum)
{
	ساخت sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	صحیح fd;

	slen = حجم(sunaddr);
	fd = accept(sockets[socknum].fd, (ساخت sockaddr *)&sunaddr, &slen);
	اگر (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		واپس -1;
	}
	اگر (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		واپس -1;
	}
	اگر ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		واپس -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	واپس 0;
}

ساکن صحیح
handle_conn_read(u_int socknum)
{
	حرف buf[AGENT_RBUF_LEN];
	ssize_t len;
	صحیح r;

	اگر ((len = اقرأ(sockets[socknum].fd, buf, حجم(buf))) <= 0) {
		اگر (len == -1) {
			اگر (errno == EAGAIN || errno == EINTR)
				واپس 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		واپس -1;
	}
	اگر ((r = sshbuf_put(sockets[socknum].داخلہ, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, حجم(buf));
	برائے (;;) {
		اگر ((r = process_پیغام(socknum)) == -1)
			واپس -1;
		ورنہ اگر (r == 0)
			توڑو;
	}
	واپس 0;
}

ساکن صحیح
handle_conn_write(u_int socknum)
{
	ssize_t len;
	صحیح r;

	اگر (sshbuf_len(sockets[socknum].output) == 0)
		واپس 0; /* shouldn't happen */
	اگر ((len = اكتب(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		اگر (len == -1) {
			اگر (errno == EAGAIN || errno == EINTR)
				واپس 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		واپس -1;
	}
	اگر ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	واپس 0;
}

ساکن خالی
after_poll(ساخت pollfd *pfd, سائز_t npfd, u_int maxfds)
{
	سائز_t i;
	u_int socknum, activefds = npfd;

	برائے (i = 0; i < npfd; i++) {
		اگر (pfd[i].revents == 0)
			جاری;
		/* Find sockets entry */
		برائے (socknum = 0; socknum < sockets_alloc; socknum++) {
			اگر (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				جاری;
			اگر (pfd[i].fd == sockets[socknum].fd)
				توڑو;
		}
		اگر (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			جاری;
		}
		/* Process events */
		انتخاب (sockets[socknum].type) {
		حالت AUTH_SOCKET:
			اگر ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				توڑو;
			اگر (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				توڑو;
			}
			اگر (handle_socket_read(socknum) == 0)
				activefds++;
			توڑو;
		حالت AUTH_CONNECTION:
			اگر ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				جاؤ close_sock;
			اگر ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				اگر (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				توڑو;
			}
			توڑو;
		طےشدہ:
			توڑو;
		}
	}
}

ساکن صحیح
prepare_poll(ساخت pollfd **pfdp, سائز_t *npfdp, ساخت timespec *timeoutp, u_int maxfds)
{
	ساخت pollfd *pfd = *pfdp;
	سائز_t i, j, npfd = 0;
	time_t deadline;
	صحیح r;

	/* Count active sockets */
	برائے (i = 0; i < sockets_alloc; i++) {
		انتخاب (sockets[i].type) {
		حالت AUTH_SOCKET:
		حالت AUTH_CONNECTION:
			npfd++;
			توڑو;
		حالت AUTH_غیر_مستعمل:
			توڑو;
		طےشدہ:
			fatal("Unknown socket type %d", sockets[i].type);
			توڑو;
		}
	}
	اگر (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, حجم(*pfd))) == تہی)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	برائے (i = j = 0; i < sockets_alloc; i++) {
		انتخاب (sockets[i].type) {
		حالت AUTH_SOCKET:
			اگر (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				توڑو;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			توڑو;
		حالت AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			اگر ((r = sshbuf_check_reserve(sockets[i].داخلہ,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			ورنہ اگر (r != SSH_ERR_NO_بفر_SPACE)
				fatal_fr(r, "reserve");
			اگر (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			توڑو;
		طےشدہ:
			توڑو;
		}
	}
	deadline = reaper();
	اگر (والد_alive_interval != 0)
		deadline = (deadline == 0) ? والد_alive_interval :
		    MINIMUM(deadline, والد_alive_interval);
	اگر (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	واپس (1);
}

ساکن خالی
cleanup_socket(خالی)
{
	اگر (cleanup_pid != 0 && getpid() != cleanup_pid)
		واپس;
	debug_f("cleanup");
	اگر (socket_name != تہی) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		آزاد(socket_name);
		socket_name = تہی;
		آزاد(socket_dir);
		socket_dir = تہی;
	}
}

خالی
cleanup_exit(صحیح i)
{
	cleanup_socket();
#اگر_تعریف_شدہ ENABLE_PKCS11
	pkcs11_terminate();
#اگر_ختم
	_exit(i);
}

ساکن خالی
cleanup_handler(صحیح sig)
{
	signalled_exit = sig;
}

ساکن خالی
keydrop_handler(صحیح sig)
{
	signalled_keydrop = sig;
}

ساکن خالی
check_والد_exists(خالی)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	اگر (والد_pid != -1 && getppid() != والد_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

ساکن خالی
usage(خالی)
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
	باہر_نکلو(1);
}

صحیح
مین(صحیح ac, حرف **av)
{
	صحیح c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	صحیح s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	صحیح sock = -1, ch, نتیجہ, saved_errno;
	pid_t pid;
 	حرف *homedir = تہی, *shell, *format, *pidstr, *agentsocket = تہی;
	حرف *cp, pidstrbuf[1 + 3 * حجم pid];
	حرف *fdstr;
	ثابت حرف *errstr = تہی;
	ثابت حرف *ccp;
#اگر_تعریف_شدہ HAVE_SETRLIMIT
	ساخت rlimit rlim;
#اگر_ختم
	خارجی صحیح optind;
	خارجی حرف *optarg;
	سائز_t len;
	منوال_t پچھلا_نقاب;
	ساخت timespec timeout;
	ساخت pollfd *pfd = تہی;
	سائز_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	صحیح socket_activated = 0;
	ساخت passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(خالی)setegid(getgid());
	(خالی)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	اگر ((pw = getpwuid(getuid())) == تہی)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#اگر_تعریف_شدہ RLIMIT_NOFILE
	اگر (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#اگر_ختم

	__progname = ssh_get_progname(av[0]);
	بیج_rng();

	جب ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		انتخاب (ch) {
		حالت 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			اگر (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			توڑو;
		حالت 'c':
			اگر (s_flag)
				usage();
			c_flag++;
			توڑو;
		حالت 'k':
			k_flag++;
			توڑو;
		حالت 'O':
			اگر (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			ورنہ اگر (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_جوڑو_provider = 1;
			ورنہ اگر ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != تہی) {
				اگر (websafe_allowlist != تہی)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} ورنہ
				fatal("Unknown -O option");
			توڑو;
		حالت 'P':
			اگر (allowed_providers != تہی)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			توڑو;
		حالت 's':
			اگر (c_flag)
				usage();
			s_flag++;
			توڑو;
		حالت 'd':
			اگر (d_flag || D_flag)
				usage();
			d_flag++;
			توڑو;
		حالت 'D':
			اگر (d_flag || D_flag)
				usage();
			D_flag++;
			توڑو;
		حالت 'a':
			agentsocket = optarg;
			توڑو;
		حالت 'A':
			socket_dirspec = xstrdup(optarg);
			توڑو;
		حالت 't':
			اگر ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			توڑو;
		حالت 'T':
			T_flag++;
			توڑو;
		حالت 'u':
			u_flag++;
			توڑو;
		حالت 'U':
			U_flag++;
			توڑو;
		حالت 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_نسخہ, SSH_OPENSSL_نسخہ);
			باہر_نکلو(0);
		طےشدہ:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	اگر (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	اگر (((socket_dirspec != تہی) + (agentsocket != تہی) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	اگر (allowed_providers == تہی)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	اگر (websafe_allowlist == تہی)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	اگر (T_flag)
		socket_dirspec = xstrdup(راستہ_SSH_AGENT_SOCKET_TMPDIR);
	ورنہ اگر (socket_dirspec == تہی && agentsocket == تہی)
		socket_dirspec = xstrdup(راستہ_SSH_AGENT_SOCKET_DIR);

	اگر (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		اگر (shell != تہی && (len = لڑی_لمبائی(shell)) > 2 &&
		    لڑی_موازنہ(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	اگر (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		اگر (pidstr == تہی) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			باہر_نکلو(1);
		}
		pid = (صحیح)strtonum(pidstr, 2, زیادہ_سے_زیادہ_عدد, &errstr);
		اگر (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			باہر_نکلو(1);
		}
		اگر (kill(pid, SIGTERM) == -1) {
			perror("kill");
			باہر_نکلو(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		لکھو(format, SSH_AUTHSOCKET_ENV_NAME);
		لکھو(format, SSH_AGENTPID_ENV_NAME);
		لکھو("echo Agent pid %ld killed;\n", (طویل)pid);
		باہر_نکلو(0);
	}
	اگر (u_flag) {
		اگر ((homedir = get_homedir()) == تہی)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		لکھو("Deleted stale agent sockets in ~/%s\n",
		    راستہ_SSH_AGENT_SOCKET_DIR);
		باہر_نکلو(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#تعریف_کرو SSH_AGENT_MIN_FDS (3+1+1+1+4)
	اگر (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (طویل طویل)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	والد_pid = getpid();

	/* Has the socket been provided via socket activation? */
	اگر (agentsocket == تہی && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != تہی &&
	    (fdstr = getenv("LISTEN_FDS")) != تہی) {
		اگر (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		اگر (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (صحیح)strtonum(pidstr, 1, زیادہ_سے_زیادہ_عدد, &errstr);
		اگر (errstr != تہی)
			fatal("invalid LISTEN_PID: %s", errstr);
		اگر (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	اگر (sock == -1 && agentsocket == تہی) {
		/* Listen on a socket in/under a given directory */
		اگر ((homedir = get_homedir()) == تہی)
			fatal("Couldn't determine home directory");
		اگر (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		اگر (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		آزاد(homedir);
	} ورنہ اگر (sock == -1) {
		/* Listen on explicit socket path */
		پچھلا_نقاب = umask(0177);
		socket_name = xstrdup(agentsocket);
		اگر ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			آزاد(socket_name);
			socket_name = تہی; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(پچھلا_نقاب);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	اگر (sock == -1) {
		پچھلا_نقاب = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		اگر (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(پچھلا_نقاب);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	اگر (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		اگر (socket_name != تہی) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			لکھو(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			آزاد(cp);
			لکھو("echo Agent pid %ld;\n", (طویل)والد_pid);
			fflush(stdout);
		}
		جاؤ skip;
	}
	pid = fork();
	اگر (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	اگر (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, حجم pidstrbuf, "%ld", (طویل)pid);
		اگر (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			لکھو(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			لکھو(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			آزاد(cp);
			لکھو("echo Agent pid %ld;\n", (طویل)pid);
			باہر_نکلو(0);
		}
		اگر (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			باہر_نکلو(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		باہر_نکلو(1);
	}
	/*بچہ*/
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	اگر (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(خالی)chdir("/");
	اگر (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#اگر_تعریف_شدہ HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	اگر (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#اگر_ختم

skip:

	cleanup_pid = getpid();

#اگر_تعریف_شدہ ENABLE_PKCS11
	pkcs11_init(0);
#اگر_ختم
	new_socket(AUTH_SOCKET, sock);
	اگر (ac > 0)
		والد_alive_interval = 10;
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

	اگر (socket_name != تہی && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	اگر (socket_dir != تہی && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	اگر (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	اگر ((ccp = getenv("SSH_SK_HELPER")) == تہی || *ccp == '\0')
		ccp = راستہ_SSH_SK_HELPER;
	اگر (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	اگر ((ccp = getenv("SSH_PKCS11_HELPER")) == تہی || *ccp == '\0')
		ccp = راستہ_SSH_PKCS11_HELPER;
	اگر (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	اگر ((ccp = getenv("SSH_ASKPASS")) == تہی || *ccp == '\0')
		ccp = راستہ_SSH_ASKPASS_DEFAULT;
	اگر (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	اگر (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	اگر (pledge("stdio rpath cpath wpath unix id proc exec", تہی) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	جب (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		اگر (signalled_exit != 0) {
			logit("exiting on signal %d", (صحیح)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		اگر (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (صحیح)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		نتیجہ = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, تہی);
		saved_errno = errno;
		اگر (والد_alive_interval != 0)
			check_والد_exists();
		(خالی) reaper();	/* remove expired keys */
		اگر (نتیجہ == -1) {
			اگر (saved_errno == EINTR)
				جاری;
			fatal("poll: %s", strerror(saved_errno));
		} ورنہ اگر (نتیجہ > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
