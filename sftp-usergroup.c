/*
 * Copyright (c) 2022 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* sftp client user/group lookup and caching */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/tree.h>

#અન્તર્ભાવ <glob.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "xmalloc.h"

#અન્તર્ભાવ "sftp-common.h"
#અન્તર્ભાવ "sftp-client.h"
#અન્તર્ભાવ "sftp-usergroup.h"

/* Tree of id, name */
સંરચના idname {
        u_int id;
	અક્ષર *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
સ્થિર પૂર્ણાંક
idname_cmp(સંરચના idname *a, સંરચના idname *b)
{
	જો (a->id == b->id)
		પાછા 0;
	પાછા a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_વૃક્ષ, idname);
RB_GENERATE_STATIC(idname_વૃક્ષ, idname, entry, idname_cmp)

સ્થિર સંરચના idname_વૃક્ષ user_idname = RB_INITIALIZER(&user_idname);
સ્થિર સંરચના idname_વૃક્ષ group_idname = RB_INITIALIZER(&group_idname);

સ્થિર શૂન્ય
idname_free(સંરચના idname *idname)
{
	જો (idname == ખાલી)
		પાછા;
	મુક્ત(idname->name);
	મુક્ત(idname);
}

સ્થિર શૂન્ય
idname_enter(સંરચના idname_વૃક્ષ *વૃક્ષ, u_int id, અચલ અક્ષર *name)
{
	સંરચના idname *idname;

	જો ((idname = xcalloc(1, કદ(*idname))) == ખાલી)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	જો (RB_ઉમેરો(idname_વૃક્ષ, વૃક્ષ, idname) != ખાલી)
		idname_free(idname);
}

સ્થિર અચલ અક્ષર *
idname_lookup(સંરચના idname_વૃક્ષ *વૃક્ષ, u_int id)
{
	સંરચના idname idname, *found;

	memset(&idname, 0, કદ(idname));
	idname.id = id;
	જો ((found = RB_FIND(idname_વૃક્ષ, વૃક્ષ, &idname)) != ખાલી)
		પાછા found->name;
	પાછા ખાલી;
}

સ્થિર શૂન્ય
freenames(અક્ષર **names, u_int nnames)
{
	u_int i;

	જો (names == ખાલી)
		પાછા;
	માટે (i = 0; i < nnames; i++)
		મુક્ત(names[i]);
	મુક્ત(names);
}

સ્થિર શૂન્ય
lookup_and_record(સંરચના sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	પૂર્ણાંક r;
	u_int i;
	અક્ષર **usernames = ખાલી, **groupnames = ખાલી;

	જો ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		પાછા;
	}
	માટે (i = 0; i < nuids; i++) {
		જો (usernames[i] == ખાલી) {
			debug3_f("uid %u not resolved", uids[i]);
			ચાલુ;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	માટે (i = 0; i < ngids; i++) {
		જો (groupnames[i] == ખાલી) {
			debug3_f("gid %u not resolved", gids[i]);
			ચાલુ;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

સ્થિર પૂર્ણાંક
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	જો (nids == 0)
		પાછા 0;

	/* XXX O(N^2) */
	માટે (i = 0; i < nids; i++) {
		જો (ids[i] == id)
			તોડો;
	}
	પાછા i < nids;
}

સ્થિર શૂન્ય
collect_ids_from_glob(glob_t *g, પૂર્ણાંક user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ખાલી;

	માટે (i = 0; g->gl_pathv[i] != ખાલી; i++) {
		જો (g->gl_statv[i] == ખાલી) /* no stat information */
			ચાલુ;
		જો (user) {
			જો (ruser_name(g->gl_statv[i]->st_uid) != ખાલી)
				ચાલુ; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} નહીંતર {
			જો (rgroup_name(g->gl_statv[i]->st_gid) != ખાલી)
				ચાલુ; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		જો (has_id(id, ids, n))
			ચાલુ;
		ids = xrecallocarray(ids, n, n + 1, કદ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

શૂન્ય
get_remote_user_groups_from_glob(સંરચના sftp_conn *conn, glob_t *g)
{
	u_int *uids = ખાલી, nuids = 0, *gids = ખાલી, ngids = 0;

	જો (!sftp_can_get_users_groups_by_id(conn))
		પાછા;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	મુક્ત(uids);
	મુક્ત(gids);
}

સ્થિર શૂન્ય
collect_ids_from_dirents(SFTP_DIRENT **d, પૂર્ણાંક user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ખાલી;

	માટે (i = 0; d[i] != ખાલી; i++) {
		જો (user) {
			જો (ruser_name((uid_t)(d[i]->a.uid)) != ખાલી)
				ચાલુ; /* Already seen */
			id = d[i]->a.uid;
		} નહીંતર {
			જો (rgroup_name((gid_t)(d[i]->a.gid)) != ખાલી)
				ચાલુ; /* Already seen */
			id = d[i]->a.gid;
		}
		જો (has_id(id, ids, n))
			ચાલુ;
		ids = xrecallocarray(ids, n, n + 1, કદ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

શૂન્ય
get_remote_user_groups_from_dirents(સંરચના sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = ખાલી, nuids = 0, *gids = ખાલી, ngids = 0;

	જો (!sftp_can_get_users_groups_by_id(conn))
		પાછા;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	મુક્ત(uids);
	મુક્ત(gids);
}

અચલ અક્ષર *
ruser_name(uid_t uid)
{
	પાછા idname_lookup(&user_idname, (u_int)uid);
}

અચલ અક્ષર *
rgroup_name(uid_t gid)
{
	પાછા idname_lookup(&group_idname, (u_int)gid);
}

