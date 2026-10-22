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

#include "includes.h"

#include <sys/types.h>
#include <sys/tree.h>

#include <glob.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "log.h"
#include "xmalloc.h"

#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-usergroup.h"

/* Tree of id, name */
sa_nracanaa idname {
        u_int id;
	var_na *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
static puur_naa_nka
idname_cmp(sa_nracanaa idname *a, sa_nracanaa idname *b)
{
	ᰀᰧ (a->id == b->id)
		ᰀᰧᰌ 0;
	ᰀᰧᰌ a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_tree, idname);
RB_GENERATE_STATIC(idname_tree, idname, entry, idname_cmp)

static sa_nracanaa idname_tree user_idname = RB_INITIALIZER(&user_idname);
static sa_nracanaa idname_tree group_idname = RB_INITIALIZER(&group_idname);

static void
idname_free(sa_nracanaa idname *idname)
{
	ᰀᰧ (idname == NULL)
		ᰀᰧᰌ;
	free(idname->name);
	free(idname);
}

static void
idname_enter(sa_nracanaa idname_tree *tree, u_int id, const var_na *name)
{
	sa_nracanaa idname *idname;

	ᰀᰧ ((idname = xcalloc(1, parimaa_na(*idname))) == NULL)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	ᰀᰧ (RB_INSERT(idname_tree, tree, idname) != NULL)
		idname_free(idname);
}

static const var_na *
idname_lookup(sa_nracanaa idname_tree *tree, u_int id)
{
	sa_nracanaa idname idname, *found;

	memset(&idname, 0, parimaa_na(idname));
	idname.id = id;
	ᰀᰧ ((found = RB_FIND(idname_tree, tree, &idname)) != NULL)
		ᰀᰧᰌ found->name;
	ᰀᰧᰌ NULL;
}

static void
freenames(var_na **names, u_int nnames)
{
	u_int i;

	ᰀᰧ (names == NULL)
		ᰀᰧᰌ;
	for (i = 0; i < nnames; i++)
		free(names[i]);
	free(names);
}

static void
lookup_and_record(sa_nracanaa sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	puur_naa_nka r;
	u_int i;
	var_na **usernames = NULL, **groupnames = NULL;

	ᰀᰧ ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		ᰀᰧᰌ;
	}
	for (i = 0; i < nuids; i++) {
		ᰀᰧ (usernames[i] == NULL) {
			debug3_f("uid %u not resolved", uids[i]);
			continue;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	for (i = 0; i < ngids; i++) {
		ᰀᰧ (groupnames[i] == NULL) {
			debug3_f("gid %u not resolved", gids[i]);
			continue;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

static puur_naa_nka
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	ᰀᰧ (nids == 0)
		ᰀᰧᰌ 0;

	/* XXX O(N^2) */
	for (i = 0; i < nids; i++) {
		ᰀᰧ (ids[i] == id)
			bha_nga;
	}
	ᰀᰧᰌ i < nids;
}

static void
collect_ids_from_glob(glob_t *g, puur_naa_nka user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = NULL;

	for (i = 0; g->gl_pathv[i] != NULL; i++) {
		ᰀᰧ (g->gl_statv[i] == NULL) /* no stat information */
			continue;
		ᰀᰧ (user) {
			ᰀᰧ (ruser_name(g->gl_statv[i]->st_uid) != NULL)
				continue; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} ᰀᰧᰀ {
			ᰀᰧ (rgroup_name(g->gl_statv[i]->st_gid) != NULL)
				continue; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		ᰀᰧ (has_id(id, ids, n))
			continue;
		ids = xrecallocarray(ids, n, n + 1, parimaa_na(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

void
get_remote_user_groups_from_glob(sa_nracanaa sftp_conn *conn, glob_t *g)
{
	u_int *uids = NULL, nuids = 0, *gids = NULL, ngids = 0;

	ᰀᰧ (!sftp_can_get_users_groups_by_id(conn))
		ᰀᰧᰌ;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	free(uids);
	free(gids);
}

static void
collect_ids_from_dirents(SFTP_DIRENT **d, puur_naa_nka user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = NULL;

	for (i = 0; d[i] != NULL; i++) {
		ᰀᰧ (user) {
			ᰀᰧ (ruser_name((uid_t)(d[i]->a.uid)) != NULL)
				continue; /* Already seen */
			id = d[i]->a.uid;
		} ᰀᰧᰀ {
			ᰀᰧ (rgroup_name((gid_t)(d[i]->a.gid)) != NULL)
				continue; /* Already seen */
			id = d[i]->a.gid;
		}
		ᰀᰧ (has_id(id, ids, n))
			continue;
		ids = xrecallocarray(ids, n, n + 1, parimaa_na(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

void
get_remote_user_groups_from_dirents(sa_nracanaa sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = NULL, nuids = 0, *gids = NULL, ngids = 0;

	ᰀᰧ (!sftp_can_get_users_groups_by_id(conn))
		ᰀᰧᰌ;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	free(uids);
	free(gids);
}

const var_na *
ruser_name(uid_t uid)
{
	ᰀᰧᰌ idname_lookup(&user_idname, (u_int)uid);
}

const var_na *
rgroup_name(uid_t gid)
{
	ᰀᰧᰌ idname_lookup(&group_idname, (u_int)gid);
}

