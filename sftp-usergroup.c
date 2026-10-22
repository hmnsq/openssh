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
struct idname {
        u_int id;
	char *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
static số_nguyên
idname_cmp(struct idname *a, struct idname *b)
{
	nếu (a->id == b->id)
		trả_về 0;
	trả_về a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_tree, idname);
RB_GENERATE_STATIC(idname_tree, idname, entry, idname_cmp)

static struct idname_tree user_idname = RB_INITIALIZER(&user_idname);
static struct idname_tree group_idname = RB_INITIALIZER(&group_idname);

static void
idname_free(struct idname *idname)
{
	nếu (idname == NULL)
		trả_về;
	free(idname->name);
	free(idname);
}

static void
idname_enter(struct idname_tree *tree, u_int id, const char *name)
{
	struct idname *idname;

	nếu ((idname = xcalloc(1, sizeof(*idname))) == NULL)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	nếu (RB_INSERT(idname_tree, tree, idname) != NULL)
		idname_free(idname);
}

static const char *
idname_lookup(struct idname_tree *tree, u_int id)
{
	struct idname idname, *found;

	memset(&idname, 0, sizeof(idname));
	idname.id = id;
	nếu ((found = RB_FIND(idname_tree, tree, &idname)) != NULL)
		trả_về found->name;
	trả_về NULL;
}

static void
freenames(char **names, u_int nnames)
{
	u_int i;

	nếu (names == NULL)
		trả_về;
	cho (i = 0; i < nnames; i++)
		free(names[i]);
	free(names);
}

static void
lookup_and_record(struct sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	số_nguyên r;
	u_int i;
	char **usernames = NULL, **groupnames = NULL;

	nếu ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		trả_về;
	}
	cho (i = 0; i < nuids; i++) {
		nếu (usernames[i] == NULL) {
			debug3_f("uid %u not resolved", uids[i]);
			continue;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	cho (i = 0; i < ngids; i++) {
		nếu (groupnames[i] == NULL) {
			debug3_f("gid %u not resolved", gids[i]);
			continue;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

static số_nguyên
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	nếu (nids == 0)
		trả_về 0;

	/* XXX O(N^2) */
	cho (i = 0; i < nids; i++) {
		nếu (ids[i] == id)
			break;
	}
	trả_về i < nids;
}

static void
collect_ids_from_glob(glob_t *g, số_nguyên user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = NULL;

	cho (i = 0; g->gl_pathv[i] != NULL; i++) {
		nếu (g->gl_statv[i] == NULL) /* no stat information */
			continue;
		nếu (user) {
			nếu (ruser_name(g->gl_statv[i]->st_uid) != NULL)
				continue; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} không_thì {
			nếu (rgroup_name(g->gl_statv[i]->st_gid) != NULL)
				continue; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		nếu (has_id(id, ids, n))
			continue;
		ids = xrecallocarray(ids, n, n + 1, sizeof(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

void
get_remote_user_groups_from_glob(struct sftp_conn *conn, glob_t *g)
{
	u_int *uids = NULL, nuids = 0, *gids = NULL, ngids = 0;

	nếu (!sftp_can_get_users_groups_by_id(conn))
		trả_về;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	free(uids);
	free(gids);
}

static void
collect_ids_from_dirents(SFTP_DIRENT **d, số_nguyên user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = NULL;

	cho (i = 0; d[i] != NULL; i++) {
		nếu (user) {
			nếu (ruser_name((uid_t)(d[i]->a.uid)) != NULL)
				continue; /* Already seen */
			id = d[i]->a.uid;
		} không_thì {
			nếu (rgroup_name((gid_t)(d[i]->a.gid)) != NULL)
				continue; /* Already seen */
			id = d[i]->a.gid;
		}
		nếu (has_id(id, ids, n))
			continue;
		ids = xrecallocarray(ids, n, n + 1, sizeof(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

void
get_remote_user_groups_from_dirents(struct sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = NULL, nuids = 0, *gids = NULL, ngids = 0;

	nếu (!sftp_can_get_users_groups_by_id(conn))
		trả_về;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	free(uids);
	free(gids);
}

const char *
ruser_name(uid_t uid)
{
	trả_về idname_lookup(&user_idname, (u_int)uid);
}

const char *
rgroup_name(uid_t gid)
{
	trả_về idname_lookup(&group_idname, (u_int)gid);
}

