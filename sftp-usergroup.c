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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/tree.h>

#ضمن <glob.h>
#ضمن <stdlib.h>
#ضمن <stdarg.h>
#ضمن <string.h>

#ضمن "log.h"
#ضمن "xmalloc.h"

#ضمن "sftp-common.h"
#ضمن "sftp-client.h"
#ضمن "sftp-usergroup.h"

/* Tree of id, name */
بنية idname {
        u_int id;
	حرف *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
ساكن صحيح
idname_cmp(بنية idname *a, بنية idname *b)
{
	אם (a->id == b->id)
		החזר 0;
	החזר a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_tree, idname);
RB_GENERATE_STATIC(idname_tree, idname, entry, idname_cmp)

ساكن بنية idname_tree user_idname = RB_INITIALIZER(&user_idname);
ساكن بنية idname_tree group_idname = RB_INITIALIZER(&group_idname);

ساكن فراغ
idname_free(بنية idname *idname)
{
	אם (idname == عدم)
		החזר;
	حرر(idname->name);
	حرر(idname);
}

ساكن فراغ
idname_enter(بنية idname_tree *tree, u_int id, ثابت حرف *name)
{
	بنية idname *idname;

	אם ((idname = xcalloc(1, حجم(*idname))) == عدم)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	אם (RB_INSERT(idname_tree, tree, idname) != عدم)
		idname_free(idname);
}

ساكن ثابت حرف *
idname_lookup(بنية idname_tree *tree, u_int id)
{
	بنية idname idname, *found;

	memset(&idname, 0, حجم(idname));
	idname.id = id;
	אם ((found = RB_FIND(idname_tree, tree, &idname)) != عدم)
		החזר found->name;
	החזר عدم;
}

ساكن فراغ
freenames(حرف **names, u_int nnames)
{
	u_int i;

	אם (names == عدم)
		החזר;
	עבור (i = 0; i < nnames; i++)
		حرر(names[i]);
	حرر(names);
}

ساكن فراغ
lookup_and_record(بنية sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	صحيح r;
	u_int i;
	حرف **usernames = عدم, **groupnames = عدم;

	אם ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		החזר;
	}
	עבור (i = 0; i < nuids; i++) {
		אם (usernames[i] == عدم) {
			debug3_f("uid %u not resolved", uids[i]);
			استمر;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	עבור (i = 0; i < ngids; i++) {
		אם (groupnames[i] == عدم) {
			debug3_f("gid %u not resolved", gids[i]);
			استمر;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

ساكن صحيح
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	אם (nids == 0)
		החזר 0;

	/* XXX O(N^2) */
	עבור (i = 0; i < nids; i++) {
		אם (ids[i] == id)
			اكسر;
	}
	החזר i < nids;
}

ساكن فراغ
collect_ids_from_glob(glob_t *g, صحيح user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = عدم;

	עבור (i = 0; g->gl_pathv[i] != عدم; i++) {
		אם (g->gl_statv[i] == عدم) /* no stat information */
			استمر;
		אם (user) {
			אם (ruser_name(g->gl_statv[i]->st_uid) != عدم)
				استمر; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} אחרת {
			אם (rgroup_name(g->gl_statv[i]->st_gid) != عدم)
				استمر; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		אם (has_id(id, ids, n))
			استمر;
		ids = xrecallocarray(ids, n, n + 1, حجم(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

فراغ
get_remote_user_groups_from_glob(بنية sftp_conn *conn, glob_t *g)
{
	u_int *uids = عدم, nuids = 0, *gids = عدم, ngids = 0;

	אם (!sftp_can_get_users_groups_by_id(conn))
		החזר;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	حرر(uids);
	حرر(gids);
}

ساكن فراغ
collect_ids_from_dirents(SFTP_DIRENT **d, صحيح user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = عدم;

	עבור (i = 0; d[i] != عدم; i++) {
		אם (user) {
			אם (ruser_name((uid_t)(d[i]->a.uid)) != عدم)
				استمر; /* Already seen */
			id = d[i]->a.uid;
		} אחרת {
			אם (rgroup_name((gid_t)(d[i]->a.gid)) != عدم)
				استمر; /* Already seen */
			id = d[i]->a.gid;
		}
		אם (has_id(id, ids, n))
			استمر;
		ids = xrecallocarray(ids, n, n + 1, حجم(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

فراغ
get_remote_user_groups_from_dirents(بنية sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = عدم, nuids = 0, *gids = عدم, ngids = 0;

	אם (!sftp_can_get_users_groups_by_id(conn))
		החזר;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	حرر(uids);
	حرر(gids);
}

ثابت حرف *
ruser_name(uid_t uid)
{
	החזר idname_lookup(&user_idname, (u_int)uid);
}

ثابت حرف *
rgroup_name(uid_t gid)
{
	החזר idname_lookup(&group_idname, (u_int)gid);
}

