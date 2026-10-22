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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/tree.h>

#شامل <glob.h>
#شامل <stdlib.h>
#شامل <stdarg.h>
#شامل <string.h>

#شامل "log.h"
#شامل "xmalloc.h"

#شامل "sftp-common.h"
#شامل "sftp-client.h"
#شامل "sftp-usergroup.h"

/* Tree of id, name */
ساختار idname {
        u_int id;
	نویسه *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
ایستا صحیح
idname_cmp(ساختار idname *a, ساختار idname *b)
{
	اگر (a->id == b->id)
		بازگشت 0;
	بازگشت a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_درخت, idname);
RB_GENERATE_STATIC(idname_درخت, idname, entry, idname_cmp)

ایستا ساختار idname_درخت user_idname = RB_INITIALIZER(&user_idname);
ایستا ساختار idname_درخت group_idname = RB_INITIALIZER(&group_idname);

ایستا تهی
idname_free(ساختار idname *idname)
{
	اگر (idname == پوچ)
		بازگشت;
	آزاد(idname->name);
	آزاد(idname);
}

ایستا تهی
idname_enter(ساختار idname_درخت *درخت, u_int id, ثابت نویسه *name)
{
	ساختار idname *idname;

	اگر ((idname = xcalloc(1, اندازه(*idname))) == پوچ)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	اگر (RB_درج(idname_درخت, درخت, idname) != پوچ)
		idname_free(idname);
}

ایستا ثابت نویسه *
idname_lookup(ساختار idname_درخت *درخت, u_int id)
{
	ساختار idname idname, *found;

	memset(&idname, 0, اندازه(idname));
	idname.id = id;
	اگر ((found = RB_FIND(idname_درخت, درخت, &idname)) != پوچ)
		بازگشت found->name;
	بازگشت پوچ;
}

ایستا تهی
freenames(نویسه **names, u_int nnames)
{
	u_int i;

	اگر (names == پوچ)
		بازگشت;
	برای (i = 0; i < nnames; i++)
		آزاد(names[i]);
	آزاد(names);
}

ایستا تهی
lookup_and_record(ساختار sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	صحیح r;
	u_int i;
	نویسه **usernames = پوچ, **groupnames = پوچ;

	اگر ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		بازگشت;
	}
	برای (i = 0; i < nuids; i++) {
		اگر (usernames[i] == پوچ) {
			debug3_f("uid %u not resolved", uids[i]);
			ادامه;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	برای (i = 0; i < ngids; i++) {
		اگر (groupnames[i] == پوچ) {
			debug3_f("gid %u not resolved", gids[i]);
			ادامه;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

ایستا صحیح
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	اگر (nids == 0)
		بازگشت 0;

	/* XXX O(N^2) */
	برای (i = 0; i < nids; i++) {
		اگر (ids[i] == id)
			بشکن;
	}
	بازگشت i < nids;
}

ایستا تهی
collect_ids_from_glob(glob_t *g, صحیح user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = پوچ;

	برای (i = 0; g->gl_pathv[i] != پوچ; i++) {
		اگر (g->gl_statv[i] == پوچ) /* no stat information */
			ادامه;
		اگر (user) {
			اگر (ruser_name(g->gl_statv[i]->st_uid) != پوچ)
				ادامه; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} وگرنه {
			اگر (rgroup_name(g->gl_statv[i]->st_gid) != پوچ)
				ادامه; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		اگر (has_id(id, ids, n))
			ادامه;
		ids = xrecallocarray(ids, n, n + 1, اندازه(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

تهی
get_remote_user_groups_from_glob(ساختار sftp_conn *conn, glob_t *g)
{
	u_int *uids = پوچ, nuids = 0, *gids = پوچ, ngids = 0;

	اگر (!sftp_can_get_users_groups_by_id(conn))
		بازگشت;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	آزاد(uids);
	آزاد(gids);
}

ایستا تهی
collect_ids_from_dirents(SFTP_DIRENT **d, صحیح user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = پوچ;

	برای (i = 0; d[i] != پوچ; i++) {
		اگر (user) {
			اگر (ruser_name((uid_t)(d[i]->a.uid)) != پوچ)
				ادامه; /* Already seen */
			id = d[i]->a.uid;
		} وگرنه {
			اگر (rgroup_name((gid_t)(d[i]->a.gid)) != پوچ)
				ادامه; /* Already seen */
			id = d[i]->a.gid;
		}
		اگر (has_id(id, ids, n))
			ادامه;
		ids = xrecallocarray(ids, n, n + 1, اندازه(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

تهی
get_remote_user_groups_from_dirents(ساختار sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = پوچ, nuids = 0, *gids = پوچ, ngids = 0;

	اگر (!sftp_can_get_users_groups_by_id(conn))
		بازگشت;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	آزاد(uids);
	آزاد(gids);
}

ثابت نویسه *
ruser_name(uid_t uid)
{
	بازگشت idname_lookup(&user_idname, (u_int)uid);
}

ثابت نویسه *
rgroup_name(uid_t gid)
{
	بازگشت idname_lookup(&group_idname, (u_int)gid);
}

