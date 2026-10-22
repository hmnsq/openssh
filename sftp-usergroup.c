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
ساخت idname {
        u_int id;
	حرف *name;
        RB_اندراج(idname) اندراج_2;
	/* XXX implement bounded cache as TAILQ */
};
ساکن صحیح
idname_cmp(ساخت idname *a, ساخت idname *b)
{
	اگر (a->id == b->id)
		واپس 0;
	واپس a->id > b->id ? 1 : -1;
}
RB_سر(idname_درخت, idname);
RB_GENERATE_STATIC(idname_درخت, idname, اندراج_2, idname_cmp)

ساکن ساخت idname_درخت user_idname = RB_INITIALIZER(&user_idname);
ساکن ساخت idname_درخت گروہ_idname = RB_INITIALIZER(&گروہ_idname);

ساکن خالی
idname_free(ساخت idname *idname)
{
	اگر (idname == تہی)
		واپس;
	آزاد(idname->name);
	آزاد(idname);
}

ساکن خالی
idname_enter(ساخت idname_درخت *درخت, u_int id, ثابت حرف *name)
{
	ساخت idname *idname;

	اگر ((idname = xcalloc(1, حجم(*idname))) == تہی)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	اگر (RB_داخل_کرو(idname_درخت, درخت, idname) != تہی)
		idname_free(idname);
}

ساکن ثابت حرف *
idname_lookup(ساخت idname_درخت *درخت, u_int id)
{
	ساخت idname idname, *ملا;

	memset(&idname, 0, حجم(idname));
	idname.id = id;
	اگر ((ملا = RB_ڈھونڈو(idname_درخت, درخت, &idname)) != تہی)
		واپس ملا->name;
	واپس تہی;
}

ساکن خالی
freenames(حرف **نام, u_int nnames)
{
	u_int i;

	اگر (نام == تہی)
		واپس;
	برائے (i = 0; i < nnames; i++)
		آزاد(نام[i]);
	آزاد(نام);
}

ساکن خالی
lookup_and_ریکارڈ(ساخت sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	صحیح r;
	u_int i;
	حرف **usernames = تہی, **groupnames = تہی;

	اگر ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		واپس;
	}
	برائے (i = 0; i < nuids; i++) {
		اگر (usernames[i] == تہی) {
			debug3_f("uid %u not resolved", uids[i]);
			جاری;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	برائے (i = 0; i < ngids; i++) {
		اگر (groupnames[i] == تہی) {
			debug3_f("gid %u not resolved", gids[i]);
			جاری;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&گروہ_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

ساکن صحیح
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	اگر (nids == 0)
		واپس 0;

	/* XXX O(N^2) */
	برائے (i = 0; i < nids; i++) {
		اگر (ids[i] == id)
			توڑو;
	}
	واپس i < nids;
}

ساکن خالی
collect_ids_from_glob(glob_t *g, صحیح user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = تہی;

	برائے (i = 0; g->gl_pathv[i] != تہی; i++) {
		اگر (g->gl_statv[i] == تہی) /* no stat information */
			جاری;
		اگر (user) {
			اگر (ruser_name(g->gl_statv[i]->st_uid) != تہی)
				جاری; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} ورنہ {
			اگر (rgroup_name(g->gl_statv[i]->st_gid) != تہی)
				جاری; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		اگر (has_id(id, ids, n))
			جاری;
		ids = xrecallocarray(ids, n, n + 1, حجم(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

خالی
get_remote_user_groups_from_glob(ساخت sftp_conn *conn, glob_t *g)
{
	u_int *uids = تہی, nuids = 0, *gids = تہی, ngids = 0;

	اگر (!sftp_can_get_users_groups_by_id(conn))
		واپس;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_ریکارڈ(conn, uids, nuids, gids, ngids);
	آزاد(uids);
	آزاد(gids);
}

ساکن خالی
collect_ids_from_dirents(SFTP_DIRENT **d, صحیح user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = تہی;

	برائے (i = 0; d[i] != تہی; i++) {
		اگر (user) {
			اگر (ruser_name((uid_t)(d[i]->a.uid)) != تہی)
				جاری; /* Already seen */
			id = d[i]->a.uid;
		} ورنہ {
			اگر (rgroup_name((gid_t)(d[i]->a.gid)) != تہی)
				جاری; /* Already seen */
			id = d[i]->a.gid;
		}
		اگر (has_id(id, ids, n))
			جاری;
		ids = xrecallocarray(ids, n, n + 1, حجم(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

خالی
get_remote_user_groups_from_dirents(ساخت sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = تہی, nuids = 0, *gids = تہی, ngids = 0;

	اگر (!sftp_can_get_users_groups_by_id(conn))
		واپس;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_ریکارڈ(conn, uids, nuids, gids, ngids);
	آزاد(uids);
	آزاد(gids);
}

ثابت حرف *
ruser_name(uid_t uid)
{
	واپس idname_lookup(&user_idname, (u_int)uid);
}

ثابت حرف *
rgroup_name(uid_t gid)
{
	واپس idname_lookup(&گروہ_idname, (u_int)gid);
}

