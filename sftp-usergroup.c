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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/tree.h>

#অন্তর্ভাব <glob.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "xmalloc.h"

#অন্তর্ভাব "sftp-common.h"
#অন্তর্ভাব "sftp-client.h"
#অন্তর্ভাব "sftp-usergroup.h"

/* Tree of id, name */
কাঠামো idname {
        u_int id;
	অক্ষর *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
স্থির পূর্ণসংখ্যা
idname_cmp(কাঠামো idname *a, কাঠামো idname *b)
{
	যদি (a->id == b->id)
		ফেরত 0;
	ফেরত a->id > b->id ? 1 : -1;
}
RB_শীর্ষ(idname_বৃক্ষ, idname);
RB_GENERATE_STATIC(idname_বৃক্ষ, idname, entry, idname_cmp)

স্থির কাঠামো idname_বৃক্ষ user_idname = RB_INITIALIZER(&user_idname);
স্থির কাঠামো idname_বৃক্ষ group_idname = RB_INITIALIZER(&group_idname);

স্থির শূন্য
idname_free(কাঠামো idname *idname)
{
	যদি (idname == ফাঁকা)
		ফেরত;
	মুক্ত(idname->name);
	মুক্ত(idname);
}

স্থির শূন্য
idname_enter(কাঠামো idname_বৃক্ষ *বৃক্ষ, u_int id, ধ্রুবক অক্ষর *name)
{
	কাঠামো idname *idname;

	যদি ((idname = xcalloc(1, আকার(*idname))) == ফাঁকা)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	যদি (RB_ঢোকাও(idname_বৃক্ষ, বৃক্ষ, idname) != ফাঁকা)
		idname_free(idname);
}

স্থির ধ্রুবক অক্ষর *
idname_lookup(কাঠামো idname_বৃক্ষ *বৃক্ষ, u_int id)
{
	কাঠামো idname idname, *found;

	memset(&idname, 0, আকার(idname));
	idname.id = id;
	যদি ((found = RB_FIND(idname_বৃক্ষ, বৃক্ষ, &idname)) != ফাঁকা)
		ফেরত found->name;
	ফেরত ফাঁকা;
}

স্থির শূন্য
freenames(অক্ষর **names, u_int nnames)
{
	u_int i;

	যদি (names == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < nnames; i++)
		মুক্ত(names[i]);
	মুক্ত(names);
}

স্থির শূন্য
lookup_and_record(কাঠামো sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	পূর্ণসংখ্যা r;
	u_int i;
	অক্ষর **usernames = ফাঁকা, **groupnames = ফাঁকা;

	যদি ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		ফেরত;
	}
	জন্য (i = 0; i < nuids; i++) {
		যদি (usernames[i] == ফাঁকা) {
			debug3_f("uid %u not resolved", uids[i]);
			চালু;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	জন্য (i = 0; i < ngids; i++) {
		যদি (groupnames[i] == ফাঁকা) {
			debug3_f("gid %u not resolved", gids[i]);
			চালু;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

স্থির পূর্ণসংখ্যা
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	যদি (nids == 0)
		ফেরত 0;

	/* XXX O(N^2) */
	জন্য (i = 0; i < nids; i++) {
		যদি (ids[i] == id)
			বিরতি;
	}
	ফেরত i < nids;
}

স্থির শূন্য
collect_ids_from_glob(glob_t *g, পূর্ণসংখ্যা user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ফাঁকা;

	জন্য (i = 0; g->gl_pathv[i] != ফাঁকা; i++) {
		যদি (g->gl_statv[i] == ফাঁকা) /* no stat information */
			চালু;
		যদি (user) {
			যদি (ruser_name(g->gl_statv[i]->st_uid) != ফাঁকা)
				চালু; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} অন্যথা {
			যদি (rgroup_name(g->gl_statv[i]->st_gid) != ফাঁকা)
				চালু; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		যদি (has_id(id, ids, n))
			চালু;
		ids = xrecallocarray(ids, n, n + 1, আকার(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

শূন্য
get_remote_user_groups_from_glob(কাঠামো sftp_conn *conn, glob_t *g)
{
	u_int *uids = ফাঁকা, nuids = 0, *gids = ফাঁকা, ngids = 0;

	যদি (!sftp_can_get_users_groups_by_id(conn))
		ফেরত;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	মুক্ত(uids);
	মুক্ত(gids);
}

স্থির শূন্য
collect_ids_from_dirents(SFTP_DIRENT **d, পূর্ণসংখ্যা user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ফাঁকা;

	জন্য (i = 0; d[i] != ফাঁকা; i++) {
		যদি (user) {
			যদি (ruser_name((uid_t)(d[i]->a.uid)) != ফাঁকা)
				চালু; /* Already seen */
			id = d[i]->a.uid;
		} অন্যথা {
			যদি (rgroup_name((gid_t)(d[i]->a.gid)) != ফাঁকা)
				চালু; /* Already seen */
			id = d[i]->a.gid;
		}
		যদি (has_id(id, ids, n))
			চালু;
		ids = xrecallocarray(ids, n, n + 1, আকার(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

শূন্য
get_remote_user_groups_from_dirents(কাঠামো sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = ফাঁকা, nuids = 0, *gids = ফাঁকা, ngids = 0;

	যদি (!sftp_can_get_users_groups_by_id(conn))
		ফেরত;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	মুক্ত(uids);
	মুক্ত(gids);
}

ধ্রুবক অক্ষর *
ruser_name(uid_t uid)
{
	ফেরত idname_lookup(&user_idname, (u_int)uid);
}

ধ্রুবক অক্ষর *
rgroup_name(uid_t gid)
{
	ফেরত idname_lookup(&group_idname, (u_int)gid);
}

