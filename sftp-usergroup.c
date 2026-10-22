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
সংরচনা idname {
        u_int id;
	বর্ণ *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
স্থির পূর্ণাঙ্ক
idname_cmp(সংরচনা idname *a, সংরচনা idname *b)
{
	যদি (a->id == b->id)
		প্রত্যাগম 0;
	প্রত্যাগম a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_বৃক্ষ, idname);
RB_GENERATE_STATIC(idname_বৃক্ষ, idname, entry, idname_cmp)

স্থির সংরচনা idname_বৃক্ষ user_idname = RB_INITIALIZER(&user_idname);
স্থির সংরচনা idname_বৃক্ষ group_idname = RB_INITIALIZER(&group_idname);

স্থির শূন্য
idname_free(সংরচনা idname *idname)
{
	যদি (idname == রিক্ত)
		প্রত্যাগম;
	মুক্ত(idname->name);
	মুক্ত(idname);
}

স্থির শূন্য
idname_enter(সংরচনা idname_বৃক্ষ *বৃক্ষ, u_int id, ধ্রুব বর্ণ *name)
{
	সংরচনা idname *idname;

	যদি ((idname = xcalloc(1, পরিমাণ(*idname))) == রিক্ত)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	যদি (RB_ঢোকাও(idname_বৃক্ষ, বৃক্ষ, idname) != রিক্ত)
		idname_free(idname);
}

স্থির ধ্রুব বর্ণ *
idname_lookup(সংরচনা idname_বৃক্ষ *বৃক্ষ, u_int id)
{
	সংরচনা idname idname, *found;

	memset(&idname, 0, পরিমাণ(idname));
	idname.id = id;
	যদি ((found = RB_FIND(idname_বৃক্ষ, বৃক্ষ, &idname)) != রিক্ত)
		প্রত্যাগম found->name;
	প্রত্যাগম রিক্ত;
}

স্থির শূন্য
freenames(বর্ণ **names, u_int nnames)
{
	u_int i;

	যদি (names == রিক্ত)
		প্রত্যাগম;
	প্রতি (i = 0; i < nnames; i++)
		মুক্ত(names[i]);
	মুক্ত(names);
}

স্থির শূন্য
lookup_and_record(সংরচনা sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	পূর্ণাঙ্ক r;
	u_int i;
	বর্ণ **usernames = রিক্ত, **groupnames = রিক্ত;

	যদি ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		প্রত্যাগম;
	}
	প্রতি (i = 0; i < nuids; i++) {
		যদি (usernames[i] == রিক্ত) {
			debug3_f("uid %u not resolved", uids[i]);
			অনুবর্ত;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	প্রতি (i = 0; i < ngids; i++) {
		যদি (groupnames[i] == রিক্ত) {
			debug3_f("gid %u not resolved", gids[i]);
			অনুবর্ত;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

স্থির পূর্ণাঙ্ক
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	যদি (nids == 0)
		প্রত্যাগম 0;

	/* XXX O(N^2) */
	প্রতি (i = 0; i < nids; i++) {
		যদি (ids[i] == id)
			ভঙ্গ;
	}
	প্রত্যাগম i < nids;
}

স্থির শূন্য
collect_ids_from_glob(glob_t *g, পূর্ণাঙ্ক user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = রিক্ত;

	প্রতি (i = 0; g->gl_pathv[i] != রিক্ত; i++) {
		যদি (g->gl_statv[i] == রিক্ত) /* no stat information */
			অনুবর্ত;
		যদি (user) {
			যদি (ruser_name(g->gl_statv[i]->st_uid) != রিক্ত)
				অনুবর্ত; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} অন্যথা {
			যদি (rgroup_name(g->gl_statv[i]->st_gid) != রিক্ত)
				অনুবর্ত; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		যদি (has_id(id, ids, n))
			অনুবর্ত;
		ids = xrecallocarray(ids, n, n + 1, পরিমাণ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

শূন্য
get_remote_user_groups_from_glob(সংরচনা sftp_conn *conn, glob_t *g)
{
	u_int *uids = রিক্ত, nuids = 0, *gids = রিক্ত, ngids = 0;

	যদি (!sftp_can_get_users_groups_by_id(conn))
		প্রত্যাগম;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	মুক্ত(uids);
	মুক্ত(gids);
}

স্থির শূন্য
collect_ids_from_dirents(SFTP_DIRENT **d, পূর্ণাঙ্ক user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = রিক্ত;

	প্রতি (i = 0; d[i] != রিক্ত; i++) {
		যদি (user) {
			যদি (ruser_name((uid_t)(d[i]->a.uid)) != রিক্ত)
				অনুবর্ত; /* Already seen */
			id = d[i]->a.uid;
		} অন্যথা {
			যদি (rgroup_name((gid_t)(d[i]->a.gid)) != রিক্ত)
				অনুবর্ত; /* Already seen */
			id = d[i]->a.gid;
		}
		যদি (has_id(id, ids, n))
			অনুবর্ত;
		ids = xrecallocarray(ids, n, n + 1, পরিমাণ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

শূন্য
get_remote_user_groups_from_dirents(সংরচনা sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = রিক্ত, nuids = 0, *gids = রিক্ত, ngids = 0;

	যদি (!sftp_can_get_users_groups_by_id(conn))
		প্রত্যাগম;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	মুক্ত(uids);
	মুক্ত(gids);
}

ধ্রুব বর্ণ *
ruser_name(uid_t uid)
{
	প্রত্যাগম idname_lookup(&user_idname, (u_int)uid);
}

ধ্রুব বর্ণ *
rgroup_name(uid_t gid)
{
	প্রত্যাগম idname_lookup(&group_idname, (u_int)gid);
}

