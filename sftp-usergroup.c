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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/tree.h>

#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

#ಅನ್ತರ್ಭಾವ "sftp-common.h"
#ಅನ್ತರ್ಭಾವ "sftp-client.h"
#ಅನ್ತರ್ಭಾವ "sftp-usergroup.h"

/* Tree of id, name */
ಸಂರಚನಾ idname {
        u_int id;
	ವರ್ಣ *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
idname_cmp(ಸಂರಚನಾ idname *a, ಸಂರಚನಾ idname *b)
{
	ಯದಿ (a->id == b->id)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_ವೃಕ್ಷ, idname);
RB_GENERATE_STATIC(idname_ವೃಕ್ಷ, idname, entry, idname_cmp)

ಸ್ಥಿರ ಸಂರಚನಾ idname_ವೃಕ್ಷ user_idname = RB_INITIALIZER(&user_idname);
ಸ್ಥಿರ ಸಂರಚನಾ idname_ವೃಕ್ಷ group_idname = RB_INITIALIZER(&group_idname);

ಸ್ಥಿರ ಶೂನ್ಯ
idname_free(ಸಂರಚನಾ idname *idname)
{
	ಯದಿ (idname == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಮುಕ್ತ(idname->name);
	ಮುಕ್ತ(idname);
}

ಸ್ಥಿರ ಶೂನ್ಯ
idname_enter(ಸಂರಚನಾ idname_ವೃಕ್ಷ *ವೃಕ್ಷ, u_int id, ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ idname *idname;

	ಯದಿ ((idname = xcalloc(1, ಪರಿಮಾಣ(*idname))) == ರಿಕ್ತ)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	ಯದಿ (RB_ಸೇರಿಸು(idname_ವೃಕ್ಷ, ವೃಕ್ಷ, idname) != ರಿಕ್ತ)
		idname_free(idname);
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
idname_lookup(ಸಂರಚನಾ idname_ವೃಕ್ಷ *ವೃಕ್ಷ, u_int id)
{
	ಸಂರಚನಾ idname idname, *found;

	memset(&idname, 0, ಪರಿಮಾಣ(idname));
	idname.id = id;
	ಯದಿ ((found = RB_FIND(idname_ವೃಕ್ಷ, ವೃಕ್ಷ, &idname)) != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ found->name;
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
freenames(ವರ್ಣ **names, u_int nnames)
{
	u_int i;

	ಯದಿ (names == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < nnames; i++)
		ಮುಕ್ತ(names[i]);
	ಮುಕ್ತ(names);
}

ಸ್ಥಿರ ಶೂನ್ಯ
lookup_and_record(ಸಂರಚನಾ sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;
	ವರ್ಣ **usernames = ರಿಕ್ತ, **groupnames = ರಿಕ್ತ;

	ಯದಿ ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಪ್ರತಿ (i = 0; i < nuids; i++) {
		ಯದಿ (usernames[i] == ರಿಕ್ತ) {
			debug3_f("uid %u not resolved", uids[i]);
			ಅನುವರ್ತ;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	ಪ್ರತಿ (i = 0; i < ngids; i++) {
		ಯದಿ (groupnames[i] == ರಿಕ್ತ) {
			debug3_f("gid %u not resolved", gids[i]);
			ಅನುವರ್ತ;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	ಯದಿ (nids == 0)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* XXX O(N^2) */
	ಪ್ರತಿ (i = 0; i < nids; i++) {
		ಯದಿ (ids[i] == id)
			ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ i < nids;
}

ಸ್ಥಿರ ಶೂನ್ಯ
collect_ids_from_glob(glob_t *g, ಪೂರ್ಣಾಙ್ಕ user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ರಿಕ್ತ;

	ಪ್ರತಿ (i = 0; g->gl_pathv[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (g->gl_statv[i] == ರಿಕ್ತ) /* no stat information */
			ಅನುವರ್ತ;
		ಯದಿ (user) {
			ಯದಿ (ruser_name(g->gl_statv[i]->st_uid) != ರಿಕ್ತ)
				ಅನುವರ್ತ; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} ಅನ್ಯಥಾ {
			ಯದಿ (rgroup_name(g->gl_statv[i]->st_gid) != ರಿಕ್ತ)
				ಅನುವರ್ತ; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		ಯದಿ (has_id(id, ids, n))
			ಅನುವರ್ತ;
		ids = xrecallocarray(ids, n, n + 1, ಪರಿಮಾಣ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ಶೂನ್ಯ
get_remote_user_groups_from_glob(ಸಂರಚನಾ sftp_conn *conn, glob_t *g)
{
	u_int *uids = ರಿಕ್ತ, nuids = 0, *gids = ರಿಕ್ತ, ngids = 0;

	ಯದಿ (!sftp_can_get_users_groups_by_id(conn))
		ಪ್ರತ್ಯಾಗಮ;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	ಮುಕ್ತ(uids);
	ಮುಕ್ತ(gids);
}

ಸ್ಥಿರ ಶೂನ್ಯ
collect_ids_from_dirents(SFTP_DIRENT **d, ಪೂರ್ಣಾಙ್ಕ user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ರಿಕ್ತ;

	ಪ್ರತಿ (i = 0; d[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (user) {
			ಯದಿ (ruser_name((uid_t)(d[i]->a.uid)) != ರಿಕ್ತ)
				ಅನುವರ್ತ; /* Already seen */
			id = d[i]->a.uid;
		} ಅನ್ಯಥಾ {
			ಯದಿ (rgroup_name((gid_t)(d[i]->a.gid)) != ರಿಕ್ತ)
				ಅನುವರ್ತ; /* Already seen */
			id = d[i]->a.gid;
		}
		ಯದಿ (has_id(id, ids, n))
			ಅನುವರ್ತ;
		ids = xrecallocarray(ids, n, n + 1, ಪರಿಮಾಣ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ಶೂನ್ಯ
get_remote_user_groups_from_dirents(ಸಂರಚನಾ sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = ರಿಕ್ತ, nuids = 0, *gids = ರಿಕ್ತ, ngids = 0;

	ಯದಿ (!sftp_can_get_users_groups_by_id(conn))
		ಪ್ರತ್ಯಾಗಮ;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	ಮುಕ್ತ(uids);
	ಮುಕ್ತ(gids);
}

ಧ್ರುವ ವರ್ಣ *
ruser_name(uid_t uid)
{
	ಪ್ರತ್ಯಾಗಮ idname_lookup(&user_idname, (u_int)uid);
}

ಧ್ರುವ ವರ್ಣ *
rgroup_name(uid_t gid)
{
	ಪ್ರತ್ಯಾಗಮ idname_lookup(&group_idname, (u_int)gid);
}

