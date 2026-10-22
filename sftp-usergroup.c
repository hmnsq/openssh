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
ರಚನೆ idname {
        u_int id;
	ಅಕ್ಷರ *name;
        RB_ನಮೂದು(idname) ನಮೂದು;
	/* XXX implement bounded cache as TAILQ */
};
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
idname_cmp(ರಚನೆ idname *a, ರಚನೆ idname *b)
{
	ಆದರೆ (a->id == b->id)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ a->id > b->id ? 1 : -1;
}
RB_ತಲೆ(idname_ವೃಕ್ಷ, idname);
RB_GENERATE_STATIC(idname_ವೃಕ್ಷ, idname, ನಮೂದು, idname_cmp)

ಸ್ಥಿರ ರಚನೆ idname_ವೃಕ್ಷ user_idname = RB_INITIALIZER(&user_idname);
ಸ್ಥಿರ ರಚನೆ idname_ವೃಕ್ಷ ಗುಂಪು_idname = RB_INITIALIZER(&ಗುಂಪು_idname);

ಸ್ಥಿರ ಶೂನ್ಯ
idname_free(ರಚನೆ idname *idname)
{
	ಆದರೆ (idname == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಬಿಡುಗಡೆ(idname->name);
	ಬಿಡುಗಡೆ(idname);
}

ಸ್ಥಿರ ಶೂನ್ಯ
idname_enter(ರಚನೆ idname_ವೃಕ್ಷ *ವೃಕ್ಷ, u_int id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ರಚನೆ idname *idname;

	ಆದರೆ ((idname = xcalloc(1, ಗಾತ್ರ(*idname))) == ಖಾಲಿ)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	ಆದರೆ (RB_ಸೇರಿಸು(idname_ವೃಕ್ಷ, ವೃಕ್ಷ, idname) != ಖಾಲಿ)
		idname_free(idname);
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
idname_lookup(ರಚನೆ idname_ವೃಕ್ಷ *ವೃಕ್ಷ, u_int id)
{
	ರಚನೆ idname idname, *ಸಿಕ್ಕಿತು;

	memset(&idname, 0, ಗಾತ್ರ(idname));
	idname.id = id;
	ಆದರೆ ((ಸಿಕ್ಕಿತು = RB_ಕಂಡುಹಿಡಿ(idname_ವೃಕ್ಷ, ವೃಕ್ಷ, &idname)) != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು->name;
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
freenames(ಅಕ್ಷರ **ಹೆಸರುಗಳು, u_int nnames)
{
	u_int i;

	ಆದರೆ (ಹೆಸರುಗಳು == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < nnames; i++)
		ಬಿಡುಗಡೆ(ಹೆಸರುಗಳು[i]);
	ಬಿಡುಗಡೆ(ಹೆಸರುಗಳು);
}

ಸ್ಥಿರ ಶೂನ್ಯ
lookup_and_ದಾಖಲೆ(ರಚನೆ sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i;
	ಅಕ್ಷರ **usernames = ಖಾಲಿ, **groupnames = ಖಾಲಿ;

	ಆದರೆ ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		ಹಿಂತಿರುಗಿ;
	}
	ಗಾಗಿ (i = 0; i < nuids; i++) {
		ಆದರೆ (usernames[i] == ಖಾಲಿ) {
			debug3_f("uid %u not resolved", uids[i]);
			ಮುಂದುವರಿ;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	ಗಾಗಿ (i = 0; i < ngids; i++) {
		ಆದರೆ (groupnames[i] == ಖಾಲಿ) {
			debug3_f("gid %u not resolved", gids[i]);
			ಮುಂದುವರಿ;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&ಗುಂಪು_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	ಆದರೆ (nids == 0)
		ಹಿಂತಿರುಗಿ 0;

	/* XXX O(N^2) */
	ಗಾಗಿ (i = 0; i < nids; i++) {
		ಆದರೆ (ids[i] == id)
			ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ i < nids;
}

ಸ್ಥಿರ ಶೂನ್ಯ
collect_ids_from_glob(glob_t *g, ಪೂರ್ಣಾಂಕ user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ಖಾಲಿ;

	ಗಾಗಿ (i = 0; g->gl_pathv[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (g->gl_statv[i] == ಖಾಲಿ) /* no stat information */
			ಮುಂದುವರಿ;
		ಆದರೆ (user) {
			ಆದರೆ (ruser_name(g->gl_statv[i]->st_uid) != ಖಾಲಿ)
				ಮುಂದುವರಿ; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (rgroup_name(g->gl_statv[i]->st_gid) != ಖಾಲಿ)
				ಮುಂದುವರಿ; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		ಆದರೆ (has_id(id, ids, n))
			ಮುಂದುವರಿ;
		ids = xrecallocarray(ids, n, n + 1, ಗಾತ್ರ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ಶೂನ್ಯ
get_remote_user_groups_from_glob(ರಚನೆ sftp_conn *conn, glob_t *g)
{
	u_int *uids = ಖಾಲಿ, nuids = 0, *gids = ಖಾಲಿ, ngids = 0;

	ಆದರೆ (!sftp_can_get_users_groups_by_id(conn))
		ಹಿಂತಿರುಗಿ;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_ದಾಖಲೆ(conn, uids, nuids, gids, ngids);
	ಬಿಡುಗಡೆ(uids);
	ಬಿಡುಗಡೆ(gids);
}

ಸ್ಥಿರ ಶೂನ್ಯ
collect_ids_from_dirents(SFTP_DIRENT **d, ಪೂರ್ಣಾಂಕ user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ಖಾಲಿ;

	ಗಾಗಿ (i = 0; d[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (user) {
			ಆದರೆ (ruser_name((uid_t)(d[i]->a.uid)) != ಖಾಲಿ)
				ಮುಂದುವರಿ; /* Already seen */
			id = d[i]->a.uid;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (rgroup_name((gid_t)(d[i]->a.gid)) != ಖಾಲಿ)
				ಮುಂದುವರಿ; /* Already seen */
			id = d[i]->a.gid;
		}
		ಆದರೆ (has_id(id, ids, n))
			ಮುಂದುವರಿ;
		ids = xrecallocarray(ids, n, n + 1, ಗಾತ್ರ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ಶೂನ್ಯ
get_remote_user_groups_from_dirents(ರಚನೆ sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = ಖಾಲಿ, nuids = 0, *gids = ಖಾಲಿ, ngids = 0;

	ಆದರೆ (!sftp_can_get_users_groups_by_id(conn))
		ಹಿಂತಿರುಗಿ;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_ದಾಖಲೆ(conn, uids, nuids, gids, ngids);
	ಬಿಡುಗಡೆ(uids);
	ಬಿಡುಗಡೆ(gids);
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ruser_name(uid_t uid)
{
	ಹಿಂತಿರುಗಿ idname_lookup(&user_idname, (u_int)uid);
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
rgroup_name(uid_t gid)
{
	ಹಿಂತಿರುಗಿ idname_lookup(&ಗುಂಪು_idname, (u_int)gid);
}

