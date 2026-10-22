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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/tree.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <glob.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-common.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-client.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-usergroup.h"

/* Tree of id, name */
ਬਣਤਰ idname {
        u_int id;
	ਅੱਖਰ *name;
        RB_ਇੰਦਰਾਜ(idname) ਇੰਦਰਾਜ;
	/* XXX implement bounded cache as TAILQ */
};
ਸਥਿਰ ਪੂਰਨ
idname_cmp(ਬਣਤਰ idname *a, ਬਣਤਰ idname *b)
{
	ਜੇ (a->id == b->id)
		ਵਾਪਸ 0;
	ਵਾਪਸ a->id > b->id ? 1 : -1;
}
RB_ਸਿਰ(idname_ਰੁੱਖ, idname);
RB_GENERATE_STATIC(idname_ਰੁੱਖ, idname, ਇੰਦਰਾਜ, idname_cmp)

ਸਥਿਰ ਬਣਤਰ idname_ਰੁੱਖ user_idname = RB_INITIALIZER(&user_idname);
ਸਥਿਰ ਬਣਤਰ idname_ਰੁੱਖ ਸਮੂਹ_idname = RB_INITIALIZER(&ਸਮੂਹ_idname);

ਸਥਿਰ ਖਾਲੀ
idname_free(ਬਣਤਰ idname *idname)
{
	ਜੇ (idname == ਨਿਰਾ)
		ਵਾਪਸ;
	ਮੁਕਤ(idname->name);
	ਮੁਕਤ(idname);
}

ਸਥਿਰ ਖਾਲੀ
idname_enter(ਬਣਤਰ idname_ਰੁੱਖ *ਰੁੱਖ, u_int id, ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ idname *idname;

	ਜੇ ((idname = xcalloc(1, ਆਕਾਰ(*idname))) == ਨਿਰਾ)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	ਜੇ (RB_ਪਾਓ(idname_ਰੁੱਖ, ਰੁੱਖ, idname) != ਨਿਰਾ)
		idname_free(idname);
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
idname_lookup(ਬਣਤਰ idname_ਰੁੱਖ *ਰੁੱਖ, u_int id)
{
	ਬਣਤਰ idname idname, *ਮਿਲਿਆ;

	memset(&idname, 0, ਆਕਾਰ(idname));
	idname.id = id;
	ਜੇ ((ਮਿਲਿਆ = RB_ਲੱਭੋ(idname_ਰੁੱਖ, ਰੁੱਖ, &idname)) != ਨਿਰਾ)
		ਵਾਪਸ ਮਿਲਿਆ->name;
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਖਾਲੀ
freenames(ਅੱਖਰ **ਨਾਂ, u_int nnames)
{
	u_int i;

	ਜੇ (ਨਾਂ == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < nnames; i++)
		ਮੁਕਤ(ਨਾਂ[i]);
	ਮੁਕਤ(ਨਾਂ);
}

ਸਥਿਰ ਖਾਲੀ
lookup_and_ਰਿਕਾਰਡ(ਬਣਤਰ sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	ਪੂਰਨ r;
	u_int i;
	ਅੱਖਰ **usernames = ਨਿਰਾ, **groupnames = ਨਿਰਾ;

	ਜੇ ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		ਵਾਪਸ;
	}
	ਲਈ (i = 0; i < nuids; i++) {
		ਜੇ (usernames[i] == ਨਿਰਾ) {
			debug3_f("uid %u not resolved", uids[i]);
			ਜਾਰੀ;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	ਲਈ (i = 0; i < ngids; i++) {
		ਜੇ (groupnames[i] == ਨਿਰਾ) {
			debug3_f("gid %u not resolved", gids[i]);
			ਜਾਰੀ;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&ਸਮੂਹ_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

ਸਥਿਰ ਪੂਰਨ
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	ਜੇ (nids == 0)
		ਵਾਪਸ 0;

	/* XXX O(N^2) */
	ਲਈ (i = 0; i < nids; i++) {
		ਜੇ (ids[i] == id)
			ਰੋਕੋ;
	}
	ਵਾਪਸ i < nids;
}

ਸਥਿਰ ਖਾਲੀ
collect_ids_from_glob(glob_t *g, ਪੂਰਨ user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ਨਿਰਾ;

	ਲਈ (i = 0; g->gl_pathv[i] != ਨਿਰਾ; i++) {
		ਜੇ (g->gl_statv[i] == ਨਿਰਾ) /* no stat information */
			ਜਾਰੀ;
		ਜੇ (user) {
			ਜੇ (ruser_name(g->gl_statv[i]->st_uid) != ਨਿਰਾ)
				ਜਾਰੀ; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (rgroup_name(g->gl_statv[i]->st_gid) != ਨਿਰਾ)
				ਜਾਰੀ; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		ਜੇ (has_id(id, ids, n))
			ਜਾਰੀ;
		ids = xrecallocarray(ids, n, n + 1, ਆਕਾਰ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ਖਾਲੀ
get_remote_user_groups_from_glob(ਬਣਤਰ sftp_conn *conn, glob_t *g)
{
	u_int *uids = ਨਿਰਾ, nuids = 0, *gids = ਨਿਰਾ, ngids = 0;

	ਜੇ (!sftp_can_get_users_groups_by_id(conn))
		ਵਾਪਸ;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_ਰਿਕਾਰਡ(conn, uids, nuids, gids, ngids);
	ਮੁਕਤ(uids);
	ਮੁਕਤ(gids);
}

ਸਥਿਰ ਖਾਲੀ
collect_ids_from_dirents(SFTP_DIRENT **d, ਪੂਰਨ user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ਨਿਰਾ;

	ਲਈ (i = 0; d[i] != ਨਿਰਾ; i++) {
		ਜੇ (user) {
			ਜੇ (ruser_name((uid_t)(d[i]->a.uid)) != ਨਿਰਾ)
				ਜਾਰੀ; /* Already seen */
			id = d[i]->a.uid;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (rgroup_name((gid_t)(d[i]->a.gid)) != ਨਿਰਾ)
				ਜਾਰੀ; /* Already seen */
			id = d[i]->a.gid;
		}
		ਜੇ (has_id(id, ids, n))
			ਜਾਰੀ;
		ids = xrecallocarray(ids, n, n + 1, ਆਕਾਰ(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ਖਾਲੀ
get_remote_user_groups_from_dirents(ਬਣਤਰ sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = ਨਿਰਾ, nuids = 0, *gids = ਨਿਰਾ, ngids = 0;

	ਜੇ (!sftp_can_get_users_groups_by_id(conn))
		ਵਾਪਸ;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_ਰਿਕਾਰਡ(conn, uids, nuids, gids, ngids);
	ਮੁਕਤ(uids);
	ਮੁਕਤ(gids);
}

ਅਚਲ ਅੱਖਰ *
ruser_name(uid_t uid)
{
	ਵਾਪਸ idname_lookup(&user_idname, (u_int)uid);
}

ਅਚਲ ਅੱਖਰ *
rgroup_name(uid_t gid)
{
	ਵਾਪਸ idname_lookup(&ਸਮੂਹ_idname, (u_int)gid);
}

