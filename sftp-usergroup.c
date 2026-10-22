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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/tree.h>

#அந்தர்பாவ <glob.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "xmalloc.h"

#அந்தர்பாவ "sftp-common.h"
#அந்தர்பாவ "sftp-client.h"
#அந்தர்பாவ "sftp-usergroup.h"

/* Tree of id, name */
கட்டமைப்பு idname {
        u_int id;
	எழுத்து *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
நிலையான முழு
idname_cmp(கட்டமைப்பு idname *a, கட்டமைப்பு idname *b)
{
	எனில் (a->id == b->id)
		திரும்பு 0;
	திரும்பு a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_மரம், idname);
RB_GENERATE_STATIC(idname_மரம், idname, entry, idname_cmp)

நிலையான கட்டமைப்பு idname_மரம் user_idname = RB_INITIALIZER(&user_idname);
நிலையான கட்டமைப்பு idname_மரம் group_idname = RB_INITIALIZER(&group_idname);

நிலையான வெறுமை
idname_free(கட்டமைப்பு idname *idname)
{
	எனில் (idname == வெற்று)
		திரும்பு;
	விடுவி(idname->name);
	விடுவி(idname);
}

நிலையான வெறுமை
idname_enter(கட்டமைப்பு idname_மரம் *மரம், u_int id, மாறிலி எழுத்து *name)
{
	கட்டமைப்பு idname *idname;

	எனில் ((idname = xcalloc(1, அளவு(*idname))) == வெற்று)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	எனில் (RB_செருகு(idname_மரம், மரம், idname) != வெற்று)
		idname_free(idname);
}

நிலையான மாறிலி எழுத்து *
idname_lookup(கட்டமைப்பு idname_மரம் *மரம், u_int id)
{
	கட்டமைப்பு idname idname, *found;

	memset(&idname, 0, அளவு(idname));
	idname.id = id;
	எனில் ((found = RB_FIND(idname_மரம், மரம், &idname)) != வெற்று)
		திரும்பு found->name;
	திரும்பு வெற்று;
}

நிலையான வெறுமை
freenames(எழுத்து **names, u_int nnames)
{
	u_int i;

	எனில் (names == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < nnames; i++)
		விடுவி(names[i]);
	விடுவி(names);
}

நிலையான வெறுமை
lookup_and_record(கட்டமைப்பு sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	முழு r;
	u_int i;
	எழுத்து **usernames = வெற்று, **groupnames = வெற்று;

	எனில் ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		திரும்பு;
	}
	க்கு (i = 0; i < nuids; i++) {
		எனில் (usernames[i] == வெற்று) {
			debug3_f("uid %u not resolved", uids[i]);
			தொடர்;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	க்கு (i = 0; i < ngids; i++) {
		எனில் (groupnames[i] == வெற்று) {
			debug3_f("gid %u not resolved", gids[i]);
			தொடர்;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

நிலையான முழு
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	எனில் (nids == 0)
		திரும்பு 0;

	/* XXX O(N^2) */
	க்கு (i = 0; i < nids; i++) {
		எனில் (ids[i] == id)
			நிறுத்து;
	}
	திரும்பு i < nids;
}

நிலையான வெறுமை
collect_ids_from_glob(glob_t *g, முழு user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = வெற்று;

	க்கு (i = 0; g->gl_pathv[i] != வெற்று; i++) {
		எனில் (g->gl_statv[i] == வெற்று) /* no stat information */
			தொடர்;
		எனில் (user) {
			எனில் (ruser_name(g->gl_statv[i]->st_uid) != வெற்று)
				தொடர்; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} இல்லையெனில் {
			எனில் (rgroup_name(g->gl_statv[i]->st_gid) != வெற்று)
				தொடர்; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		எனில் (has_id(id, ids, n))
			தொடர்;
		ids = xrecallocarray(ids, n, n + 1, அளவு(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

வெறுமை
get_remote_user_groups_from_glob(கட்டமைப்பு sftp_conn *conn, glob_t *g)
{
	u_int *uids = வெற்று, nuids = 0, *gids = வெற்று, ngids = 0;

	எனில் (!sftp_can_get_users_groups_by_id(conn))
		திரும்பு;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	விடுவி(uids);
	விடுவி(gids);
}

நிலையான வெறுமை
collect_ids_from_dirents(SFTP_DIRENT **d, முழு user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = வெற்று;

	க்கு (i = 0; d[i] != வெற்று; i++) {
		எனில் (user) {
			எனில் (ruser_name((uid_t)(d[i]->a.uid)) != வெற்று)
				தொடர்; /* Already seen */
			id = d[i]->a.uid;
		} இல்லையெனில் {
			எனில் (rgroup_name((gid_t)(d[i]->a.gid)) != வெற்று)
				தொடர்; /* Already seen */
			id = d[i]->a.gid;
		}
		எனில் (has_id(id, ids, n))
			தொடர்;
		ids = xrecallocarray(ids, n, n + 1, அளவு(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

வெறுமை
get_remote_user_groups_from_dirents(கட்டமைப்பு sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = வெற்று, nuids = 0, *gids = வெற்று, ngids = 0;

	எனில் (!sftp_can_get_users_groups_by_id(conn))
		திரும்பு;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	விடுவி(uids);
	விடுவி(gids);
}

மாறிலி எழுத்து *
ruser_name(uid_t uid)
{
	திரும்பு idname_lookup(&user_idname, (u_int)uid);
}

மாறிலி எழுத்து *
rgroup_name(uid_t gid)
{
	திரும்பு idname_lookup(&group_idname, (u_int)gid);
}

