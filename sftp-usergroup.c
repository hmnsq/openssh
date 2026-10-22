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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/tree.h>

#അന്തര്ഭാവ <glob.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "xmalloc.h"

#അന്തര്ഭാവ "sftp-common.h"
#അന്തര്ഭാവ "sftp-client.h"
#അന്തര്ഭാവ "sftp-usergroup.h"

/* Tree of id, name */
ഘടന idname {
        u_int id;
	അക്ഷരം *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
സ്ഥിതം പൂർണ്ണസംഖ്യ
idname_cmp(ഘടന idname *a, ഘടന idname *b)
{
	എങ്കിൽ (a->id == b->id)
		തിരികെ 0;
	തിരികെ a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_വൃക്ഷം, idname);
RB_GENERATE_STATIC(idname_വൃക്ഷം, idname, entry, idname_cmp)

സ്ഥിതം ഘടന idname_വൃക്ഷം user_idname = RB_INITIALIZER(&user_idname);
സ്ഥിതം ഘടന idname_വൃക്ഷം group_idname = RB_INITIALIZER(&group_idname);

സ്ഥിതം ശൂന്യം
idname_free(ഘടന idname *idname)
{
	എങ്കിൽ (idname == ശൂന്യ)
		തിരികെ;
	സ്വതന്ത്രം(idname->name);
	സ്വതന്ത്രം(idname);
}

സ്ഥിതം ശൂന്യം
idname_enter(ഘടന idname_വൃക്ഷം *വൃക്ഷം, u_int id, സ്ഥിരം അക്ഷരം *name)
{
	ഘടന idname *idname;

	എങ്കിൽ ((idname = xcalloc(1, വലുപ്പം(*idname))) == ശൂന്യ)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	എങ്കിൽ (RB_തിരുകുക(idname_വൃക്ഷം, വൃക്ഷം, idname) != ശൂന്യ)
		idname_free(idname);
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
idname_lookup(ഘടന idname_വൃക്ഷം *വൃക്ഷം, u_int id)
{
	ഘടന idname idname, *found;

	memset(&idname, 0, വലുപ്പം(idname));
	idname.id = id;
	എങ്കിൽ ((found = RB_FIND(idname_വൃക്ഷം, വൃക്ഷം, &idname)) != ശൂന്യ)
		തിരികെ found->name;
	തിരികെ ശൂന്യ;
}

സ്ഥിതം ശൂന്യം
freenames(അക്ഷരം **names, u_int nnames)
{
	u_int i;

	എങ്കിൽ (names == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < nnames; i++)
		സ്വതന്ത്രം(names[i]);
	സ്വതന്ത്രം(names);
}

സ്ഥിതം ശൂന്യം
lookup_and_record(ഘടന sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i;
	അക്ഷരം **usernames = ശൂന്യ, **groupnames = ശൂന്യ;

	എങ്കിൽ ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		തിരികെ;
	}
	വേണ്ടി (i = 0; i < nuids; i++) {
		എങ്കിൽ (usernames[i] == ശൂന്യ) {
			debug3_f("uid %u not resolved", uids[i]);
			തുടരുക;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	വേണ്ടി (i = 0; i < ngids; i++) {
		എങ്കിൽ (groupnames[i] == ശൂന്യ) {
			debug3_f("gid %u not resolved", gids[i]);
			തുടരുക;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	എങ്കിൽ (nids == 0)
		തിരികെ 0;

	/* XXX O(N^2) */
	വേണ്ടി (i = 0; i < nids; i++) {
		എങ്കിൽ (ids[i] == id)
			നിർത്തുക;
	}
	തിരികെ i < nids;
}

സ്ഥിതം ശൂന്യം
collect_ids_from_glob(glob_t *g, പൂർണ്ണസംഖ്യ user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ശൂന്യ;

	വേണ്ടി (i = 0; g->gl_pathv[i] != ശൂന്യ; i++) {
		എങ്കിൽ (g->gl_statv[i] == ശൂന്യ) /* no stat information */
			തുടരുക;
		എങ്കിൽ (user) {
			എങ്കിൽ (ruser_name(g->gl_statv[i]->st_uid) != ശൂന്യ)
				തുടരുക; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (rgroup_name(g->gl_statv[i]->st_gid) != ശൂന്യ)
				തുടരുക; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		എങ്കിൽ (has_id(id, ids, n))
			തുടരുക;
		ids = xrecallocarray(ids, n, n + 1, വലുപ്പം(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ശൂന്യം
get_remote_user_groups_from_glob(ഘടന sftp_conn *conn, glob_t *g)
{
	u_int *uids = ശൂന്യ, nuids = 0, *gids = ശൂന്യ, ngids = 0;

	എങ്കിൽ (!sftp_can_get_users_groups_by_id(conn))
		തിരികെ;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	സ്വതന്ത്രം(uids);
	സ്വതന്ത്രം(gids);
}

സ്ഥിതം ശൂന്യം
collect_ids_from_dirents(SFTP_DIRENT **d, പൂർണ്ണസംഖ്യ user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ശൂന്യ;

	വേണ്ടി (i = 0; d[i] != ശൂന്യ; i++) {
		എങ്കിൽ (user) {
			എങ്കിൽ (ruser_name((uid_t)(d[i]->a.uid)) != ശൂന്യ)
				തുടരുക; /* Already seen */
			id = d[i]->a.uid;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (rgroup_name((gid_t)(d[i]->a.gid)) != ശൂന്യ)
				തുടരുക; /* Already seen */
			id = d[i]->a.gid;
		}
		എങ്കിൽ (has_id(id, ids, n))
			തുടരുക;
		ids = xrecallocarray(ids, n, n + 1, വലുപ്പം(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ശൂന്യം
get_remote_user_groups_from_dirents(ഘടന sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = ശൂന്യ, nuids = 0, *gids = ശൂന്യ, ngids = 0;

	എങ്കിൽ (!sftp_can_get_users_groups_by_id(conn))
		തിരികെ;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	സ്വതന്ത്രം(uids);
	സ്വതന്ത്രം(gids);
}

സ്ഥിരം അക്ഷരം *
ruser_name(uid_t uid)
{
	തിരികെ idname_lookup(&user_idname, (u_int)uid);
}

സ്ഥിരം അക്ഷരം *
rgroup_name(uid_t gid)
{
	തിരികെ idname_lookup(&group_idname, (u_int)gid);
}

