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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/tree.h>

#అన్తర్భావ <glob.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "xmalloc.h"

#అన్తర్భావ "sftp-common.h"
#అన్తర్భావ "sftp-client.h"
#అన్తర్భావ "sftp-usergroup.h"

/* Tree of id, name */
నిర్మాణం idname {
        u_int id;
	అక్షరం *name;
        RB_నమోదు(idname) నమోదు_2;
	/* XXX implement bounded cache as TAILQ */
};
స్థిర పూర్ణాంకం
idname_cmp(నిర్మాణం idname *a, నిర్మాణం idname *b)
{
	ఒకవేళ (a->id == b->id)
		తిరిగి 0;
	తిరిగి a->id > b->id ? 1 : -1;
}
RB_తల(idname_వృక్షం, idname);
RB_GENERATE_STATIC(idname_వృక్షం, idname, నమోదు_2, idname_cmp)

స్థిర నిర్మాణం idname_వృక్షం user_idname = RB_INITIALIZER(&user_idname);
స్థిర నిర్మాణం idname_వృక్షం సమూహం_idname = RB_INITIALIZER(&సమూహం_idname);

స్థిర శూన్య
idname_free(నిర్మాణం idname *idname)
{
	ఒకవేళ (idname == ఖాళీ)
		తిరిగి;
	విడుదల(idname->name);
	విడుదల(idname);
}

స్థిర శూన్య
idname_enter(నిర్మాణం idname_వృక్షం *వృక్షం, u_int id, స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం idname *idname;

	ఒకవేళ ((idname = xcalloc(1, పరిమాణం(*idname))) == ఖాళీ)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	ఒకవేళ (RB_చొప్పించు(idname_వృక్షం, వృక్షం, idname) != ఖాళీ)
		idname_free(idname);
}

స్థిర స్థిరరాశి అక్షరం *
idname_lookup(నిర్మాణం idname_వృక్షం *వృక్షం, u_int id)
{
	నిర్మాణం idname idname, *దొరికింది;

	memset(&idname, 0, పరిమాణం(idname));
	idname.id = id;
	ఒకవేళ ((దొరికింది = RB_కనుగొను(idname_వృక్షం, వృక్షం, &idname)) != ఖాళీ)
		తిరిగి దొరికింది->name;
	తిరిగి ఖాళీ;
}

స్థిర శూన్య
freenames(అక్షరం **పేర్లు, u_int nnames)
{
	u_int i;

	ఒకవేళ (పేర్లు == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < nnames; i++)
		విడుదల(పేర్లు[i]);
	విడుదల(పేర్లు);
}

స్థిర శూన్య
lookup_and_రికార్డు(నిర్మాణం sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	పూర్ణాంకం r;
	u_int i;
	అక్షరం **usernames = ఖాళీ, **groupnames = ఖాళీ;

	ఒకవేళ ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		తిరిగి;
	}
	కొరకు (i = 0; i < nuids; i++) {
		ఒకవేళ (usernames[i] == ఖాళీ) {
			debug3_f("uid %u not resolved", uids[i]);
			కొనసాగు;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	కొరకు (i = 0; i < ngids; i++) {
		ఒకవేళ (groupnames[i] == ఖాళీ) {
			debug3_f("gid %u not resolved", gids[i]);
			కొనసాగు;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&సమూహం_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

స్థిర పూర్ణాంకం
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	ఒకవేళ (nids == 0)
		తిరిగి 0;

	/* XXX O(N^2) */
	కొరకు (i = 0; i < nids; i++) {
		ఒకవేళ (ids[i] == id)
			ఆపు;
	}
	తిరిగి i < nids;
}

స్థిర శూన్య
collect_ids_from_glob(glob_t *g, పూర్ణాంకం user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ఖాళీ;

	కొరకు (i = 0; g->gl_pathv[i] != ఖాళీ; i++) {
		ఒకవేళ (g->gl_statv[i] == ఖాళీ) /* no stat information */
			కొనసాగు;
		ఒకవేళ (user) {
			ఒకవేళ (ruser_name(g->gl_statv[i]->st_uid) != ఖాళీ)
				కొనసాగు; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} లేకపోతే {
			ఒకవేళ (rgroup_name(g->gl_statv[i]->st_gid) != ఖాళీ)
				కొనసాగు; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		ఒకవేళ (has_id(id, ids, n))
			కొనసాగు;
		ids = xrecallocarray(ids, n, n + 1, పరిమాణం(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

శూన్య
get_remote_user_groups_from_glob(నిర్మాణం sftp_conn *conn, glob_t *g)
{
	u_int *uids = ఖాళీ, nuids = 0, *gids = ఖాళీ, ngids = 0;

	ఒకవేళ (!sftp_can_get_users_groups_by_id(conn))
		తిరిగి;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_రికార్డు(conn, uids, nuids, gids, ngids);
	విడుదల(uids);
	విడుదల(gids);
}

స్థిర శూన్య
collect_ids_from_dirents(SFTP_DIRENT **d, పూర్ణాంకం user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ఖాళీ;

	కొరకు (i = 0; d[i] != ఖాళీ; i++) {
		ఒకవేళ (user) {
			ఒకవేళ (ruser_name((uid_t)(d[i]->a.uid)) != ఖాళీ)
				కొనసాగు; /* Already seen */
			id = d[i]->a.uid;
		} లేకపోతే {
			ఒకవేళ (rgroup_name((gid_t)(d[i]->a.gid)) != ఖాళీ)
				కొనసాగు; /* Already seen */
			id = d[i]->a.gid;
		}
		ఒకవేళ (has_id(id, ids, n))
			కొనసాగు;
		ids = xrecallocarray(ids, n, n + 1, పరిమాణం(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

శూన్య
get_remote_user_groups_from_dirents(నిర్మాణం sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = ఖాళీ, nuids = 0, *gids = ఖాళీ, ngids = 0;

	ఒకవేళ (!sftp_can_get_users_groups_by_id(conn))
		తిరిగి;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_రికార్డు(conn, uids, nuids, gids, ngids);
	విడుదల(uids);
	విడుదల(gids);
}

స్థిరరాశి అక్షరం *
ruser_name(uid_t uid)
{
	తిరిగి idname_lookup(&user_idname, (u_int)uid);
}

స్థిరరాశి అక్షరం *
rgroup_name(uid_t gid)
{
	తిరిగి idname_lookup(&సమూహం_idname, (u_int)gid);
}

