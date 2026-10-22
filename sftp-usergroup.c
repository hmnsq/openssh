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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/tree.h>

#ଅନ୍ତର୍ଭାଵ <glob.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

#ଅନ୍ତର୍ଭାଵ "sftp-common.h"
#ଅନ୍ତର୍ଭାଵ "sftp-client.h"
#ଅନ୍ତର୍ଭାଵ "sftp-usergroup.h"

/* Tree of id, name */
ସଂରଚନା idname {
        u_int id;
	ଅକ୍ଷର *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
idname_cmp(ସଂରଚନା idname *a, ସଂରଚନା idname *b)
{
	ଯଦି (a->id == b->id)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_ବୃକ୍ଷ, idname);
RB_GENERATE_STATIC(idname_ବୃକ୍ଷ, idname, entry, idname_cmp)

ସ୍ଥିର ସଂରଚନା idname_ବୃକ୍ଷ user_idname = RB_INITIALIZER(&user_idname);
ସ୍ଥିର ସଂରଚନା idname_ବୃକ୍ଷ group_idname = RB_INITIALIZER(&group_idname);

ସ୍ଥିର ଶୂନ୍ୟ
idname_free(ସଂରଚନା idname *idname)
{
	ଯଦି (idname == ଖାଲି)
		ଫେରନ୍ତୁ;
	ମୁକ୍ତ(idname->name);
	ମୁକ୍ତ(idname);
}

ସ୍ଥିର ଶୂନ୍ୟ
idname_enter(ସଂରଚନା idname_ବୃକ୍ଷ *ବୃକ୍ଷ, u_int id, ଅଚଳ ଅକ୍ଷର *name)
{
	ସଂରଚନା idname *idname;

	ଯଦି ((idname = xcalloc(1, ଆକାର(*idname))) == ଖାଲି)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	ଯଦି (RB_ଭର୍ତ୍ତି(idname_ବୃକ୍ଷ, ବୃକ୍ଷ, idname) != ଖାଲି)
		idname_free(idname);
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
idname_lookup(ସଂରଚନା idname_ବୃକ୍ଷ *ବୃକ୍ଷ, u_int id)
{
	ସଂରଚନା idname idname, *found;

	memset(&idname, 0, ଆକାର(idname));
	idname.id = id;
	ଯଦି ((found = RB_FIND(idname_ବୃକ୍ଷ, ବୃକ୍ଷ, &idname)) != ଖାଲି)
		ଫେରନ୍ତୁ found->name;
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ଶୂନ୍ୟ
freenames(ଅକ୍ଷର **names, u_int nnames)
{
	u_int i;

	ଯଦି (names == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < nnames; i++)
		ମୁକ୍ତ(names[i]);
	ମୁକ୍ତ(names);
}

ସ୍ଥିର ଶୂନ୍ୟ
lookup_and_record(ସଂରଚନା sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;
	ଅକ୍ଷର **usernames = ଖାଲି, **groupnames = ଖାଲି;

	ଯଦି ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		ଫେରନ୍ତୁ;
	}
	ପାଇଁ (i = 0; i < nuids; i++) {
		ଯଦି (usernames[i] == ଖାଲି) {
			debug3_f("uid %u not resolved", uids[i]);
			ଜାରି;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	ପାଇଁ (i = 0; i < ngids; i++) {
		ଯଦି (groupnames[i] == ଖାଲି) {
			debug3_f("gid %u not resolved", gids[i]);
			ଜାରି;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	ଯଦି (nids == 0)
		ଫେରନ୍ତୁ 0;

	/* XXX O(N^2) */
	ପାଇଁ (i = 0; i < nids; i++) {
		ଯଦି (ids[i] == id)
			ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ i < nids;
}

ସ୍ଥିର ଶୂନ୍ୟ
collect_ids_from_glob(glob_t *g, ପୂର୍ଣ୍ଣସଂଖ୍ୟା user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ଖାଲି;

	ପାଇଁ (i = 0; g->gl_pathv[i] != ଖାଲି; i++) {
		ଯଦି (g->gl_statv[i] == ଖାଲି) /* no stat information */
			ଜାରି;
		ଯଦି (user) {
			ଯଦି (ruser_name(g->gl_statv[i]->st_uid) != ଖାଲି)
				ଜାରି; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} ଅନ୍ୟଥା {
			ଯଦି (rgroup_name(g->gl_statv[i]->st_gid) != ଖାଲି)
				ଜାରି; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		ଯଦି (has_id(id, ids, n))
			ଜାରି;
		ids = xrecallocarray(ids, n, n + 1, ଆକାର(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ଶୂନ୍ୟ
get_remote_user_groups_from_glob(ସଂରଚନା sftp_conn *conn, glob_t *g)
{
	u_int *uids = ଖାଲି, nuids = 0, *gids = ଖାଲି, ngids = 0;

	ଯଦି (!sftp_can_get_users_groups_by_id(conn))
		ଫେରନ୍ତୁ;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	ମୁକ୍ତ(uids);
	ମୁକ୍ତ(gids);
}

ସ୍ଥିର ଶୂନ୍ୟ
collect_ids_from_dirents(SFTP_DIRENT **d, ପୂର୍ଣ୍ଣସଂଖ୍ୟା user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = ଖାଲି;

	ପାଇଁ (i = 0; d[i] != ଖାଲି; i++) {
		ଯଦି (user) {
			ଯଦି (ruser_name((uid_t)(d[i]->a.uid)) != ଖାଲି)
				ଜାରି; /* Already seen */
			id = d[i]->a.uid;
		} ଅନ୍ୟଥା {
			ଯଦି (rgroup_name((gid_t)(d[i]->a.gid)) != ଖାଲି)
				ଜାରି; /* Already seen */
			id = d[i]->a.gid;
		}
		ଯଦି (has_id(id, ids, n))
			ଜାରି;
		ids = xrecallocarray(ids, n, n + 1, ଆକାର(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

ଶୂନ୍ୟ
get_remote_user_groups_from_dirents(ସଂରଚନା sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = ଖାଲି, nuids = 0, *gids = ଖାଲି, ngids = 0;

	ଯଦି (!sftp_can_get_users_groups_by_id(conn))
		ଫେରନ୍ତୁ;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	ମୁକ୍ତ(uids);
	ମୁକ୍ତ(gids);
}

ଅଚଳ ଅକ୍ଷର *
ruser_name(uid_t uid)
{
	ଫେରନ୍ତୁ idname_lookup(&user_idname, (u_int)uid);
}

ଅଚଳ ଅକ୍ଷର *
rgroup_name(uid_t gid)
{
	ଫେରନ୍ତୁ idname_lookup(&group_idname, (u_int)gid);
}

