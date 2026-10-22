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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/tree.h>

#समावेश <glob.h>
#समावेश <stdlib.h>
#समावेश <stdarg.h>
#समावेश <string.h>

#समावेश "log.h"
#समावेश "xmalloc.h"

#समावेश "sftp-common.h"
#समावेश "sftp-client.h"
#समावेश "sftp-usergroup.h"

/* Tree of id, name */
काष्ठा idname {
        u_int id;
	अक्षर *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
अटल पूर्णांक
idname_cmp(काष्ठा idname *a, काष्ठा idname *b)
{
	अगर (a->id == b->id)
		वापस 0;
	वापस a->id > b->id ? 1 : -1;
}
RB_शीर्ष(idname_वृक्ष, idname);
RB_GENERATE_STATIC(idname_वृक्ष, idname, entry, idname_cmp)

अटल काष्ठा idname_वृक्ष user_idname = RB_INITIALIZER(&user_idname);
अटल काष्ठा idname_वृक्ष group_idname = RB_INITIALIZER(&group_idname);

अटल व्योम
idname_free(काष्ठा idname *idname)
{
	अगर (idname == शून्य)
		वापस;
	मुक्त(idname->name);
	मुक्त(idname);
}

अटल व्योम
idname_enter(काष्ठा idname_वृक्ष *वृक्ष, u_int id, स्थिर अक्षर *name)
{
	काष्ठा idname *idname;

	अगर ((idname = xcalloc(1, माप(*idname))) == शून्य)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	अगर (RB_जोड़ो(idname_वृक्ष, वृक्ष, idname) != शून्य)
		idname_free(idname);
}

अटल स्थिर अक्षर *
idname_lookup(काष्ठा idname_वृक्ष *वृक्ष, u_int id)
{
	काष्ठा idname idname, *found;

	स_रखो(&idname, 0, माप(idname));
	idname.id = id;
	अगर ((found = RB_FIND(idname_वृक्ष, वृक्ष, &idname)) != शून्य)
		वापस found->name;
	वापस शून्य;
}

अटल व्योम
freenames(अक्षर **names, u_int nnames)
{
	u_int i;

	अगर (names == शून्य)
		वापस;
	क्रम (i = 0; i < nnames; i++)
		मुक्त(names[i]);
	मुक्त(names);
}

अटल व्योम
lookup_and_record(काष्ठा sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	पूर्णांक r;
	u_int i;
	अक्षर **usernames = शून्य, **groupnames = शून्य;

	अगर ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		वापस;
	}
	क्रम (i = 0; i < nuids; i++) {
		अगर (usernames[i] == शून्य) {
			debug3_f("uid %u not resolved", uids[i]);
			जारी;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	क्रम (i = 0; i < ngids; i++) {
		अगर (groupnames[i] == शून्य) {
			debug3_f("gid %u not resolved", gids[i]);
			जारी;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

अटल पूर्णांक
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	अगर (nids == 0)
		वापस 0;

	/* XXX O(N^2) */
	क्रम (i = 0; i < nids; i++) {
		अगर (ids[i] == id)
			अवरोध;
	}
	वापस i < nids;
}

अटल व्योम
collect_ids_from_glob(glob_t *g, पूर्णांक user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = शून्य;

	क्रम (i = 0; g->gl_pathv[i] != शून्य; i++) {
		अगर (g->gl_statv[i] == शून्य) /* no stat information */
			जारी;
		अगर (user) {
			अगर (ruser_name(g->gl_statv[i]->st_uid) != शून्य)
				जारी; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} अन्यथा {
			अगर (rgroup_name(g->gl_statv[i]->st_gid) != शून्य)
				जारी; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		अगर (has_id(id, ids, n))
			जारी;
		ids = xrecallocarray(ids, n, n + 1, माप(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

व्योम
get_remote_user_groups_from_glob(काष्ठा sftp_conn *conn, glob_t *g)
{
	u_int *uids = शून्य, nuids = 0, *gids = शून्य, ngids = 0;

	अगर (!sftp_can_get_users_groups_by_id(conn))
		वापस;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	मुक्त(uids);
	मुक्त(gids);
}

अटल व्योम
collect_ids_from_dirents(SFTP_DIRENT **d, पूर्णांक user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = शून्य;

	क्रम (i = 0; d[i] != शून्य; i++) {
		अगर (user) {
			अगर (ruser_name((uid_t)(d[i]->a.uid)) != शून्य)
				जारी; /* Already seen */
			id = d[i]->a.uid;
		} अन्यथा {
			अगर (rgroup_name((gid_t)(d[i]->a.gid)) != शून्य)
				जारी; /* Already seen */
			id = d[i]->a.gid;
		}
		अगर (has_id(id, ids, n))
			जारी;
		ids = xrecallocarray(ids, n, n + 1, माप(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

व्योम
get_remote_user_groups_from_dirents(काष्ठा sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = शून्य, nuids = 0, *gids = शून्य, ngids = 0;

	अगर (!sftp_can_get_users_groups_by_id(conn))
		वापस;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	मुक्त(uids);
	मुक्त(gids);
}

स्थिर अक्षर *
ruser_name(uid_t uid)
{
	वापस idname_lookup(&user_idname, (u_int)uid);
}

स्थिर अक्षर *
rgroup_name(uid_t gid)
{
	वापस idname_lookup(&group_idname, (u_int)gid);
}

