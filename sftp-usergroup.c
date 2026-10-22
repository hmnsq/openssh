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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/tree.h>

#अन्तर्भाव <glob.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "xmalloc.h"

#अन्तर्भाव "sftp-common.h"
#अन्तर्भाव "sftp-client.h"
#अन्तर्भाव "sftp-usergroup.h"

/* Tree of id, name */
संरचना idname {
        u_int id;
	अक्षर *name;
        RB_ENTRY(idname) entry;
	/* XXX implement bounded cache as TAILQ */
};
स्थिर पूर्णांक
idname_cmp(संरचना idname *a, संरचना idname *b)
{
	जर (a->id == b->id)
		परत 0;
	परत a->id > b->id ? 1 : -1;
}
RB_HEAD(idname_वृक्ष, idname);
RB_GENERATE_STATIC(idname_वृक्ष, idname, entry, idname_cmp)

स्थिर संरचना idname_वृक्ष user_idname = RB_INITIALIZER(&user_idname);
स्थिर संरचना idname_वृक्ष group_idname = RB_INITIALIZER(&group_idname);

स्थिर शून्य
idname_free(संरचना idname *idname)
{
	जर (idname == रिक्त)
		परत;
	मुक्त(idname->name);
	मुक्त(idname);
}

स्थिर शून्य
idname_enter(संरचना idname_वृक्ष *वृक्ष, u_int id, स्थिरांक अक्षर *name)
{
	संरचना idname *idname;

	जर ((idname = xcalloc(1, आकार(*idname))) == रिक्त)
		fatal_f("alloc");
	idname->id = id;
	idname->name = xstrdup(name);
	जर (RB_घाला(idname_वृक्ष, वृक्ष, idname) != रिक्त)
		idname_free(idname);
}

स्थिर स्थिरांक अक्षर *
idname_lookup(संरचना idname_वृक्ष *वृक्ष, u_int id)
{
	संरचना idname idname, *found;

	स_रखो(&idname, 0, आकार(idname));
	idname.id = id;
	जर ((found = RB_FIND(idname_वृक्ष, वृक्ष, &idname)) != रिक्त)
		परत found->name;
	परत रिक्त;
}

स्थिर शून्य
freenames(अक्षर **names, u_int nnames)
{
	u_int i;

	जर (names == रिक्त)
		परत;
	साठी (i = 0; i < nnames; i++)
		मुक्त(names[i]);
	मुक्त(names);
}

स्थिर शून्य
lookup_and_record(संरचना sftp_conn *conn,
    u_int *uids, u_int nuids, u_int *gids, u_int ngids)
{
	पूर्णांक r;
	u_int i;
	अक्षर **usernames = रिक्त, **groupnames = रिक्त;

	जर ((r = sftp_get_users_groups_by_id(conn, uids, nuids, gids, ngids,
	    &usernames, &groupnames)) != 0) {
		debug_fr(r, "sftp_get_users_groups_by_id");
		परत;
	}
	साठी (i = 0; i < nuids; i++) {
		जर (usernames[i] == रिक्त) {
			debug3_f("uid %u not resolved", uids[i]);
			सुरूठेवा;
		}
		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
		idname_enter(&user_idname, uids[i], usernames[i]);
	}
	साठी (i = 0; i < ngids; i++) {
		जर (groupnames[i] == रिक्त) {
			debug3_f("gid %u not resolved", gids[i]);
			सुरूठेवा;
		}
		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
		idname_enter(&group_idname, gids[i], groupnames[i]);
	}
	freenames(usernames, nuids);
	freenames(groupnames, ngids);
}

स्थिर पूर्णांक
has_id(u_int id, u_int *ids, u_int nids)
{
	u_int i;

	जर (nids == 0)
		परत 0;

	/* XXX O(N^2) */
	साठी (i = 0; i < nids; i++) {
		जर (ids[i] == id)
			थांबा;
	}
	परत i < nids;
}

स्थिर शून्य
collect_ids_from_glob(glob_t *g, पूर्णांक user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = रिक्त;

	साठी (i = 0; g->gl_pathv[i] != रिक्त; i++) {
		जर (g->gl_statv[i] == रिक्त) /* no stat information */
			सुरूठेवा;
		जर (user) {
			जर (ruser_name(g->gl_statv[i]->st_uid) != रिक्त)
				सुरूठेवा; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_uid;
		} अन्यथा {
			जर (rgroup_name(g->gl_statv[i]->st_gid) != रिक्त)
				सुरूठेवा; /* Already seen */
			id = (u_int)g->gl_statv[i]->st_gid;
		}
		जर (has_id(id, ids, n))
			सुरूठेवा;
		ids = xrecallocarray(ids, n, n + 1, आकार(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

शून्य
get_remote_user_groups_from_glob(संरचना sftp_conn *conn, glob_t *g)
{
	u_int *uids = रिक्त, nuids = 0, *gids = रिक्त, ngids = 0;

	जर (!sftp_can_get_users_groups_by_id(conn))
		परत;

	collect_ids_from_glob(g, 1, &uids, &nuids);
	collect_ids_from_glob(g, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	मुक्त(uids);
	मुक्त(gids);
}

स्थिर शून्य
collect_ids_from_dirents(SFTP_DIRENT **d, पूर्णांक user, u_int **idsp, u_int *nidsp)
{
	u_int id, i, n = 0, *ids = रिक्त;

	साठी (i = 0; d[i] != रिक्त; i++) {
		जर (user) {
			जर (ruser_name((uid_t)(d[i]->a.uid)) != रिक्त)
				सुरूठेवा; /* Already seen */
			id = d[i]->a.uid;
		} अन्यथा {
			जर (rgroup_name((gid_t)(d[i]->a.gid)) != रिक्त)
				सुरूठेवा; /* Already seen */
			id = d[i]->a.gid;
		}
		जर (has_id(id, ids, n))
			सुरूठेवा;
		ids = xrecallocarray(ids, n, n + 1, आकार(*ids));
		ids[n++] = id;
	}
	*idsp = ids;
	*nidsp = n;
}

शून्य
get_remote_user_groups_from_dirents(संरचना sftp_conn *conn, SFTP_DIRENT **d)
{
	u_int *uids = रिक्त, nuids = 0, *gids = रिक्त, ngids = 0;

	जर (!sftp_can_get_users_groups_by_id(conn))
		परत;

	collect_ids_from_dirents(d, 1, &uids, &nuids);
	collect_ids_from_dirents(d, 0, &gids, &ngids);
	lookup_and_record(conn, uids, nuids, gids, ngids);
	मुक्त(uids);
	मुक्त(gids);
}

स्थिरांक अक्षर *
ruser_name(uid_t uid)
{
	परत idname_lookup(&user_idname, (u_int)uid);
}

स्थिरांक अक्षर *
rgroup_name(uid_t gid)
{
	परत idname_lookup(&group_idname, (u_int)gid);
}

