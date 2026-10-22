/*
 * Copyright (c) 2006 Chad Mynhier.
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

#समावेश "config.h"
#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <errno.h>
#अगर_घोषित HAVE_FCNTL_H
# include <fcntl.h>
#पूर्ण_अगर
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "log.h"

#अगर_घोषित USE_SOLARIS_PROCESS_CONTRACTS

#समावेश <libcontract.h>
#समावेश <sys/contract/process.h>
#समावेश <sys/ctfs.h>

#घोषणा CT_TEMPLATE	CTFS_मूल "/process/template"
#घोषणा CT_LATEST	CTFS_मूल "/process/latest"

अटल पूर्णांक tmpl_fd = -1;

/* Lookup the latest process contract */
अटल ctid_t
get_active_process_contract_id(व्योम)
{
	पूर्णांक stat_fd;
	ctid_t ctid = -1;
	ct_stathdl_t stathdl;

	अगर ((stat_fd = open64(CT_LATEST, O_RDONLY)) == -1) {
		error("%s: Error opening 'latest' process "
		    "contract: %s", __func__, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (ct_status_read(stat_fd, CTD_COMMON, &stathdl) != 0) {
		error("%s: Error reading process contract "
		    "status: %s", __func__, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर ((ctid = ct_status_get_id(stathdl)) < 0) {
		error("%s: Error getting process contract id: %s",
		    __func__, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}

	ct_status_free(stathdl);
 out:
	बंद(stat_fd);
	वापस ctid;
}

व्योम
solaris_contract_pre_fork(व्योम)
{
	अगर ((tmpl_fd = open64(CT_TEMPLATE, O_RDWR)) == -1) {
		error("%s: open %s: %s", __func__,
		    CT_TEMPLATE, म_त्रुटि(त्रुटि_सं));
		वापस;
	}

	debug2("%s: setting up process contract template on fd %d",
	    __func__, tmpl_fd);

	/* First we set the template parameters and event sets. */
	अगर (ct_pr_tmpl_set_param(tmpl_fd, CT_PR_PGRPONLY) != 0) {
		error("%s: Error setting process contract parameter set "
		    "(pgrponly): %s", __func__, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}
	अगर (ct_pr_tmpl_set_fatal(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "fatal events: %s", __func__, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}
	अगर (ct_tmpl_set_critical(tmpl_fd, 0) != 0) {
		error("%s: Error setting process contract template "
		    "critical events: %s", __func__, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}
	अगर (ct_tmpl_set_informative(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "informative events: %s", __func__, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}

	/* Now make this the active template for this process. */
	अगर (ct_tmpl_activate(tmpl_fd) != 0) {
		error("%s: Error activating process contract "
		    "template: %s", __func__, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}
	वापस;

 fail:
	अगर (tmpl_fd != -1) {
		बंद(tmpl_fd);
		tmpl_fd = -1;
	}
}

व्योम
solaris_contract_post_fork_child()
{
	debug2("%s: clearing process contract template on fd %d",
	    __func__, tmpl_fd);

	/* Clear the active template. */
	अगर (ct_tmpl_clear(tmpl_fd) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, म_त्रुटि(त्रुटि_सं));

	बंद(tmpl_fd);
	tmpl_fd = -1;
}

व्योम
solaris_contract_post_fork_parent(pid_t pid)
{
	ctid_t ctid;
	अक्षर ctl_path[256];
	पूर्णांक r, ctl_fd = -1, stat_fd = -1;

	debug2("%s: clearing template (fd %d)", __func__, tmpl_fd);

	अगर (tmpl_fd == -1)
		वापस;

	/* First clear the active template. */
	अगर ((r = ct_tmpl_clear(tmpl_fd)) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, म_त्रुटि(त्रुटि_सं));

	बंद(tmpl_fd);
	tmpl_fd = -1;

	/*
	 * If either the fork didn't succeed (pid < 0), or clearing
	 * th active contract failed (r != 0), then we have nothing
	 * more do.
	 */
	अगर (r != 0 || pid <= 0)
		वापस;

	/* Now lookup and abandon the contract we've created. */
	ctid = get_active_process_contract_id();

	debug2("%s: abandoning contract id %ld", __func__, ctid);

	snprintf(ctl_path, माप(ctl_path),
	    CTFS_मूल "/process/%ld/ctl", ctid);
	अगर ((ctl_fd = open64(ctl_path, O_WRONLY)) < 0) {
		error("%s: Error opening process contract "
		    "ctl file: %s", __func__, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}
	अगर (ct_ctl_abandon(ctl_fd) < 0) {
		error("%s: Error abandoning process contract: %s",
		    __func__, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}
	बंद(ctl_fd);
	वापस;

 fail:
	अगर (tmpl_fd != -1) {
		बंद(tmpl_fd);
		tmpl_fd = -1;
	}
	अगर (stat_fd != -1)
		बंद(stat_fd);
	अगर (ctl_fd != -1)
		बंद(ctl_fd);
}
#पूर्ण_अगर

#अगर_घोषित USE_SOLARIS_PROJECTS
#समावेश <sys/task.h>
#समावेश <project.h>

/*
 * Get/set solaris default project.
 * If we fail, just run along gracefully.
 */
व्योम
solaris_set_default_project(काष्ठा passwd *pw)
{
	काष्ठा project  *defaultproject;
	काष्ठा project   tempproject;
	अक्षर buf[1024];

	/* get default project, if we fail just return gracefully  */
	अगर ((defaultproject = getdefaultproj(pw->pw_name, &tempproject, &buf,
	    माप(buf))) != शून्य) {
		/* set default project */
		अगर (setproject(defaultproject->pj_name, pw->pw_name,
		    TASK_NORMAL) != 0)
			debug("setproject(%s): %s", defaultproject->pj_name,
			    म_त्रुटि(त्रुटि_सं));
	} अन्यथा {
		/* debug on getdefaultproj() error */
		debug("getdefaultproj(%s): %s", pw->pw_name, म_त्रुटि(त्रुटि_सं));
	}
}
#पूर्ण_अगर /* USE_SOLARIS_PROJECTS */

#अगर_घोषित USE_SOLARIS_PRIVS
# ifdef HAVE_PRIV_H
#  include <priv.h>
# endif

priv_set_t *
solaris_basic_privset(व्योम)
{
	priv_set_t *pset;

#अगर_घोषित HAVE_PRIV_BASICSET
	अगर ((pset = priv_allocset()) == शून्य) {
		error("priv_allocset: %s", म_त्रुटि(त्रुटि_सं));
		वापस शून्य;
	}
	priv_basicset(pset);
#अन्यथा
	अगर ((pset = priv_str_to_set("basic", ",", शून्य)) == शून्य) {
		error("priv_str_to_set: %s", म_त्रुटि(त्रुटि_सं));
		वापस शून्य;
	}
#पूर्ण_अगर
	वापस pset;
}

व्योम
solaris_drop_privs_pinfo_net_fork_exec(व्योम)
{
	priv_set_t *pset = शून्य, *npset = शून्य;

	/*
	 * Note: this variant avoids dropping DAC filesystem rights, in case
	 * the process calling it is running as root and should have the
	 * ability to read/write/chown any file on the system.
	 *
	 * We start with the basic set, then *add* the DAC rights to it while
	 * taking away other parts of BASIC we don't need. Then we intersect
	 * this with our existing PERMITTED set. In this way we keep any
	 * DAC rights we had before, while otherwise reducing ourselves to
	 * the minimum set of privileges we need to proceed.
	 *
	 * This also means we drop any other parts of "root" that we don't
	 * need (e.g. the ability to kill any process, create new device nodes
	 * etc etc).
	 */

	अगर ((pset = priv_allocset()) == शून्य)
		fatal("priv_allocset: %s", म_त्रुटि(त्रुटि_सं));
	अगर ((npset = solaris_basic_privset()) == शून्य)
		fatal("solaris_basic_privset: %s", म_त्रुटि(त्रुटि_सं));

	अगर (priv_addset(npset, PRIV_FILE_CHOWN) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_READ) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_खोज) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_WRITE) != 0 ||
	    priv_addset(npset, PRIV_FILE_OWNER) != 0)
		fatal("priv_addset: %s", म_त्रुटि(त्रुटि_सं));

	अगर (priv_delset(npset, PRIV_PROC_EXEC) != 0 ||
#अगर_घोषित PRIV_NET_ACCESS
	    priv_delset(npset, PRIV_NET_ACCESS) != 0 ||
#पूर्ण_अगर
	    priv_delset(npset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(npset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(npset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", म_त्रुटि(त्रुटि_सं));

#अगर_घोषित PRIV_XPOLICY
	/*
	 * It is possible that the user has an extended policy
	 * in place; the LIMIT set restricts the extended policy
	 * and so should not be restricted.
	 * PRIV_XPOLICY is newly defined in Solaris 11 though the extended
	 * policy was not implemented until Solaris 11.1.
	 */
	अगर (getpflags(PRIV_XPOLICY) == 1) {
		अगर (getppriv(PRIV_LIMIT, pset) != 0)
			fatal("getppriv: %s", म_त्रुटि(त्रुटि_सं));
		priv_intersect(pset, npset);
		अगर (setppriv(PRIV_SET, PRIV_LIMIT, npset) != 0)
			fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));
	} अन्यथा
#पूर्ण_अगर
	{
		/* Cannot exec, so we can kill the limit set. */
		priv_emptyset(pset);
		अगर (setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0)
			fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));
	}

	अगर (getppriv(PRIV_PERMITTED, pset) != 0)
		fatal("getppriv: %s", म_त्रुटि(त्रुटि_सं));

	priv_intersect(pset, npset);

	अगर (setppriv(PRIV_SET, PRIV_PERMITTED, npset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, npset) != 0)
		fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));

	priv_freeset(pset);
	priv_freeset(npset);
}

व्योम
solaris_drop_privs_मूल_pinfo_net(व्योम)
{
	priv_set_t *pset = शून्य;

	/* Start with "basic" and drop everything we don't need. */
	अगर ((pset = solaris_basic_privset()) == शून्य)
		fatal("solaris_basic_privset: %s", म_त्रुटि(त्रुटि_सं));

	अगर (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#अगर_घोषित PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#पूर्ण_अगर
	    priv_delset(pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(pset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", म_त्रुटि(त्रुटि_सं));

	अगर (setppriv(PRIV_SET, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));

	priv_freeset(pset);
}

व्योम
solaris_drop_privs_मूल_pinfo_net_exec(व्योम)
{
	priv_set_t *pset = शून्य;


	/* Start with "basic" and drop everything we don't need. */
	अगर ((pset = solaris_basic_privset()) == शून्य)
		fatal("solaris_basic_privset: %s", म_त्रुटि(त्रुटि_सं));

	अगर (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#अगर_घोषित PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#पूर्ण_अगर
	    priv_delset(pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(pset, PRIV_PROC_INFO) != 0)
		fatal("priv_delset: %s", म_त्रुटि(त्रुटि_सं));

	अगर (setppriv(PRIV_SET, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));

	priv_freeset(pset);
}

#पूर्ण_अगर
