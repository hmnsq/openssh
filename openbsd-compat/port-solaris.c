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

#अन्तर्भाव "config.h"
#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"

#ifdef USE_SOLARIS_PROCESS_CONTRACTS

#अन्तर्भाव <libcontract.h>
#अन्तर्भाव <sys/contract/process.h>
#अन्तर्भाव <sys/ctfs.h>

#define CT_TEMPLATE	CTFS_जरा "/process/template"
#define CT_LATEST	CTFS_जरा "/process/latest"

स्थिर पूर्णाङ्क tmpl_fd = -1;

/* Lookup the latest process contract */
स्थिर ctid_t
get_active_process_contract_id(शून्य)
{
	पूर्णाङ्क stat_fd;
	ctid_t ctid = -1;
	ct_stathdl_t stathdl;

	यदि ((stat_fd = open64(CT_LATEST, O_RDONLY)) == -1) {
		error("%s: Error opening 'latest' process "
		    "contract: %s", __func__, म_त्रुटि(त्रुटि_सं));
		फर्काऊ -1;
	}
	यदि (ct_status_read(stat_fd, CTD_COMMON, &stathdl) != 0) {
		error("%s: Error reading process contract "
		    "status: %s", __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	यदि ((ctid = ct_status_get_id(stathdl)) < 0) {
		error("%s: Error getting process contract id: %s",
		    __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}

	ct_status_free(stathdl);
 out:
	बंद(stat_fd);
	फर्काऊ ctid;
}

शून्य
solaris_contract_pre_fork(शून्य)
{
	यदि ((tmpl_fd = open64(CT_TEMPLATE, O_RDWR)) == -1) {
		error("%s: open %s: %s", __func__,
		    CT_TEMPLATE, म_त्रुटि(त्रुटि_सं));
		फर्काऊ;
	}

	debug2("%s: setting up process contract template on fd %d",
	    __func__, tmpl_fd);

	/* First we set the template parameters and event sets. */
	यदि (ct_pr_tmpl_set_param(tmpl_fd, CT_PR_PGRPONLY) != 0) {
		error("%s: Error setting process contract parameter set "
		    "(pgrponly): %s", __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}
	यदि (ct_pr_tmpl_set_fatal(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "fatal events: %s", __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}
	यदि (ct_tmpl_set_critical(tmpl_fd, 0) != 0) {
		error("%s: Error setting process contract template "
		    "critical events: %s", __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}
	यदि (ct_tmpl_set_informative(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "informative events: %s", __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}

	/* Now make this the active template for this process. */
	यदि (ct_tmpl_activate(tmpl_fd) != 0) {
		error("%s: Error activating process contract "
		    "template: %s", __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}
	फर्काऊ;

 fail:
	यदि (tmpl_fd != -1) {
		बंद(tmpl_fd);
		tmpl_fd = -1;
	}
}

शून्य
solaris_contract_post_fork_child()
{
	debug2("%s: clearing process contract template on fd %d",
	    __func__, tmpl_fd);

	/* Clear the active template. */
	यदि (ct_tmpl_clear(tmpl_fd) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, म_त्रुटि(त्रुटि_सं));

	बंद(tmpl_fd);
	tmpl_fd = -1;
}

शून्य
solaris_contract_post_fork_parent(pid_t pid)
{
	ctid_t ctid;
	वर्ण ctl_path[256];
	पूर्णाङ्क r, ctl_fd = -1, stat_fd = -1;

	debug2("%s: clearing template (fd %d)", __func__, tmpl_fd);

	यदि (tmpl_fd == -1)
		फर्काऊ;

	/* First clear the active template. */
	यदि ((r = ct_tmpl_clear(tmpl_fd)) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, म_त्रुटि(त्रुटि_सं));

	बंद(tmpl_fd);
	tmpl_fd = -1;

	/*
	 * If either the fork didn't succeed (pid < 0), or clearing
	 * th active contract failed (r != 0), then we have nothing
	 * more do.
	 */
	यदि (r != 0 || pid <= 0)
		फर्काऊ;

	/* Now lookup and abandon the contract we've created. */
	ctid = get_active_process_contract_id();

	debug2("%s: abandoning contract id %ld", __func__, ctid);

	snprintf(ctl_path, परिमाण(ctl_path),
	    CTFS_जरा "/process/%ld/ctl", ctid);
	यदि ((ctl_fd = open64(ctl_path, O_WRONLY)) < 0) {
		error("%s: Error opening process contract "
		    "ctl file: %s", __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}
	यदि (ct_ctl_abandon(ctl_fd) < 0) {
		error("%s: Error abandoning process contract: %s",
		    __func__, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}
	बंद(ctl_fd);
	फर्काऊ;

 fail:
	यदि (tmpl_fd != -1) {
		बंद(tmpl_fd);
		tmpl_fd = -1;
	}
	यदि (stat_fd != -1)
		बंद(stat_fd);
	यदि (ctl_fd != -1)
		बंद(ctl_fd);
}
#endif

#ifdef USE_SOLARIS_PROJECTS
#अन्तर्भाव <sys/task.h>
#अन्तर्भाव <project.h>

/*
 * Get/set solaris default project.
 * If we fail, just run along gracefully.
 */
शून्य
solaris_set_default_project(संरचना passwd *pw)
{
	संरचना project  *defaultproject;
	संरचना project   tempproject;
	वर्ण buf[1024];

	/* get default project, if we fail just return gracefully  */
	यदि ((defaultproject = getdefaultproj(pw->pw_name, &tempproject, &buf,
	    परिमाण(buf))) != रिक्त) {
		/* set default project */
		यदि (setproject(defaultproject->pj_name, pw->pw_name,
		    TASK_NORMAL) != 0)
			debug("setproject(%s): %s", defaultproject->pj_name,
			    म_त्रुटि(त्रुटि_सं));
	} अन्यथा {
		/* debug on getdefaultproj() error */
		debug("getdefaultproj(%s): %s", pw->pw_name, म_त्रुटि(त्रुटि_सं));
	}
}
#endif /* USE_SOLARIS_PROJECTS */

#ifdef USE_SOLARIS_PRIVS
# ifdef HAVE_PRIV_H
#  include <priv.h>
# endif

priv_set_t *
solaris_basic_privset(शून्य)
{
	priv_set_t *pset;

#ifdef HAVE_PRIV_BASICSET
	यदि ((pset = priv_allocset()) == रिक्त) {
		error("priv_allocset: %s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ रिक्त;
	}
	priv_basicset(pset);
#अन्यथा
	यदि ((pset = priv_str_to_set("basic", ",", रिक्त)) == रिक्त) {
		error("priv_str_to_set: %s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ रिक्त;
	}
#endif
	फर्काऊ pset;
}

शून्य
solaris_drop_privs_pinfo_net_fork_exec(शून्य)
{
	priv_set_t *pset = रिक्त, *npset = रिक्त;

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

	यदि ((pset = priv_allocset()) == रिक्त)
		fatal("priv_allocset: %s", म_त्रुटि(त्रुटि_सं));
	यदि ((npset = solaris_basic_privset()) == रिक्त)
		fatal("solaris_basic_privset: %s", म_त्रुटि(त्रुटि_सं));

	यदि (priv_addset(npset, PRIV_FILE_CHOWN) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_READ) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_खोज) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_WRITE) != 0 ||
	    priv_addset(npset, PRIV_FILE_OWNER) != 0)
		fatal("priv_addset: %s", म_त्रुटि(त्रुटि_सं));

	यदि (priv_delset(npset, PRIV_PROC_EXEC) != 0 ||
#ifdef PRIV_NET_ACCESS
	    priv_delset(npset, PRIV_NET_ACCESS) != 0 ||
#endif
	    priv_delset(npset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(npset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(npset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", म_त्रुटि(त्रुटि_सं));

#ifdef PRIV_XPOLICY
	/*
	 * It is possible that the user has an extended policy
	 * in place; the LIMIT set restricts the extended policy
	 * and so should not be restricted.
	 * PRIV_XPOLICY is newly defined in Solaris 11 though the extended
	 * policy was not implemented until Solaris 11.1.
	 */
	यदि (getpflags(PRIV_XPOLICY) == 1) {
		यदि (getppriv(PRIV_LIMIT, pset) != 0)
			fatal("getppriv: %s", म_त्रुटि(त्रुटि_सं));
		priv_intersect(pset, npset);
		यदि (setppriv(PRIV_SET, PRIV_LIMIT, npset) != 0)
			fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));
	} अन्यथा
#endif
	{
		/* Cannot exec, so we can kill the limit set. */
		priv_emptyset(pset);
		यदि (setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0)
			fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));
	}

	यदि (getppriv(PRIV_PERMITTED, pset) != 0)
		fatal("getppriv: %s", म_त्रुटि(त्रुटि_सं));

	priv_intersect(pset, npset);

	यदि (setppriv(PRIV_SET, PRIV_PERMITTED, npset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, npset) != 0)
		fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));

	priv_freeset(pset);
	priv_freeset(npset);
}

शून्य
solaris_drop_privs_जरा_pinfo_net(शून्य)
{
	priv_set_t *pset = रिक्त;

	/* Start with "basic" and drop everything we don't need. */
	यदि ((pset = solaris_basic_privset()) == रिक्त)
		fatal("solaris_basic_privset: %s", म_त्रुटि(त्रुटि_सं));

	यदि (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#ifdef PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#endif
	    priv_delset(pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(pset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", म_त्रुटि(त्रुटि_सं));

	यदि (setppriv(PRIV_SET, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));

	priv_freeset(pset);
}

शून्य
solaris_drop_privs_जरा_pinfo_net_exec(शून्य)
{
	priv_set_t *pset = रिक्त;


	/* Start with "basic" and drop everything we don't need. */
	यदि ((pset = solaris_basic_privset()) == रिक्त)
		fatal("solaris_basic_privset: %s", म_त्रुटि(त्रुटि_सं));

	यदि (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#ifdef PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#endif
	    priv_delset(pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(pset, PRIV_PROC_INFO) != 0)
		fatal("priv_delset: %s", म_त्रुटि(त्रुटि_सं));

	यदि (setppriv(PRIV_SET, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));

	priv_freeset(pset);
}

#endif
