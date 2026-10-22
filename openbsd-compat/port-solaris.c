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

#ಅನ್ತರ್ಭಾವ "config.h"
#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCNTL_H
# include <fcntl.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SOLARIS_PROCESS_CONTRACTS

#ಅನ್ತರ್ಭಾವ <libcontract.h>
#ಅನ್ತರ್ಭಾವ <sys/contract/process.h>
#ಅನ್ತರ್ಭಾವ <sys/ctfs.h>

#ವ್ಯಾಖ್ಯಾನಿಸು CT_TEMPLATE	CTFS_ಬೇರು "/process/template"
#ವ್ಯಾಖ್ಯಾನಿಸು CT_LATEST	CTFS_ಬೇರು "/process/latest"

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ tmpl_fd = -1;

/* Lookup the latest process contract */
ಸ್ಥಿರ ctid_t
get_ಸಕ್ರಿಯ_process_contract_id(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ stat_fd;
	ctid_t ctid = -1;
	ct_stathdl_t stathdl;

	ಆದರೆ ((stat_fd = open64(CT_LATEST, O_RDONLY)) == -1) {
		error("%s: Error opening 'latest' process "
		    "contract: %s", __func__, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (ct_ಸ್ಥಿತಿ_read(stat_fd, CTD_COMMON, &stathdl) != 0) {
		error("%s: Error reading process contract "
		    "status: %s", __func__, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ctid = ct_ಸ್ಥಿತಿ_get_id(stathdl)) < 0) {
		error("%s: Error getting process contract id: %s",
		    __func__, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ct_ಸ್ಥಿತಿ_free(stathdl);
 ಹೊರಹೋಗು:
	close(stat_fd);
	ಹಿಂತಿರುಗಿ ctid;
}

ಶೂನ್ಯ
solaris_contract_pre_fork(ಶೂನ್ಯ)
{
	ಆದರೆ ((tmpl_fd = open64(CT_TEMPLATE, O_RDWR)) == -1) {
		error("%s: open %s: %s", __func__,
		    CT_TEMPLATE, strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}

	debug2("%s: setting up process contract template on fd %d",
	    __func__, tmpl_fd);

	/* First we set the template parameters and event sets. */
	ಆದರೆ (ct_pr_tmpl_ಗಣ_param(tmpl_fd, CT_PR_PGRPONLY) != 0) {
		error("%s: Error setting process contract parameter set "
		    "(pgrponly): %s", __func__, strerror(errno));
		ಹೋಗು fail;
	}
	ಆದರೆ (ct_pr_tmpl_ಗಣ_fatal(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "fatal events: %s", __func__, strerror(errno));
		ಹೋಗು fail;
	}
	ಆದರೆ (ct_tmpl_ಗಣ_critical(tmpl_fd, 0) != 0) {
		error("%s: Error setting process contract template "
		    "critical events: %s", __func__, strerror(errno));
		ಹೋಗು fail;
	}
	ಆದರೆ (ct_tmpl_ಗಣ_informative(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "informative events: %s", __func__, strerror(errno));
		ಹೋಗು fail;
	}

	/* Now make this the active template for this process. */
	ಆದರೆ (ct_tmpl_activate(tmpl_fd) != 0) {
		error("%s: Error activating process contract "
		    "template: %s", __func__, strerror(errno));
		ಹೋಗು fail;
	}
	ಹಿಂತಿರುಗಿ;

 fail:
	ಆದರೆ (tmpl_fd != -1) {
		close(tmpl_fd);
		tmpl_fd = -1;
	}
}

ಶೂನ್ಯ
solaris_contract_post_fork_ಮಗು()
{
	debug2("%s: clearing process contract template on fd %d",
	    __func__, tmpl_fd);

	/* Clear the active template. */
	ಆದರೆ (ct_tmpl_clear(tmpl_fd) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, strerror(errno));

	close(tmpl_fd);
	tmpl_fd = -1;
}

ಶೂನ್ಯ
solaris_contract_post_fork_ಪೋಷಕ(pid_t pid)
{
	ctid_t ctid;
	ಅಕ್ಷರ ctl_ಮಾರ್ಗ[256];
	ಪೂರ್ಣಾಂಕ r, ctl_fd = -1, stat_fd = -1;

	debug2("%s: clearing template (fd %d)", __func__, tmpl_fd);

	ಆದರೆ (tmpl_fd == -1)
		ಹಿಂತಿರುಗಿ;

	/* First clear the active template. */
	ಆದರೆ ((r = ct_tmpl_clear(tmpl_fd)) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, strerror(errno));

	close(tmpl_fd);
	tmpl_fd = -1;

	/*
	 * If either the fork didn't succeed (pid < 0), or clearing
	 * th active contract failed (r != 0), then we have nothing
	 * more do.
	 */
	ಆದರೆ (r != 0 || pid <= 0)
		ಹಿಂತಿರುಗಿ;

	/* Now lookup and abandon the contract we've created. */
	ctid = get_ಸಕ್ರಿಯ_process_contract_id();

	debug2("%s: abandoning contract id %ld", __func__, ctid);

	snprintf(ctl_ಮಾರ್ಗ, ಗಾತ್ರ(ctl_ಮಾರ್ಗ),
	    CTFS_ಬೇರು "/process/%ld/ctl", ctid);
	ಆದರೆ ((ctl_fd = open64(ctl_ಮಾರ್ಗ, O_WRONLY)) < 0) {
		error("%s: Error opening process contract "
		    "ctl file: %s", __func__, strerror(errno));
		ಹೋಗು fail;
	}
	ಆದರೆ (ct_ctl_abandon(ctl_fd) < 0) {
		error("%s: Error abandoning process contract: %s",
		    __func__, strerror(errno));
		ಹೋಗು fail;
	}
	close(ctl_fd);
	ಹಿಂತಿರುಗಿ;

 fail:
	ಆದರೆ (tmpl_fd != -1) {
		close(tmpl_fd);
		tmpl_fd = -1;
	}
	ಆದರೆ (stat_fd != -1)
		close(stat_fd);
	ಆದರೆ (ctl_fd != -1)
		close(ctl_fd);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SOLARIS_PROJECTS
#ಅನ್ತರ್ಭಾವ <sys/task.h>
#ಅನ್ತರ್ಭಾವ <project.h>

/*
 * Get/set solaris default project.
 * If we fail, just run along gracefully.
 */
ಶೂನ್ಯ
solaris_ಗಣ_default_project(ರಚನೆ passwd *pw)
{
	ರಚನೆ project  *defaultproject;
	ರಚನೆ project   tempproject;
	ಅಕ್ಷರ buf[1024];

	/* get default project, if we fail just return gracefully  */
	ಆದರೆ ((defaultproject = getdefaultproj(pw->pw_name, &tempproject, &buf,
	    ಗಾತ್ರ(buf))) != ಖಾಲಿ) {
		/* set default project */
		ಆದರೆ (setproject(defaultproject->pj_name, pw->pw_name,
		    TASK_ಸಾಮಾನ್ಯ) != 0)
			debug("setproject(%s): %s", defaultproject->pj_name,
			    strerror(errno));
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* debug on getdefaultproj() error */
		debug("getdefaultproj(%s): %s", pw->pw_name, strerror(errno));
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_SOLARIS_PROJECTS */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SOLARIS_PRIVS
# ifdef HAVE_PRIV_H
#  include <priv.h>
# endif

priv_ಗಣ_t *
solaris_basic_privset(ಶೂನ್ಯ)
{
	priv_ಗಣ_t *pset;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_PRIV_BASICSET
	ಆದರೆ ((pset = priv_allocset()) == ಖಾಲಿ) {
		error("priv_allocset: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	priv_basicset(pset);
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ ((pset = priv_str_ಗಮ್ಯ_ಗಣ("basic", ",", ಖಾಲಿ)) == ಖಾಲಿ) {
		error("priv_str_to_set: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ pset;
}

ಶೂನ್ಯ
solaris_drop_privs_pinfo_net_fork_exec(ಶೂನ್ಯ)
{
	priv_ಗಣ_t *pset = ಖಾಲಿ, *npset = ಖಾಲಿ;

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

	ಆದರೆ ((pset = priv_allocset()) == ಖಾಲಿ)
		fatal("priv_allocset: %s", strerror(errno));
	ಆದರೆ ((npset = solaris_basic_privset()) == ಖಾಲಿ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ಆದರೆ (priv_addset(npset, PRIV_FILE_CHOWN) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_READ) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_ಹುಡುಕು) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_WRITE) != 0 ||
	    priv_addset(npset, PRIV_FILE_OWNER) != 0)
		fatal("priv_addset: %s", strerror(errno));

	ಆದರೆ (priv_delset(npset, PRIV_PROC_EXEC) != 0 ||
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRIV_NET_ACCESS
	    priv_delset(npset, PRIV_NET_ACCESS) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
	    priv_delset(npset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(npset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(npset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", strerror(errno));

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRIV_XPOLICY
	/*
	 * It is possible that the user has an extended policy
	 * in place; the LIMIT set restricts the extended policy
	 * and so should not be restricted.
	 * PRIV_XPOLICY is newly defined in Solaris 11 though the extended
	 * policy was not implemented until Solaris 11.1.
	 */
	ಆದರೆ (getpflags(PRIV_XPOLICY) == 1) {
		ಆದರೆ (getppriv(PRIV_ಎಲ್ಲೆ, pset) != 0)
			fatal("getppriv: %s", strerror(errno));
		priv_intersect(pset, npset);
		ಆದರೆ (setppriv(PRIV_ಗಣ, PRIV_ಎಲ್ಲೆ, npset) != 0)
			fatal("setppriv: %s", strerror(errno));
	} ಇಲ್ಲದಿದ್ದರೆ
#ಆದರೆ_ಅಂತ್ಯ
	{
		/* Cannot exec, so we can kill the limit set. */
		priv_emptyset(pset);
		ಆದರೆ (setppriv(PRIV_ಗಣ, PRIV_ಎಲ್ಲೆ, pset) != 0)
			fatal("setppriv: %s", strerror(errno));
	}

	ಆದರೆ (getppriv(PRIV_PERMITTED, pset) != 0)
		fatal("getppriv: %s", strerror(errno));

	priv_intersect(pset, npset);

	ಆದರೆ (setppriv(PRIV_ಗಣ, PRIV_PERMITTED, npset) != 0 ||
	    setppriv(PRIV_ಗಣ, PRIV_INHERITABLE, npset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
	priv_freeset(npset);
}

ಶೂನ್ಯ
solaris_drop_privs_ಬೇರು_pinfo_net(ಶೂನ್ಯ)
{
	priv_ಗಣ_t *pset = ಖಾಲಿ;

	/* Start with "basic" and drop everything we don't need. */
	ಆದರೆ ((pset = solaris_basic_privset()) == ಖಾಲಿ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ಆದರೆ (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
	    priv_delset(pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(pset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", strerror(errno));

	ಆದರೆ (setppriv(PRIV_ಗಣ, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_ಗಣ, PRIV_ಎಲ್ಲೆ, pset) != 0 ||
	    setppriv(PRIV_ಗಣ, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
}

ಶೂನ್ಯ
solaris_drop_privs_ಬೇರು_pinfo_net_exec(ಶೂನ್ಯ)
{
	priv_ಗಣ_t *pset = ಖಾಲಿ;


	/* Start with "basic" and drop everything we don't need. */
	ಆದರೆ ((pset = solaris_basic_privset()) == ಖಾಲಿ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ಆದರೆ (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
	    priv_delset(pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(pset, PRIV_PROC_INFO) != 0)
		fatal("priv_delset: %s", strerror(errno));

	ಆದರೆ (setppriv(PRIV_ಗಣ, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_ಗಣ, PRIV_ಎಲ್ಲೆ, pset) != 0 ||
	    setppriv(PRIV_ಗಣ, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
}

#ಆದರೆ_ಅಂತ್ಯ
