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

#అన్తర్భావ "config.h"
#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <errno.h>
#నిర్వచితమైతే HAVE_FCNTL_H
# include <fcntl.h>
#అయితే_ముగింపు
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"

#నిర్వచితమైతే USE_SOLARIS_PROCESS_CONTRACTS

#అన్తర్భావ <libcontract.h>
#అన్తర్భావ <sys/contract/process.h>
#అన్తర్భావ <sys/ctfs.h>

#నిర్వచించు CT_TEMPLATE	CTFS_మూలం "/process/template"
#నిర్వచించు CT_LATEST	CTFS_మూలం "/process/latest"

స్థిర పూర్ణాంకం tmpl_fd = -1;

/* Lookup the latest process contract */
స్థిర ctid_t
get_చురుకైన_process_contract_id(శూన్య)
{
	పూర్ణాంకం stat_fd;
	ctid_t ctid = -1;
	ct_stathdl_t stathdl;

	ఒకవేళ ((stat_fd = open64(CT_LATEST, O_RDONLY)) == -1) {
		error("%s: Error opening 'latest' process "
		    "contract: %s", __func__, strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (ct_స్థితి_read(stat_fd, CTD_COMMON, &stathdl) != 0) {
		error("%s: Error reading process contract "
		    "status: %s", __func__, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ctid = ct_స్థితి_get_id(stathdl)) < 0) {
		error("%s: Error getting process contract id: %s",
		    __func__, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}

	ct_స్థితి_free(stathdl);
 బహిర్గతం:
	close(stat_fd);
	తిరిగి ctid;
}

శూన్య
solaris_contract_pre_fork(శూన్య)
{
	ఒకవేళ ((tmpl_fd = open64(CT_TEMPLATE, O_RDWR)) == -1) {
		error("%s: open %s: %s", __func__,
		    CT_TEMPLATE, strerror(errno));
		తిరిగి;
	}

	debug2("%s: setting up process contract template on fd %d",
	    __func__, tmpl_fd);

	/* First we set the template parameters and event sets. */
	ఒకవేళ (ct_pr_tmpl_సమితి_param(tmpl_fd, CT_PR_PGRPONLY) != 0) {
		error("%s: Error setting process contract parameter set "
		    "(pgrponly): %s", __func__, strerror(errno));
		వెళ్ళు fail;
	}
	ఒకవేళ (ct_pr_tmpl_సమితి_fatal(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "fatal events: %s", __func__, strerror(errno));
		వెళ్ళు fail;
	}
	ఒకవేళ (ct_tmpl_సమితి_critical(tmpl_fd, 0) != 0) {
		error("%s: Error setting process contract template "
		    "critical events: %s", __func__, strerror(errno));
		వెళ్ళు fail;
	}
	ఒకవేళ (ct_tmpl_సమితి_informative(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "informative events: %s", __func__, strerror(errno));
		వెళ్ళు fail;
	}

	/* Now make this the active template for this process. */
	ఒకవేళ (ct_tmpl_activate(tmpl_fd) != 0) {
		error("%s: Error activating process contract "
		    "template: %s", __func__, strerror(errno));
		వెళ్ళు fail;
	}
	తిరిగి;

 fail:
	ఒకవేళ (tmpl_fd != -1) {
		close(tmpl_fd);
		tmpl_fd = -1;
	}
}

శూన్య
solaris_contract_post_fork_బిడ్డ()
{
	debug2("%s: clearing process contract template on fd %d",
	    __func__, tmpl_fd);

	/* Clear the active template. */
	ఒకవేళ (ct_tmpl_clear(tmpl_fd) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, strerror(errno));

	close(tmpl_fd);
	tmpl_fd = -1;
}

శూన్య
solaris_contract_post_fork_మాతృ(pid_t pid)
{
	ctid_t ctid;
	అక్షరం ctl_మార్గం[256];
	పూర్ణాంకం r, ctl_fd = -1, stat_fd = -1;

	debug2("%s: clearing template (fd %d)", __func__, tmpl_fd);

	ఒకవేళ (tmpl_fd == -1)
		తిరిగి;

	/* First clear the active template. */
	ఒకవేళ ((r = ct_tmpl_clear(tmpl_fd)) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, strerror(errno));

	close(tmpl_fd);
	tmpl_fd = -1;

	/*
	 * If either the fork didn't succeed (pid < 0), or clearing
	 * th active contract failed (r != 0), then we have nothing
	 * more do.
	 */
	ఒకవేళ (r != 0 || pid <= 0)
		తిరిగి;

	/* Now lookup and abandon the contract we've created. */
	ctid = get_చురుకైన_process_contract_id();

	debug2("%s: abandoning contract id %ld", __func__, ctid);

	snprintf(ctl_మార్గం, పరిమాణం(ctl_మార్గం),
	    CTFS_మూలం "/process/%ld/ctl", ctid);
	ఒకవేళ ((ctl_fd = open64(ctl_మార్గం, O_WRONLY)) < 0) {
		error("%s: Error opening process contract "
		    "ctl file: %s", __func__, strerror(errno));
		వెళ్ళు fail;
	}
	ఒకవేళ (ct_ctl_abandon(ctl_fd) < 0) {
		error("%s: Error abandoning process contract: %s",
		    __func__, strerror(errno));
		వెళ్ళు fail;
	}
	close(ctl_fd);
	తిరిగి;

 fail:
	ఒకవేళ (tmpl_fd != -1) {
		close(tmpl_fd);
		tmpl_fd = -1;
	}
	ఒకవేళ (stat_fd != -1)
		close(stat_fd);
	ఒకవేళ (ctl_fd != -1)
		close(ctl_fd);
}
#అయితే_ముగింపు

#నిర్వచితమైతే USE_SOLARIS_PROJECTS
#అన్తర్భావ <sys/task.h>
#అన్తర్భావ <project.h>

/*
 * Get/set solaris default project.
 * If we fail, just run along gracefully.
 */
శూన్య
solaris_సమితి_default_project(నిర్మాణం passwd *pw)
{
	నిర్మాణం project  *defaultproject;
	నిర్మాణం project   tempproject;
	అక్షరం buf[1024];

	/* get default project, if we fail just return gracefully  */
	ఒకవేళ ((defaultproject = getdefaultproj(pw->pw_name, &tempproject, &buf,
	    పరిమాణం(buf))) != ఖాళీ) {
		/* set default project */
		ఒకవేళ (setproject(defaultproject->pj_name, pw->pw_name,
		    TASK_సాధారణ) != 0)
			debug("setproject(%s): %s", defaultproject->pj_name,
			    strerror(errno));
	} లేకపోతే {
		/* debug on getdefaultproj() error */
		debug("getdefaultproj(%s): %s", pw->pw_name, strerror(errno));
	}
}
#అయితే_ముగింపు /* USE_SOLARIS_PROJECTS */

#నిర్వచితమైతే USE_SOLARIS_PRIVS
# ifdef HAVE_PRIV_H
#  include <priv.h>
# endif

priv_సమితి_t *
solaris_basic_privset(శూన్య)
{
	priv_సమితి_t *pset;

#నిర్వచితమైతే HAVE_PRIV_BASICSET
	ఒకవేళ ((pset = priv_allocset()) == ఖాళీ) {
		error("priv_allocset: %s", strerror(errno));
		తిరిగి ఖాళీ;
	}
	priv_basicset(pset);
#లేకపోతే
	ఒకవేళ ((pset = priv_str_గమ్యం_సమితి("basic", ",", ఖాళీ)) == ఖాళీ) {
		error("priv_str_to_set: %s", strerror(errno));
		తిరిగి ఖాళీ;
	}
#అయితే_ముగింపు
	తిరిగి pset;
}

శూన్య
solaris_drop_privs_pinfo_net_fork_exec(శూన్య)
{
	priv_సమితి_t *pset = ఖాళీ, *npset = ఖాళీ;

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

	ఒకవేళ ((pset = priv_allocset()) == ఖాళీ)
		fatal("priv_allocset: %s", strerror(errno));
	ఒకవేళ ((npset = solaris_basic_privset()) == ఖాళీ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ఒకవేళ (priv_addset(npset, PRIV_FILE_CHOWN) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_READ) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_శోధన) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_WRITE) != 0 ||
	    priv_addset(npset, PRIV_FILE_OWNER) != 0)
		fatal("priv_addset: %s", strerror(errno));

	ఒకవేళ (priv_delset(npset, PRIV_PROC_EXEC) != 0 ||
#నిర్వచితమైతే PRIV_NET_ACCESS
	    priv_delset(npset, PRIV_NET_ACCESS) != 0 ||
#అయితే_ముగింపు
	    priv_delset(npset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(npset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(npset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", strerror(errno));

#నిర్వచితమైతే PRIV_XPOLICY
	/*
	 * It is possible that the user has an extended policy
	 * in place; the LIMIT set restricts the extended policy
	 * and so should not be restricted.
	 * PRIV_XPOLICY is newly defined in Solaris 11 though the extended
	 * policy was not implemented until Solaris 11.1.
	 */
	ఒకవేళ (getpflags(PRIV_XPOLICY) == 1) {
		ఒకవేళ (getppriv(PRIV_హద్దు, pset) != 0)
			fatal("getppriv: %s", strerror(errno));
		priv_intersect(pset, npset);
		ఒకవేళ (setppriv(PRIV_సమితి, PRIV_హద్దు, npset) != 0)
			fatal("setppriv: %s", strerror(errno));
	} లేకపోతే
#అయితే_ముగింపు
	{
		/* Cannot exec, so we can kill the limit set. */
		priv_emptyset(pset);
		ఒకవేళ (setppriv(PRIV_సమితి, PRIV_హద్దు, pset) != 0)
			fatal("setppriv: %s", strerror(errno));
	}

	ఒకవేళ (getppriv(PRIV_PERMITTED, pset) != 0)
		fatal("getppriv: %s", strerror(errno));

	priv_intersect(pset, npset);

	ఒకవేళ (setppriv(PRIV_సమితి, PRIV_PERMITTED, npset) != 0 ||
	    setppriv(PRIV_సమితి, PRIV_INHERITABLE, npset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
	priv_freeset(npset);
}

శూన్య
solaris_drop_privs_మూలం_pinfo_net(శూన్య)
{
	priv_సమితి_t *pset = ఖాళీ;

	/* Start with "basic" and drop everything we don't need. */
	ఒకవేళ ((pset = solaris_basic_privset()) == ఖాళీ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ఒకవేళ (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#నిర్వచితమైతే PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#అయితే_ముగింపు
	    priv_delset(pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(pset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", strerror(errno));

	ఒకవేళ (setppriv(PRIV_సమితి, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_సమితి, PRIV_హద్దు, pset) != 0 ||
	    setppriv(PRIV_సమితి, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
}

శూన్య
solaris_drop_privs_మూలం_pinfo_net_exec(శూన్య)
{
	priv_సమితి_t *pset = ఖాళీ;


	/* Start with "basic" and drop everything we don't need. */
	ఒకవేళ ((pset = solaris_basic_privset()) == ఖాళీ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ఒకవేళ (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#నిర్వచితమైతే PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#అయితే_ముగింపు
	    priv_delset(pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(pset, PRIV_PROC_INFO) != 0)
		fatal("priv_delset: %s", strerror(errno));

	ఒకవేళ (setppriv(PRIV_సమితి, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_సమితి, PRIV_హద్దు, pset) != 0 ||
	    setppriv(PRIV_సమితి, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
}

#అయితే_ముగింపు
