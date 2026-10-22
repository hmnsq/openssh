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

#અન્તર્ભાવ "config.h"
#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <errno.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"

#ifdef USE_SOLARIS_PROCESS_CONTRACTS

#અન્તર્ભાવ <libcontract.h>
#અન્તર્ભાવ <sys/contract/process.h>
#અન્તર્ભાવ <sys/ctfs.h>

#define CT_TEMPLATE	CTFS_મૂળ "/process/template"
#define CT_LATEST	CTFS_મૂળ "/process/latest"

સ્થિર પૂર્ણાંક tmpl_fd = -1;

/* Lookup the latest process contract */
સ્થિર ctid_t
get_active_process_contract_id(શૂન્ય)
{
	પૂર્ણાંક stat_fd;
	ctid_t ctid = -1;
	ct_stathdl_t stathdl;

	જો ((stat_fd = open64(CT_LATEST, O_RDONLY)) == -1) {
		error("%s: Error opening 'latest' process "
		    "contract: %s", __func__, strerror(errno));
		પાછા -1;
	}
	જો (ct_status_read(stat_fd, CTD_COMMON, &stathdl) != 0) {
		error("%s: Error reading process contract "
		    "status: %s", __func__, strerror(errno));
		જાઓ out;
	}
	જો ((ctid = ct_status_get_id(stathdl)) < 0) {
		error("%s: Error getting process contract id: %s",
		    __func__, strerror(errno));
		જાઓ out;
	}

	ct_status_free(stathdl);
 out:
	close(stat_fd);
	પાછા ctid;
}

શૂન્ય
solaris_contract_pre_fork(શૂન્ય)
{
	જો ((tmpl_fd = open64(CT_TEMPLATE, O_RDWR)) == -1) {
		error("%s: open %s: %s", __func__,
		    CT_TEMPLATE, strerror(errno));
		પાછા;
	}

	debug2("%s: setting up process contract template on fd %d",
	    __func__, tmpl_fd);

	/* First we set the template parameters and event sets. */
	જો (ct_pr_tmpl_set_param(tmpl_fd, CT_PR_PGRPONLY) != 0) {
		error("%s: Error setting process contract parameter set "
		    "(pgrponly): %s", __func__, strerror(errno));
		જાઓ fail;
	}
	જો (ct_pr_tmpl_set_fatal(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "fatal events: %s", __func__, strerror(errno));
		જાઓ fail;
	}
	જો (ct_tmpl_set_critical(tmpl_fd, 0) != 0) {
		error("%s: Error setting process contract template "
		    "critical events: %s", __func__, strerror(errno));
		જાઓ fail;
	}
	જો (ct_tmpl_set_informative(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "informative events: %s", __func__, strerror(errno));
		જાઓ fail;
	}

	/* Now make this the active template for this process. */
	જો (ct_tmpl_activate(tmpl_fd) != 0) {
		error("%s: Error activating process contract "
		    "template: %s", __func__, strerror(errno));
		જાઓ fail;
	}
	પાછા;

 fail:
	જો (tmpl_fd != -1) {
		close(tmpl_fd);
		tmpl_fd = -1;
	}
}

શૂન્ય
solaris_contract_post_fork_child()
{
	debug2("%s: clearing process contract template on fd %d",
	    __func__, tmpl_fd);

	/* Clear the active template. */
	જો (ct_tmpl_clear(tmpl_fd) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, strerror(errno));

	close(tmpl_fd);
	tmpl_fd = -1;
}

શૂન્ય
solaris_contract_post_fork_parent(pid_t pid)
{
	ctid_t ctid;
	અક્ષર ctl_path[256];
	પૂર્ણાંક r, ctl_fd = -1, stat_fd = -1;

	debug2("%s: clearing template (fd %d)", __func__, tmpl_fd);

	જો (tmpl_fd == -1)
		પાછા;

	/* First clear the active template. */
	જો ((r = ct_tmpl_clear(tmpl_fd)) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, strerror(errno));

	close(tmpl_fd);
	tmpl_fd = -1;

	/*
	 * If either the fork didn't succeed (pid < 0), or clearing
	 * th active contract failed (r != 0), then we have nothing
	 * more do.
	 */
	જો (r != 0 || pid <= 0)
		પાછા;

	/* Now lookup and abandon the contract we've created. */
	ctid = get_active_process_contract_id();

	debug2("%s: abandoning contract id %ld", __func__, ctid);

	snprintf(ctl_path, કદ(ctl_path),
	    CTFS_મૂળ "/process/%ld/ctl", ctid);
	જો ((ctl_fd = open64(ctl_path, O_WRONLY)) < 0) {
		error("%s: Error opening process contract "
		    "ctl file: %s", __func__, strerror(errno));
		જાઓ fail;
	}
	જો (ct_ctl_abandon(ctl_fd) < 0) {
		error("%s: Error abandoning process contract: %s",
		    __func__, strerror(errno));
		જાઓ fail;
	}
	close(ctl_fd);
	પાછા;

 fail:
	જો (tmpl_fd != -1) {
		close(tmpl_fd);
		tmpl_fd = -1;
	}
	જો (stat_fd != -1)
		close(stat_fd);
	જો (ctl_fd != -1)
		close(ctl_fd);
}
#endif

#ifdef USE_SOLARIS_PROJECTS
#અન્તર્ભાવ <sys/task.h>
#અન્તર્ભાવ <project.h>

/*
 * Get/set solaris default project.
 * If we fail, just run along gracefully.
 */
શૂન્ય
solaris_set_default_project(સંરચના passwd *pw)
{
	સંરચના project  *defaultproject;
	સંરચના project   tempproject;
	અક્ષર buf[1024];

	/* get default project, if we fail just return gracefully  */
	જો ((defaultproject = getdefaultproj(pw->pw_name, &tempproject, &buf,
	    કદ(buf))) != ખાલી) {
		/* set default project */
		જો (setproject(defaultproject->pj_name, pw->pw_name,
		    TASK_NORMAL) != 0)
			debug("setproject(%s): %s", defaultproject->pj_name,
			    strerror(errno));
	} નહીંતર {
		/* debug on getdefaultproj() error */
		debug("getdefaultproj(%s): %s", pw->pw_name, strerror(errno));
	}
}
#endif /* USE_SOLARIS_PROJECTS */

#ifdef USE_SOLARIS_PRIVS
# ifdef HAVE_PRIV_H
#  include <priv.h>
# endif

priv_set_t *
solaris_basic_privset(શૂન્ય)
{
	priv_set_t *pset;

#ifdef HAVE_PRIV_BASICSET
	જો ((pset = priv_allocset()) == ખાલી) {
		error("priv_allocset: %s", strerror(errno));
		પાછા ખાલી;
	}
	priv_basicset(pset);
#નહીંતર
	જો ((pset = priv_str_to_set("basic", ",", ખાલી)) == ખાલી) {
		error("priv_str_to_set: %s", strerror(errno));
		પાછા ખાલી;
	}
#endif
	પાછા pset;
}

શૂન્ય
solaris_drop_privs_pinfo_net_fork_exec(શૂન્ય)
{
	priv_set_t *pset = ખાલી, *npset = ખાલી;

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

	જો ((pset = priv_allocset()) == ખાલી)
		fatal("priv_allocset: %s", strerror(errno));
	જો ((npset = solaris_basic_privset()) == ખાલી)
		fatal("solaris_basic_privset: %s", strerror(errno));

	જો (priv_addset(npset, PRIV_FILE_CHOWN) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_READ) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_શોધ) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_WRITE) != 0 ||
	    priv_addset(npset, PRIV_FILE_OWNER) != 0)
		fatal("priv_addset: %s", strerror(errno));

	જો (priv_delset(npset, PRIV_PROC_EXEC) != 0 ||
#ifdef PRIV_NET_ACCESS
	    priv_delset(npset, PRIV_NET_ACCESS) != 0 ||
#endif
	    priv_delset(npset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(npset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(npset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", strerror(errno));

#ifdef PRIV_XPOLICY
	/*
	 * It is possible that the user has an extended policy
	 * in place; the LIMIT set restricts the extended policy
	 * and so should not be restricted.
	 * PRIV_XPOLICY is newly defined in Solaris 11 though the extended
	 * policy was not implemented until Solaris 11.1.
	 */
	જો (getpflags(PRIV_XPOLICY) == 1) {
		જો (getppriv(PRIV_LIMIT, pset) != 0)
			fatal("getppriv: %s", strerror(errno));
		priv_intersect(pset, npset);
		જો (setppriv(PRIV_SET, PRIV_LIMIT, npset) != 0)
			fatal("setppriv: %s", strerror(errno));
	} નહીંતર
#endif
	{
		/* Cannot exec, so we can kill the limit set. */
		priv_emptyset(pset);
		જો (setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0)
			fatal("setppriv: %s", strerror(errno));
	}

	જો (getppriv(PRIV_PERMITTED, pset) != 0)
		fatal("getppriv: %s", strerror(errno));

	priv_intersect(pset, npset);

	જો (setppriv(PRIV_SET, PRIV_PERMITTED, npset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, npset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
	priv_freeset(npset);
}

શૂન્ય
solaris_drop_privs_મૂળ_pinfo_net(શૂન્ય)
{
	priv_set_t *pset = ખાલી;

	/* Start with "basic" and drop everything we don't need. */
	જો ((pset = solaris_basic_privset()) == ખાલી)
		fatal("solaris_basic_privset: %s", strerror(errno));

	જો (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#ifdef PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#endif
	    priv_delset(pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(pset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", strerror(errno));

	જો (setppriv(PRIV_SET, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
}

શૂન્ય
solaris_drop_privs_મૂળ_pinfo_net_exec(શૂન્ય)
{
	priv_set_t *pset = ખાલી;


	/* Start with "basic" and drop everything we don't need. */
	જો ((pset = solaris_basic_privset()) == ખાલી)
		fatal("solaris_basic_privset: %s", strerror(errno));

	જો (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#ifdef PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#endif
	    priv_delset(pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(pset, PRIV_PROC_INFO) != 0)
		fatal("priv_delset: %s", strerror(errno));

	જો (setppriv(PRIV_SET, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
}

#endif
