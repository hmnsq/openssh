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

#ਅਨ੍ਤਰ੍ਭਾਵ "config.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCNTL_H
# include <fcntl.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SOLARIS_PROCESS_CONTRACTS

#ਅਨ੍ਤਰ੍ਭਾਵ <libcontract.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/contract/process.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ctfs.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CT_TEMPLATE	CTFS_ਜੜ੍ਹ "/process/template"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CT_LATEST	CTFS_ਜੜ੍ਹ "/process/latest"

ਸਥਿਰ ਪੂਰਨ tmpl_fd = -1;

/* Lookup the latest process contract */
ਸਥਿਰ ctid_t
get_ਸਰਗਰਮ_process_contract_id(ਖਾਲੀ)
{
	ਪੂਰਨ stat_fd;
	ctid_t ctid = -1;
	ct_stathdl_t stathdl;

	ਜੇ ((stat_fd = open64(CT_LATEST, O_RDONLY)) == -1) {
		error("%s: Error opening 'latest' process "
		    "contract: %s", __func__, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (ct_ਸਥਿਤੀ_read(stat_fd, CTD_COMMON, &stathdl) != 0) {
		error("%s: Error reading process contract "
		    "status: %s", __func__, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ctid = ct_ਸਥਿਤੀ_get_id(stathdl)) < 0) {
		error("%s: Error getting process contract id: %s",
		    __func__, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ct_ਸਥਿਤੀ_free(stathdl);
 ਬਾਹਰਲਾ:
	close(stat_fd);
	ਵਾਪਸ ctid;
}

ਖਾਲੀ
solaris_contract_pre_fork(ਖਾਲੀ)
{
	ਜੇ ((tmpl_fd = open64(CT_TEMPLATE, O_RDWR)) == -1) {
		error("%s: open %s: %s", __func__,
		    CT_TEMPLATE, strerror(errno));
		ਵਾਪਸ;
	}

	debug2("%s: setting up process contract template on fd %d",
	    __func__, tmpl_fd);

	/* First we set the template parameters and event sets. */
	ਜੇ (ct_pr_tmpl_ਸੈੱਟ_param(tmpl_fd, CT_PR_PGRPONLY) != 0) {
		error("%s: Error setting process contract parameter set "
		    "(pgrponly): %s", __func__, strerror(errno));
		ਜਾਓ fail;
	}
	ਜੇ (ct_pr_tmpl_ਸੈੱਟ_fatal(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "fatal events: %s", __func__, strerror(errno));
		ਜਾਓ fail;
	}
	ਜੇ (ct_tmpl_ਸੈੱਟ_critical(tmpl_fd, 0) != 0) {
		error("%s: Error setting process contract template "
		    "critical events: %s", __func__, strerror(errno));
		ਜਾਓ fail;
	}
	ਜੇ (ct_tmpl_ਸੈੱਟ_informative(tmpl_fd, CT_PR_EV_HWERR) != 0) {
		error("%s: Error setting process contract template "
		    "informative events: %s", __func__, strerror(errno));
		ਜਾਓ fail;
	}

	/* Now make this the active template for this process. */
	ਜੇ (ct_tmpl_activate(tmpl_fd) != 0) {
		error("%s: Error activating process contract "
		    "template: %s", __func__, strerror(errno));
		ਜਾਓ fail;
	}
	ਵਾਪਸ;

 fail:
	ਜੇ (tmpl_fd != -1) {
		close(tmpl_fd);
		tmpl_fd = -1;
	}
}

ਖਾਲੀ
solaris_contract_post_fork_ਬੱਚਾ()
{
	debug2("%s: clearing process contract template on fd %d",
	    __func__, tmpl_fd);

	/* Clear the active template. */
	ਜੇ (ct_tmpl_clear(tmpl_fd) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, strerror(errno));

	close(tmpl_fd);
	tmpl_fd = -1;
}

ਖਾਲੀ
solaris_contract_post_fork_ਮਾਪਾ(pid_t pid)
{
	ctid_t ctid;
	ਅੱਖਰ ctl_ਰਸਤਾ[256];
	ਪੂਰਨ r, ctl_fd = -1, stat_fd = -1;

	debug2("%s: clearing template (fd %d)", __func__, tmpl_fd);

	ਜੇ (tmpl_fd == -1)
		ਵਾਪਸ;

	/* First clear the active template. */
	ਜੇ ((r = ct_tmpl_clear(tmpl_fd)) != 0)
		error("%s: Error clearing active process contract "
		    "template: %s", __func__, strerror(errno));

	close(tmpl_fd);
	tmpl_fd = -1;

	/*
	 * If either the fork didn't succeed (pid < 0), or clearing
	 * th active contract failed (r != 0), then we have nothing
	 * more do.
	 */
	ਜੇ (r != 0 || pid <= 0)
		ਵਾਪਸ;

	/* Now lookup and abandon the contract we've created. */
	ctid = get_ਸਰਗਰਮ_process_contract_id();

	debug2("%s: abandoning contract id %ld", __func__, ctid);

	snprintf(ctl_ਰਸਤਾ, ਆਕਾਰ(ctl_ਰਸਤਾ),
	    CTFS_ਜੜ੍ਹ "/process/%ld/ctl", ctid);
	ਜੇ ((ctl_fd = open64(ctl_ਰਸਤਾ, O_WRONLY)) < 0) {
		error("%s: Error opening process contract "
		    "ctl file: %s", __func__, strerror(errno));
		ਜਾਓ fail;
	}
	ਜੇ (ct_ctl_abandon(ctl_fd) < 0) {
		error("%s: Error abandoning process contract: %s",
		    __func__, strerror(errno));
		ਜਾਓ fail;
	}
	close(ctl_fd);
	ਵਾਪਸ;

 fail:
	ਜੇ (tmpl_fd != -1) {
		close(tmpl_fd);
		tmpl_fd = -1;
	}
	ਜੇ (stat_fd != -1)
		close(stat_fd);
	ਜੇ (ctl_fd != -1)
		close(ctl_fd);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SOLARIS_PROJECTS
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/task.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <project.h>

/*
 * Get/set solaris default project.
 * If we fail, just run along gracefully.
 */
ਖਾਲੀ
solaris_ਸੈੱਟ_default_project(ਬਣਤਰ passwd *pw)
{
	ਬਣਤਰ project  *defaultproject;
	ਬਣਤਰ project   tempproject;
	ਅੱਖਰ buf[1024];

	/* get default project, if we fail just return gracefully  */
	ਜੇ ((defaultproject = getdefaultproj(pw->pw_name, &tempproject, &buf,
	    ਆਕਾਰ(buf))) != ਨਿਰਾ) {
		/* set default project */
		ਜੇ (setproject(defaultproject->pj_name, pw->pw_name,
		    TASK_ਸਾਧਾਰਨ) != 0)
			debug("setproject(%s): %s", defaultproject->pj_name,
			    strerror(errno));
	} ਨਹੀਂਤਾਂ {
		/* debug on getdefaultproj() error */
		debug("getdefaultproj(%s): %s", pw->pw_name, strerror(errno));
	}
}
#ਜੇ_ਅੰਤ /* USE_SOLARIS_PROJECTS */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SOLARIS_PRIVS
# ifdef HAVE_PRIV_H
#  include <priv.h>
# endif

priv_ਸੈੱਟ_t *
solaris_basic_privset(ਖਾਲੀ)
{
	priv_ਸੈੱਟ_t *pset;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_PRIV_BASICSET
	ਜੇ ((pset = priv_allocset()) == ਨਿਰਾ) {
		error("priv_allocset: %s", strerror(errno));
		ਵਾਪਸ ਨਿਰਾ;
	}
	priv_basicset(pset);
#ਨਹੀਂਤਾਂ
	ਜੇ ((pset = priv_str_ਮੰਜ਼ਿਲ_ਸੈੱਟ("basic", ",", ਨਿਰਾ)) == ਨਿਰਾ) {
		error("priv_str_to_set: %s", strerror(errno));
		ਵਾਪਸ ਨਿਰਾ;
	}
#ਜੇ_ਅੰਤ
	ਵਾਪਸ pset;
}

ਖਾਲੀ
solaris_drop_privs_pinfo_net_fork_exec(ਖਾਲੀ)
{
	priv_ਸੈੱਟ_t *pset = ਨਿਰਾ, *npset = ਨਿਰਾ;

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

	ਜੇ ((pset = priv_allocset()) == ਨਿਰਾ)
		fatal("priv_allocset: %s", strerror(errno));
	ਜੇ ((npset = solaris_basic_privset()) == ਨਿਰਾ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ਜੇ (priv_addset(npset, PRIV_FILE_CHOWN) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_READ) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_ਖੋਜ) != 0 ||
	    priv_addset(npset, PRIV_FILE_DAC_WRITE) != 0 ||
	    priv_addset(npset, PRIV_FILE_OWNER) != 0)
		fatal("priv_addset: %s", strerror(errno));

	ਜੇ (priv_delset(npset, PRIV_PROC_EXEC) != 0 ||
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRIV_NET_ACCESS
	    priv_delset(npset, PRIV_NET_ACCESS) != 0 ||
#ਜੇ_ਅੰਤ
	    priv_delset(npset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(npset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(npset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", strerror(errno));

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRIV_XPOLICY
	/*
	 * It is possible that the user has an extended policy
	 * in place; the LIMIT set restricts the extended policy
	 * and so should not be restricted.
	 * PRIV_XPOLICY is newly defined in Solaris 11 though the extended
	 * policy was not implemented until Solaris 11.1.
	 */
	ਜੇ (getpflags(PRIV_XPOLICY) == 1) {
		ਜੇ (getppriv(PRIV_ਹੱਦਬੰਦੀ, pset) != 0)
			fatal("getppriv: %s", strerror(errno));
		priv_intersect(pset, npset);
		ਜੇ (setppriv(PRIV_ਸੈੱਟ, PRIV_ਹੱਦਬੰਦੀ, npset) != 0)
			fatal("setppriv: %s", strerror(errno));
	} ਨਹੀਂਤਾਂ
#ਜੇ_ਅੰਤ
	{
		/* Cannot exec, so we can kill the limit set. */
		priv_emptyset(pset);
		ਜੇ (setppriv(PRIV_ਸੈੱਟ, PRIV_ਹੱਦਬੰਦੀ, pset) != 0)
			fatal("setppriv: %s", strerror(errno));
	}

	ਜੇ (getppriv(PRIV_PERMITTED, pset) != 0)
		fatal("getppriv: %s", strerror(errno));

	priv_intersect(pset, npset);

	ਜੇ (setppriv(PRIV_ਸੈੱਟ, PRIV_PERMITTED, npset) != 0 ||
	    setppriv(PRIV_ਸੈੱਟ, PRIV_INHERITABLE, npset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
	priv_freeset(npset);
}

ਖਾਲੀ
solaris_drop_privs_ਜੜ੍ਹ_pinfo_net(ਖਾਲੀ)
{
	priv_ਸੈੱਟ_t *pset = ਨਿਰਾ;

	/* Start with "basic" and drop everything we don't need. */
	ਜੇ ((pset = solaris_basic_privset()) == ਨਿਰਾ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ਜੇ (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#ਜੇ_ਅੰਤ
	    priv_delset(pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(pset, PRIV_PROC_SESSION) != 0)
		fatal("priv_delset: %s", strerror(errno));

	ਜੇ (setppriv(PRIV_ਸੈੱਟ, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_ਸੈੱਟ, PRIV_ਹੱਦਬੰਦੀ, pset) != 0 ||
	    setppriv(PRIV_ਸੈੱਟ, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
}

ਖਾਲੀ
solaris_drop_privs_ਜੜ੍ਹ_pinfo_net_exec(ਖਾਲੀ)
{
	priv_ਸੈੱਟ_t *pset = ਨਿਰਾ;


	/* Start with "basic" and drop everything we don't need. */
	ਜੇ ((pset = solaris_basic_privset()) == ਨਿਰਾ)
		fatal("solaris_basic_privset: %s", strerror(errno));

	ਜੇ (priv_delset(pset, PRIV_FILE_LINK_ANY) != 0 ||
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRIV_NET_ACCESS
	    priv_delset(pset, PRIV_NET_ACCESS) != 0 ||
#ਜੇ_ਅੰਤ
	    priv_delset(pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(pset, PRIV_PROC_INFO) != 0)
		fatal("priv_delset: %s", strerror(errno));

	ਜੇ (setppriv(PRIV_ਸੈੱਟ, PRIV_PERMITTED, pset) != 0 ||
	    setppriv(PRIV_ਸੈੱਟ, PRIV_ਹੱਦਬੰਦੀ, pset) != 0 ||
	    setppriv(PRIV_ਸੈੱਟ, PRIV_INHERITABLE, pset) != 0)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(pset);
}

#ਜੇ_ਅੰਤ
