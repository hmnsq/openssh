/*
 * Copyright (c) 2006 Darren Tucker.  All rights reserved.
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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "platform.h"

#అన్తర్భావ "openbsd-compat/openbsd-compat.h"

శూన్య
platform_pre_listen(శూన్య)
{
#నిర్వచితమైతే LINUX_OOM_ADJUST
	/* Adjust out-of-memory killer so listening process is not killed */
	oom_adjust_అమరిక();
#అయితే_ముగింపు
#నిర్వచితమైతే LINUX_MEMLOCK_ONFAULT
	/*
	 * Protect ourselves against kcompactd so that we are able to process
	 * new connections while it is active and migrating pages.
	 */
	memlock_onfault_అమరిక();
#అయితే_ముగింపు
}

శూన్య
platform_post_listen(శూన్య)
{
#నిర్వచితమైతే SYSTEMD_NOTIFY
	ssh_systemd_notify_ready();
#అయితే_ముగింపు
}

శూన్య
platform_pre_fork(శూన్య)
{
#నిర్వచితమైతే USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_pre_fork();
#అయితే_ముగింపు
}

శూన్య
platform_pre_restart(శూన్య)
{
#నిర్వచితమైతే SYSTEMD_NOTIFY
	ssh_systemd_notify_reload();
#అయితే_ముగింపు
#నిర్వచితమైతే LINUX_OOM_ADJUST
	oom_adjust_restore();
#అయితే_ముగింపు
}

శూన్య
platform_post_fork_మాతృ(pid_t బిడ్డ_pid)
{
#నిర్వచితమైతే USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_మాతృ(బిడ్డ_pid);
#అయితే_ముగింపు
}

శూన్య
platform_post_fork_బిడ్డ(శూన్య)
{
#నిర్వచితమైతే USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_బిడ్డ();
#అయితే_ముగింపు
#నిర్వచితమైతే LINUX_OOM_ADJUST
	oom_adjust_restore();
#అయితే_ముగింపు
}

శూన్య platform_pre_session_ప్రారంభం(శూన్య)
{
#నిర్వచితమైతే LINUX_MEMLOCK_ONFAULT
	/*
	 * Memlock flags are dropped on fork, lock the memory again so that the
	 * child connection is also protected against kcompactd.
	 */
	memlock_onfault_అమరిక();
#అయితే_ముగింపు
}
