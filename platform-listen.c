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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "platform.h"

#अन्तर्भाव "openbsd-compat/openbsd-compat.h"

शून्य
platform_pre_listen(शून्य)
{
#यदि_परिभाषितम् LINUX_OOM_ADJUST
	/* Adjust out-of-memory killer so listening process is not killed */
	oom_adjust_सज्जता();
#यदि_अन्तः
#यदि_परिभाषितम् LINUX_MEMLOCK_ONFAULT
	/*
	 * Protect ourselves against kcompactd so that we are able to process
	 * new connections while it is active and migrating pages.
	 */
	memlock_onfault_सज्जता();
#यदि_अन्तः
}

शून्य
platform_post_listen(शून्य)
{
#यदि_परिभाषितम् SYSTEMD_NOTIFY
	ssh_systemd_notify_ready();
#यदि_अन्तः
}

शून्य
platform_pre_fork(शून्य)
{
#यदि_परिभाषितम् USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_pre_fork();
#यदि_अन्तः
}

शून्य
platform_pre_restart(शून्य)
{
#यदि_परिभाषितम् SYSTEMD_NOTIFY
	ssh_systemd_notify_reload();
#यदि_अन्तः
#यदि_परिभाषितम् LINUX_OOM_ADJUST
	oom_adjust_restore();
#यदि_अन्तः
}

शून्य
platform_post_fork_parent(pid_t child_pid)
{
#यदि_परिभाषितम् USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_parent(child_pid);
#यदि_अन्तः
}

शून्य
platform_post_fork_child(शून्य)
{
#यदि_परिभाषितम् USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_child();
#यदि_अन्तः
#यदि_परिभाषितम् LINUX_OOM_ADJUST
	oom_adjust_restore();
#यदि_अन्तः
}

शून्य platform_pre_session_start(शून्य)
{
#यदि_परिभाषितम् LINUX_MEMLOCK_ONFAULT
	/*
	 * Memlock flags are dropped on fork, lock the memory again so that the
	 * child connection is also protected against kcompactd.
	 */
	memlock_onfault_सज्जता();
#यदि_अन्तः
}
