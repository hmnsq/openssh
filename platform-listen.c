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

#ضمن "includes.h"

#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "log.h"
#ضمن "misc.h"
#ضمن "platform.h"

#ضمن "openbsd-compat/openbsd-compat.h"

فراغ
platform_pre_listen(فراغ)
{
#جيڪڏهن_وصف_ٿيل LINUX_OOM_ADJUST
	/* Adjust out-of-memory killer so listening process is not killed */
	oom_adjust_تياري();
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل LINUX_MEMLOCK_ONFAULT
	/*
	 * Protect ourselves against kcompactd so that we are able to process
	 * new connections while it is active and migrating pages.
	 */
	memlock_onfault_تياري();
#جيڪڏهن_پورو
}

فراغ
platform_post_listen(فراغ)
{
#جيڪڏهن_وصف_ٿيل SYSTEMD_NOTIFY
	ssh_systemd_notify_ready();
#جيڪڏهن_پورو
}

فراغ
platform_pre_fork(فراغ)
{
#جيڪڏهن_وصف_ٿيل USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_pre_fork();
#جيڪڏهن_پورو
}

فراغ
platform_pre_restart(فراغ)
{
#جيڪڏهن_وصف_ٿيل SYSTEMD_NOTIFY
	ssh_systemd_notify_reload();
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل LINUX_OOM_ADJUST
	oom_adjust_restore();
#جيڪڏهن_پورو
}

فراغ
platform_post_fork_والد(pid_t ٻار_pid)
{
#جيڪڏهن_وصف_ٿيل USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_والد(ٻار_pid);
#جيڪڏهن_پورو
}

فراغ
platform_post_fork_ٻار(فراغ)
{
#جيڪڏهن_وصف_ٿيل USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_ٻار();
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل LINUX_OOM_ADJUST
	oom_adjust_restore();
#جيڪڏهن_پورو
}

فراغ platform_pre_session_شروعات(فراغ)
{
#جيڪڏهن_وصف_ٿيل LINUX_MEMLOCK_ONFAULT
	/*
	 * Memlock flags are dropped on fork, lock the memory again so that the
	 * child connection is also protected against kcompactd.
	 */
	memlock_onfault_تياري();
#جيڪڏهن_پورو
}
