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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "platform.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openbsd-compat.h"

ਖਾਲੀ
platform_pre_listen(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_OOM_ADJUST
	/* Adjust out-of-memory killer so listening process is not killed */
	oom_adjust_ਤਿਆਰੀ();
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_MEMLOCK_ONFAULT
	/*
	 * Protect ourselves against kcompactd so that we are able to process
	 * new connections while it is active and migrating pages.
	 */
	memlock_onfault_ਤਿਆਰੀ();
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
platform_post_listen(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SYSTEMD_NOTIFY
	ssh_systemd_notify_ready();
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
platform_pre_fork(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_pre_fork();
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
platform_pre_restart(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SYSTEMD_NOTIFY
	ssh_systemd_notify_reload();
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_OOM_ADJUST
	oom_adjust_restore();
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
platform_post_fork_ਮਾਪਾ(pid_t ਬੱਚਾ_pid)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_ਮਾਪਾ(ਬੱਚਾ_pid);
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
platform_post_fork_ਬੱਚਾ(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_ਬੱਚਾ();
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_OOM_ADJUST
	oom_adjust_restore();
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ platform_pre_session_ਸ਼ੁਰੂ(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_MEMLOCK_ONFAULT
	/*
	 * Memlock flags are dropped on fork, lock the memory again so that the
	 * child connection is also protected against kcompactd.
	 */
	memlock_onfault_ਤਿਆਰੀ();
#ਜੇ_ਅੰਤ
}
