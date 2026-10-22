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

#شامل "includes.h"

#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "log.h"
#شامل "misc.h"
#شامل "platform.h"

#شامل "openbsd-compat/openbsd-compat.h"

خالی
platform_pre_listen(خالی)
{
#اگر_تعریف_شدہ LINUX_OOM_ADJUST
	/* Adjust out-of-memory killer so listening process is not killed */
	oom_adjust_تیاری();
#اگر_ختم
#اگر_تعریف_شدہ LINUX_MEMLOCK_ONFAULT
	/*
	 * Protect ourselves against kcompactd so that we are able to process
	 * new connections while it is active and migrating pages.
	 */
	memlock_onfault_تیاری();
#اگر_ختم
}

خالی
platform_post_listen(خالی)
{
#اگر_تعریف_شدہ SYSTEMD_NOTIFY
	ssh_systemd_notify_ready();
#اگر_ختم
}

خالی
platform_pre_fork(خالی)
{
#اگر_تعریف_شدہ USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_pre_fork();
#اگر_ختم
}

خالی
platform_pre_restart(خالی)
{
#اگر_تعریف_شدہ SYSTEMD_NOTIFY
	ssh_systemd_notify_reload();
#اگر_ختم
#اگر_تعریف_شدہ LINUX_OOM_ADJUST
	oom_adjust_restore();
#اگر_ختم
}

خالی
platform_post_fork_والد(pid_t بچہ_pid)
{
#اگر_تعریف_شدہ USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_والد(بچہ_pid);
#اگر_ختم
}

خالی
platform_post_fork_بچہ(خالی)
{
#اگر_تعریف_شدہ USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_بچہ();
#اگر_ختم
#اگر_تعریف_شدہ LINUX_OOM_ADJUST
	oom_adjust_restore();
#اگر_ختم
}

خالی platform_pre_session_آغاز(خالی)
{
#اگر_تعریف_شدہ LINUX_MEMLOCK_ONFAULT
	/*
	 * Memlock flags are dropped on fork, lock the memory again so that the
	 * child connection is also protected against kcompactd.
	 */
	memlock_onfault_تیاری();
#اگر_ختم
}
