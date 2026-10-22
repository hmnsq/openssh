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

#समावेश "includes.h"

#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "log.h"
#समावेश "misc.h"
#समावेश "platform.h"

#समावेश "openbsd-compat/openbsd-compat.h"

व्योम
platform_pre_listen(व्योम)
{
#अगर_घोषित LINUX_OOM_ADJUST
	/* Adjust out-of-memory killer so listening process is not killed */
	oom_adjust_setup();
#पूर्ण_अगर
#अगर_घोषित LINUX_MEMLOCK_ONFAULT
	/*
	 * Protect ourselves against kcompactd so that we are able to process
	 * new connections while it is active and migrating pages.
	 */
	memlock_onfault_setup();
#पूर्ण_अगर
}

व्योम
platform_post_listen(व्योम)
{
#अगर_घोषित SYSTEMD_NOTIFY
	ssh_systemd_notify_ready();
#पूर्ण_अगर
}

व्योम
platform_pre_fork(व्योम)
{
#अगर_घोषित USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_pre_fork();
#पूर्ण_अगर
}

व्योम
platform_pre_restart(व्योम)
{
#अगर_घोषित SYSTEMD_NOTIFY
	ssh_systemd_notify_reload();
#पूर्ण_अगर
#अगर_घोषित LINUX_OOM_ADJUST
	oom_adjust_restore();
#पूर्ण_अगर
}

व्योम
platform_post_fork_parent(pid_t child_pid)
{
#अगर_घोषित USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_parent(child_pid);
#पूर्ण_अगर
}

व्योम
platform_post_fork_child(व्योम)
{
#अगर_घोषित USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_child();
#पूर्ण_अगर
#अगर_घोषित LINUX_OOM_ADJUST
	oom_adjust_restore();
#पूर्ण_अगर
}

व्योम platform_pre_session_start(व्योम)
{
#अगर_घोषित LINUX_MEMLOCK_ONFAULT
	/*
	 * Memlock flags are dropped on fork, lock the memory again so that the
	 * child connection is also protected against kcompactd.
	 */
	memlock_onfault_setup();
#पूर्ण_अगर
}
