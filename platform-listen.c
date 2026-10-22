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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "platform.h"

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openbsd-compat.h"

ଶୂନ୍ୟ
platform_pre_listen(ଶୂନ୍ୟ)
{
#ifdef LINUX_OOM_ADJUST
	/* Adjust out-of-memory killer so listening process is not killed */
	oom_adjust_setup();
#endif
#ifdef LINUX_MEMLOCK_ONFAULT
	/*
	 * Protect ourselves against kcompactd so that we are able to process
	 * new connections while it is active and migrating pages.
	 */
	memlock_onfault_setup();
#endif
}

ଶୂନ୍ୟ
platform_post_listen(ଶୂନ୍ୟ)
{
#ifdef SYSTEMD_NOTIFY
	ssh_systemd_notify_ready();
#endif
}

ଶୂନ୍ୟ
platform_pre_fork(ଶୂନ୍ୟ)
{
#ifdef USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_pre_fork();
#endif
}

ଶୂନ୍ୟ
platform_pre_restart(ଶୂନ୍ୟ)
{
#ifdef SYSTEMD_NOTIFY
	ssh_systemd_notify_reload();
#endif
#ifdef LINUX_OOM_ADJUST
	oom_adjust_restore();
#endif
}

ଶୂନ୍ୟ
platform_post_fork_parent(pid_t child_pid)
{
#ifdef USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_parent(child_pid);
#endif
}

ଶୂନ୍ୟ
platform_post_fork_child(ଶୂନ୍ୟ)
{
#ifdef USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_child();
#endif
#ifdef LINUX_OOM_ADJUST
	oom_adjust_restore();
#endif
}

ଶୂନ୍ୟ platform_pre_session_start(ଶୂନ୍ୟ)
{
#ifdef LINUX_MEMLOCK_ONFAULT
	/*
	 * Memlock flags are dropped on fork, lock the memory again so that the
	 * child connection is also protected against kcompactd.
	 */
	memlock_onfault_setup();
#endif
}
