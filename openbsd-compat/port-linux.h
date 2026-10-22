/*
 * Copyright (c) 2006 Damien Miller <djm@openbsd.org>
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

#ifndef _PORT_LINUX_H
#define _PORT_LINUX_H

#ifdef WITH_SELINUX
صحیح ssh_selinux_enabled(تهی);
تهی ssh_selinux_setup_pty(نویسه *, ثابت نویسه *);
تهی ssh_selinux_setup_exec_context(نویسه *);
تهی ssh_selinux_change_context(ثابت نویسه *);
تهی ssh_selinux_setfscreatecon(ثابت نویسه *);
#endif

#ifdef LINUX_OOM_ADJUST
تهی oom_adjust_restore(تهی);
تهی oom_adjust_setup(تهی);
#endif

#ifdef LINUX_MEMLOCK_ONFAULT
تهی memlock_onfault_setup(تهی);
#endif

#ifdef SYSTEMD_NOTIFY
تهی ssh_systemd_notify_ready(تهی);
تهی ssh_systemd_notify_reload(تهی);
#endif

#endif /* ! _PORT_LINUX_H */
