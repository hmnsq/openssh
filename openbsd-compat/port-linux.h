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
पूर्णांक ssh_selinux_enabled(शून्य);
शून्य ssh_selinux_setup_pty(अक्षर *, स्थिरांक अक्षर *);
शून्य ssh_selinux_setup_exec_context(अक्षर *);
शून्य ssh_selinux_change_context(स्थिरांक अक्षर *);
शून्य ssh_selinux_setfscreatecon(स्थिरांक अक्षर *);
#endif

#ifdef LINUX_OOM_ADJUST
शून्य oom_adjust_restore(शून्य);
शून्य oom_adjust_setup(शून्य);
#endif

#ifdef LINUX_MEMLOCK_ONFAULT
शून्य memlock_onfault_setup(शून्य);
#endif

#ifdef SYSTEMD_NOTIFY
शून्य ssh_systemd_notify_ready(शून्य);
शून्य ssh_systemd_notify_reload(शून्य);
#endif

#endif /* ! _PORT_LINUX_H */
