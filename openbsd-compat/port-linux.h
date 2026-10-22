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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_selinux_enabled(ଶୂନ୍ୟ);
ଶୂନ୍ୟ ssh_selinux_setup_pty(ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ ssh_selinux_setup_exec_context(ଅକ୍ଷର *);
ଶୂନ୍ୟ ssh_selinux_change_context(ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ ssh_selinux_setfscreatecon(ଅଚଳ ଅକ୍ଷର *);
#endif

#ifdef LINUX_OOM_ADJUST
ଶୂନ୍ୟ oom_adjust_restore(ଶୂନ୍ୟ);
ଶୂନ୍ୟ oom_adjust_setup(ଶୂନ୍ୟ);
#endif

#ifdef LINUX_MEMLOCK_ONFAULT
ଶୂନ୍ୟ memlock_onfault_setup(ଶୂନ୍ୟ);
#endif

#ifdef SYSTEMD_NOTIFY
ଶୂନ୍ୟ ssh_systemd_notify_ready(ଶୂନ୍ୟ);
ଶୂନ୍ୟ ssh_systemd_notify_reload(ଶୂନ୍ୟ);
#endif

#endif /* ! _PORT_LINUX_H */
