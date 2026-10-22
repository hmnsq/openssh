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

#جيڪڏهن_وصف_نه_ٿيل پورٽ_LINUX_H
#وصف_ڪريو پورٽ_LINUX_H

#جيڪڏهن_وصف_ٿيل WITH_SELINUX
صحيح ssh_selinux_enabled(فراغ);
فراغ ssh_selinux_تياري_pty(حرف *, ثابت حرف *);
فراغ ssh_selinux_تياري_exec_context(حرف *);
فراغ ssh_selinux_change_context(ثابت حرف *);
فراغ ssh_selinux_setfscreatecon(ثابت حرف *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل LINUX_OOM_ADJUST
فراغ oom_adjust_restore(فراغ);
فراغ oom_adjust_تياري(فراغ);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل LINUX_MEMLOCK_ONFAULT
فراغ memlock_onfault_تياري(فراغ);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل SYSTEMD_NOTIFY
فراغ ssh_systemd_notify_ready(فراغ);
فراغ ssh_systemd_notify_reload(فراغ);
#جيڪڏهن_پورو

#جيڪڏهن_پورو /* ! _PORT_LINUX_H */
