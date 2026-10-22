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

#اگر_غیر_تعریف_شدہ پورٹ_LINUX_H
#تعریف_کرو پورٹ_LINUX_H

#اگر_تعریف_شدہ WITH_SELINUX
صحیح ssh_selinux_enabled(خالی);
خالی ssh_selinux_تیاری_pty(حرف *, ثابت حرف *);
خالی ssh_selinux_تیاری_exec_context(حرف *);
خالی ssh_selinux_change_context(ثابت حرف *);
خالی ssh_selinux_setfscreatecon(ثابت حرف *);
#اگر_ختم

#اگر_تعریف_شدہ LINUX_OOM_ADJUST
خالی oom_adjust_restore(خالی);
خالی oom_adjust_تیاری(خالی);
#اگر_ختم

#اگر_تعریف_شدہ LINUX_MEMLOCK_ONFAULT
خالی memlock_onfault_تیاری(خالی);
#اگر_ختم

#اگر_تعریف_شدہ SYSTEMD_NOTIFY
خالی ssh_systemd_notify_ready(خالی);
خالی ssh_systemd_notify_reload(خالی);
#اگر_ختم

#اگر_ختم /* ! _PORT_LINUX_H */
