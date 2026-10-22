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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਪੋਰਟ_LINUX_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪੋਰਟ_LINUX_H

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
ਪੂਰਨ ssh_selinux_enabled(ਖਾਲੀ);
ਖਾਲੀ ssh_selinux_ਤਿਆਰੀ_pty(ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ ssh_selinux_ਤਿਆਰੀ_exec_context(ਅੱਖਰ *);
ਖਾਲੀ ssh_selinux_change_context(ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ ssh_selinux_setfscreatecon(ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_OOM_ADJUST
ਖਾਲੀ oom_adjust_restore(ਖਾਲੀ);
ਖਾਲੀ oom_adjust_ਤਿਆਰੀ(ਖਾਲੀ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_MEMLOCK_ONFAULT
ਖਾਲੀ memlock_onfault_ਤਿਆਰੀ(ਖਾਲੀ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SYSTEMD_NOTIFY
ਖਾਲੀ ssh_systemd_notify_ready(ਖਾਲੀ);
ਖਾਲੀ ssh_systemd_notify_reload(ਖਾਲੀ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* ! _PORT_LINUX_H */
