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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಪೋರ್ಟ್_LINUX_H
#ವ್ಯಾಖ್ಯಾನಿಸು ಪೋರ್ಟ್_LINUX_H

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
ಪೂರ್ಣಾಂಕ ssh_selinux_enabled(ಶೂನ್ಯ);
ಶೂನ್ಯ ssh_selinux_ಸಿದ್ಧತೆ_pty(ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ ssh_selinux_ಸಿದ್ಧತೆ_exec_context(ಅಕ್ಷರ *);
ಶೂನ್ಯ ssh_selinux_change_context(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ ssh_selinux_setfscreatecon(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LINUX_OOM_ADJUST
ಶೂನ್ಯ oom_adjust_restore(ಶೂನ್ಯ);
ಶೂನ್ಯ oom_adjust_ಸಿದ್ಧತೆ(ಶೂನ್ಯ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LINUX_MEMLOCK_ONFAULT
ಶೂನ್ಯ memlock_onfault_ಸಿದ್ಧತೆ(ಶೂನ್ಯ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SYSTEMD_NOTIFY
ಶೂನ್ಯ ssh_systemd_notify_ready(ಶೂನ್ಯ);
ಶೂನ್ಯ ssh_systemd_notify_reload(ಶೂನ್ಯ);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* ! _PORT_LINUX_H */
