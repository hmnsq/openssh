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

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <pwd.h>

ಶೂನ್ಯ platform_pre_listen(ಶೂನ್ಯ);
ಶೂನ್ಯ platform_pre_fork(ಶೂನ್ಯ);
ಶೂನ್ಯ platform_pre_restart(ಶೂನ್ಯ);
ಶೂನ್ಯ platform_post_listen(ಶೂನ್ಯ);
ಶೂನ್ಯ platform_post_fork_ಪೋಷಕ(pid_t ಮಗು_pid);
ಶೂನ್ಯ platform_post_fork_ಮಗು(ಶೂನ್ಯ);
ಶೂನ್ಯ platform_pre_session_ಆರಂಭ(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ  platform_privileged_uidswap(ಶೂನ್ಯ);
ಶೂನ್ಯ platform_setusercontext(ರಚನೆ passwd *);
ಶೂನ್ಯ platform_setusercontext_post_groups(ರಚನೆ passwd *);
ಅಕ್ಷರ *platform_get_krb5_client(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಅಕ್ಷರ *platform_krb5_get_principal_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ platform_locked_account(ರಚನೆ passwd *);
ಪೂರ್ಣಾಂಕ platform_sys_dir_uid(uid_t);
ಶೂನ್ಯ platform_disable_tracing(ಪೂರ್ಣಾಂಕ);

/* in platform-pledge.c */
ಶೂನ್ಯ platform_pledge_agent(ಶೂನ್ಯ);
ಶೂನ್ಯ platform_pledge_sftp_server(ಶೂನ್ಯ);
ಶೂನ್ಯ platform_pledge_mux(ಶೂನ್ಯ);
