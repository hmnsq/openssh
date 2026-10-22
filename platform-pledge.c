/*
 * Copyright (c) 2015 Joyent, Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
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

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "platform.h"

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openbsd-compat.h"

/*
 * Drop any fine-grained privileges that are not needed for post-startup
 * operation of ssh-agent
 *
 * Should be as close as possible to pledge("stdio cpath unix id proc exec", ...)
 */
ଶୂନ୍ୟ
platform_pledge_agent(ଶୂନ୍ୟ)
{
#ifdef USE_SOLARIS_PRIVS
	/*
	 * Note: Solaris priv dropping is closer to tame() than pledge(), but
	 * we will use what we have.
	 */
	solaris_drop_privs_ମୂଳ_pinfo_net();
#endif
}

/*
 * Drop any fine-grained privileges that are not needed for post-startup
 * operation of sftp-server
 */
ଶୂନ୍ୟ
platform_pledge_sftp_server(ଶୂନ୍ୟ)
{
#ifdef USE_SOLARIS_PRIVS
	solaris_drop_privs_pinfo_net_fork_exec();
#endif
}

/*
 * Drop any fine-grained privileges that are not needed for the post-startup
 * operation of the SSH client mux
 *
 * Should be as close as possible to pledge("stdio proc tty", ...)
 */
ଶୂନ୍ୟ
platform_pledge_mux(ଶୂନ୍ୟ)
{
#ifdef USE_SOLARIS_PRIVS
	solaris_drop_privs_ମୂଳ_pinfo_net_exec();
#endif
}
