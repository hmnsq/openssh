/* $OpenBSD: misc-agent.c,v 1.11 2026/09/22 22:29:27 djm Exp $ */
/*
 * Copyright (c) 2025 Damien Miller <djm@mindrot.org>
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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/stat.h>
#ضمن <sys/un.h>

#ضمن <dirent.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <netdb.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>
#ضمن <libgen.h>

#ضمن "digest.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "pathnames.h"
#ضمن "ssh.h"
#ضمن "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#تعریف_کن SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ساكن ثابت حرف presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ساكن حرف *
hostname_hash(اندازه_t len)
{
	حرف hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	صحيح r;
	اندازه_t l, i;

	l = ssh_digest_بایتها(SSH_DIGEST_SHA512);
	إذا (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		أرجع عدم;
	}
	إذا (gethostname(hostname, حجم(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		أرجع عدم;
	}
	إذا ((r = ssh_digest_حافظه(SSH_DIGEST_SHA512,
	    hostname, طول_رشته(hostname), hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		أرجع عدم;
	}
	memset(p, '\0', حجم(p));
	لكل (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (حجم(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	أرجع xstrdup(p);
}

ساكن حرف *
agent_hostname_hash(فراغ)
{
	أرجع hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
ساكن صحيح
unix_listener_tmp(حرف *مسیر, صحيح backlog)
{
	بنية sockaddr_un sunaddr;
	صحيح good, sock = -1;
	اندازه_t i, xstart;
	نما_t prev_ماسک;

	/* Find first 'X' template character back from end of string */
	xstart = طول_رشته(مسیر);
	طالما (xstart > 0 && مسیر[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_ماسک = umask(0177);
	لكل (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		لكل (i = xstart; مسیر[i] != '\0'; i++) {
			مسیر[i] = presentation_chars[
			    arc4random_یکنواخت(حجم(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", مسیر);

		إذا (strlcpy(sunaddr.sun_مسیر, مسیر,
		    حجم(sunaddr.sun_مسیر)) >= حجم(sunaddr.sun_مسیر)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    مسیر);
			اكسر;
		}

		إذا ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			اكسر;
		}
		إذا (bind(sock, (بنية sockaddr *)&sunaddr,
		    حجم(sunaddr)) == -1) {
			إذا (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    مسیر, strerror(errno));
				close(sock);
				sock = -1;
				استمر;
			}
			error_f("bind \"%s\": %.100s", مسیر, strerror(errno));
			اكسر;
		}
		إذا (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", مسیر, strerror(errno));
			اكسر;
		}
		good = 1;
	}
	umask(prev_ماسک);
	إذا (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    مسیر, sock);
	} وإلا إذا (sock != -1) {
		close(sock);
		sock = -1;
	}
	أرجع sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
ساكن صحيح
agent_listener_shared(ثابت حرف *والد_dir, pid_t pid, ثابت حرف *برچسب,
    صحيح *sockp, حرف **pathp, حرف **dirp)
{
	حرف *dir = عدم, *مسیر = عدم;
	صحيح sock, ret = -1;
	نما_t prev_ماسک;

	*pathp = *dirp = عدم;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", والد_dir);
	إذا (mkdtemp(dir) == عدم) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		اذهب بیرون;
	}
	xasprintf(&مسیر, "%s/agent.%s.%ld", dir, برچسب, (دراز)pid);
	prev_ماسک = umask(0177);
	إذا ((sock = unix_listener(مسیر, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_ماسک);
		إذا (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		اذهب بیرون;
	}
	umask(prev_ماسک);

	/* Success */
	*dirp = dir;
	dir = عدم; /* transferred */
	*pathp = مسیر;
	مسیر = عدم; /* transferred */
	*sockp = sock;
	ret = 0;
 بیرون:
	حرر(dir);
	حرر(مسیر);
	أرجع ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ساكن صحيح
agent_listener_user(ثابت حرف *dir, pid_t pid, ثابت حرف *برچسب,
    صحيح *sockp, حرف **pathp)
{
	حرف *hostnamehash = عدم, *مسیر = عدم;
	صحيح sock, ret = -1;

	إذا ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == عدم)
		أرجع -1;
	xasprintf(&مسیر, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, برچسب, (دراز دراز)pid);
	إذا (mkdir_مسیر(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		اذهب بیرون;
	}
	إذا ((sock = unix_listener_tmp(مسیر, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		اذهب بیرون;
	}
	/* Success */
	*pathp = مسیر;
	مسیر = عدم; /* transferred */
	*sockp = sock;
	ret = 0;
 بیرون:
	حرر(hostnamehash);
	حرر(مسیر);
	أرجع ret;
}

ساكن حرف *
expand_pathspec(ثابت حرف *مسیر, ثابت حرف *username,
    uid_t uid, ثابت حرف *homedir)
{
	حرف *uidbuf = عدم, *dir = عدم, *tmp = عدم;

	xasprintf(&uidbuf, "%lld", (دراز دراز)uid);

	إذا ((tmp = percent_expand(مسیر, "u", username, "U", uidbuf,
	    "h", homedir, عدم)) == عدم) {
		error_f("failed to percent-expand agent socket directory");
		اذهب بیرون;
	}
	إذا (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		اذهب بیرون;
	}
	إذا (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		حرر(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 بیرون:
	حرر(uidbuf);
	حرر(tmp);
	أرجع dir;
}

صحيح
agent_listener(ثابت حرف *pathspec, ثابت حرف *username, uid_t uid,
    ثابت حرف *homedir, pid_t pid, ثابت حرف *برچسب, صحيح *sockp,
    حرف **pathp, حرف **dirp)
{
	صحيح sock = -1, ret = -1;
	حرف *مسیر = عدم, *dir = عدم;

	*sockp = -1;
	*pathp = *dirp = عدم;

	إذا (pathspec == عدم || pathspec[0] == '\0') {
		error_f("no agent path specified");
		أرجع -1;
	}
	إذا (مقایسه_رشته(pathspec, "shared:", 7) == 0) {
		إذا (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			اذهب بیرون;
		}
		إذا ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == عدم) {
			/* Error already logged */
			اذهب بیرون;
		}
		إذا (agent_listener_shared(dir, pid, برچسب,
		    &sock, &مسیر, dirp) != 0) {
			/* Error already logged */
			اذهب بیرون;
		}
	} وإلا إذا (مقایسه_رشته(pathspec, "user:", 5) == 0) {
		إذا ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == عدم) {
			/* Error already logged */
			اذهب بیرون;
		}
		إذا (agent_listener_user(dir, pid, برچسب, &sock, &مسیر) != 0) {
			/* Error already logged */
			اذهب بیرون;
		}
	} وإلا {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		اذهب بیرون;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = مسیر;
	مسیر = عدم; /* transferred */
 بیرون:
	حرر(مسیر);
	حرر(dir);
	أرجع ret;
}

صحيح
agent_listener_cleanup(ثابت حرف *pathspec, ثابت حرف *sockpath,
    ثابت حرف *sockdir)
{
	إذا (sockpath == عدم)
		أرجع 0;
	إذا (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		أرجع -1;
	}
	debug3_f("removed socket %s", sockpath);

	إذا (pathspec == عدم)
		أرجع 0;
	إذا (مقایسه_رشته(pathspec, "shared:", 7) == 0 && sockdir != عدم) {
		إذا (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			أرجع -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	أرجع 0;
}

ساكن صحيح
socket_is_stale(ثابت حرف *مسیر)
{
	صحيح fd, r;
	بنية sockaddr_un sunaddr;
	socklen_t l = حجم(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	إذا (strlcpy(sunaddr.sun_مسیر, مسیر,
	    حجم(sunaddr.sun_مسیر)) >= حجم(sunaddr.sun_مسیر)) {
		debug_f("path for \"%s\" too long for sockaddr_un", مسیر);
		أرجع 0;
	}
	إذا ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		أرجع 0;
	}
	مجموعه_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	إذا (connect(fd, (بنية sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", مسیر, strerror(errno));
		close(fd);
		أرجع 1;
	}
	إذا (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		أرجع 0;
	}
	إذا (r != 0) {
		debug_f("socket error on %s: %s", مسیر, strerror(errno));
		close(fd);
		أرجع 1;
	}
	close(fd);
	debug_f("socket %s seems still active", مسیر);
	أرجع 0;
}

#اگر_تعریف_نشده HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(مسیر, buf)
#پایان_اگر
#اگر_تعریف_نشده HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(مسیر)
#پایان_اگر

فراغ
agent_cleanup_stale(ثابت حرف *pathspec, ثابت حرف *username, uid_t uid,
    ثابت حرف *homedir, صحيح ignore_hosthash)
{
	DIR *d = عدم;
	بنية dirent *dp;
	بنية stat sb;
	حرف *پیشوند = عدم, *dir = عدم, *مسیر;
	بنية timespec now, sub, *mtimp = عدم;

	/* Only clean up user socket directories */
	إذا (pathspec == عدم || مقایسه_رشته(pathspec, "user:", 5) != 0)
		أرجع;

	إذا ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == عدم)
		أرجع; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	إذا (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		اذهب بیرون;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	إذا (!ignore_hosthash) {
		إذا ((مسیر = agent_hostname_hash()) == عدم) {
			error_f("couldn't get hostname hash");
			اذهب بیرون;
		}
		xasprintf(&پیشوند, "s.%s.", مسیر);
		حرر(مسیر);
	}

	إذا ((d = opendir(dir)) == عدم) {
		إذا (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		اذهب بیرون;
	}
	طالما ((dp = readdir(d)) != عدم) {
#اگر_تعریف_شده HAVE_DIRENT_D_TYPE
		إذا (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			استمر;
#پایان_اگر
		إذا (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			استمر;
		}
		إذا (!S_ISSOCK(sb.st_mode))
			استمر;
#اگر_تعریف_شده HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#وإلا
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#پایان_اگر
		إذا (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			استمر;
		}
		إذا (!ignore_hosthash &&
		    مقایسه_رشته(dp->d_name, پیشوند, طول_رشته(پیشوند)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			استمر;
		}
		xasprintf(&مسیر, "%s/%s", dir, dp->d_name);
		إذا (socket_is_stale(مسیر)) {
			debug_f("cleanup stale socket %s", مسیر);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		حرر(مسیر);
	}
 بیرون:
	إذا (d != عدم)
		closedir(d);
	حرر(dir);
	حرر(پیشوند);
}

#لغو_تعریف unlinkat
#لغو_تعریف fstatat
