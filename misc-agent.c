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

#وصف_ڪريو SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ساكن ثابت حرف presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ساكن حرف *
hostname_hash(سائيز_t len)
{
	حرف hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	صحيح r;
	سائيز_t l, i;

	l = ssh_digest_بائيٽون(SSH_DIGEST_SHA512);
	إذا (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		أرجع عدم;
	}
	إذا (gethostname(hostname, حجم(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		أرجع عدم;
	}
	إذا ((r = ssh_digest_يادگيري(SSH_DIGEST_SHA512,
	    hostname, لڙي_ڊيگهه(hostname), hash, حجم(hash))) != 0) {
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
unix_listener_tmp(حرف *رستو, صحيح backlog)
{
	بنية sockaddr_un sunaddr;
	صحيح good, sock = -1;
	سائيز_t i, xstart;
	گهڻائي_t prev_نقاب;

	/* Find first 'X' template character back from end of string */
	xstart = لڙي_ڊيگهه(رستو);
	طالما (xstart > 0 && رستو[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_نقاب = umask(0177);
	لكل (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		لكل (i = xstart; رستو[i] != '\0'; i++) {
			رستو[i] = presentation_chars[
			    arc4random_هڪجهڙو(حجم(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", رستو);

		إذا (strlcpy(sunaddr.sun_رستو, رستو,
		    حجم(sunaddr.sun_رستو)) >= حجم(sunaddr.sun_رستو)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    رستو);
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
				    رستو, strerror(errno));
				close(sock);
				sock = -1;
				استمر;
			}
			error_f("bind \"%s\": %.100s", رستو, strerror(errno));
			اكسر;
		}
		إذا (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", رستو, strerror(errno));
			اكسر;
		}
		good = 1;
	}
	umask(prev_نقاب);
	إذا (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    رستو, sock);
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
agent_listener_shared(ثابت حرف *والد_dir, pid_t pid, ثابت حرف *ٽيگ,
    صحيح *sockp, حرف **pathp, حرف **dirp)
{
	حرف *dir = عدم, *رستو = عدم;
	صحيح sock, ret = -1;
	گهڻائي_t prev_نقاب;

	*pathp = *dirp = عدم;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", والد_dir);
	إذا (mkdtemp(dir) == عدم) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		اذهب ٻاهريون;
	}
	xasprintf(&رستو, "%s/agent.%s.%ld", dir, ٽيگ, (ڊگهو)pid);
	prev_نقاب = umask(0177);
	إذا ((sock = unix_listener(رستو, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_نقاب);
		إذا (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		اذهب ٻاهريون;
	}
	umask(prev_نقاب);

	/* Success */
	*dirp = dir;
	dir = عدم; /* transferred */
	*pathp = رستو;
	رستو = عدم; /* transferred */
	*sockp = sock;
	ret = 0;
 ٻاهريون:
	حرر(dir);
	حرر(رستو);
	أرجع ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ساكن صحيح
agent_listener_user(ثابت حرف *dir, pid_t pid, ثابت حرف *ٽيگ,
    صحيح *sockp, حرف **pathp)
{
	حرف *hostnamehash = عدم, *رستو = عدم;
	صحيح sock, ret = -1;

	إذا ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == عدم)
		أرجع -1;
	xasprintf(&رستو, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, ٽيگ, (ڊگهو ڊگهو)pid);
	إذا (mkdir_رستو(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		اذهب ٻاهريون;
	}
	إذا ((sock = unix_listener_tmp(رستو, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		اذهب ٻاهريون;
	}
	/* Success */
	*pathp = رستو;
	رستو = عدم; /* transferred */
	*sockp = sock;
	ret = 0;
 ٻاهريون:
	حرر(hostnamehash);
	حرر(رستو);
	أرجع ret;
}

ساكن حرف *
expand_pathspec(ثابت حرف *رستو, ثابت حرف *username,
    uid_t uid, ثابت حرف *homedir)
{
	حرف *uidbuf = عدم, *dir = عدم, *tmp = عدم;

	xasprintf(&uidbuf, "%lld", (ڊگهو ڊگهو)uid);

	إذا ((tmp = percent_expand(رستو, "u", username, "U", uidbuf,
	    "h", homedir, عدم)) == عدم) {
		error_f("failed to percent-expand agent socket directory");
		اذهب ٻاهريون;
	}
	إذا (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		اذهب ٻاهريون;
	}
	إذا (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		حرر(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 ٻاهريون:
	حرر(uidbuf);
	حرر(tmp);
	أرجع dir;
}

صحيح
agent_listener(ثابت حرف *pathspec, ثابت حرف *username, uid_t uid,
    ثابت حرف *homedir, pid_t pid, ثابت حرف *ٽيگ, صحيح *sockp,
    حرف **pathp, حرف **dirp)
{
	صحيح sock = -1, ret = -1;
	حرف *رستو = عدم, *dir = عدم;

	*sockp = -1;
	*pathp = *dirp = عدم;

	إذا (pathspec == عدم || pathspec[0] == '\0') {
		error_f("no agent path specified");
		أرجع -1;
	}
	إذا (لڙي_ڀيٽ(pathspec, "shared:", 7) == 0) {
		إذا (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			اذهب ٻاهريون;
		}
		إذا ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == عدم) {
			/* Error already logged */
			اذهب ٻاهريون;
		}
		إذا (agent_listener_shared(dir, pid, ٽيگ,
		    &sock, &رستو, dirp) != 0) {
			/* Error already logged */
			اذهب ٻاهريون;
		}
	} وإلا إذا (لڙي_ڀيٽ(pathspec, "user:", 5) == 0) {
		إذا ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == عدم) {
			/* Error already logged */
			اذهب ٻاهريون;
		}
		إذا (agent_listener_user(dir, pid, ٽيگ, &sock, &رستو) != 0) {
			/* Error already logged */
			اذهب ٻاهريون;
		}
	} وإلا {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		اذهب ٻاهريون;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = رستو;
	رستو = عدم; /* transferred */
 ٻاهريون:
	حرر(رستو);
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
	إذا (لڙي_ڀيٽ(pathspec, "shared:", 7) == 0 && sockdir != عدم) {
		إذا (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			أرجع -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	أرجع 0;
}

ساكن صحيح
socket_is_stale(ثابت حرف *رستو)
{
	صحيح fd, r;
	بنية sockaddr_un sunaddr;
	socklen_t l = حجم(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	إذا (strlcpy(sunaddr.sun_رستو, رستو,
	    حجم(sunaddr.sun_رستو)) >= حجم(sunaddr.sun_رستو)) {
		debug_f("path for \"%s\" too long for sockaddr_un", رستو);
		أرجع 0;
	}
	إذا ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		أرجع 0;
	}
	سيٽ_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	إذا (connect(fd, (بنية sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", رستو, strerror(errno));
		close(fd);
		أرجع 1;
	}
	إذا (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		أرجع 0;
	}
	إذا (r != 0) {
		debug_f("socket error on %s: %s", رستو, strerror(errno));
		close(fd);
		أرجع 1;
	}
	close(fd);
	debug_f("socket %s seems still active", رستو);
	أرجع 0;
}

#جيڪڏهن_وصف_نه_ٿيل HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(رستو, buf)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(رستو)
#جيڪڏهن_پورو

فراغ
agent_cleanup_stale(ثابت حرف *pathspec, ثابت حرف *username, uid_t uid,
    ثابت حرف *homedir, صحيح ignore_hosthash)
{
	DIR *d = عدم;
	بنية dirent *dp;
	بنية stat sb;
	حرف *اڳياڙي = عدم, *dir = عدم, *رستو;
	بنية timespec now, sub, *mtimp = عدم;

	/* Only clean up user socket directories */
	إذا (pathspec == عدم || لڙي_ڀيٽ(pathspec, "user:", 5) != 0)
		أرجع;

	إذا ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == عدم)
		أرجع; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	إذا (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		اذهب ٻاهريون;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	إذا (!ignore_hosthash) {
		إذا ((رستو = agent_hostname_hash()) == عدم) {
			error_f("couldn't get hostname hash");
			اذهب ٻاهريون;
		}
		xasprintf(&اڳياڙي, "s.%s.", رستو);
		حرر(رستو);
	}

	إذا ((d = opendir(dir)) == عدم) {
		إذا (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		اذهب ٻاهريون;
	}
	طالما ((dp = readdir(d)) != عدم) {
#جيڪڏهن_وصف_ٿيل HAVE_DIRENT_D_TYPE
		إذا (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			استمر;
#جيڪڏهن_پورو
		إذا (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			استمر;
		}
		إذا (!S_ISSOCK(sb.st_mode))
			استمر;
#جيڪڏهن_وصف_ٿيل HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#وإلا
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#جيڪڏهن_پورو
		إذا (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			استمر;
		}
		إذا (!ignore_hosthash &&
		    لڙي_ڀيٽ(dp->d_name, اڳياڙي, لڙي_ڊيگهه(اڳياڙي)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			استمر;
		}
		xasprintf(&رستو, "%s/%s", dir, dp->d_name);
		إذا (socket_is_stale(رستو)) {
			debug_f("cleanup stale socket %s", رستو);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		حرر(رستو);
	}
 ٻاهريون:
	إذا (d != عدم)
		closedir(d);
	حرر(dir);
	حرر(اڳياڙي);
}

#وصف_رد unlinkat
#وصف_رد fstatat
