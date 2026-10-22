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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/stat.h>
#شامل <sys/un.h>

#شامل <dirent.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netdb.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <libgen.h>

#شامل "digest.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "pathnames.h"
#شامل "ssh.h"
#شامل "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#تعریف_کرو SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ساکن ثابت حرف presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ساکن حرف *
hostname_hash(سائز_t len)
{
	حرف hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	صحیح r;
	سائز_t l, i;

	l = ssh_digest_بائٹیں(SSH_DIGEST_SHA512);
	اگر (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		واپس تہی;
	}
	اگر (gethostname(hostname, حجم(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		واپس تہی;
	}
	اگر ((r = ssh_digest_حافظہ(SSH_DIGEST_SHA512,
	    hostname, لڑی_لمبائی(hostname), hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		واپس تہی;
	}
	memset(p, '\0', حجم(p));
	برائے (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (حجم(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	واپس xstrdup(p);
}

ساکن حرف *
agent_hostname_hash(خالی)
{
	واپس hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
ساکن صحیح
unix_listener_tmp(حرف *راستہ, صحیح backlog)
{
	ساخت sockaddr_un sunaddr;
	صحیح good, sock = -1;
	سائز_t i, xstart;
	منوال_t پچھلا_نقاب;

	/* Find first 'X' template character back from end of string */
	xstart = لڑی_لمبائی(راستہ);
	جب (xstart > 0 && راستہ[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	پچھلا_نقاب = umask(0177);
	برائے (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		برائے (i = xstart; راستہ[i] != '\0'; i++) {
			راستہ[i] = presentation_chars[
			    arc4random_یکساں(حجم(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", راستہ);

		اگر (strlcpy(sunaddr.sun_راستہ, راستہ,
		    حجم(sunaddr.sun_راستہ)) >= حجم(sunaddr.sun_راستہ)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    راستہ);
			توڑو;
		}

		اگر ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			توڑو;
		}
		اگر (bind(sock, (ساخت sockaddr *)&sunaddr,
		    حجم(sunaddr)) == -1) {
			اگر (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    راستہ, strerror(errno));
				close(sock);
				sock = -1;
				جاری;
			}
			error_f("bind \"%s\": %.100s", راستہ, strerror(errno));
			توڑو;
		}
		اگر (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", راستہ, strerror(errno));
			توڑو;
		}
		good = 1;
	}
	umask(پچھلا_نقاب);
	اگر (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    راستہ, sock);
	} ورنہ اگر (sock != -1) {
		close(sock);
		sock = -1;
	}
	واپس sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
ساکن صحیح
agent_listener_shared(ثابت حرف *والد_dir, pid_t pid, ثابت حرف *لیبل,
    صحیح *sockp, حرف **pathp, حرف **dirp)
{
	حرف *dir = تہی, *راستہ = تہی;
	صحیح sock, ret = -1;
	منوال_t پچھلا_نقاب;

	*pathp = *dirp = تہی;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", والد_dir);
	اگر (mkdtemp(dir) == تہی) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		جاؤ برآمد;
	}
	xasprintf(&راستہ, "%s/agent.%s.%ld", dir, لیبل, (طویل)pid);
	پچھلا_نقاب = umask(0177);
	اگر ((sock = unix_listener(راستہ, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(پچھلا_نقاب);
		اگر (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		جاؤ برآمد;
	}
	umask(پچھلا_نقاب);

	/* Success */
	*dirp = dir;
	dir = تہی; /* transferred */
	*pathp = راستہ;
	راستہ = تہی; /* transferred */
	*sockp = sock;
	ret = 0;
 برآمد:
	آزاد(dir);
	آزاد(راستہ);
	واپس ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ساکن صحیح
agent_listener_user(ثابت حرف *dir, pid_t pid, ثابت حرف *لیبل,
    صحیح *sockp, حرف **pathp)
{
	حرف *hostnamehash = تہی, *راستہ = تہی;
	صحیح sock, ret = -1;

	اگر ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == تہی)
		واپس -1;
	xasprintf(&راستہ, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, لیبل, (طویل طویل)pid);
	اگر (mkdir_راستہ(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		جاؤ برآمد;
	}
	اگر ((sock = unix_listener_tmp(راستہ, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		جاؤ برآمد;
	}
	/* Success */
	*pathp = راستہ;
	راستہ = تہی; /* transferred */
	*sockp = sock;
	ret = 0;
 برآمد:
	آزاد(hostnamehash);
	آزاد(راستہ);
	واپس ret;
}

ساکن حرف *
expand_pathspec(ثابت حرف *راستہ, ثابت حرف *username,
    uid_t uid, ثابت حرف *homedir)
{
	حرف *uidbuf = تہی, *dir = تہی, *tmp = تہی;

	xasprintf(&uidbuf, "%lld", (طویل طویل)uid);

	اگر ((tmp = percent_expand(راستہ, "u", username, "U", uidbuf,
	    "h", homedir, تہی)) == تہی) {
		error_f("failed to percent-expand agent socket directory");
		جاؤ برآمد;
	}
	اگر (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		جاؤ برآمد;
	}
	اگر (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		آزاد(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 برآمد:
	آزاد(uidbuf);
	آزاد(tmp);
	واپس dir;
}

صحیح
agent_listener(ثابت حرف *pathspec, ثابت حرف *username, uid_t uid,
    ثابت حرف *homedir, pid_t pid, ثابت حرف *لیبل, صحیح *sockp,
    حرف **pathp, حرف **dirp)
{
	صحیح sock = -1, ret = -1;
	حرف *راستہ = تہی, *dir = تہی;

	*sockp = -1;
	*pathp = *dirp = تہی;

	اگر (pathspec == تہی || pathspec[0] == '\0') {
		error_f("no agent path specified");
		واپس -1;
	}
	اگر (لڑی_موازنہ(pathspec, "shared:", 7) == 0) {
		اگر (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			جاؤ برآمد;
		}
		اگر ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == تہی) {
			/* Error already logged */
			جاؤ برآمد;
		}
		اگر (agent_listener_shared(dir, pid, لیبل,
		    &sock, &راستہ, dirp) != 0) {
			/* Error already logged */
			جاؤ برآمد;
		}
	} ورنہ اگر (لڑی_موازنہ(pathspec, "user:", 5) == 0) {
		اگر ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == تہی) {
			/* Error already logged */
			جاؤ برآمد;
		}
		اگر (agent_listener_user(dir, pid, لیبل, &sock, &راستہ) != 0) {
			/* Error already logged */
			جاؤ برآمد;
		}
	} ورنہ {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		جاؤ برآمد;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = راستہ;
	راستہ = تہی; /* transferred */
 برآمد:
	آزاد(راستہ);
	آزاد(dir);
	واپس ret;
}

صحیح
agent_listener_cleanup(ثابت حرف *pathspec, ثابت حرف *sockpath,
    ثابت حرف *sockdir)
{
	اگر (sockpath == تہی)
		واپس 0;
	اگر (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		واپس -1;
	}
	debug3_f("removed socket %s", sockpath);

	اگر (pathspec == تہی)
		واپس 0;
	اگر (لڑی_موازنہ(pathspec, "shared:", 7) == 0 && sockdir != تہی) {
		اگر (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			واپس -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	واپس 0;
}

ساکن صحیح
socket_is_stale(ثابت حرف *راستہ)
{
	صحیح fd, r;
	ساخت sockaddr_un sunaddr;
	socklen_t l = حجم(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	اگر (strlcpy(sunaddr.sun_راستہ, راستہ,
	    حجم(sunaddr.sun_راستہ)) >= حجم(sunaddr.sun_راستہ)) {
		debug_f("path for \"%s\" too long for sockaddr_un", راستہ);
		واپس 0;
	}
	اگر ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		واپس 0;
	}
	سیٹ_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	اگر (connect(fd, (ساخت sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", راستہ, strerror(errno));
		close(fd);
		واپس 1;
	}
	اگر (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		واپس 0;
	}
	اگر (r != 0) {
		debug_f("socket error on %s: %s", راستہ, strerror(errno));
		close(fd);
		واپس 1;
	}
	close(fd);
	debug_f("socket %s seems still active", راستہ);
	واپس 0;
}

#اگر_غیر_تعریف_شدہ HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(راستہ, buf)
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(راستہ)
#اگر_ختم

خالی
agent_cleanup_stale(ثابت حرف *pathspec, ثابت حرف *username, uid_t uid,
    ثابت حرف *homedir, صحیح ignore_hosthash)
{
	DIR *d = تہی;
	ساخت dirent *dp;
	ساخت stat sb;
	حرف *سابقہ = تہی, *dir = تہی, *راستہ;
	ساخت timespec now, sub, *mtimp = تہی;

	/* Only clean up user socket directories */
	اگر (pathspec == تہی || لڑی_موازنہ(pathspec, "user:", 5) != 0)
		واپس;

	اگر ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == تہی)
		واپس; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	اگر (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		جاؤ برآمد;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	اگر (!ignore_hosthash) {
		اگر ((راستہ = agent_hostname_hash()) == تہی) {
			error_f("couldn't get hostname hash");
			جاؤ برآمد;
		}
		xasprintf(&سابقہ, "s.%s.", راستہ);
		آزاد(راستہ);
	}

	اگر ((d = opendir(dir)) == تہی) {
		اگر (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		جاؤ برآمد;
	}
	جب ((dp = readdir(d)) != تہی) {
#اگر_تعریف_شدہ HAVE_DIRENT_D_TYPE
		اگر (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			جاری;
#اگر_ختم
		اگر (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			جاری;
		}
		اگر (!S_ISSOCK(sb.st_mode))
			جاری;
#اگر_تعریف_شدہ HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#ورنہ
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#اگر_ختم
		اگر (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			جاری;
		}
		اگر (!ignore_hosthash &&
		    لڑی_موازنہ(dp->d_name, سابقہ, لڑی_لمبائی(سابقہ)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			جاری;
		}
		xasprintf(&راستہ, "%s/%s", dir, dp->d_name);
		اگر (socket_is_stale(راستہ)) {
			debug_f("cleanup stale socket %s", راستہ);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		آزاد(راستہ);
	}
 برآمد:
	اگر (d != تہی)
		closedir(d);
	آزاد(dir);
	آزاد(سابقہ);
}

#تعریف_منسوخ unlinkat
#تعریف_منسوخ fstatat
