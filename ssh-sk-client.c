/* $OpenBSD: ssh-sk-client.c,v 1.18 2026/03/11 09:10:59 dtucker Exp $ */
/*
 * Copyright (c) 2019 Google LLC
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

/* #define DEBUG_SK 1 */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
start_helper(ಪೂರ್ಣಾಙ್ಕ *fdp, pid_t *pidp, ಶೂನ್ಯ (**osigchldp)(ಪೂರ್ಣಾಙ್ಕ))
{
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ);
	ಪೂರ್ಣಾಙ್ಕ oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	ವರ್ಣ execbuf[100], *helper, *verbosity = ರಿಕ್ತ;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	ಯದಿ (helper == ರಿಕ್ತ || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	ಯದಿ (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ಯದಿ ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}
	ಯದಿ (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		ಯದಿ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, ಪರಿಮಾಣ execbuf,
			    "dup2: %s", strerror(errno));
			ಲಿಖ(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == ರಿಕ್ತ ? "" : verbosity);
		execlp(helper, helper, verbosity, (ವರ್ಣ *)ರಿಕ್ತ);
		snprintf(execbuf, ಪರಿಮಾಣ execbuf,
		    "execlp: %s", strerror(errno));
		ಲಿಖ(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = ಪಠ(execpipe[0], execbuf, ಪರಿಮಾಣ execbuf);
	close(execpipe[0]);
	ಯದಿ (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
reap_helper(pid_t pid)
{
	ಪೂರ್ಣಾಙ್ಕ status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	ಯಾವತ್ (waitpid(pid, &status, 0) == -1) {
		ಯದಿ (errno == EINTR) {
			errno = 0;
			ಅನುವರ್ತ;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}
	ಯದಿ (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_FAILURE;
	} ಅನ್ಯಥಾ ಯದಿ (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_FAILURE;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
client_converse(ಸಂರಚನಾ sshbuf *ಸಂದೇಶ, ಸಂರಚನಾ sshbuf **respp, u_int type)
{
	ಪೂರ್ಣಾಙ್ಕ oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ);
	ಸಂರಚನಾ sshbuf *req = ರಿಕ್ತ, *resp = ರಿಕ್ತ;
	*respp = ರಿಕ್ತ;

	ಯದಿ ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಯದಿ ((req = sshbuf_new()) == ರಿಕ್ತ || (resp = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	ಯದಿ ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, ಸಂದೇಶ)) != 0) {
		error_fr(r, "compose");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = ssh_ಸಂದೇಶ_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = ssh_ಸಂದೇಶ_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		ಗಚ್ಛ out;
	}
	ಯದಿ (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		ಗಚ್ಛ out;
	}
	ಯದಿ (rtype == SSH_SK_HELPER_ERROR) {
		ಯದಿ ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			ಗಚ್ಛ out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		ಯದಿ (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		ಅನ್ಯಥಾ
			r = -(ಪೂರ್ಣಾಙ್ಕ)rerr;
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ ಯದಿ (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	ಯದಿ ((r2 = reap_helper(pid)) != 0) {
		ಯದಿ (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	ಯದಿ (r == 0) {
		*respp = resp;
		resp = ರಿಕ್ತ;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;

}

ಪೂರ್ಣಾಙ್ಕ
sshsk_sign(ಧ್ರುವ ವರ್ಣ *provider, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp, ಧ್ರುವ u_char *data, size_t datalen,
    u_int compat, ಧ್ರುವ ವರ್ಣ *pin)
{
	ಪೂರ್ಣಾಙ್ಕ oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *kbuf = ರಿಕ್ತ, *req = ರಿಕ್ತ, *resp = ರಿಕ್ತ;

	*sigp = ರಿಕ್ತ;
	*lenp = 0;

#ifndef ENABLE_SK
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
#endif

	ಯದಿ ((kbuf = sshbuf_new()) == ರಿಕ್ತ ||
	    (req = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshkey_private_serialize(ಕೀಲಿ, kbuf)) != 0) {
		error_fr(r, "encode key");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, ರಿಕ್ತ)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	ಯದಿ (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = ರಿಕ್ತ;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsk_enroll(ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *provider_path, ಧ್ರುವ ವರ್ಣ *device,
    ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ ವರ್ಣ *userid, uint8_t flags,
    ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sshbuf *challenge_buf,
    ಸಂರಚನಾ sshkey **keyp, ಸಂರಚನಾ sshbuf *attest)
{
	ಪೂರ್ಣಾಙ್ಕ oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *kbuf = ರಿಕ್ತ, *abuf = ರಿಕ್ತ, *req = ರಿಕ್ತ, *resp = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;

	*keyp = ರಿಕ್ತ;
	ಯದಿ (attest != ರಿಕ್ತ)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
#endif

	ಯದಿ (type < 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((abuf = sshbuf_new()) == ರಿಕ್ತ ||
	    (kbuf = sshbuf_new()) == ರಿಕ್ತ ||
	    (req = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_private_deserialize(kbuf, &ಕೀಲಿ)) != 0) {
		error_fr(r, "encode");
		ಗಚ್ಛ out;
	}
	ಯದಿ (attest != ರಿಕ್ತ && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		ಗಚ್ಛ out;
	}

	/* success */
	r = 0;
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ರಿಕ್ತ;
 out:
	oerrno = errno;
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_resident_ಕೀಲಿ(ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ *srk)
{
	ಯದಿ (srk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	sshkey_free(srk->ಕೀಲಿ);
	freezero(srk->user_id, srk->user_id_len);
	ಮುಕ್ತ(srk);
}


ಶೂನ್ಯ
sshsk_free_resident_ಕೀಲಿಗಳು(ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ **srks, size_t nsrks)
{
	size_t i;

	ಯದಿ (srks == ರಿಕ್ತ || nsrks == 0)
		ಪ್ರತ್ಯಾಗಮ;

	ಪ್ರತಿ (i = 0; i < nsrks; i++)
		sshsk_free_resident_ಕೀಲಿ(srks[i]);
	ಮುಕ್ತ(srks);
}

ಪೂರ್ಣಾಙ್ಕ
sshsk_load_resident(ಧ್ರುವ ವರ್ಣ *provider_path, ಧ್ರುವ ವರ್ಣ *device,
    ಧ್ರುವ ವರ್ಣ *pin, u_int flags, ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ ***srksp,
    size_t *nsrksp)
{
	ಪೂರ್ಣಾಙ್ಕ oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *kbuf = ರಿಕ್ತ, *req = ರಿಕ್ತ, *resp = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ *srk = ರಿಕ್ತ, **srks = ರಿಕ್ತ, **tmp;
	u_char *userid = ರಿಕ್ತ;
	size_t userid_len = 0, nsrks = 0;

	*srksp = ರಿಕ್ತ;
	*nsrksp = 0;

	ಯದಿ ((kbuf = sshbuf_new()) == ರಿಕ್ತ ||
	    (req = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		ಗಚ್ಛ out;

	ಯಾವತ್ (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		ಯದಿ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshkey_private_deserialize(kbuf, &ಕೀಲಿ)) != 0) {
			error_fr(r, "decode key");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((srk = calloc(1, ಪರಿಮಾಣ(*srk))) == ರಿಕ್ತ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		srk->ಕೀಲಿ = ಕೀಲಿ;
		ಕೀಲಿ = ರಿಕ್ತ;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = ರಿಕ್ತ;
		userid_len = 0;
		ಯದಿ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    ಪರಿಮಾಣ(*srks))) == ರಿಕ್ತ) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->ಕೀಲಿ), srk->ಕೀಲಿ->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ರಿಕ್ತ;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ರಿಕ್ತ;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_ಕೀಲಿ(srk);
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}
