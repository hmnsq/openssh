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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಂಭ_helper(ಪೂರ್ಣಾಂಕ *fdp, pid_t *pidp, ಶೂನ್ಯ (**osigchldp)(ಪೂರ್ಣಾಂಕ))
{
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ);
	ಪೂರ್ಣಾಂಕ oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	ಅಕ್ಷರ execbuf[100], *helper, *verbosity = ಖಾಲಿ;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	ಆದರೆ (helper == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(helper) == 0)
		helper = ಮಾರ್ಗ_SSH_SK_HELPER;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	verbosity = "-vvv";
#ಆದರೆ_ಅಂತ್ಯ

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	ಆದರೆ (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ಆದರೆ ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}
	ಆದರೆ (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		ಆದರೆ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, ಗಾತ್ರ execbuf,
			    "dup2: %s", strerror(errno));
			ಲಿಖ(execpipe[1], execbuf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == ಖಾಲಿ ? "" : verbosity);
		execlp(helper, helper, verbosity, (ಅಕ್ಷರ *)ಖಾಲಿ);
		snprintf(execbuf, ಗಾತ್ರ execbuf,
		    "execlp: %s", strerror(errno));
		ಲಿಖ(execpipe[1], execbuf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = ಪಠ(execpipe[0], execbuf, ಗಾತ್ರ execbuf);
	close(execpipe[0]);
	ಆದರೆ (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (ದೀರ್ಘ)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
reap_helper(pid_t pid)
{
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2, oerrno;

	debug3_f("pid=%ld", (ದೀರ್ಘ)pid);

	errno = 0;
	ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, 0) == -1) {
		ಆದರೆ (errno == EINTR) {
			errno = 0;
			ಮುಂದುವರಿ;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}
	ಆದರೆ (!WIFEXITED(ಸ್ಥಿತಿ_2)) {
		error_f("helper exited abnormally");
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_FAILURE;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0) {
		error_f("helper exited with non-zero exit status");
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_FAILURE;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
client_converse(ರಚನೆ sshbuf *ಸಂದೇಶ, ರಚನೆ sshbuf **respp, u_int type)
{
	ಪೂರ್ಣಾಂಕ oerrno, fd, r2, ll, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char ಆವೃತ್ತಿ;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ);
	ರಚನೆ sshbuf *req = ಖಾಲಿ, *resp = ಖಾಲಿ;
	*respp = ಖಾಲಿ;

	ಆದರೆ ((r = ಆರಂಭ_helper(&fd, &pid, &osigchld)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಆದರೆ ((req = sshbuf_new()) == ಖಾಲಿ || (resp = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	ಆದರೆ ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, ಸಂದೇಶ)) != 0) {
		error_fr(r, "compose");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = ssh_ಸಂದೇಶ_send(fd, SSH_SK_HELPER_ಆವೃತ್ತಿ, req)) != 0) {
		error_fr(r, "send");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = ssh_ಸಂದೇಶ_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_u8(resp, &ಆವೃತ್ತಿ)) != 0) {
		error_fr(r, "parse version");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ಆವೃತ್ತಿ != SSH_SK_HELPER_ಆವೃತ್ತಿ) {
		error_f("unsupported version: got %u, expected %u",
		    ಆವೃತ್ತಿ, SSH_SK_HELPER_ಆವೃತ್ತಿ);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (rtype == SSH_SK_HELPER_ERROR) {
		ಆದರೆ ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		ಆದರೆ (rerr == 0 || rerr >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
			r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಇಲ್ಲದಿದ್ದರೆ
			r = -(ಪೂರ್ಣಾಂಕ)rerr;
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	oerrno = errno;
	close(fd);
	ಆದರೆ ((r2 = reap_helper(pid)) != 0) {
		ಆದರೆ (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	ಆದರೆ (r == 0) {
		*respp = resp;
		resp = ಖಾಲಿ;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	ಹಿಂತಿರುಗಿ r;

}

ಪೂರ್ಣಾಂಕ
sshsk_sign(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider, ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    u_int compat, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin)
{
	ಪೂರ್ಣಾಂಕ oerrno, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *kbuf = ಖಾಲಿ, *req = ಖಾಲಿ, *resp = ಖಾಲಿ;

	*sigp = ಖಾಲಿ;
	*lenp = 0;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ENABLE_SK
	ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ ((kbuf = sshbuf_new()) == ಖಾಲಿ ||
	    (req = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_serialize(ಕೀಲಿ, kbuf)) != 0) {
		error_fr(r, "encode key");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, ದತ್ತಾಂಶ, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, ಖಾಲಿ)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	oerrno = errno;
	ಆದರೆ (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = ಖಾಲಿ;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsk_enroll(ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *userid, uint8_t flags,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sshbuf *challenge_buf,
    ರಚನೆ sshkey **keyp, ರಚನೆ sshbuf *attest)
{
	ಪೂರ್ಣಾಂಕ oerrno, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *kbuf = ಖಾಲಿ, *abuf = ಖಾಲಿ, *req = ಖಾಲಿ, *resp = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;

	*keyp = ಖಾಲಿ;
	ಆದರೆ (attest != ಖಾಲಿ)
		sshbuf_reset(attest);

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ENABLE_SK
	ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (type < 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((abuf = sshbuf_new()) == ಖಾಲಿ ||
	    (kbuf = sshbuf_new()) == ಖಾಲಿ ||
	    (req = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_ಮಾರ್ಗ)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_deserialize(kbuf, &ಕೀಲಿ)) != 0) {
		error_fr(r, "encode");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (attest != ಖಾಲಿ && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* success */
	r = 0;
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	oerrno = errno;
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_resident_ಕೀಲಿ(ರಚನೆ sshsk_resident_ಕೀಲಿ *srk)
{
	ಆದರೆ (srk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	sshkey_free(srk->ಕೀಲಿ);
	freezero(srk->user_id, srk->user_id_len);
	ಬಿಡುಗಡೆ(srk);
}


ಶೂನ್ಯ
sshsk_free_resident_ಕೀಲಿಗಳು(ರಚನೆ sshsk_resident_ಕೀಲಿ **srks, ಗಾತ್ರ_t nsrks)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (srks == ಖಾಲಿ || nsrks == 0)
		ಹಿಂತಿರುಗಿ;

	ಗಾಗಿ (i = 0; i < nsrks; i++)
		sshsk_free_resident_ಕೀಲಿ(srks[i]);
	ಬಿಡುಗಡೆ(srks);
}

ಪೂರ್ಣಾಂಕ
sshsk_ತುಂಬು_resident(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, u_int flags, ರಚನೆ sshsk_resident_ಕೀಲಿ ***srksp,
    ಗಾತ್ರ_t *nsrksp)
{
	ಪೂರ್ಣಾಂಕ oerrno, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *kbuf = ಖಾಲಿ, *req = ಖಾಲಿ, *resp = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshsk_resident_ಕೀಲಿ *srk = ಖಾಲಿ, **srks = ಖಾಲಿ, **tmp;
	u_char *userid = ಖಾಲಿ;
	ಗಾತ್ರ_t userid_len = 0, nsrks = 0;

	*srksp = ಖಾಲಿ;
	*nsrksp = 0;

	ಆದರೆ ((kbuf = sshbuf_new()) == ಖಾಲಿ ||
	    (req = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshbuf_put_cstring(req, provider_ಮಾರ್ಗ)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = client_converse(req, &resp, SSH_SK_HELPER_ತುಂಬು_RESIDENT)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆಗ (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		ಆದರೆ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_deserialize(kbuf, &ಕೀಲಿ)) != 0) {
			error_fr(r, "decode key");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((srk = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*srk))) == ಖಾಲಿ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		srk->ಕೀಲಿ = ಕೀಲಿ;
		ಕೀಲಿ = ಖಾಲಿ;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = ಖಾಲಿ;
		userid_len = 0;
		ಆದರೆ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    ಗಾತ್ರ(*srks))) == ಖಾಲಿ) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->ಕೀಲಿ), srk->ಕೀಲಿ->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ಖಾಲಿ;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ಖಾಲಿ;
	nsrks = 0;
 ಹೊರಹೋಗು:
	oerrno = errno;
	sshsk_free_resident_ಕೀಲಿ(srk);
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}
