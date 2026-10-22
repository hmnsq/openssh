/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for OpenSSH SFTP client response parser (sftp-client.c)
 *
 * Target: sftp-client.c
 *
 * Drives every public sftp-client API on a socketpair using the
 * fuzzer input as the reply payload. A helper opens a fresh
 * socketpair, pre-fills a valid FXP_VERSION reply so sftp_init
 * succeeds, then writes the fuzzer body which the API call consumes
 * as its own response. Each iteration runs all 12 APIs on the same
 * input so no API is starved by a selector byte.
 *
 * Primary functions exercised:
 * - sftp_init, sftp_stat, sftp_lstat, sftp_realpath, sftp_expand_path
 * - sftp_readdir, sftp_statvfs, sftp_get_limits
 * - sftp_rm, sftp_mkdir, sftp_rmdir, sftp_rename, sftp_symlink
 * - decode_attrib via every reply path (sftp-common.c)
 *
 * Threat model: a malicious SFTP server returning crafted attribute
 * lists, name lists, status responses, and statvfs payloads to a
 * connected client (sshfs, sftp, scp to a hostile host).
 *
 * Failure handling: sftp-client.c calls fatal() liberally on
 * protocol violations. A custom cleanup_exit() longjmp()s back to
 * the helper. fuzz_arena (linker --wrap'd malloc family) frees
 * every still-live allocation on both the success and longjmp paths
 * so LSan sees zero per-iteration leaks.
 */

#ಅನ್ತರ್ಭಾವ <setjmp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

ಬಾಹ್ಯ "C" {
#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "sftp-common.h"
#ಅನ್ತರ್ಭಾವ "sftp-client.h"

ಶೂನ್ಯ fuzz_arena_begin(ಶೂನ್ಯ);
ಶೂನ್ಯ fuzz_arena_cleanup(ಶೂನ್ಯ);
}

ಬಾಹ್ಯ "C" ಅಸ್ಥಿರ sig_atomic_t interrupted = 0;
ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಂಕ showprogress = 0;
ಬಾಹ್ಯ "C" ಶೂನ್ಯ ಆರಂಭ_ಪ್ರಗತಿ_meter(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, off_t filesize,
    off_t *ctr) { (ಶೂನ್ಯ)file; (ಶೂನ್ಯ)filesize; (ಶೂನ್ಯ)ctr; }
ಬಾಹ್ಯ "C" ಶೂನ್ಯ refresh_ಪ್ರಗತಿ_meter(ಪೂರ್ಣಾಂಕ force_update) { (ಶೂನ್ಯ)force_update; }
ಬಾಹ್ಯ "C" ಶೂನ್ಯ stop_ಪ್ರಗತಿ_meter(ಶೂನ್ಯ) { }

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಅಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳ_fuzz = 0;

ಬಾಹ್ಯ "C" ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ ಸಂಕೇತ_2)
{
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, ಸಂಕೇತ_2 ? ಸಂಕೇತ_2 : 1);
	_exit(ಸಂಕೇತ_2);
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ uint8_t k_ಆವೃತ್ತಿ_ಉತ್ತರ[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

ಎಣಿಕೆ {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_ಮಾರ್ಗ,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_ಎಣಿಕೆ,
};

ಸ್ಥಿರ ಶೂನ್ಯ
ಸತತ_one(ಪೂರ್ಣಾಂಕ api, ಸ್ಥಿರಾಂಕ uint8_t *body, ಗಾತ್ರ_t bsize)
{
	ಪೂರ್ಣಾಂಕ sv[2] = { -1, -1 };
	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ಹಿಂತಿರುಗಿ;

	ssize_t w = ಲಿಖ(sv[0], k_ಆವೃತ್ತಿ_ಉತ್ತರ, ಗಾತ್ರ(k_ಆವೃತ್ತಿ_ಉತ್ತರ));
	(ಶೂನ್ಯ)w;
	ಆದರೆ (bsize > 0)
		w = ಲಿಖ(sv[0], body, bsize);
	(ಶೂನ್ಯ)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	ಒಳ_fuzz = 1;
	ಆದರೆ (setjmp(fuzz_env) == 0) {
		ರಚನೆ sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		ಆದರೆ (conn != ಖಾಲಿ) {
			Attrib attr;
			attrib_clear(&attr);

			ಆಯ್ಕೆ (api) {
			ಸ್ಥಿತಿ API_STAT: {
				Attrib a;
				(ಶೂನ್ಯ)sftp_stat(conn, "/fuzz", 1, &a);
				ನಿಲ್ಲಿಸು;
			}
			ಸ್ಥಿತಿ API_LSTAT: {
				Attrib a;
				(ಶೂನ್ಯ)sftp_lstat(conn, "/fuzz", 1, &a);
				ನಿಲ್ಲಿಸು;
			}
			ಸ್ಥಿತಿ API_REALPATH: {
				ಅಕ್ಷರ *p = sftp_realpath(conn, "/fuzz");
				ಬಿಡುಗಡೆ(p);
				ನಿಲ್ಲಿಸು;
			}
			ಸ್ಥಿತಿ API_EXPAND_ಮಾರ್ಗ: {
				ಅಕ್ಷರ *p = sftp_expand_ಮಾರ್ಗ(conn, "~");
				ಬಿಡುಗಡೆ(p);
				ನಿಲ್ಲಿಸು;
			}
			ಸ್ಥಿತಿ API_READDIR: {
				SFTP_DIRENT **dir = ಖಾಲಿ;
				(ಶೂನ್ಯ)sftp_readdir(conn, "/fuzz", &dir);
				ಆದರೆ (dir != ಖಾಲಿ)
					sftp_free_dirents(dir);
				ನಿಲ್ಲಿಸು;
			}
			ಸ್ಥಿತಿ API_STATVFS: {
				ರಚನೆ sftp_statvfs vfs;
				(ಶೂನ್ಯ)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				ನಿಲ್ಲಿಸು;
			}
			ಸ್ಥಿತಿ API_GET_LIMITS: {
				ರಚನೆ sftp_limits lim;
				(ಶೂನ್ಯ)sftp_get_limits(conn, &lim);
				ನಿಲ್ಲಿಸು;
			}
			ಸ್ಥಿತಿ API_RM:
				(ಶೂನ್ಯ)sftp_rm(conn, "/fuzz");
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ API_MKDIR:
				(ಶೂನ್ಯ)sftp_mkdir(conn, "/fuzz", &attr, 0);
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ API_RMDIR:
				(ಶೂನ್ಯ)sftp_rmdir(conn, "/fuzz");
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ API_RENAME:
				(ಶೂನ್ಯ)sftp_rename(conn, "/a", "/b", 0);
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ API_SYMLINK:
				(ಶೂನ್ಯ)sftp_symlink(conn, "/a", "/b");
				ನಿಲ್ಲಿಸು;
			}

			sftp_free(conn);
		}
	}
	ಒಳ_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಂಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ initialized = 0;
	ಆದರೆ (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	ಆದರೆ (ಗಾತ್ರ_2 > 65536)
		ಹಿಂತಿರುಗಿ 0;

	ಗಾಗಿ (ಪೂರ್ಣಾಂಕ api = 0; api < API_ಎಣಿಕೆ; api++)
		ಸತತ_one(api, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);

	ಹಿಂತಿರುಗಿ 0;
}
