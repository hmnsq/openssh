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

#अन्तर्भाव <setjmp.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/types.h>

बाह्य "C" {
#अन्तर्भाव "includes.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sftp.h"
#अन्तर्भाव "sftp-common.h"
#अन्तर्भाव "sftp-client.h"

शून्य fuzz_arena_begin(शून्य);
शून्य fuzz_arena_cleanup(शून्य);
}

बाह्य "C" चञ्चल sig_atomic_t interrupted = 0;
बाह्य "C" पूर्णाङ्क showprogress = 0;
बाह्य "C" शून्य start_progress_meter(ध्रुव वर्ण *file, off_t filesize,
    off_t *ctr) { (शून्य)file; (शून्य)filesize; (शून्य)ctr; }
बाह्य "C" शून्य refresh_progress_meter(पूर्णाङ्क force_update) { (शून्य)force_update; }
बाह्य "C" शून्य stop_progress_meter(शून्य) { }

स्थिर jmp_buf fuzz_env;
स्थिर चञ्चल पूर्णाङ्क in_fuzz = 0;

बाह्य "C" शून्य
cleanup_exit(पूर्णाङ्क code)
{
	जइ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

स्थिर ध्रुव uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

गणना {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_PATH,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_गणनम्,
};

स्थिर शून्य
run_one(पूर्णाङ्क api, ध्रुव uint8_t *body, size_t bsize)
{
	पूर्णाङ्क sv[2] = { -1, -1 };
	जइ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		प्रत्यागम;

	ssize_t w = लिख(sv[0], k_version_reply, परिमाण(k_version_reply));
	(शून्य)w;
	जइ (bsize > 0)
		w = लिख(sv[0], body, bsize);
	(शून्य)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	जइ (setjmp(fuzz_env) == 0) {
		संरचना sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		जइ (conn != रिक्त) {
			Attrib attr;
			attrib_clear(&attr);

			विकल्प (api) {
			पक्ष API_STAT: {
				Attrib a;
				(शून्य)sftp_stat(conn, "/fuzz", 1, &a);
				भङ्ग;
			}
			पक्ष API_LSTAT: {
				Attrib a;
				(शून्य)sftp_lstat(conn, "/fuzz", 1, &a);
				भङ्ग;
			}
			पक्ष API_REALPATH: {
				वर्ण *p = sftp_realpath(conn, "/fuzz");
				मुक्त(p);
				भङ्ग;
			}
			पक्ष API_EXPAND_PATH: {
				वर्ण *p = sftp_expand_path(conn, "~");
				मुक्त(p);
				भङ्ग;
			}
			पक्ष API_READDIR: {
				SFTP_DIRENT **dir = रिक्त;
				(शून्य)sftp_readdir(conn, "/fuzz", &dir);
				जइ (dir != रिक्त)
					sftp_free_dirents(dir);
				भङ्ग;
			}
			पक्ष API_STATVFS: {
				संरचना sftp_statvfs vfs;
				(शून्य)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				भङ्ग;
			}
			पक्ष API_GET_LIMITS: {
				संरचना sftp_limits lim;
				(शून्य)sftp_get_limits(conn, &lim);
				भङ्ग;
			}
			पक्ष API_RM:
				(शून्य)sftp_rm(conn, "/fuzz");
				भङ्ग;
			पक्ष API_MKDIR:
				(शून्य)sftp_mkdir(conn, "/fuzz", &attr, 0);
				भङ्ग;
			पक्ष API_RMDIR:
				(शून्य)sftp_rmdir(conn, "/fuzz");
				भङ्ग;
			पक्ष API_RENAME:
				(शून्य)sftp_rename(conn, "/a", "/b", 0);
				भङ्ग;
			पक्ष API_SYMLINK:
				(शून्य)sftp_symlink(conn, "/a", "/b");
				भङ्ग;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

बाह्य "C" पूर्णाङ्क
LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t *data, size_t size)
{
	स्थिर पूर्णाङ्क initialized = 0;
	जइ (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	जइ (size > 65536)
		प्रत्यागम 0;

	प्रति (पूर्णाङ्क api = 0; api < API_गणनम्; api++)
		run_one(api, data, size);

	प्रत्यागम 0;
}
