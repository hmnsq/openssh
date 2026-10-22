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

#شامل <setjmp.h>
#شامل <signal.h>
#شامل <stddef.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <sys/socket.h>
#شامل <sys/types.h>

بیرونی "C" {
#شامل "includes.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "log.h"
#شامل "sftp.h"
#شامل "sftp-common.h"
#شامل "sftp-client.h"

تهی fuzz_arena_begin(تهی);
تهی fuzz_arena_cleanup(تهی);
}

بیرونی "C" فرار sig_atomic_t interrupted = 0;
بیرونی "C" صحیح showprogress = 0;
بیرونی "C" تهی start_progress_meter(ثابت نویسه *file, off_t filesize,
    off_t *ctr) { (تهی)file; (تهی)filesize; (تهی)ctr; }
بیرونی "C" تهی refresh_progress_meter(صحیح force_update) { (تهی)force_update; }
بیرونی "C" تهی stop_progress_meter(تهی) { }

ایستا jmp_buf fuzz_env;
ایستا فرار صحیح in_fuzz = 0;

بیرونی "C" تهی
cleanup_exit(صحیح code)
{
	اگر (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ایستا ثابت uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

شمارش {
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
	API_شمار,
};

ایستا تهی
run_one(صحیح api, ثابت uint8_t *body, size_t bsize)
{
	صحیح sv[2] = { -1, -1 };
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		بازگشت;

	ssize_t w = اكتب(sv[0], k_version_reply, اندازه(k_version_reply));
	(تهی)w;
	اگر (bsize > 0)
		w = اكتب(sv[0], body, bsize);
	(تهی)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		ساختار sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		اگر (conn != پوچ) {
			Attrib attr;
			attrib_clear(&attr);

			انتخاب (api) {
			حالت API_STAT: {
				Attrib a;
				(تهی)sftp_stat(conn, "/fuzz", 1, &a);
				بشکن;
			}
			حالت API_LSTAT: {
				Attrib a;
				(تهی)sftp_lstat(conn, "/fuzz", 1, &a);
				بشکن;
			}
			حالت API_REALPATH: {
				نویسه *p = sftp_realpath(conn, "/fuzz");
				آزاد(p);
				بشکن;
			}
			حالت API_EXPAND_PATH: {
				نویسه *p = sftp_expand_path(conn, "~");
				آزاد(p);
				بشکن;
			}
			حالت API_READDIR: {
				SFTP_DIRENT **dir = پوچ;
				(تهی)sftp_readdir(conn, "/fuzz", &dir);
				اگر (dir != پوچ)
					sftp_free_dirents(dir);
				بشکن;
			}
			حالت API_STATVFS: {
				ساختار sftp_statvfs vfs;
				(تهی)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				بشکن;
			}
			حالت API_GET_LIMITS: {
				ساختار sftp_limits lim;
				(تهی)sftp_get_limits(conn, &lim);
				بشکن;
			}
			حالت API_RM:
				(تهی)sftp_rm(conn, "/fuzz");
				بشکن;
			حالت API_MKDIR:
				(تهی)sftp_mkdir(conn, "/fuzz", &attr, 0);
				بشکن;
			حالت API_RMDIR:
				(تهی)sftp_rmdir(conn, "/fuzz");
				بشکن;
			حالت API_RENAME:
				(تهی)sftp_rename(conn, "/a", "/b", 0);
				بشکن;
			حالت API_SYMLINK:
				(تهی)sftp_symlink(conn, "/a", "/b");
				بشکن;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

بیرونی "C" صحیح
LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t *data, size_t size)
{
	ایستا صحیح initialized = 0;
	اگر (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	اگر (size > 65536)
		بازگشت 0;

	برای (صحیح api = 0; api < API_شمار; api++)
		run_one(api, data, size);

	بازگشت 0;
}
