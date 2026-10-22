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

خارجی "C" {
#شامل "includes.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "log.h"
#شامل "sftp.h"
#شامل "sftp-common.h"
#شامل "sftp-client.h"

خالی fuzz_arena_begin(خالی);
خالی fuzz_arena_cleanup(خالی);
}

خارجی "C" متلون sig_atomic_t interrupted = 0;
خارجی "C" صحیح showprogress = 0;
خارجی "C" خالی آغاز_پیش_رفت_meter(ثابت حرف *file, off_t filesize,
    off_t *ctr) { (خالی)file; (خالی)filesize; (خالی)ctr; }
خارجی "C" خالی refresh_پیش_رفت_meter(صحیح force_update) { (خالی)force_update; }
خارجی "C" خالی stop_پیش_رفت_meter(خالی) { }

ساکن jmp_buf fuzz_env;
ساکن متلون صحیح اندر_fuzz = 0;

خارجی "C" خالی
cleanup_exit(صحیح رمز)
{
	اگر (اندر_fuzz)
		longjmp(fuzz_env, رمز ? رمز : 1);
	_exit(رمز);
}

ساکن ثابت uint8_t k_نسخہ_جواب[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

شمار {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_راستہ,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_گنتی,
};

ساکن خالی
تسلسل_one(صحیح api, ثابت uint8_t *body, سائز_t bsize)
{
	صحیح sv[2] = { -1, -1 };
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		واپس;

	ssize_t w = اكتب(sv[0], k_نسخہ_جواب, حجم(k_نسخہ_جواب));
	(خالی)w;
	اگر (bsize > 0)
		w = اكتب(sv[0], body, bsize);
	(خالی)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	اندر_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		ساخت sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		اگر (conn != تہی) {
			Attrib attr;
			attrib_clear(&attr);

			انتخاب (api) {
			حالت API_STAT: {
				Attrib a;
				(خالی)sftp_stat(conn, "/fuzz", 1, &a);
				توڑو;
			}
			حالت API_LSTAT: {
				Attrib a;
				(خالی)sftp_lstat(conn, "/fuzz", 1, &a);
				توڑو;
			}
			حالت API_REALPATH: {
				حرف *p = sftp_realpath(conn, "/fuzz");
				آزاد(p);
				توڑو;
			}
			حالت API_EXPAND_راستہ: {
				حرف *p = sftp_expand_راستہ(conn, "~");
				آزاد(p);
				توڑو;
			}
			حالت API_READDIR: {
				SFTP_DIRENT **dir = تہی;
				(خالی)sftp_readdir(conn, "/fuzz", &dir);
				اگر (dir != تہی)
					sftp_free_dirents(dir);
				توڑو;
			}
			حالت API_STATVFS: {
				ساخت sftp_statvfs vfs;
				(خالی)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				توڑو;
			}
			حالت API_GET_LIMITS: {
				ساخت sftp_limits lim;
				(خالی)sftp_get_limits(conn, &lim);
				توڑو;
			}
			حالت API_RM:
				(خالی)sftp_rm(conn, "/fuzz");
				توڑو;
			حالت API_MKDIR:
				(خالی)sftp_mkdir(conn, "/fuzz", &attr, 0);
				توڑو;
			حالت API_RMDIR:
				(خالی)sftp_rmdir(conn, "/fuzz");
				توڑو;
			حالت API_RENAME:
				(خالی)sftp_rename(conn, "/a", "/b", 0);
				توڑو;
			حالت API_SYMLINK:
				(خالی)sftp_symlink(conn, "/a", "/b");
				توڑو;
			}

			sftp_free(conn);
		}
	}
	اندر_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

خارجی "C" صحیح
LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	ساکن صحیح initialized = 0;
	اگر (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	اگر (سائز > 65536)
		واپس 0;

	برائے (صحیح api = 0; api < API_گنتی; api++)
		تسلسل_one(api, ڈیٹا, سائز);

	واپس 0;
}
