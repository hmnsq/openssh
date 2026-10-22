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
 * Fuzzer for OpenSSH SFTP server message dispatch (sftp-server.c)
 *
 * Target: sftp-server.c
 *
 * Follows the agent_fuzz_helper.c pattern: #include's sftp-server.c so
 * process() and the static process_* handlers, plus the file-scope
 * globals (iqueue, oqueue, pw, init_done, handles), are reachable from
 * this translation unit. Each iteration bootstraps an FXP_INIT then
 * feeds the fuzzer input as a single framed SFTP message.
 *
 * Primary functions exercised:
 * - process() and the 17 base process_* handlers (open / close / read /
 *   write / stat / lstat / fstat / setstat / fsetstat / opendir /
 *   readdir / remove / mkdir / rmdir / realpath / rename / readlink /
 *   symlink)
 * - process_extended_* (11 variants including posix-rename, statvfs,
 *   hardlink, fsync, lsetstat, limits, expand-path, copy-data,
 *   home-directory, users-groups-by-id)
 * - decode_attrib / encode_attrib (sftp-common.c)
 *
 * Failure handling: fatal() -> cleanup_exit() and
 * sftp_server_cleanup_exit() are intercepted with overriding
 * definitions that longjmp() back to the entry point. fuzz_arena
 * (linker --wrap'd malloc family) frees every still-live allocation on
 * recovery so LSan sees zero per-iteration leaks.
 */

#شامل <setjmp.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <pwd.h>
#شامل <sys/types.h>

#شامل "log.h"

خارجی خالی fuzz_arena_begin(خالی);
خارجی خالی fuzz_arena_release(خالی);
خارجی خالی fuzz_arena_cleanup(خالی);

ساکن jmp_buf fuzz_server_env;
ساکن متلون صحیح اندر_fuzz_server = 0;

خالی
cleanup_exit(صحیح رمز)
{
	اگر (اندر_fuzz_server)
		longjmp(fuzz_server_env, رمز ? رمز : 1);
	_exit(رمز);
}

#تعریف_کرو sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#شامل "../../../sftp-server.c"
#تعریف_منسوخ sftp_server_cleanup_exit

خالی
sftp_server_cleanup_exit(صحیح رمز)
{
	اگر (اندر_fuzz_server)
		longjmp(fuzz_server_env, رمز ? رمز : 1);
	_exit(رمز);
}

ساکن خالی (* ثابت __force_use_renamed)(صحیح) =
    __orig_sftp_server_cleanup_exit;

ساکن ساخت passwd fuzz_pw;
ساکن صحیح log_initialized = 0;

ساکن خالی
cleanup_handles(خالی)
{
	u_int i;
	اگر (handles == تہی)
		واپس;
	برائے (i = 0; i < عدد_handles; i++) {
		اگر (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		ورنہ اگر (handles[i].use == HANDLE_DIR && handles[i].dirp != تہی)
			closedir(handles[i].dirp);
		آزاد(handles[i].name);
	}
	آزاد(handles);
	handles = تہی;
	عدد_handles = 0;
	پہلا_غیر_مستعمل_handle = -1;
}

ساکن خالی
reset_module_globals(خالی)
{
	pw = &fuzz_pw;
	client_addr = تہی;
	نسخہ = 0;
	init_مکمل = 0;
	readonly = 0;
	request_allowlist = تہی;
	request_denylist = تہی;
	handles = تہی;
	عدد_handles = 0;
	پہلا_غیر_مستعمل_handle = -1;
	iqueue = تہی;
	oqueue = تہی;
}

خالی
fuzz_server_one(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	اگر (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		حرف tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		اگر (mkdtemp(tmpdir) != تہی && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, حجم(fuzz_pw));
		fuzz_pw.pw_name = (حرف *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (حرف *)"/tmp";
		fuzz_pw.pw_shell = (حرف *)"/bin/sh";
	}

	اگر (سائز == 0 || سائز > 65000)
		واپس;

	reset_module_globals();

	fuzz_arena_begin();
	اندر_fuzz_server = 1;
	اگر (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		اگر (iqueue == تہی || oqueue == تہی)
			جاؤ برآمد;

		ثابت uint8_t init_پیغام[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		اگر (sshbuf_put(iqueue, init_پیغام, حجم(init_پیغام)) != 0)
			جاؤ برآمد;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((سائز >> 24) & 0xff),
		    (uint8_t)((سائز >> 16) & 0xff),
		    (uint8_t)((سائز >> 8) & 0xff),
		    (uint8_t)(سائز & 0xff),
		};
		اگر (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, ڈیٹا, سائز) != 0)
			جاؤ برآمد;
		process();
	برآمد:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		آزاد(client_addr);
		iqueue = oqueue = تہی;
		client_addr = تہی;
		اندر_fuzz_server = 0;
		fuzz_arena_release();
		واپس;
	}
	cleanup_handles();
	اندر_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = تہی;
	client_addr = تہی;
}
