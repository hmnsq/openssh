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

#ଅନ୍ତର୍ଭାଵ <setjmp.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ "log.h"

ବାହ୍ୟ ଶୂନ୍ୟ fuzz_arena_begin(ଶୂନ୍ୟ);
ବାହ୍ୟ ଶୂନ୍ୟ fuzz_arena_release(ଶୂନ୍ୟ);
ବାହ୍ୟ ଶୂନ୍ୟ fuzz_arena_cleanup(ଶୂନ୍ୟ);

ସ୍ଥିର jmp_buf fuzz_server_env;
ସ୍ଥିର ଅସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fuzz_server = 0;

ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା code)
{
	ଯଦି (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#ଅନ୍ତର୍ଭାଵ "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

ଶୂନ୍ୟ
sftp_server_cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା code)
{
	ଯଦି (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

ସ୍ଥିର ଶୂନ୍ୟ (* ଅଚଳ __force_use_renamed)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା) =
    __orig_sftp_server_cleanup_exit;

ସ୍ଥିର ସଂରଚନା passwd fuzz_pw;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_initialized = 0;

ସ୍ଥିର ଶୂନ୍ୟ
cleanup_handles(ଶୂନ୍ୟ)
{
	u_int i;
	ଯଦି (handles == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < ଅଙ୍କ_handles; i++) {
		ଯଦି (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		ଅନ୍ୟଥା ଯଦି (handles[i].use == HANDLE_DIR && handles[i].dirp != ଖାଲି)
			closedir(handles[i].dirp);
		ମୁକ୍ତ(handles[i].name);
	}
	ମୁକ୍ତ(handles);
	handles = ଖାଲି;
	ଅଙ୍କ_handles = 0;
	first_unused_handle = -1;
}

ସ୍ଥିର ଶୂନ୍ୟ
reset_module_globals(ଶୂନ୍ୟ)
{
	pw = &fuzz_pw;
	client_addr = ଖାଲି;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = ଖାଲି;
	request_denylist = ଖାଲି;
	handles = ଖାଲି;
	ଅଙ୍କ_handles = 0;
	first_unused_handle = -1;
	iqueue = ଖାଲି;
	oqueue = ଖାଲି;
}

ଶୂନ୍ୟ
fuzz_server_one(ଅଚଳ uint8_t *data, size_t size)
{
	ଯଦି (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		ଅକ୍ଷର tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		ଯଦି (mkdtemp(tmpdir) != ଖାଲି && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, ଆକାର(fuzz_pw));
		fuzz_pw.pw_name = (ଅକ୍ଷର *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (ଅକ୍ଷର *)"/tmp";
		fuzz_pw.pw_shell = (ଅକ୍ଷର *)"/bin/sh";
	}

	ଯଦି (size == 0 || size > 65000)
		ଫେରନ୍ତୁ;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	ଯଦି (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		ଯଦି (iqueue == ଖାଲି || oqueue == ଖାଲି)
			ଯାଅ out;

		ଅଚଳ uint8_t init_ସନ୍ଦେଶ[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		ଯଦି (sshbuf_put(iqueue, init_ସନ୍ଦେଶ, ଆକାର(init_ସନ୍ଦେଶ)) != 0)
			ଯାଅ out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((size >> 24) & 0xff),
		    (uint8_t)((size >> 16) & 0xff),
		    (uint8_t)((size >> 8) & 0xff),
		    (uint8_t)(size & 0xff),
		};
		ଯଦି (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, data, size) != 0)
			ଯାଅ out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		ମୁକ୍ତ(client_addr);
		iqueue = oqueue = ଖାଲି;
		client_addr = ଖାଲି;
		in_fuzz_server = 0;
		fuzz_arena_release();
		ଫେରନ୍ତୁ;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = ଖାଲି;
	client_addr = ଖାଲି;
}
