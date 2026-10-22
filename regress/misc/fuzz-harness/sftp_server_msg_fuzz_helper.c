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

#અન્તર્ભાવ <setjmp.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ "log.h"

બાહ્ય શૂન્ય fuzz_arena_begin(શૂન્ય);
બાહ્ય શૂન્ય fuzz_arena_release(શૂન્ય);
બાહ્ય શૂન્ય fuzz_arena_cleanup(શૂન્ય);

સ્થિર jmp_buf fuzz_server_env;
સ્થિર અસ્થિર પૂર્ણાંક in_fuzz_server = 0;

શૂન્ય
cleanup_exit(પૂર્ણાંક code)
{
	જો (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#અન્તર્ભાવ "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

શૂન્ય
sftp_server_cleanup_exit(પૂર્ણાંક code)
{
	જો (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

સ્થિર શૂન્ય (* અચલ __force_use_renamed)(પૂર્ણાંક) =
    __orig_sftp_server_cleanup_exit;

સ્થિર સંરચના passwd fuzz_pw;
સ્થિર પૂર્ણાંક log_initialized = 0;

સ્થિર શૂન્ય
cleanup_handles(શૂન્ય)
{
	u_int i;
	જો (handles == ખાલી)
		પાછા;
	માટે (i = 0; i < અંક_handles; i++) {
		જો (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		નહીંતર જો (handles[i].use == HANDLE_DIR && handles[i].dirp != ખાલી)
			closedir(handles[i].dirp);
		મુક્ત(handles[i].name);
	}
	મુક્ત(handles);
	handles = ખાલી;
	અંક_handles = 0;
	first_unused_handle = -1;
}

સ્થિર શૂન્ય
reset_module_globals(શૂન્ય)
{
	pw = &fuzz_pw;
	client_addr = ખાલી;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = ખાલી;
	request_denylist = ખાલી;
	handles = ખાલી;
	અંક_handles = 0;
	first_unused_handle = -1;
	iqueue = ખાલી;
	oqueue = ખાલી;
}

શૂન્ય
fuzz_server_one(અચલ uint8_t *data, size_t size)
{
	જો (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		અક્ષર tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		જો (mkdtemp(tmpdir) != ખાલી && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, કદ(fuzz_pw));
		fuzz_pw.pw_name = (અક્ષર *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (અક્ષર *)"/tmp";
		fuzz_pw.pw_shell = (અક્ષર *)"/bin/sh";
	}

	જો (size == 0 || size > 65000)
		પાછા;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	જો (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		જો (iqueue == ખાલી || oqueue == ખાલી)
			જાઓ out;

		અચલ uint8_t init_સંદેશ[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		જો (sshbuf_put(iqueue, init_સંદેશ, કદ(init_સંદેશ)) != 0)
			જાઓ out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((size >> 24) & 0xff),
		    (uint8_t)((size >> 16) & 0xff),
		    (uint8_t)((size >> 8) & 0xff),
		    (uint8_t)(size & 0xff),
		};
		જો (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, data, size) != 0)
			જાઓ out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		મુક્ત(client_addr);
		iqueue = oqueue = ખાલી;
		client_addr = ખાલી;
		in_fuzz_server = 0;
		fuzz_arena_release();
		પાછા;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = ખાલી;
	client_addr = ખાલી;
}
