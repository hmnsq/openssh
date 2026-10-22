// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <pwd.h>
#شامل <unistd.h>

بیرونی "C" {

#شامل "includes.h"
#شامل "ssh.h"
#شامل "misc.h"
#شامل "log.h"
#شامل "readconf.h"
#شامل "xmalloc.h"

// Stub out log output to reduce noise
تهی sshsig_free(ساختار sshsig_ctx *ctx) {}

}  // extern "C"

ایستا ساختار passwd fuzz_pw;
ایستا نویسه fuzz_username[] = "fuzzer";
ایستا نویسه fuzz_home[] = "/tmp";
ایستا نویسه fuzz_shell[] = "/bin/sh";

ایستا تهی init_pw(تهی) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

بیرونی "C" صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t *data, size_t size) {
    ایستا صحیح initialized = 0;
    اگر (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    نویسه tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    صحیح fd = mkstemp(tmpfile);
    اگر (fd < 0)
        بازگشت 0;

    اگر (اكتب(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        بازگشت 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     پوچ, &options, 0, پوچ);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    بازگشت 0;
}
