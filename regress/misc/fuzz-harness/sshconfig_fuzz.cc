// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <unistd.h>

বাহ্য "C" {

#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "readconf.h"
#অন্তর্ভাৱ "xmalloc.h"

// Stub out log output to reduce noise
শূন্য sshsig_free(সংরচনা sshsig_ctx *ctx) {}

}  // extern "C"

স্থির সংরচনা passwd fuzz_pw;
স্থির ৱর্ণ fuzz_username[] = "fuzzer";
স্থির ৱর্ণ fuzz_home[] = "/tmp";
স্থির ৱর্ণ fuzz_shell[] = "/bin/sh";

স্থির শূন্য init_pw(শূন্য) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

বাহ্য "C" পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t *data, size_t size) {
    স্থির পূর্ণাঙ্ক initialized = 0;
    যদি (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    ৱর্ণ tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    পূর্ণাঙ্ক fd = mkstemp(tmpfile);
    যদি (fd < 0)
        ঘূৰাই 0;

    যদি (লিখ(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        ঘূৰাই 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     রিক্ত, &options, 0, রিক্ত);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    ঘূৰাই 0;
}
