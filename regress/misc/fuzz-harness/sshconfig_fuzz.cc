// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <pwd.h>
#समावेश <unistd.h>

बाह्य "C" {

#समावेश "includes.h"
#समावेश "ssh.h"
#समावेश "misc.h"
#समावेश "log.h"
#समावेश "readconf.h"
#समावेश "xmalloc.h"

// Stub out log output to reduce noise
व्योम sshsig_free(काष्ठा sshsig_ctx *ctx) {}

}  // extern "C"

अटल काष्ठा passwd fuzz_pw;
अटल अक्षर fuzz_username[] = "fuzzer";
अटल अक्षर fuzz_home[] = "/tmp";
अटल अक्षर fuzz_shell[] = "/bin/sh";

अटल व्योम init_pw(व्योम) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

बाह्य "C" पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t *तथ्य, माप_प्रकार आकार) {
    अटल पूर्णांक initialized = 0;
    अगर (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    अक्षर क्षणिक_ख[] = "/tmp/sshconfig_fuzz_XXXXXX";
    पूर्णांक fd = mkstemp(क्षणिक_ख);
    अगर (fd < 0)
        वापस 0;

    अगर (ग_लिखो(fd, तथ्य, आकार) != (ssize_t)आकार) {
        बंद(fd);
        unlink(क्षणिक_ख);
        वापस 0;
    }
    बंद(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(क्षणिक_ख, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     शून्य, &options, 0, शून्य);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(क्षणिक_ख);
    वापस 0;
}
