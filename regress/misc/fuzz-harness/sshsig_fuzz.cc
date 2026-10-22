// cc_fuzz_target test for sshsig verification.

#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

बाह्य "C" {

#समावेश "includes.h"
#समावेश "sshkey.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "sshsig.h"
#समावेश "log.h"

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* sig, माप_प्रकार slen)
{
  अटल स्थिर अक्षर *तथ्य = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  काष्ठा sshbuf *signature = sshbuf_from(sig, slen);
  काष्ठा sshbuf *message = sshbuf_from(तथ्य, म_माप(तथ्य));
  काष्ठा sshkey *k = शून्य;
  काष्ठा sshkey_sig_details *details = शून्य;
  बाह्य अक्षर *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  वापस 0;
}

} // extern
