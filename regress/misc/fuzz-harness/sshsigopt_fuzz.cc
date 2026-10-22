#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <string.h>
#समावेश <stdlib.h>

बाह्य "C" {

#समावेश "sshsig.h"

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* तथ्य, माप_प्रकार आकार)
{
	अक्षर *cp = (अक्षर *)दो_स्मृति(आकार + 1);
	काष्ठा sshsigopt *opts = शून्य;

	अगर (cp == शून्य)
		जाओ out;
	स_नकल(cp, तथ्य, आकार);
	cp[आकार] = '\0';
	अगर ((opts = sshsigopt_parse(cp, "libfuzzer", 0, शून्य)) == शून्य)
		जाओ out;

 out:
	मुक्त(cp);
	sshsigopt_free(opts);
	वापस 0;
}

} // extern "C"
