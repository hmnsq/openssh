#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <string.h>
#समावेश <stdlib.h>

बाह्य "C" {

#समावेश "auth-options.h"

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* तथ्य, माप_प्रकार आकार)
{
	अक्षर *cp = (अक्षर *)दो_स्मृति(आकार + 1);
	काष्ठा sshauthopt *opts = शून्य, *merge = शून्य, *add = sshauthopt_new();

	अगर (cp == शून्य || add == शून्य)
		जाओ out;
	स_नकल(cp, तथ्य, आकार);
	cp[आकार] = '\0';
	अगर ((opts = sshauthopt_parse(cp, शून्य)) == शून्य)
		जाओ out;
	अगर ((merge = sshauthopt_merge(opts, add, शून्य)) == शून्य)
		जाओ out;

 out:
	मुक्त(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	वापस 0;
}

} // extern "C"
