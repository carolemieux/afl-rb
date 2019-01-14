#include <stdio.h>
#include<string.h>
#include <stdlib.h>
#include <unistd.h>
#define verifier_nondet(type, printchar) \
type __VERIFIER_nondet_##type(){ \
  char buf[8];\
  memset(&buf, 0, sizeof(type));\
  int value;\
  if (read( 0, buf, sizeof(type))>0) {\
      memcpy(&value, &buf, sizeof(type));\
  }  \
  else {\
      memcpy(&value, &buf, sizeof(type));\
  }\
  FILE * input_file = fopen(".fairfuzz_input_xml", "a");\
  fprintf(input_file, "<input type=\""#type"\"> %"#printchar" </input>\n", value);\
  return value;\
}

void __VERIFIER_error(){
   printf("Hello theres");
   abort();
}

verifier_nondet(int, i);
