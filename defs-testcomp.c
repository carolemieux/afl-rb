#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>

#define verifier_nondet_name(typename, type, printchar) \
type __VERIFIER_nondet_##typename(){ \
  char buf[16];\
  memset(&buf, 0, sizeof(type));\
  type value;\
  if (read( 0, buf, sizeof(type))>0) {\
      memcpy(&value, &buf, sizeof(type));\
  }  \
  else {\
      memcpy(&value, &buf, sizeof(type));\
  }\
  FILE * input_file = fopen(".fairfuzz_input_xml", "a");\
  fprintf(input_file, "<input type=\""#type"\"> %"#printchar" </input>\n", value);\
  fclose(input_file);\
  return value;\
}

#define verifier_nondet(type, printchar) verifier_nondet_name(type, type, printchar)

void __VERIFIER_error(){
   abort();
}

void __VERIFIER_assume(int expression) { if (!expression) { LOOP: goto LOOP; }; return; }

verifier_nondet(int, i);
verifier_nondet(char, u);
verifier_nondet(float, f);
verifier_nondet(double, f);
verifier_nondet(off_t, li);
#ifdef loff_t
verifier_nondet(loff_t, lli);
#endif
#ifdef u32
verifier_nondet(u32, lli);
#endif
#ifdef sector_t
verifier_nondet(sector_t, lli);
#endif
verifier_nondet(long, li);
verifier_nondet(pthread_t, lu);
verifier_nondet(short, i);
verifier_nondet(size_t, lu);
verifier_nondet_name(uchar, unsigned char, u);
verifier_nondet_name(uint, unsigned int, u);
verifier_nondet_name(ulong, unsigned long, lu);
verifier_nondet_name(ushort, unsigned short, u);
verifier_nondet(unsigned, u);

bool __VERIFIER_nondet_bool(){ 
  char buf[16];
  memset(&buf, 0, sizeof(bool));
  bool value;
  if (read( 0, buf, sizeof(bool))>0) {
      memcpy(&value, &buf, sizeof(bool));
  } 
  else {
      memcpy(&value, &buf, sizeof(bool));
  }
  FILE * input_file = fopen(".fairfuzz_input_xml", "a");
  fprintf(input_file, "<input type=\"bool\"> %i </input>\n", value);
  fclose(input_file);
  return value;
}

void * __VERIFIER_nondet_pointer(){ 
  char buf[16];
  memset(&buf, 0, sizeof(void *));
  void * value;
  if (read( 0, buf, sizeof(void *))>0) {
      memcpy(&value, &buf, sizeof(void *));
  } 
  else {
      memcpy(&value, &buf, sizeof(void *));
  }
  FILE * input_file = fopen(".fairfuzz_input_xml", "a");
  fprintf(input_file, "<input type=\"pointer\"> %p </input>\n", value);
  fclose(input_file);
  return value;
}

// This causes a memory leak, but what can you do when you're asked to return a char *? 
char * __VERIFIER_nondet_pchar(){ 
  char * buf= malloc(sizeof(char)*17);
  memset(buf, 0, 17);
  int chars_read= read( 0, buf, 16); 
  FILE * input_file = fopen(".fairfuzz_input_xml", "a");
  fprintf(input_file, "<input type=\"pointer\"> %s </input>\n", buf);
  fclose(input_file);
  return buf;
}

