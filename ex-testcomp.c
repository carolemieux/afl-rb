extern void __VERIFIER_error() __attribute__ ((__noreturn__));

void __VERIFIER_assert(int cond) {
  if (!(cond)) {
    ERROR: __VERIFIER_error();
  }
  return;
}
int __VERIFIER_nondet_int();

int main()
{
  unsigned int SIZE=1;
  unsigned int j,k;
  int array[SIZE], menor;

  menor = __VERIFIER_nondet_int();

  for(j=0;j<SIZE;j++) {
       array[j] = __VERIFIER_nondet_int();

       if(array[j]<=menor)
          menor = array[j];
    }

  k = __VERIFIER_nondet_int();
  if (k > 0) {
     menor = menor - k;
     k = __VERIFIER_nondet_int();
     if (k > 0) {
        __VERIFIER_assert(menor < k);
     }

  }
   __VERIFIER_assert(array[0]>=menor);

    return 0;
}
