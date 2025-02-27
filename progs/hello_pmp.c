// Will Buziak 

// Generate a large array and randomly access indices

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  int size, *arr;

  size = 100000000; // 100 million

  // initialize the PMP
  struct metal_pmp *pmp = metal_pmp_get_device();
  if (!pmp) {
    fprintf(stderr, "failed to get PMP device handle\n");
    exit(1);
  }

  printf("hello pmp\n");

  return 0;
 }
