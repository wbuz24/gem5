// Will Buziak 

// Generate a large array and randomly access indices

#include <stdio.h>
#include <stdlib.h>

void main(int argc, char** argv) {
  int size, iter, buf, i, *arr;

  if (argc != 2) { printf("Format:\n./arrtest <SIZE>\n"); exit(1); }
  
  if (sscanf(argv[1], "%d", &size) != 1) { printf("Invalid size, must be an integer\n"); exit(1); }

  iter = size / 10000;

  arr = (int *) malloc(sizeof(int) * size);
  if (arr == NULL) { fprintf(stderr, "malloc(%d) failed.\n", size); exit(1); }

  for (i = 0; i < iter; i++) {
    buf = i * rand() % size;
    if (arr[buf]) arr[buf] = 0;
    else arr[buf] = 1;
  }

  arr = NULL;
  free(arr);
}
