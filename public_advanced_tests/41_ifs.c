#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf2[32];
  char buf1[64];

  control = 41;
  fgets(buf1, 64, stdin);
  if (control ==  41)
    strcpy(buf2, buf1);
  else
    strncpy(buf2, buf1, 32);

  return 0;
}