#include <stdio.h>

int main(void) {
  unsigned x = 1;
  puts(((const unsigned char *)&x)[0] ? "little" : "big");
  return 0;
}
