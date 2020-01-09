#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define GEN_FUNC(x)                                                            \
  __attribute__((noinline)) void increment_##x(int *i)                         \
  {                                                                            \
    (*i)++;                                                                    \
  }

GEN_FUNC(0)
GEN_FUNC(1)
GEN_FUNC(2)
GEN_FUNC(3)
GEN_FUNC(4)
GEN_FUNC(5)
GEN_FUNC(6)
GEN_FUNC(7)
GEN_FUNC(8)
GEN_FUNC(9)
GEN_FUNC(10)
GEN_FUNC(11)
GEN_FUNC(12)
GEN_FUNC(13)
GEN_FUNC(14)
GEN_FUNC(15)
GEN_FUNC(16)
GEN_FUNC(17)
GEN_FUNC(18)
GEN_FUNC(19)
GEN_FUNC(20)

int main()
{
  increment_0(malloc(sizeof(int)));
  increment_1(malloc(sizeof(int)));
  increment_2(malloc(sizeof(int)));
  increment_3(malloc(sizeof(int)));
  increment_4(malloc(sizeof(int)));
  increment_5(malloc(sizeof(int)));
  increment_6(malloc(sizeof(int)));
  increment_7(malloc(sizeof(int)));
  increment_8(malloc(sizeof(int)));
  increment_9(malloc(sizeof(int)));
  increment_10(malloc(sizeof(int)));
  increment_11(malloc(sizeof(int)));
  increment_12(malloc(sizeof(int)));
  increment_13(malloc(sizeof(int)));
  increment_14(malloc(sizeof(int)));
  increment_15(malloc(sizeof(int)));
  increment_16(malloc(sizeof(int)));
  increment_17(malloc(sizeof(int)));
  increment_18(malloc(sizeof(int)));
  increment_19(malloc(sizeof(int)));
  increment_20(malloc(sizeof(int)));
}
