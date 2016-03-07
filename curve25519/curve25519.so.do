# curve25519.so.do version 20081027
# Ian Goldberg
# based on curve25519.a.do version 20050915:
# D. J. Bernstein
# Public domain.

impl=`cat curve25519.impl`

case ${impl} in
  athlon)
    $* -fpic -c curve25519_${impl}.c
    $* -fpic -c curve25519_${impl}_const.s
    $* -fpic -c curve25519_${impl}_fromdouble.s
    $* -fpic -c curve25519_${impl}_init.s
    $* -fpic -c curve25519_${impl}_mainloop.s
    $* -fpic -c curve25519_${impl}_mult.s
    $* -fpic -c curve25519_${impl}_square.s
    $* -fpic -c curve25519_${impl}_todouble.s
    gcc -shared -o curve25519.so \
      curve25519_${impl}.o \
      curve25519_${impl}_const.o \
      curve25519_${impl}_fromdouble.o \
      curve25519_${impl}_init.o \
      curve25519_${impl}_mainloop.o \
      curve25519_${impl}_mult.o \
      curve25519_${impl}_square.o \
      curve25519_${impl}_todouble.o
    ;;
  *) echo 'unknown implementation' >&2; exit 1 ;;
esac
