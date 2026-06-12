# Makefile for kerberoasting BOF
# -------------------------------------
# Requires: mingw-w64 cross-compiler
#   sudo apt install mingw-w64
#
# Usage:
#   make        → build x64 (default)
#   make clean  → remove compiled objects

CC64 = x86_64-w64-mingw32-gcc

# -c             = compile only, don't link
# -masm=intel    = intel syntax for any inline asm
# -std=gnu99     = specify standard to avoid bool typedef errors
# -w -Wno-incompatible-pointer-types = suppress warnings from imported code
# -I ./          = include current directory for headers
# -Os -s         = optimize for size, strip debugging info
CFLAGS = -c -masm=intel -std=gnu99 -w -Wno-incompatible-pointer-types -I ./ -Os -s -o

all: x64

x64:
	$(CC64) $(CFLAGS) kerberoasting.o kerberoasting.c
	x86_64-w64-mingw32-strip --strip-unneeded kerberoasting.o

clean:
	rm -f *.o
