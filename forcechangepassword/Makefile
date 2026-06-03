# Makefile for forcechangepassword BOF
# -------------------------------------
# Requires: mingw-w64 cross-compiler
#   sudo apt install mingw-w64
#
# Usage:
#   make        → build x64 (default)
#   make x86    → build x86
#   make clean  → remove compiled objects

CC64 = x86_64-w64-mingw32-gcc
CC32 = i686-w64-mingw32-gcc

# -c             = compile only, don't link (BOFs are object files, not executables)
# -masm=intel    = intel syntax for any inline asm
# -Wall          = show all warnings
# -o             = output file name
CFLAGS = -c -masm=intel -Wall -o

all: x64

x64:
	$(CC64) $(CFLAGS) forcechangepassword.o forcechangepassword.c

x86:
	$(CC32) $(CFLAGS) forcechangepassword.x86.o forcechangepassword.c

clean:
	rm -f *.o
