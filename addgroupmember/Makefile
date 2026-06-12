# Makefile  –  addgroupmember BOF  (single-file, no ldap_common.c)
#
# Requirements: mingw-w64 cross-compiler
#   apt install mingw-w64   (Debian/Ubuntu/Kali)
#
# Usage:
#   make          – build x64 .o
#   make x86      – build x86 .o
#   make all      – build both
#   make clean    – remove artefacts

CC64   = x86_64-w64-mingw32-gcc
CC32   = i686-w64-mingw32-gcc
SRC    = addgroupmember.c

CFLAGS = -c                     \
         -masm=intel            \
         -Wall                  \
         -Wno-unused-function   \
         -I.                    \
         -DWIN32_LEAN_AND_MEAN  \
         -D_WIN32_WINNT=0x0601

.PHONY: all x64 x86 clean

all: x64 x86

x64: addgroupmember.x64.o

x86: addgroupmember.x86.o

addgroupmember.x64.o: $(SRC) beacon.h
	$(CC64) $(CFLAGS) -o $@ $<
	@echo "[+] Built $@"

addgroupmember.x86.o: $(SRC) beacon.h
	$(CC32) $(CFLAGS) -o $@ $<
	@echo "[+] Built $@"

clean:
	rm -f *.o
