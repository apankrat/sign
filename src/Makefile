CFLAGS += -Wall -DNDEBUG -g
LDFLAGS += -lcrypto

OBJS =	buf.o die.o msg.o digest.o uue.o pki.o str.o system-nix.o \
	system-nix-readpass.o util.o

all: sign
#	strip sign

sign: $(OBJS)

clean:
	rm -f sign $(OBJS)
