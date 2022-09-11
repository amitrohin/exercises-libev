PROG= ex3
SRCS= $(PROG).c
OBJS= $(SRCS:.c=.o)
CFLAGS+= -g -O -pipe -I. -I/usr/include -I/usr/local/include
LDFLAGS+= -L/usr/lib -L/usr/local/lib
LDLIBS+= -lev -lpcap -lpthread

$(PROG)	: $(OBJS)

.PHONY	: clean

clean	:
	@-rm $(OBJS) $(PROG)
