PROG= ex1
SRCS= ex1.c
OBJS= $(SRCS:.c=.o)
CFLAGS+= -g -O -pipe -I/usr/local/include
#CPPFLAGS+= -DNDEBUG
LDFLAGS+= -L/usr/local/lib
LDLIBS+= -lev

$(PROG)	: $(OBJS)

.PHONY	: clean

clean	:
	unlink ex1.o
	unlink ex1
