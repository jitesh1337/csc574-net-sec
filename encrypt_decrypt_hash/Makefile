CC=gcc
CFLAGS=-g -I/usr/include  -Wall 
LD=-L/usr/lib  -lssl -lcrypto

DIST=	client.c \
	client.h \
	common.c \
	common.h \
	server.c \
	server.h \
	Makefile.in \
	client.pem \
	server.pem \
	root.pem 

OBJS=common.o 

all:  wclient wserver

wclient: wclient.o client.o  $(OBJS)
	$(CC) wclient.o client.o $(OBJS) -o wclient $(LD)

wserver: server.o wserver.o  $(OBJS)
	$(CC) wserver.o server.o $(OBJS) -o wserver $(LD)

clean:	
	rm *.o wclient wserver
