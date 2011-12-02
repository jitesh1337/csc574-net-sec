CC=gcc
CFLAGS=-g -I/usr/include  -Wall 
LD=-L/usr/lib  -lssl -lcrypto

OBJS=common.o 

all:  customer_server

customer_server: server.o customer_server.o  $(OBJS)
	$(CC) customer_server.o server.o $(OBJS) -o customer_server $(LD)

clean:	
	rm *.o customer_server
