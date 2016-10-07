CC = gcc
CFLAGS	= -O2 -std=c99 -Wall -W -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -g
INCLUDES = -I./mbedtls/include -I./ -I./readline #-I./zlib/include -I./readline -I./
LFLAGS = -L./mbedtls/library	\
	 -L./readline/shlib	\
	 #-L./zlib 
LIBS =	-lmbedtls 			\
	-lmbedx509			\
	-lmbedcrypto			\
	-lncurses			\
	-lreadline			\
	#-lz

all:
	#cd readline; make; cd shlib; mv libreadline.so.6* libreadline.so; cd ../..
	#cd zlib; make; cd ..
	#cd mbedtls; make; cd ..

	$(CC) $(CFLAGS) $(INCLUDES) -o rat rat.c $(LFLAGS) $(LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) -o rat-client rat-client.c $(LFLAGS) $(LIBS)

clean:
	rm -f rat rat-client
