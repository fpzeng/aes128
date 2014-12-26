.PHONY : clean
OPT=-O0
DEBUG= -g
CFLAGS=-Wall -fPIC $(XCFLAGS) $(INC) $(OPT) $(SO_DEF) $(DEBUG) $(DEF)

INCLUDES = -I./ \
	   -Ibase64/

SRCS = aes.c \
       base64/Base64Encode.c \
       base64/Base64Decode.c
OBJS = $(SRCS:.c=.o)
LIBS = -lssl -lcrypto -lm 


MAIN = aes
all:    $(MAIN)
	@echo $(MAIN) has been compiled

$(MAIN): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)
	@echo output: $(OBJS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	@echo clean $(MAIN) $(OBJS)
	rm -fr $(MAIN) $(OBJS)
