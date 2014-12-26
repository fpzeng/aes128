.PHONY : clean
OPT=-O0
DEBUG= -g
CFLAGS=-Wall -fPIC $(XCFLAGS) $(INC) $(OPT) $(SO_DEF) $(DEBUG) $(DEF)

INCLUDES = -I./ 

SRCS = Base64Decode.c \
       Base64Encode.c \
       Main.c

OBJS = $(SRCS:.c=.o)
LIBS = -lcrypto -lm 


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
