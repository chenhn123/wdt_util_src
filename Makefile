###########################################
# Simple Makefile for wdt_util
#
# chenhn
# 2017-01-20
###########################################

AP	= wdt_util

all: $(AP)

CPP		= g++
CPPFLAGS	= -Wall -g

LDFLAGS		= 

CPPOBJS  	= wdt_ct/wdt_ct.o wdt_ct/w8755_funcs.o \
		  wdt_ct/wdt_dev_api.o wdt_ct/func_i2c.o

OBJS      	= $(CPPOBJS)
LIBS		= -pthread -lrt 
	  
$(AP): $(OBJS)
	$(CPP) $(CPPFLAGS) $(LDFLAGS) $^ $(LIBS) -o $(AP)

$(CPPOBJS): %.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $(INCLUDES) $< -o $@

clean:
	rm -f $(OBJS) $(AP)

.PHONY: clean
