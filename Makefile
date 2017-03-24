###########################################
# Simple Makefile for wdt_util
#
# chenhn
# 2017-01-20
###########################################

AP	= wdt_util

all: $(AP)

CC       ?= gcc
CFLAGS   ?= -Wall -g

CXX      ?= g++
CXXFLAGS ?= -Wall -g

LDFLAGS	 ?= 

COBJS     = 
CPPOBJS   = 	wdt_ct/wdt_ct.o wdt_ct/w8755_funcs.o \
		wdt_ct/wdt_dev_api.o wdt_ct/func_i2c.o

OBJS      = $(COBJS) $(CPPOBJS)
LIBS	= -pthread -lrt 
	  
INCLUDES   = 


$(AP): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $(AP)

$(COBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $(INCLUDES) $< -o $@

$(CPPOBJS): %.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $(INCLUDES) $< -o $@

clean:
	rm -f $(OBJS) $(AP)

.PHONY: clean
