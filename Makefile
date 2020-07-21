###########################################
# Simple Makefile for wdt_util
#
# chenhn
# 2017-01-20
###########################################

AP	= wdt_util

all: $(AP)

CXXFLAGS	?= -Wall -Os

CPPOBJS  	= wdt_ct/wdt_ct.o \
		  wdt_ct/w8755_funcs.o \
		  wdt_ct/w8760_funcs.o \
		  wdt_ct/wdt_dev_api.o \
		  wdt_ct/func_i2c.o \

OBJS      	= $(CPPOBJS) 
LIBS		= -pthread -lrt 
	  
$(AP): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $(AP)

$(CPPOBJS): %.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(AP)

.PHONY: clean
