INCDIRS = /opt/local/include
LIBDIRS = /opt/local/lib
LIBS = event
SOURCES = sockutil.c afcgitest.c
EXECUTABLE = afcgitest

CFLAGS = -Wall $(addprefix -I, $(INCDIRS))
LDLIBS = $(addprefix -l, $(LIBS) $(LIBS_$(notdir $*)))
LDFLAGS = $(addprefix -L, $(LIBDIRS)) $(LDLIBS)
OBJECTS = $(SOURCES:.c=.o)

#-----------------------------------------------------
# Options

# Optimize
#CFLAGS += -O3 -DNDEBUG

# If Mac OS X:
CFLAGS += -arch i386
LDFLAGS += -arch i386

#-----------------------------------------------------

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)

.PHONY: all clean
