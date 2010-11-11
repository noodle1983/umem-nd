CC=g++
cc=gcc
CXXFLAGS=-g 
CFLAGs=
LDFLAGS=
LIB=-lpthread

TARGET=findleak_test

CPPFILES=$(wildcard *.cpp)

OBJECTS=$(patsubst %.cpp, %.o, $(CPPFILES))

$(TARGET):$(OBJECTS)
	$(CC) -o $(TARGET) $(LDFLAGS) $(LIB) $(OBJECTS)

%.o:%.cpp
	$(CC) $(CXXFLAGS) -o $@ -c $<

clean:
	rm -rf $(TARGET)
	rm -rf *.o
