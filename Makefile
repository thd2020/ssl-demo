SOURCE = src/keygen.cpp src/main.cpp
INCLUDE = src/keygen.h
CC = gcc -g -wall -lpthread
OBJS = obj/keygen.o obj/main.o
EXEC = bin/ssl-demo

${EXEC} : ${OBJS}
	${CC} -o ${EXEC} ${OBJS}
obj/keygen.o : src/keygen.cpp
	${CC} -c src/keygen.cpp -o obj/keygen.obj
obj/main.o : src/main.cpp
	${CC} -c src/main.cpp -o obj/main.o

clean:
	rm -rf ${EXEC} ${OBJS}