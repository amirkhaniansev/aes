test: ../include/aes_128.h ../test/main.c aes_128.o
		gcc aes_128.o ../test/main.c -o test

aes_128.o: ../include/aes_128.h ../src/aes_128.c
		gcc ../src/aes_128.c -c -o aes_128.o