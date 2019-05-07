# Structured Searchable Public-key Ciphertexts for Parallel Retrieval
# Coding: Shuanghong he, CS School of HUST
# E-mail: 740310627@qq.com
# Date  : 2016-4-10
# Copyright (c) 2016 Render. All Rights Reserved.

../sspcpr: entry.o sspcpr.o pri.o avltree.o time.o
	gcc -L ../pbc/lib -o $@ $^ -lpbc -lgmp -lpthread
#	gcc -g -L ../pbc -o $@ $^ -lpbc -lgmp -lpthread

entry.o: entry.c sspcpr.h pri.h avltree.h time.h global.h
	gcc  -I ../pbc/include -Wall -O2 -c $<
#	gcc -g  -I ../pbc/include -Wall -c $<

sspcpr.o: sspcpr.c sspcpr.h pri.h avltree.h global.h
	gcc  -I ../pbc/include -Wall -O3 -funroll-loops -c $<
#	gcc -g  -I ../pbc/include -Wall -c $<

pri.o: pri.c pri.h global.h
	gcc  -Wall -O2 -c $<
#	gcc -g  -Wall -c $<

avltree.o: avltree.c avltree.h global.h
	gcc  -Wall -O2 -c $<
#	gcc -g  -Wall -c $<

time.o: time.c time.h global.h
	gcc  -Wall -O2 -c $<
#	gcc -g  -Wall -c $<

.PHONY: clean
clean:
	rm -rf *.o *~
