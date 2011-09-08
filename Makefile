DIRS = lisp_int lisp_mod lispd lispconf

all:
	for d in $(DIRS); do (cd $$d; make); done

clean:
	for d in $(DIRS); do (cd $$d; make clean); done

install:
	for d in $(DIRS); do (cd $$d; make install); done
