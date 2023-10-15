OBJECTS= messager.o util.o

messager: $(OBJECTS)
	gcc $(OBJECTS) -o messager -lm

%.o:%.c
	gcc -c -Wall -Werror $^ -o $@

clean:
	rm -f messager $(OBJECTS)
