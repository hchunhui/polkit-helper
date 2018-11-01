O = polkit-agent-helper-1
all: $O

$O: helper.c helper-private.c
	gcc -o $@ $^ `pkg-config polkit-gobject-1 --cflags --libs`

clean:
	rm -f $O
