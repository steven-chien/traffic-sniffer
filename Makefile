CC=mips-openwrt-linux-uclibc-gcc
CC=clang

SRC := $(wildcard src/*.c)
OBJ := $(addprefix obj/,$(notdir $(SRC:.c=.o)))
LD_FLAGS := $(shell pkg-config --libs json-c) -lpcap
#LD_FLAGS := -ljson-c -lpcap
CC_FLAGS := -Wall -g -MMD
INCLUDE := $(shell pkg-config --cflags json-c)
#INCLUDE := -I/home/Steven/Programs/openwrt/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/lib

bin/traffic_sniffer: $(OBJ)
	mkdir -p bin/ obj/
	$(CC) $(LD_FLAGS) -o $@ $^

obj/%.o: src/%.c
	$(CC) $(CC_FLAGS) -c -o $@ $<

clean:
	rm bin/* obj/*

-include $(OBJ:.o=.d)
