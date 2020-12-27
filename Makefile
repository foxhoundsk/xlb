CLANG ?= clang
CC ?= gcc
LLC ?= llc

USER_PROG = xlb_user
KERN_PROG = lb_kern.o

KERN_INC = -Ibpf/linux_header -Ibpf
KERN_SRCS = bpf/lb_kern.c bpf/*.h

LIBBPF_DIR ?= libbpf/src
USER_INC = -Ibpf -I$(LIBBPF_DIR)/build/usr/include/bpf
USER_SRCS = user/xlb.c bpf/*.h

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a
LIBBPF_SRCS = libbpf/src/*.c

LDFLAGS ?= -L$(LIBBPF_DIR)
LIBS = -l:libbpf.a -lelf -lz

all: $(USER_PROG) $(KERN_PROG)

$(USER_PROG): $(USER_SRCS) $(OBJECT_LIBBPF) 
	$(CC) $(USER_INC) $(LDFLAGS) -Wall -o $@ $< $(LIBS)

$(KERN_PROG): $(KERN_SRCS)
	$(CLANG) \
		-target bpf \
		$(KERN_INC) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
# is -mcpu=probe necessary?
$(OBJECT_LIBBPF): $(LIBBPF_SRCS)
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

clean:
	rm -f $(KERN_PROG) $(USER_PROG) *.ll *.o 
