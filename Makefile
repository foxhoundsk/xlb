CLANG ?= clang
CC ?= gcc
LLC ?= llc

USER_PROG = xlb_user
KERN_PROG = lb_kern.o

KERN_INC = -Ibpf/linux_header -Ibpf

LIBBPF_DIR ?= libbpf/src
USER_INC = -Ibpf -I$(LIBBPF_DIR)/build/usr/include
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a
LDFLAGS ?= -L$(LIBBPF_DIR)
LIBS = -l:libbpf.a -lelf

$(USER_PROG): user/xlb.c $(OBJECT_LIBBPF) 
	$(CC) $(USER_INC) $(LDFLAGS) $(LIBS) -Wall -o $@ $<

$(KERN_PROG): bpf/lb_kern.c
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

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

clean:
	rm $(KERN_PROG) $(USER_PROG) *.ll *.o 
