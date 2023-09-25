macfilter.bpf.o: %o: %c
	clang \
		-target bpf \
		-I /usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -c $< -o $@
	bpftool gen skeleton macfilter.bpf.o > include/macfilter.skel.h
	cd build && make

clean:
	rm include/macfilter.skel.h
	rm macfilter.bpf.o
	rm build/eBPF

