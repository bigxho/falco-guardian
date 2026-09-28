# Makefile per il componente eBPF/C di FALCO Guardian.
#
# Dipendenze (Debian):
#   sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) \
#                     linux-tools-common linux-tools-$(uname -r) build-essential
#
# Uso tipico su una macchina nuova:
#   make vmlinux   # genera src/vmlinux.h dal BTF del kernel corrente (una tantum)
#   make           # compila capture.bpf.o, capture.skel.h e il loader
#   sudo ./build/loader eth0

CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed -E 's/x86_64/x86/; s/aarch64/arm64/')

SRC_DIR := src
OUT_DIR := build

.PHONY: all clean vmlinux

all: $(OUT_DIR)/loader

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Genera l'header col layout delle strutture kernel (dipende dal kernel target,
# va rigenerato se si compila su una macchina diversa da quella di destinazione).
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(SRC_DIR)/vmlinux.h

$(OUT_DIR)/capture.bpf.o: $(SRC_DIR)/capture.bpf.c $(SRC_DIR)/common.h | $(OUT_DIR)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(SRC_DIR) -c $< -o $@

$(OUT_DIR)/capture.skel.h: $(OUT_DIR)/capture.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUT_DIR)/loader: $(SRC_DIR)/loader.c $(OUT_DIR)/capture.skel.h $(SRC_DIR)/common.h
	$(CLANG) -O2 -g -I$(OUT_DIR) -I$(SRC_DIR) $< -lbpf -lpthread -o $@

clean:
	rm -rf $(OUT_DIR)
