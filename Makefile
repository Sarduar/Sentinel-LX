CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
CPPFLAGS ?= -D_GNU_SOURCE -Iinclude
LDLIBS ?=
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -lssl -lcrypto
endif
CPPFLAGS += $(OPENSSL_CFLAGS)
LDLIBS += $(OPENSSL_LIBS)
UNAME_S := $(shell uname -s 2>/dev/null)
ifeq ($(UNAME_S),FreeBSD)
LDLIBS += -lbsm
endif
SRC = src/main.c src/harden.c src/ring.c src/sha256.c src/json.c src/net.c src/audit.c src/correlation.c src/report.c src/proc_identity.c src/platform.c src/ship.c src/receive.c src/signature.c
OBJ = $(SRC:.c=.o)
all: sentinel-lx
sentinel-lx: $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJ) $(LDLIBS)
clean:
	rm -f $(OBJ) sentinel-lx
test: sentinel-lx
	./tests/test_build.sh
	./tests/scenario_local.sh
	./tests/test_explain.sh
	./tests/test_causal_ids.sh
	./tests/test_ring.sh
	./tests/test_audit_writer.sh
	./tests/test_ship.sh
	./tests/test_receive_limit.sh
	./tests/test_journal_verify.sh
	./tests/test_fim_recovery.sh
	./tests/test_signature.sh
	./tests/test_report_evidence.sh
