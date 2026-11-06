CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g
CPPFLAGS = -Iinclude
LDLIBS = -lsodium

APP = pwman
APP_SOURCES = src/main.c src/cli.c src/auth.c src/vault.c src/crypto.c
TEST_APP = build/test-vault
TEST_SOURCES = tests/test_vault.c src/vault.c src/crypto.c

.PHONY: all test clean

all: $(APP)

$(APP): $(APP_SOURCES) include/auth.h include/cli.h include/crypto.h include/vault.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(APP_SOURCES) -o $@ $(LDLIBS)

$(TEST_APP): $(TEST_SOURCES) include/crypto.h include/vault.h
	mkdir -p build
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TEST_SOURCES) -o $@ $(LDLIBS)

test: $(TEST_APP)
	./$(TEST_APP)

clean:
	rm -f $(APP) *.o test-vault.db test-vault.db.tmp
	rm -rf build
