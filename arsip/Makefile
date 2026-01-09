CXX         = clang++
CC          = clang

# =========================================================
#  ARCH tuning untuk Snapdragon 662 (Cortex-A73 / A53)
# =========================================================
ARCH_FLAGS  = -march=armv8-a+crypto -mtune=cortex-a73

# =========================================================
#  Optimisasi Clang++ yang aman & efektif
# =========================================================
OPT_FLAGS   = -O3 -ffast-math -funroll-loops -flto=full \
              -fomit-frame-pointer -fstrict-aliasing \
              -fvectorize -fslp-vectorize -fno-exceptions -fno-rtti \
              -DNDEBUG -Wno-unused-result -Wno-write-strings \
              -Wno-deprecated -Wno-deprecated-declarations

CFLAGS      = -Wall -Wextra $(ARCH_FLAGS) $(OPT_FLAGS)


# =========================================================
#  Build Legacy KeyHunt (GMP asli, bukan mpz_w.h)
# =========================================================
legacy:
	@echo "[BUILD] KeyHunt Clang++ ARMv8-A (Cortex-A73) — GMP System..."

	$(CXX) $(CFLAGS) -c oldbloom/bloom.cpp -o oldbloom.o
	$(CXX) $(CFLAGS) -c bloom/bloom.cpp -o bloom.o
	$(CC)  $(CFLAGS) -c base58/base58.c -o base58.o
	$(CC)  $(CFLAGS) -c xxhash/xxhash.c -o xxhash.o
	$(CXX) $(CFLAGS) -c util.c -o util.o
	$(CXX) $(CFLAGS) -c sha3/sha3.c -o sha3.o
	$(CXX) $(CFLAGS) -c sha3/keccak.c -o keccak.o
	$(CXX) $(CFLAGS) -c hashing.c -o hashing.o

	# === GMP256K1 engine ===
	$(CXX) $(CFLAGS) -c gmp256k1/Int.cpp -o Int.o
	$(CXX) $(CFLAGS) -c gmp256k1/Point.cpp -o Point.o
	$(CXX) $(CFLAGS) -c gmp256k1/GMP256K1.cpp -o GMP256K1.o
	$(CXX) $(CFLAGS) -c gmp256k1/IntMod.cpp -o IntMod.o
	$(CXX) $(CFLAGS) -c gmp256k1/Random.cpp -o Random.o
	$(CXX) $(CFLAGS) -c gmp256k1/IntGroup.cpp -o IntGroup.o

	# === Link: gunakan GMP sistem ===
	$(CXX) $(CFLAGS) -o keyhunt main.cpp \
	  base58.o bloom.o oldbloom.o xxhash.o util.o \
	  Int.o Point.o GMP256K1.o IntMod.o IntGroup.o Random.o \
	  hashing.o sha3.o keccak.o \
	  -lgmp -lm -lpthread -lcrypto

	@echo "[DONE] keyhunt built successfully (SYSTEM GMP)."


# =========================================================
#  Clean target
# =========================================================
clean:
	rm -f *.o keyhunt
	@echo "[CLEAN] Build artifacts removed."
