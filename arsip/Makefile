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
              -fvectorize -fslp-vectorize \
              -DNDEBUG -Wno-unused-result -Wno-write-strings \
              -Wno-deprecated -Wno-deprecated-declarations

# Flags terpisah C dan C++
CFLAGS      = -Wall -Wextra $(ARCH_FLAGS) $(OPT_FLAGS)
CXXFLAGS    = $(CFLAGS) -fno-exceptions -fno-rtti

# Default: build semuanya
all: legacy auto
	@echo "[DONE] all targets built."

# =========================================================
#  Build Legacy KeyHunt (GMP asli, bukan mpz_w.h)
# =========================================================
legacy: keyhunt

keyhunt:
	@echo "[BUILD] KeyHunt Clang++ ARMv8-A (Cortex-A73) — GMP System..."

	$(CXX) $(CXXFLAGS) -c oldbloom/bloom.cpp -o oldbloom.o
	$(CXX) $(CXXFLAGS) -c bloom/bloom.cpp -o bloom.o
	$(CC)  $(CFLAGS)   -c base58/base58.c -o base58.o
	$(CC)  $(CFLAGS)   -c xxhash/xxhash.c -o xxhash.o
	$(CXX) $(CXXFLAGS) -c util.c -o util.o
	$(CC)  $(CFLAGS)   -c sha3/sha3.c -o sha3.o
	$(CC)  $(CFLAGS)   -c sha3/keccak.c -o keccak.o
	$(CXX) $(CXXFLAGS) -c hashing.c -o hashing.o

	# === GMP256K1 engine ===
	$(CXX) $(CXXFLAGS) -c gmp256k1/Int.cpp -o Int.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/Point.cpp -o Point.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/GMP256K1.cpp -o GMP256K1.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/IntMod.cpp -o IntMod.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/Random.cpp -o Random.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/IntGroup.cpp -o IntGroup.o

	# === Link: gunakan GMP sistem ===
	$(CXX) $(CXXFLAGS) -o keyhunt keyhunt.cpp \
	  base58.o bloom.o oldbloom.o xxhash.o util.o \
	  Int.o Point.o GMP256K1.o IntMod.o IntGroup.o Random.o \
	  hashing.o sha3.o keccak.o \
	  -lgmp -lm -lpthread -lcrypto

	@echo "[DONE] keyhunt built successfully (SYSTEM GMP)."

# =========================================================
#  Build AUTO (auto.c)
# =========================================================
auto:
	@echo "[BUILD] AUTO (auto.c) — GMP System..."
	$(CC) $(CFLAGS) -std=c11 auto.c -o auto -lgmp -lm -lpthread
	@echo "[DONE] auto built successfully."

# =========================================================
#  Clean target
# =========================================================
clean:
	rm -f *.o keyhunt auto
	@echo "[CLEAN] Build artifacts removed."
