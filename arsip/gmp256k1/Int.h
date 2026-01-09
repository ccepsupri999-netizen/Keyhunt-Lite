
// Big integer class (GMP)

#ifndef BIGINTH
#define BIGINTH

#include "Random.h"
#include<stdlib.h>
#include<stdint.h>
#include <gmp.h>

class Int {
public:
	mpz_t num;

    Int();
    Int(const char*);
    Int(const int32_t);
    Int(const uint32_t);
    Int(const int64_t);
    Int(const uint64_t);
    Int(const Int*);
	Int(const Int&);

	/* Aritmetic*/
	void Add(const uint64_t);
	void Add(const uint32_t);
	void Add(const Int*);
	void Add(const Int*,const Int*);
	void AddOne();
	void Sub(const uint64_t);
	void Sub(const uint32_t);
	void Sub(Int *);
	void Sub(Int *a, Int *b);
	void Mult(Int *);
	void Mult(uint64_t );
	void IMult(int64_t );
	
	void Div(Int *a,Int *mod = NULL);
	/*
	void Mult(Int *a,uint64_t b);
	void IMult(Int *a, int64_t b);
	void Mult(Int *a,Int *b)M
	*/
	void Neg();
	void Abs();

	bool IsGreater(Int *a);
	bool IsGreaterOrEqual(Int *a);
	bool IsLowerOrEqual(Int *a);
	bool IsLower(Int *a);
	bool IsEqual(Int *a);
	bool IsZero();
	bool IsOne();
	//bool IsStrictPositive();
	bool IsPositive();
	bool IsNegative();
	bool IsEven();
	bool IsOdd();
	
	/*Setters*/
	void SetInt64(const uint64_t value);
	void SetInt32(const uint32_t value);
	void Set(const Int* other);
	void Set(const char *str);
	void SetBase10(const char *str);
	void SetBase16(const char *str);
	// ====== Tambahan: Set integer (generic 64-bit) ======
// ====== Tambahan: Helper Setters cepat & aman ======

/**
 * Set integer nilai 64-bit (universal).
 * Contoh: a.SetInt(12345);
 */
inline void SetInt(uint64_t value) {
    mpz_set_ui(this->num, value);
}

/**
 * Set nilai ke 0 (nol)
 * Contoh: a.SetZero();
 */
inline void SetZero() {
    mpz_set_ui(this->num, 0);
}

/**
 * Set nilai ke 1 (satu)
 * Contoh: a.SetOne();
 */
inline void SetOne() {
    mpz_set_ui(this->num, 1);
}

/**
 * Salin nilai dari integer C biasa (int32_t)
 * Contoh: a.SetFromInt(i);
 */
inline void SetFromInt(int value) {
    if (value >= 0)
        mpz_set_ui(this->num, static_cast<unsigned long>(value));
    else
        mpz_set_si(this->num, static_cast<long>(value));
}


	// Size
	int GetSize();
	int GetBitLength();
	//
	uint64_t GetInt64();
	uint32_t GetInt32();
	int GetBit(uint32_t n);
	unsigned char GetByte(int n);
	void Get32Bytes(unsigned char *buff);
	void Set32Bytes(unsigned char *buff);

	char* GetBase2();
	char* GetBase10();
	char* GetBase16();
	
	
	void SetBit(uint32_t n);
	void ClearBit(uint32_t n);
	/*
	char* GetBaseN(int n,const char *charset);
	char* GetBlockStr();
	char* GetC64Str(int nbDigit);
	*/
	// Left shift
	void ShiftL(uint32_t n);
	void Mod(Int *a);							// this <- this (mod a)
	
	/*
		All next mod n are setup as mod P, where P = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
	*/
	void ModInv();								// this <- this^-1 (mod n)
	void ModAdd(Int *a);						// this <- this+a (mod n) [0<a<P]
	void ModAdd(uint32_t a);					// this <- this+a (mod n) [0<a<P]
	void ModAdd(Int *a, Int *b);				// this <- a+b (mod n) [0<a,b<P]
	void ModSub(Int *a);    					// this <- this-a (mod n) [0<a<P]
	void ModSub(Int *a, Int *b);				// this <- a-b (mod n) [0<a,b<P]
	void ModSub(uint64_t a);					// this <- this-a (mod n) [0<a<P]
	void ModMul(Int *a);						// this <- this*b (mod n)
	void ModMul(Int *a,Int *b);					// this <- a*b (mod n)
	void ModNeg();								// this <- -this (mod n)
	void ModDouble();							// this <- 2*this (mod n)
	void ModSqrt();                             // this <- +/-sqrt(this) (mod n)
	bool HasSqrt();                             // true if this admit a square root
	
	/*
		Rand functions are
	*/
	void Rand(int nbit);						// return a rand number bewteen [ 2^(nbit-1) and 2^nbit
	void Rand(Int *min,Int *max);				// return a rand number bewteen [min and max)

	static void SetupField(Int *n);
	
	// Specific SecpK1
	static void InitK1(Int *order);
	void ModMulK1(Int *a, Int *b);
	void ModMulK1(Int *a);
	void ModMulK1order(Int *a);
	void ModInvorder();								// this <- this^-1 (mod O)
	
	void ModSquareK1(Int *a);
	void ModAddK1order(Int *a,Int *b);
		
	~Int();
	Int& operator=(const Int& other); // Declaration
	void CLEAR();

};
#endif // BIGINTH