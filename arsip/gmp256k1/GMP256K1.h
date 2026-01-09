

#ifndef SECP256K1H
#define SECP256K1H

#include "Point.h"
#include <vector>

// Address type
#define P2PKH  0
#define P2SH   1
#define BECH32 2


class Secp256K1 {

public:

  Secp256K1();
  ~Secp256K1();
  void  Init();
  Point ComputePublicKey(Int *privKey);
  Point Add(Point &p1, Point &p2);
  Point Add2(Point &p1, Point &p2);
  Point NextKey(Point &key);
  bool  EC(Point &p);

	void GetHash160_fromX(int type,unsigned char prefix,
	Int *k0,Int *k1,Int *k2,Int *k3,
	uint8_t *h0,uint8_t *h1,uint8_t *h2,uint8_t *h3);
	bool ParsePublicKeyHex(char *str,Point &p,bool &isCompressed);
	bool ParsePublicKeyHex_OpenSSL(const char *hex, Point &ret, bool &isCompressed);
	Point ScalarMultiplication(Point &P,Int *scalar);
	char* GetPublicKeyHex(bool compressed, Point &p);
	void GetPublicKeyHex(bool compressed, Point &pubKey,char *dst);

	char* GetPublicKeyRaw(bool compressed, Point &p);
	void GetPublicKeyRaw(bool compressed, Point &pubKey,char *dst);
	void GetHash160(int type,bool compressed, Point &pubKey, unsigned char *hash);
	void GetHash160(int type,bool compressed,
    Point &k0, Point &k1, Point &k2, Point &k3,
    uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3);
	
	Point Negation(Point &p);
	Point Double(Point &p);
	Point DoubleDirect(Point &p);
	Point AddDirect(Point &p1, Point &p2);
	Point G;                 // Generator
	Int P;                   // Prime for the finite field
	Int   order;             // Curve order
Int DecompressY(Int x, bool isEven); // <- tambahkan ini

private:

	uint8_t GetByte(char *str,int idx);
	Int GetY(Int x, bool isEven);
	Point GTable[256*32];       // Generator table

};

#endif // SECP256K1H
