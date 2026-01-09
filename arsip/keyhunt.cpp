/* clang++ -Wall -Wextra \-march=armv8-a+crypto+crc+sha3 \
              -mtune=cortex-a73 \
              -O3 -ffast-math -funroll-loops -fomit-frame-pointer \
              -fstrict-aliasing -fno-math-errno -pthread -DNDEBUG \
              -Wno-unused-result -Wno-write-strings -Wno-deprecated -Wno-deprecated-declarations \
               -o keyhunt keyhunt.cpp \
               bloom.o oldbloom.o xxhash.o util.o \
              Int.o Point.o GMP256K1.o IntMod.o IntGroup.o Random.o \
              hashing.o sha3.o  \
               -lm -lpthread -lcrypto -lgmp
*/

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "oldbloom/oldbloom.h"
#include "bloom/bloom.h"
#include "gmp256k1/GMP256K1.h"
#include "gmp256k1/Point.h"
#include "gmp256k1/Int.h"
#include "gmp256k1/IntGroup.h"
#include "gmp256k1/Random.h"
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#include <linux/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread>
#include <chrono>
#include <string>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <algorithm>

#define CPU_GRP_SIZE 1024

struct checksumsha256 {
	char data[32];
	char backup[32];
};

struct BSGS_xvalue {
	uint8_t value[6];
	uint64_t index;
};

struct bPload {
	uint32_t threadid;
	uint64_t from;
	uint64_t to;
	uint64_t counter;
	uint64_t workload;
	uint32_t aux;
	uint32_t finished;
};

struct tothread {
	int nt;
	Int RangeMin;
	Int RangeMax;
};

typedef struct str_tokenizer {
	int current;
	int n;
	char **tokens;
}Tokenizer;

const char *default_fileName = "pubtes.txt";
uint32_t THREADBPWORKLOAD = 1048576;
int USEPUBKEY = 0;
int FLAGSKIPCHECKSUM = 0;
int KFACTOR = 1;
int NTHREADS = 1;
int SafeBloom = 0;
int ReadBloom1 = 0;
int ReadBloom2 = 0;
int ReadBloom3 = 0;
int ReadBloom4 = 0;
int UpdateBloom = 0;
int FLAGFILE = 0;


uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;
uint64_t bytes = 0;
uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t BSGS_m = 4194304;
uint64_t BSGS_m2 = 0;
uint64_t BSGS_m3 = 0;
uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;

unsigned long BSGS_aux = 0;
uint32_t PubkeyNumber = 0;

char PUBKEYARG[140] = {
	0
};
char *RangeMin = NULL;
char *RangeMax = NULL;
char checksum[32], checksum_backup[32];
char buffer_bloom_file[1024];
char *nextToken(Tokenizer *t);
char *tohex(char *ptr, int length);

int *BSGS_found = NULL;
bool *BSGSCompPoint = NULL;
std::vector < Point > BSGSPoint;
std::vector < Point > Gn;
std::vector < Point > GSn;
std::vector < Point > BSGS_AMP2;
std::vector < Point > BSGS_AMP3;

struct BSGS_xvalue *bPtable = NULL;
struct oldbloom oldbloom_bP;
struct bloom *bloom_bP = NULL;
struct bloom *bloom_bPx2nd = NULL;
struct bloom *bloom_bPx3rd = NULL;
struct checksumsha256 *bloom_bP_checksums = NULL;
struct checksumsha256 *bloom_bPx2nd_checksums = NULL;
struct checksumsha256 *bloom_bPx3rd_checksums = NULL;

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t BSGS_thread;
pthread_mutex_t *bPload_mutex = NULL;
pthread_mutex_t *bloom_bP_mutex = NULL;
pthread_mutex_t *bloom_bPx2nd_mutex = NULL;
pthread_mutex_t *bloom_bPx3rd_mutex = NULL;
pthread_mutex_t global_log_lock = PTHREAD_MUTEX_INITIALIZER;

Point _2Gn;
Point _2GSn;
Point BSGS_P;
Point BSGS_MP;
Point BSGS_MP2;
Point BSGS_MP3;
Point BSGS_MP_double;
Point BSGS_MP2_double;
Point BSGS_MP3_double;
Point point_temp, point_temp2;

Int ONE;
Int ZERO;
Int MPZAUX;
Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_N_double;
Int BSGS_M;
Int BSGS_M_double;
Int BSGS_M2;
Int BSGS_M2_double;
Int BSGS_M3;
Int BSGS_M3_double;
Int n_RangeMin;
Int n_RangeMax;
Int n_range_diff;
Int n_range_aux;
Int keyfound;
Int int_limits[7];
static Int RANGE_CURSOR;

Secp256K1 *secp = NULL;

#define CLR_RESET   "\033[0m"
#define CLR_RED     "\033[1;31m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_WHITE   "\033[1;37m"

int isValidHex(char *data);
int sha256(const unsigned char *data, size_t length, unsigned char *digest);
void stringtokenizer(char *data, Tokenizer *t);


static void SortBSGSTable(struct BSGS_xvalue *arr, int64_t n) {
	auto swap_func = [](struct BSGS_xvalue *a, struct BSGS_xvalue *b) {
		struct BSGS_xvalue t = *a;
		*a = *b;
		*b = t;
	};

	std::function < void(struct BSGS_xvalue*, int64_t, int64_t) > heapify;
	heapify = [&swap_func,
		&heapify](struct BSGS_xvalue *arr, int64_t n, int64_t i) {
		int64_t largest = i;
		int64_t l = 2 * i + 1;
		int64_t r = 2 * i + 2;
		if (l < n && memcmp(arr[l].value, arr[largest].value, BSGS_XVALUE_RAM) > 0) largest = l;
		if (r < n && memcmp(arr[r].value, arr[largest].value, BSGS_XVALUE_RAM) > 0) largest = r;
		if (largest != i) {
			swap_func(&arr[i], &arr[largest]);
			heapify(arr, n, largest);
		}
	};

	auto insertionSort = [](struct BSGS_xvalue *arr, int64_t n) {
		int64_t j,
		i;
		struct BSGS_xvalue key;
		for(i = 1; i < n; i++) {
			key = arr[i];
			j = i-1;
			while(j >= 0 && memcmp(arr[j].value, key.value, BSGS_XVALUE_RAM) > 0) {
				arr[j+1] = arr[j];
				j--;
			}
			arr[j+1] = key;
		}
	};

	auto heapSort = [&heapify,
		&swap_func](struct BSGS_xvalue *arr, int64_t n) {
		for (int64_t i = (n / 2) - 1; i >= 0; i--) heapify(arr, n, i);
		for (int64_t i = n - 1; i > 0; i--) {
			swap_func(&arr[0], &arr[i]);
			heapify(arr, i, 0);
		}
	};

	auto partition = [&swap_func](struct BSGS_xvalue *arr, int64_t n) -> int64_t {
		struct BSGS_xvalue pivot;
		int64_t r,
		left,
		right;
		r = n/2;
		pivot = arr[r];
		left = 0;
		right = n-1;
		do {
			while(left < right && memcmp(arr[left].value, pivot.value, BSGS_XVALUE_RAM) <= 0) left++;
			while(right >= left && memcmp(arr[right].value, pivot.value, BSGS_XVALUE_RAM) > 0) right--;
			if(left < right) {
				if(left == r || right == r) {
					if(left == r) r = right;
					if(right == r) r = left;
				}
				swap_func(&arr[right], &arr[left]);
			}
		} while(left < right);
		if(right != r) swap_func(&arr[right], &arr[r]);
		return right;
	};

	std::function < void(struct BSGS_xvalue*, uint32_t, int64_t) > introsort;
	introsort = [&](struct BSGS_xvalue *arr, uint32_t depthLimit, int64_t n) {
		if(n > 1) {
			if(n <= 16) {
				insertionSort(arr, n);
			} else {
				if(depthLimit == 0) {
					heapSort(arr, n);
				} else {
					int64_t p = partition(arr, n);
					if(p > 0) introsort(arr, depthLimit-1, p);
					if(p < n) introsort(&arr[p+1], depthLimit-1, n-(p+1));
				}
			}
		}
	};

	if (n <= 0) return;
	uint32_t depthLimit = ((uint32_t) ceil(log2(n))) * 2;
	introsort(arr, depthLimit, n);
}

int FindTable(struct BSGS_xvalue *buffer, char *data, int64_t array_length, uint64_t *r_value) {
	int64_t min,
	max,
	half,
	current;
	int r = 0,
	rcmp;
	min = 0;
	current = 0;
	max = array_length;
	half = array_length;
	while(!r && half >= 1) {
		half = (max - min)/2;
		rcmp = memcmp(data+16, buffer[current+half].value, BSGS_XVALUE_RAM);
		if(rcmp == 0) {
			*r_value = buffer[current+half].index;
			r = 1;
		} else {
			if(rcmp < 0) max = (max-half);
			else min = (min+half);
			current = min;
		}
	}
	return r;
}

void init_generator() {
	Point G = secp->ComputePublicKey(&ONE);
	Point g;
	Gn.resize(CPU_GRP_SIZE / 2, g);
	g.Set(G);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g, G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

void checkpointer(void *ptr, const char *file, const char *function, const char *name, int line) {
	if(ptr == NULL) {
		fprintf(stderr, "[E] error in file %s, %s pointer %s on line %i\n", file, function, name, line);
		exit(EXIT_FAILURE);
	}
}

void caIcndex(int i, Int *key) {
	if(i == 0) key->Set(&BSGS_M3);
	else {
		key->SetInt32(i);
		key->Mult(&BSGS_M3_double);
		key->Add(&BSGS_M3);
	}
}

int BSGS_C3(Int *start_range, uint32_t a, uint32_t k_index, Int *privatekey) {
	uint64_t j = 0;
	int i = 0,
	found = 0,
	r = 0;
	Int base_key,
	calculatedkey;
	Point base_point,
	point_aux;
	Point BSGS_Q,
	BSGS_S,
	BSGS_Q_AMP;
	char xpoint_raw[32];

	base_key.SetInt32(a);
	base_key.Mult(&BSGS_M2_double);
	base_key.Add(start_range);

	base_point = secp->ComputePublicKey(&base_key);
	point_aux = secp->Negation(base_point);

	BSGS_S = secp->AddDirect(BSGSPoint[k_index], point_aux);
	BSGS_Q.Set(BSGS_S);

	do {
		BSGS_Q_AMP = secp->AddDirect(BSGS_Q, BSGS_AMP3[i]);
		BSGS_S.Set(BSGS_Q_AMP);
		BSGS_S.x.Get32Bytes((unsigned char *)xpoint_raw);
		r = bloom_check(&bloom_bPx3rd[(uint8_t)xpoint_raw[0]], xpoint_raw, 32);
		if(r) {
			r = FindTable(bPtable, xpoint_raw, BSGS_m3, &j);
			if(r) {
				caIcndex(i, &calculatedkey);
				privatekey->Set(&calculatedkey);
				privatekey->Add((uint64_t)(j+1));
				privatekey->Add(&base_key);
				point_aux = secp->ComputePublicKey(privatekey);
				if(point_aux.x.IsEqual(&BSGSPoint[k_index].x)) found = 1;
				else {
					caIcndex(i, &calculatedkey);
					privatekey->Set(&calculatedkey);
					privatekey->Sub((uint64_t)(j+1));
					privatekey->Add(&base_key);
					point_aux = secp->ComputePublicKey(privatekey);
					if(point_aux.x.IsEqual(&BSGSPoint[k_index].x)) found = 1;
				}
			}
		} else {
			if(BSGS_Q.x.IsEqual(&BSGS_AMP3[i].x)) {
				caIcndex(i, &calculatedkey);
				privatekey->Set(&calculatedkey);
				privatekey->Add(&base_key);
				found = 1;
			}
		}
		i++;
	} while(i < 32 && !found);
	return found;
}


int BSGS_C2(Int *start_range, uint32_t a, uint32_t k_index, Int *privatekey) {
	int i = 0,
	found = 0,
	r = 0;
	Int base_key;
	Point base_point,
	point_aux;
	Point BSGS_Q,
	BSGS_S,
	BSGS_Q_AMP;
	char xpoint_raw[32];

	base_key.Set(&BSGS_M_double);
	base_key.Mult((uint64_t) a);
	base_key.Add(start_range);

	base_point = secp->ComputePublicKey(&base_key);
	point_aux = secp->Negation(base_point);

	BSGS_S = secp->AddDirect(BSGSPoint[k_index], point_aux);
	BSGS_Q.Set(BSGS_S);
	do {
		BSGS_Q_AMP = secp->AddDirect(BSGS_Q, BSGS_AMP2[i]);
		BSGS_S.Set(BSGS_Q_AMP);
		BSGS_S.x.Get32Bytes((unsigned char *) xpoint_raw);
		r = bloom_check(&bloom_bPx2nd[(uint8_t) xpoint_raw[0]], xpoint_raw, 32);
		if(r) found = BSGS_C3(&base_key, i, k_index, privatekey);
		i++;
	} while(i < 32 && !found);
	return found;
}

void *thread_BSGS(void *vargp) {
	FILE *filekey;
	struct tothread *tt = (struct tothread *)vargp;
	uint32_t thread_number = tt->nt;
	free(tt);

	char xpoint_raw[32],
	*aux_c,
	*hextemp;
	Int base_key,
	keyfound; Int km,
	intaux;
	Point base_point,
	point_aux,
	point_found;
	Point startP;
	uint32_t j,
	k,
	l,
	r,
	salir;
	uint32_t cycles;

	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	int i;
	int hLength = (CPU_GRP_SIZE / 2 - 1);

	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];
	Int dy,
	dyn;
	Int _s,
	_p;
	Point pp,
	pn;

	grp->Set(dx);
	base_key.Set(&n_RangeMin);
	cycles = BSGS_aux / 1024;
	if (BSGS_aux % 1024 != 0) cycles++;

	intaux.Set(&BSGS_M_double);
	intaux.Mult(CPU_GRP_SIZE / 2);
	intaux.Add(&BSGS_M);

	while (!base_key.IsGreaterOrEqual(&n_RangeMax)) {

		aux_c = base_key.GetBase16();
		printf("\r[T%u] BaseKey = 0x%s   \r", thread_number, aux_c);
		fflush(stdout);
		free(aux_c);


		base_point = secp->ComputePublicKey(&base_key);
		km.Set(&base_key);
		km.Neg();
		km.Add(&secp->order);
		km.Sub(&intaux);
		point_aux = secp->ComputePublicKey(&km);

		for (k = thread_number; k < PubkeyNumber; k += NTHREADS) {
			if (BSGS_found[k]) continue;
			startP = secp->AddDirect(BSGSPoint[k], point_aux);
			j = 0;

			while (j < cycles && !BSGS_found[k]) {
				for (i = 0; i < hLength; i++) dx[i].ModSub(&GSn[i].x, &startP.x);
				dx[i].ModSub(&GSn[i].x, &startP.x);
				dx[i + 1].ModSub(&_2GSn.x, &startP.x);
				grp->ModInv();

				pts[CPU_GRP_SIZE / 2] = startP;

				for (i = 0; i < hLength; i++) {
					pp = startP;
					pn = startP;

					dy.ModSub(&GSn[i].y, &pp.y);
					_s.ModMulK1(&dy, &dx[i]);
					_p.ModSquareK1(&_s);
					pp.x.ModNeg();
					pp.x.ModAdd(&_p);
					pp.x.ModSub(&GSn[i].x);

					dyn.Set(&GSn[i].y);
					dyn.ModNeg();
					dyn.ModSub(&pn.y);
					_s.ModMulK1(&dyn, &dx[i]);
					_p.ModSquareK1(&_s);
					pn.x.ModNeg();
					pn.x.ModAdd(&_p);
					pn.x.ModSub(&GSn[i].x);

					pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
					pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
				}

				pn = startP;
				dyn.Set(&GSn[i].y);
				dyn.ModNeg();
				dyn.ModSub(&pn.y);
				_s.ModMulK1(&dyn, &dx[i]);
				_p.ModSquareK1(&_s);
				pn.x.ModNeg();
				pn.x.ModAdd(&_p);
				pn.x.ModSub(&GSn[i].x);
				pts[0] = pn;

				for (int ii = 0; ii < CPU_GRP_SIZE && !BSGS_found[k]; ii++) {
					pts[ii].x.Get32Bytes((unsigned char *)xpoint_raw);
					r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);

					if (r) {
						r = BSGS_C2(&base_key, ((j * 1024) + ii), k, &keyfound);
						if (r) {
							hextemp = keyfound.GetBase16();
							point_found = secp->ComputePublicKey(&keyfound);
							aux_c = secp->GetPublicKeyHex(BSGSCompPoint[k], point_found);

							printf("[KF] PRIV=%s PUB=%s\n", hextemp, aux_c);

							pthread_mutex_lock(&write_keys);
							filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
							if (filekey) {
								fprintf(filekey, "Key found privkey %s\nPublickey %s\n", hextemp, aux_c);
								fclose(filekey);
							}
							pthread_mutex_unlock(&write_keys);

							free(hextemp);
							free(aux_c);
							BSGS_found[k] = 1;

							salir = 1;
							for (l = 0; l < PubkeyNumber && salir; l++) salir &= BSGS_found[l];
							if (salir) {
								printf("All points were found\n");
								exit(EXIT_FAILURE);
							}
						}
					}
				}

				pp = startP;
				dy.ModSub(&_2GSn.y, &pp.y);
				_s.ModMulK1(&dy, &dx[i + 1]);
				_p.ModSquareK1(&_s);
				pp.x.ModNeg();
				pp.x.ModAdd(&_p);
				pp.x.ModSub(&_2GSn.x);
				pp.y.ModSub(&_2GSn.x, &pp.x);
				pp.y.ModMulK1(&_s);
				pp.y.ModSub(&_2GSn.y);
				startP = pp;
				j++;
			}
		}
		base_key.Add(&BSGS_N_double);
	}
	pthread_exit(NULL);
	return NULL;
}

void *thread_bPload(void *vargp) {
	char rawvalue[32];
	struct bPload *tt;
	uint64_t i_counter,
	j,
	nbStep,
	to;

	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];
	Int dy,
	dyn,
	_s,
	_p;
	Point pp,
	pn;

	int i,
	bloom_bP_index,
	hLength = (CPU_GRP_SIZE / 2 - 1),
	threadid;
	tt = (struct bPload *)vargp;
	Int km((uint64_t)(tt->from + 1));
	threadid = tt->threadid;
	i_counter = tt->from;
	nbStep = (tt->to - tt->from) / CPU_GRP_SIZE;
	if(((tt->to - tt->from) % CPU_GRP_SIZE) != 0) nbStep++;
	to = tt->to;

	km.Add((uint64_t)(CPU_GRP_SIZE / 2));
	startP = secp->ComputePublicKey(&km);
	grp->Set(dx);
	for(uint64_t s = 0; s < nbStep; s++) {
		for(i = 0; i < hLength; i++) dx[i].ModSub(&Gn[i].x, &startP.x);
		dx[i].ModSub(&Gn[i].x, &startP.x);
		dx[i + 1].ModSub(&_2Gn.x, &startP.x);
		grp->ModInv();

		pts[CPU_GRP_SIZE / 2] = startP;

		for(i = 0; i < hLength; i++) {
			pp = startP;
			pn = startP;

			dy.ModSub(&Gn[i].y, &pp.y);
			_s.ModMulK1(&dy, &dx[i]);
			_p.ModSquareK1(&_s);
			pp.x.ModNeg();
			pp.x.ModAdd(&_p);
			pp.x.ModSub(&Gn[i].x);

			dyn.Set(&Gn[i].y);
			dyn.ModNeg();
			dyn.ModSub(&pn.y);
			_s.ModMulK1(&dyn, &dx[i]);
			_p.ModSquareK1(&_s);
			pn.x.ModNeg();
			pn.x.ModAdd(&_p);
			pn.x.ModSub(&Gn[i].x);

			pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
			pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
		}

		pn = startP;
		dyn.Set(&Gn[i].y);
		dyn.ModNeg();
		dyn.ModSub(&pn.y);
		_s.ModMulK1(&dyn, &dx[i]);
		_p.ModSquareK1(&_s);
		pn.x.ModNeg();
		pn.x.ModAdd(&_p);
		pn.x.ModSub(&Gn[i].x);
		pts[0] = pn;

		for(j = 0; j < CPU_GRP_SIZE; j++) {
			pts[j].x.Get32Bytes((unsigned char*)rawvalue);
			bloom_bP_index = (uint8_t)rawvalue[0];
			if(i_counter < BSGS_m3) {
				if(!ReadBloom3) {
					memcpy(bPtable[i_counter].value, rawvalue+16, BSGS_XVALUE_RAM);
					bPtable[i_counter].index = i_counter;
				}
				if(!ReadBloom4) {
					pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_index]);
					bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
					pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_index]);
				}
			}
			if(i_counter < BSGS_m2 && !ReadBloom2) {
				pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_index]);
				bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
				pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_index]);
			}
			if(i_counter < to && !ReadBloom1) {
				pthread_mutex_lock(&bloom_bP_mutex[bloom_bP_index]);
				bloom_add(&bloom_bP[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
				pthread_mutex_unlock(&bloom_bP_mutex[bloom_bP_index]);
			}
			i_counter++;
		}

		pp = startP;
		dy.ModSub(&_2Gn.y, &pp.y);
		_s.ModMulK1(&dy, &dx[i + 1]);
		_p.ModSquareK1(&_s);
		pp.x.ModNeg();
		pp.x.ModAdd(&_p);
		pp.x.ModSub(&_2Gn.x);
		pp.y.ModSub(&_2Gn.x, &pp.x);
		pp.y.ModMulK1(&_s);
		pp.y.ModSub(&_2Gn.y);
		startP = pp;
	}
	delete grp;

	pthread_mutex_lock(&bPload_mutex[threadid]);
	tt->finished = 1;
	pthread_mutex_unlock(&bPload_mutex[threadid]);
	pthread_exit(NULL);
	return NULL;
}

void *thread_bPload_2blooms(void *vargp) {
	char rawvalue[32];
	struct bPload *tt;
	uint64_t i_counter,
	j,
	nbStep;
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];
	Int dy,
	dyn,
	_s,
	_p;
	Point pp,
	pn;
	int i,
	bloom_bP_index,
	hLength = (CPU_GRP_SIZE / 2 - 1),
	threadid;
	tt = (struct bPload *)vargp;
	Int km((uint64_t)(tt->from +1));
	threadid = tt->threadid;

	i_counter = tt->from;
	nbStep = (tt->to - (tt->from)) / CPU_GRP_SIZE;
	if(((tt->to - (tt->from)) % CPU_GRP_SIZE) != 0) nbStep++;

	km.Add((uint64_t)(CPU_GRP_SIZE / 2));
	startP = secp->ComputePublicKey(&km);
	grp->Set(dx);
	for(uint64_t s = 0; s < nbStep; s++) {
		for(i = 0; i < hLength; i++) dx[i].ModSub(&Gn[i].x, &startP.x);
		dx[i].ModSub(&Gn[i].x, &startP.x);
		dx[i + 1].ModSub(&_2Gn.x, &startP.x);
		grp->ModInv();

		pts[CPU_GRP_SIZE / 2] = startP;

		for(i = 0; i < hLength; i++) {
			pp = startP;
			pn = startP;

			dy.ModSub(&Gn[i].y, &pp.y);
			_s.ModMulK1(&dy, &dx[i]);
			_p.ModSquareK1(&_s);
			pp.x.ModNeg();
			pp.x.ModAdd(&_p);
			pp.x.ModSub(&Gn[i].x);

			dyn.Set(&Gn[i].y);
			dyn.ModNeg();
			dyn.ModSub(&pn.y);
			_s.ModMulK1(&dyn, &dx[i]);
			_p.ModSquareK1(&_s);
			pn.x.ModNeg();
			pn.x.ModAdd(&_p);
			pn.x.ModSub(&Gn[i].x);

			pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
			pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
		}

		pn = startP;
		dyn.Set(&Gn[i].y);
		dyn.ModNeg();
		dyn.ModSub(&pn.y);
		_s.ModMulK1(&dyn, &dx[i]);
		_p.ModSquareK1(&_s);
		pn.x.ModNeg();
		pn.x.ModAdd(&_p);
		pn.x.ModSub(&Gn[i].x);
		pts[0] = pn;

		for(j = 0; j < CPU_GRP_SIZE; j++) {
			pts[j].x.Get32Bytes((unsigned char*)rawvalue);
			bloom_bP_index = (uint8_t)rawvalue[0];
			if(i_counter < BSGS_m3) {
				if(!ReadBloom3) {
					memcpy(bPtable[i_counter].value, rawvalue+16, BSGS_XVALUE_RAM);
					bPtable[i_counter].index = i_counter;
				}
				if(!ReadBloom4) {
					pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_index]);
					bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
					pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_index]);
				}
			}
			if(i_counter < BSGS_m2 && !ReadBloom2) {
				pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_index]);
				bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
				pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_index]);
			}
			i_counter++;
		}

		pp = startP;
		dy.ModSub(&_2Gn.y, &pp.y);
		_s.ModMulK1(&dy, &dx[i + 1]);
		_p.ModSquareK1(&_s);
		pp.x.ModNeg();
		pp.x.ModAdd(&_p);
		pp.x.ModSub(&_2Gn.x);
		pp.y.ModSub(&_2Gn.x, &pp.x);
		pp.y.ModMulK1(&_s);
		pp.y.ModSub(&_2Gn.y);
		startP = pp;
	}
	delete grp;

	pthread_mutex_lock(&bPload_mutex[threadid]);
	tt->finished = 1;
	pthread_mutex_unlock(&bPload_mutex[threadid]);
	pthread_exit(NULL);
	return NULL;
}

static void InitMutexSecp() {
	pthread_mutex_init(&write_keys, NULL);
	pthread_mutex_init(&write_random, NULL);
	pthread_mutex_init(&BSGS_thread, NULL);
	srand(time(NULL));
	secp = new Secp256K1();
	secp->Init();
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
	int_randominit();
}

void show_help() {
	printf("\nkeyhunt - BSGS Private Key Recovery\n");
	printf("=====================================\n\n");
	printf("Usage: ./keyhunt [options]\n\n");
	printf("Required (one of):\n");
	printf("  -f <file>      File containing public keys (hex 33/65 bytes)\n");
	printf("  -P <pubkey>    Single public key\n\n");
	printf("Range Options:\n");
	printf("  -r <start:end> Private key range in hex\n");
	printf("                 Example: -r 1:FFFFFFFF\n\n");
	printf("Performance Options:\n");
	printf("  -t <N>         Number of threads (default: 1)\n");
	printf("  -k <factor>    K-factor to increase M size (default: 1)\n\n");
	printf("Examples:\n");
	printf("  ./keyhunt -f addresses.txt -r 1:1000000 -t 4\n");
	printf("  ./keyhunt -P 02abc123... -r 800000:FFFFFFFF -t 8 -k 2\n\n");
	printf("Note: BSGS mode is enabled by default\n");
}

static void ArgParser(int argc, char **argv, char **fileName) {
	int c;
	Tokenizer t;

	if (argc == 1) {
		show_help();
		exit(EXIT_FAILURE);
	}

	SafeBloom = 1;
	FLAGSKIPCHECKSUM = 0;
	FLAGFILE = 0;
	USEPUBKEY = 0;
	KFACTOR = 1;
	NTHREADS = 1;
	RangeMin = NULL;
	RangeMax = NULL;

	while ((c = getopt(argc, argv, "r:f:t:k:P:h")) != -1) {
		switch(c) {
			case 'r':
			if(optarg != NULL) {
				stringtokenizer(optarg, &t);
				if(t.n == 2) {
					char *RangeMin_local = nextToken(&t);
					char *RangeMax_local = nextToken(&t);
					if(isValidHex(RangeMin_local) && isValidHex(RangeMax_local)) {
						RangeMin = strdup(RangeMin_local);
						RangeMax = strdup(RangeMax_local);
					} else {
						fprintf(stderr, "[E] Invalid hex string in range\n");
						exit(EXIT_FAILURE);
					}
				} else {
					fprintf(stderr, "[E] Range format should be: start:end (in hex)\n");
					fprintf(stderr, "[E] Example: -r 0:100000000000000\n");
					exit(EXIT_FAILURE);
				}
			}
			break;

			case 'f':
			FLAGFILE = 1;
			*fileName = optarg;
			break;

			case 't':
			NTHREADS = strtol(optarg, NULL, 10);
			if(NTHREADS <= 0) NTHREADS = 1;
			break;

			case 'k':
			KFACTOR = (int)strtol(optarg, NULL, 10);
			if(KFACTOR <= 0) KFACTOR = 1;
			break;

			case 'P':
			USEPUBKEY = 1;
			strncpy(PUBKEYARG, optarg, sizeof(PUBKEYARG)-1);
			PUBKEYARG[sizeof(PUBKEYARG)-1] = 0;
			break;

			case 'h':
			show_help();
			exit(EXIT_SUCCESS);
			break;

			default:
			fprintf(stderr, "[E] Unknown option -%c\n", c);
			fprintf(stderr, "Use -h for help\n");
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (!FLAGFILE && !USEPUBKEY) {
		fprintf(stderr, "[E] Error: Either -f <file> or -P <pubkey> must be specified\n");
		fprintf(stderr, "Use -h for help\n");
		exit(EXIT_FAILURE);
	}
}

static void InitRange() {
	n_RangeMin.SetBase16(RangeMin);
	if(n_RangeMin.IsZero()) n_RangeMin.AddOne();
	n_RangeMax.SetBase16(RangeMax);
	if(n_RangeMin.IsEqual(&n_RangeMax) == false) {
		if(n_RangeMin.IsLower(&secp->order) && n_RangeMax.IsLowerOrEqual(&secp->order)) {
			if(n_RangeMin.IsGreater(&n_RangeMax)) {
				fprintf(stderr, "[W] Opps, start range can't be great than end range. Swapping them\n");
				n_range_aux.Set(&n_RangeMin);
				n_RangeMin.Set(&n_RangeMax);
				n_RangeMax.Set(&n_range_aux);
			}
			n_range_diff.Set(&n_RangeMax);
			n_range_diff.Sub(&n_RangeMin);
		}
		else {
			fprintf(stderr, "[E] Start and End range can't be great than N\nFallback to random mode!\n");

		}
	} else {
		fprintf(stderr, "[E] Start and End range can't be the same\nFallback to random mode!\n");
	}

}

static void CalcBsgsTable() {
	char *hextemp = NULL;
	uint64_t itemsbloom,
	itemsbloom2,
	itemsbloom3;
	int i;

	BSGS_N.SetInt32(0);
	BSGS_M.SetInt32(0);
	BSGS_M.SetInt64(BSGS_m);
	BSGS_N.SetInt64((uint64_t)0x100000000000);


	if(BSGS_N.HasSqrt()) {
		BSGS_M.Set(&BSGS_N);
		BSGS_M.ModSqrt();
	} else {
		fprintf(stderr, "[E] -n param doesn't have exact square root\n");
		exit(EXIT_FAILURE);
	}

	BSGS_AUX.Set(&BSGS_M);
	BSGS_AUX.Mod(&BSGS_GROUP_SIZE);

	if(!BSGS_AUX.IsZero()) {
		hextemp = BSGS_GROUP_SIZE.GetBase10();
		fprintf(stderr, "[E] M value is not divisible by %s\n", hextemp);
		exit(EXIT_FAILURE);
	}

	BSGS_m = BSGS_M.GetInt64();
	BSGS_CURRENT.Set(&n_RangeMin);
	BSGS_M.Mult((uint64_t)KFACTOR);
	BSGS_AUX.SetInt32(32);
	BSGS_R.Set(&BSGS_M);
	BSGS_R.Mod(&BSGS_AUX);
	BSGS_M2.Set(&BSGS_M);
	BSGS_M2.Div(&BSGS_AUX);

	if(!BSGS_R.IsZero()) BSGS_M2.AddOne();

	BSGS_M_double.SetInt32(2);
	BSGS_M_double.Mult(&BSGS_M);
	BSGS_M2_double.SetInt32(2);
	BSGS_M2_double.Mult(&BSGS_M2);

	BSGS_R.Set(&BSGS_M2);
	BSGS_R.Mod(&BSGS_AUX);
	BSGS_M3.Set(&BSGS_M2);
	BSGS_M3.Div(&BSGS_AUX);

	if(!BSGS_R.IsZero()) BSGS_M3.AddOne();

	BSGS_M3_double.SetInt32(2);
	BSGS_M3_double.Mult(&BSGS_M3);

	BSGS_m2 = BSGS_M2.GetInt64();
	BSGS_m3 = BSGS_M3.GetInt64();

	BSGS_AUX.Set(&BSGS_N);
	BSGS_AUX.Div(&BSGS_M);
	BSGS_R.Set(&BSGS_N);
	BSGS_R.Mod(&BSGS_M);

	if(!BSGS_R.IsZero()) BSGS_N.Set(&BSGS_M);
	BSGS_N.Mult(&BSGS_AUX);

	BSGS_m = BSGS_M.GetInt64();
	BSGS_aux = BSGS_AUX.GetInt64();

	BSGS_N_double.SetInt32(2);
	BSGS_N_double.Mult(&BSGS_N);

	hextemp = BSGS_N.GetBase16();
	free(hextemp);

	if(((uint64_t)(BSGS_m/256)) > 10000) {
		itemsbloom = (uint64_t)(BSGS_m / 256);
		if(BSGS_m % 256 != 0) itemsbloom++;
	} else itemsbloom = 1000;

	if(((uint64_t)(BSGS_m2/256)) > 1000) {
		itemsbloom2 = (uint64_t)(BSGS_m2 / 256);
		if(BSGS_m2 % 256 != 0) itemsbloom2++;
	} else itemsbloom2 = 1000;

	if(((uint64_t)(BSGS_m3/256)) > 1000) {
		itemsbloom3 = (uint64_t)(BSGS_m3/256);
		if(BSGS_m3 % 256 != 0) itemsbloom3++;
	} else itemsbloom3 = 1000;

	bloom_bP = (struct bloom*)calloc(256, sizeof(struct bloom));
	checkpointer((void *)bloom_bP, __FILE__, "calloc", "bloom_bP", __LINE__ -1);
	bloom_bP_checksums = (struct checksumsha256*)calloc(256, sizeof(struct checksumsha256));
	checkpointer((void *)bloom_bP_checksums, __FILE__, "calloc", "bloom_bP_checksums", __LINE__ -1);
	bloom_bP_mutex = (pthread_mutex_t*) calloc(256, sizeof(pthread_mutex_t));
	checkpointer((void *)bloom_bP_mutex, __FILE__, "calloc", "bloom_bP_mutex", __LINE__ -1);
	fflush(stdout);
	bloom_bP_totalbytes = 0;
	for(i = 0; i < 256; i++) {
		pthread_mutex_init(&bloom_bP_mutex[i], NULL);
		if(bloom_init2(&bloom_bP[i], itemsbloom, 0.001) == 1) {
			fprintf(stderr, "[E] error bloom_init _ [%i]\n", i);
			exit(EXIT_FAILURE);
		}
		bloom_bP_totalbytes += bloom_bP[i].bytes;
	}

	bloom_bPx2nd_mutex = (pthread_mutex_t*) calloc(256, sizeof(pthread_mutex_t));
	checkpointer((void *)bloom_bPx2nd_mutex, __FILE__, "calloc", "bloom_bPx2nd_mutex", __LINE__ -1);
	bloom_bPx2nd = (struct bloom*)calloc(256, sizeof(struct bloom));
	checkpointer((void *)bloom_bPx2nd, __FILE__, "calloc", "bloom_bPx2nd", __LINE__ -1);
	bloom_bPx2nd_checksums = (struct checksumsha256*) calloc(256, sizeof(struct checksumsha256));
	checkpointer((void *)bloom_bPx2nd_checksums, __FILE__, "calloc", "bloom_bPx2nd_checksums", __LINE__ -1);
	bloom_bP2_totalbytes = 0;
	for(i = 0; i < 256; i++) {
		pthread_mutex_init(&bloom_bPx2nd_mutex[i], NULL);
		if(bloom_init2(&bloom_bPx2nd[i], itemsbloom2, 0.001) == 1) {
			fprintf(stderr, "[E] error bloom_init _ [%i]\n", i);
			exit(EXIT_FAILURE);
		}
		bloom_bP2_totalbytes += bloom_bPx2nd[i].bytes;
	}

	bloom_bPx3rd_mutex = (pthread_mutex_t*) calloc(256, sizeof(pthread_mutex_t));
	checkpointer((void *)bloom_bPx3rd_mutex, __FILE__, "calloc", "bloom_bPx3rd_mutex", __LINE__ -1);
	bloom_bPx3rd = (struct bloom*)calloc(256, sizeof(struct bloom));
	checkpointer((void *)bloom_bPx3rd, __FILE__, "calloc", "bloom_bPx3rd", __LINE__ -1);
	bloom_bPx3rd_checksums = (struct checksumsha256*) calloc(256, sizeof(struct checksumsha256));
	checkpointer((void *)bloom_bPx3rd_checksums, __FILE__, "calloc", "bloom_bPx3rd_checksums", __LINE__ -1);
	bloom_bP3_totalbytes = 0;
	for(i = 0; i < 256; i++) {
		pthread_mutex_init(&bloom_bPx3rd_mutex[i], NULL);
		if(bloom_init2(&bloom_bPx3rd[i], itemsbloom3, 0.001) == 1) {
			fprintf(stderr, "[E] error bloom_init [%i]\n", i);
			exit(EXIT_FAILURE);
		}
		bloom_bP3_totalbytes += bloom_bPx3rd[i].bytes;
	}

	BSGS_MP = secp->ComputePublicKey(&BSGS_M);
	BSGS_MP_double = secp->ComputePublicKey(&BSGS_M_double);
	BSGS_MP2 = secp->ComputePublicKey(&BSGS_M2);
	BSGS_MP2_double = secp->ComputePublicKey(&BSGS_M2_double);
	BSGS_MP3 = secp->ComputePublicKey(&BSGS_M3);
	BSGS_MP3_double = secp->ComputePublicKey(&BSGS_M3_double);

	Point bsP = secp->Negation(BSGS_MP_double);
	Point g = bsP;
	GSn.resize(CPU_GRP_SIZE/2, g);
	BSGS_AMP2.resize(32, g);
	BSGS_AMP3.resize(32, g);

	GSn[0] = g;
	g = secp->DoubleDirect(g);
	GSn[1] = g;
	for(int j = 2; j < CPU_GRP_SIZE / 2; j++) {
		g = secp->AddDirect(g, bsP);
		GSn[j] = g;
	}

	_2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);

	Point point_temp;
	point_temp.Set(BSGS_MP2);
	BSGS_AMP2[0] = secp->Negation(point_temp);
	BSGS_AMP2[0].Reduce();
	point_temp.Set(BSGS_MP2_double);
	point_temp = secp->Negation(point_temp);
	point_temp.Reduce();
	for(i = 1; i < 32; i++) {
		BSGS_AMP2[i] = secp->AddDirect(BSGS_AMP2[i-1], point_temp);
		BSGS_AMP2[i].Reduce();
	}

	point_temp.Set(BSGS_MP3);
	BSGS_AMP3[0] = secp->Negation(point_temp);
	BSGS_AMP3[0].Reduce();
	point_temp.Set(BSGS_MP3_double);
	point_temp = secp->Negation(point_temp);
	point_temp.Reduce();
	for(i = 1; i < 32; i++) {
		BSGS_AMP3[i] = secp->AddDirect(BSGS_AMP3[i-1], point_temp);
		BSGS_AMP3[i].Reduce();
	}

	bytes = (uint64_t)BSGS_m3 * (uint64_t) sizeof(struct BSGS_xvalue);
	bPtable = (struct BSGS_xvalue*) malloc(bytes);
	checkpointer((void *)bPtable, __FILE__, "malloc", "bPtable", __LINE__ -1);
	memset(bPtable, 0, bytes);
}

static int LoadBloom(const char* filename, struct bloom* blooms, struct checksumsha256* checksums, int file_version) {
	FILE* fd = fopen(filename, "rb");
	if (fd == NULL) return 0;

	char rawvalue[32];
	char* bf_ptr = NULL;

	for (int i = 0; i < 256; i++) {
		bf_ptr = (char*) blooms[i].bf;

		if (file_version == 3) {
			struct oldbloom oldbloom;
			if (fread(&oldbloom, sizeof(struct oldbloom), 1, fd) != 1) {
				fclose(fd);
				return 0;
			}
			memcpy(&blooms[i], &oldbloom, sizeof(struct bloom));
			blooms[i].bf = (uint8_t*)bf_ptr;

			if (fread(blooms[i].bf, blooms[i].bytes, 1, fd) != 1) {
				fclose(fd);
				return 0;
			}

			memcpy(checksums[i].data, oldbloom.checksum, 32);
			memcpy(checksums[i].backup, oldbloom.checksum_backup, 32);
		} else {
			if (fread(&blooms[i], sizeof(struct bloom), 1, fd) != 1) {
				fclose(fd);
				return 0;
			}
			blooms[i].bf = (uint8_t*)bf_ptr;

			if (fread(blooms[i].bf, blooms[i].bytes, 1, fd) != 1) {
				fclose(fd);
				return 0;
			}

			if (fread(&checksums[i], sizeof(struct checksumsha256), 1, fd) != 1) {
				fclose(fd);
				return 0;
			}
		}

		if (FLAGSKIPCHECKSUM == 0) {
			sha256((uint8_t*)blooms[i].bf, blooms[i].bytes, (uint8_t*)rawvalue);
			if (memcmp(checksums[i].data, rawvalue, 32) != 0 ||
				memcmp(checksums[i].backup, rawvalue, 32) != 0) {
				fclose(fd);
				return 0;
			}
		}

		if (i % 64 == 0) fflush(stdout);
	}

	fclose(fd);
	return 1;
}

static int LoadTable(const char* filename) {
	FILE* fd = fopen(filename, "rb");
	if (fd == NULL) return 0;

	if (fread(bPtable, bytes, 1, fd) != 1) {
		fclose(fd);
		return 0;
	}

	if (fread(checksum, 32, 1, fd) != 1) {
		fclose(fd);
		return 0;
	}

	if (FLAGSKIPCHECKSUM == 0) {
		sha256((uint8_t*)bPtable, bytes, (uint8_t*)checksum_backup);
		if (memcmp(checksum, checksum_backup, 32) != 0) {
			fclose(fd);
			return 0;
		}
	}

	fclose(fd);
	return 1;
}

static void CheckBloom(uint64_t BSGS_m, uint64_t BSGS_m2) {
	char filename[1024];

	snprintf(filename, sizeof(filename), "BabyBloom_3_%" PRIu64 ".blm", BSGS_m);
	FILE* fd = fopen(filename, "rb");
	if (fd != NULL) {
		printf("[W] Unused file detected %s you can delete it without worry\n", filename);
		fclose(fd);
	}

	memset(filename, 0, sizeof(filename));
	snprintf(filename, sizeof(filename), "BabyBloom_5_%" PRIu64 ".blm", BSGS_m2);
	fd = fopen(filename, "rb");
	if (fd != NULL) {
		printf("[W] Unused file detected %s you can delete it without worry\n", filename);
		fclose(fd);
	}

	memset(filename, 0, sizeof(filename));
	snprintf(filename, sizeof(filename), "BabyBloom_1_%" PRIu64 ".blm", BSGS_m2);
	fd = fopen(filename, "rb");
	if (fd != NULL) {
		printf("[W] Unused file detected %s you can delete it without worry\n", filename);
		fclose(fd);
	}
}

static void CalcChecksum() {
	printf("[+] Making checksums .. ");
	fflush(stdout);

	for (int i = 0; i < 256; i++) {
		if (!ReadBloom1) {
			sha256((uint8_t*)bloom_bP[i].bf, bloom_bP[i].bytes, (uint8_t*)bloom_bP_checksums[i].data);
			memcpy(bloom_bP_checksums[i].backup, bloom_bP_checksums[i].data, 32);
		}

		if (!ReadBloom2) {
			sha256((uint8_t*)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, (uint8_t*)bloom_bPx2nd_checksums[i].data);
			memcpy(bloom_bPx2nd_checksums[i].backup, bloom_bPx2nd_checksums[i].data, 32);
		}

		if (!ReadBloom4) {
			sha256((uint8_t*)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, (uint8_t*)bloom_bPx3rd_checksums[i].data);
			memcpy(bloom_bPx3rd_checksums[i].backup, bloom_bPx3rd_checksums[i].data, 32);
		}
	}
}

static void SortTable() {
	if (!ReadBloom3) {
		printf("[+] Sorting %lu elements... ", BSGS_m3);
		fflush(stdout);
		SortBSGSTable(bPtable, BSGS_m3);
		sha256((uint8_t*)bPtable, bytes, (uint8_t*)checksum);
		memcpy(checksum_backup, checksum, 32);
		fflush(stdout);
	}
}

static void SaveBloom(const char* filename, struct bloom* blooms, struct checksumsha256* checksums) {
	FILE* fd = fopen(filename, "wb");
	if (fd == NULL) {
		fprintf(stderr, "[E] Error can't create the file %s\n", filename);
		exit(EXIT_FAILURE);
	}

	printf("[+] Writing bloom filter to file %s ", filename);
	fflush(stdout);

	for (int i = 0; i < 256; i++) {
		if (fwrite(&blooms[i], sizeof(struct bloom), 1, fd) != 1 ||
			fwrite(blooms[i].bf, blooms[i].bytes, 1, fd) != 1 ||
			fwrite(&checksums[i], sizeof(struct checksumsha256), 1, fd) != 1) {
			fprintf(stderr, "[E] Error writing the file %s\n", filename);
			fclose(fd);
			exit(EXIT_FAILURE);
		}

		if (i % 64 == 0) fflush(stdout);
	}

	fclose(fd);
}

static void SaveTable(const char* filename) {
	FILE* fd = fopen(filename, "wb");
	if (fd == NULL) {
		fprintf(stderr, "[E] Error can't create the file %s\n", filename);
		exit(EXIT_FAILURE);
	}

	printf("[+] Writing bP Table to file %s .. ", filename);
	fflush(stdout);

	if (fwrite(bPtable, bytes, 1, fd) != 1 ||
		fwrite(checksum, 32, 1, fd) != 1) {
		fprintf(stderr, "[E] Error writing the file %s\n", filename);
		fclose(fd);
		exit(EXIT_FAILURE);
	}

	fclose(fd);
}

static void PointGenerator(int mode, uint64_t total_points) {
	uint64_t BASE,
	PERTHREAD_R;
	uint32_t finished;
	int i,
	salir;
	int s = 0;

	uint64_t THREADCYCLES = 0;
	uint64_t THREADCOUNTER = 0;
	uint64_t FINISHED_ITEMS = 0;
	uint64_t OLDFINISHED_ITEMS = 0;

	FINISHED_THREADS_COUNTER = 0;
	FINISHED_THREADS_BP = 0;
	salir = 0;
	BASE = 0;

	if (THREADBPWORKLOAD >= total_points) THREADBPWORKLOAD = total_points;

	THREADCYCLES = total_points / THREADBPWORKLOAD;
	PERTHREAD_R = total_points % THREADBPWORKLOAD;
	if (PERTHREAD_R != 0) THREADCYCLES++;

	printf("\r[+] processing bP points\r");
	fflush(stdout);

	tid = (pthread_t *) calloc(NTHREADS, sizeof(pthread_t));
	bPload_mutex = (pthread_mutex_t*) calloc(NTHREADS, sizeof(pthread_mutex_t));
	struct bPload* bPload_temp_ptr = (struct bPload*) calloc(NTHREADS, sizeof(struct bPload));
	char* bPload_threads_available = (char*) calloc(NTHREADS, sizeof(char));

	checkpointer((void *)tid, __FILE__, "calloc", "tid", __LINE__ -1);
	checkpointer((void *)bPload_mutex, __FILE__, "calloc", "bPload_mutex", __LINE__ -1);
	checkpointer((void *)bPload_temp_ptr, __FILE__, "calloc", "bPload_temp_ptr", __LINE__ -1);
	checkpointer((void *)bPload_threads_available, __FILE__, "calloc", "bPload_threads_available", __LINE__ -1);

	memset(bPload_threads_available, 1, NTHREADS);

	for (i = 0; i < NTHREADS; i++) pthread_mutex_init(&bPload_mutex[i], NULL);

	THREADCOUNTER = 0;
	do {
		for (i = 0; i < NTHREADS && !salir; i++) {
			if (bPload_threads_available[i] && !salir) {
				bPload_threads_available[i] = 0;
				bPload_temp_ptr[i].from = BASE;
				bPload_temp_ptr[i].threadid = i;
				bPload_temp_ptr[i].finished = 0;

				if (THREADCOUNTER < THREADCYCLES - 1) {
					bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD;
					bPload_temp_ptr[i].workload = THREADBPWORKLOAD;
				} else {
					bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
					bPload_temp_ptr[i].workload = THREADBPWORKLOAD + PERTHREAD_R;
					salir = 1;
				}

				if (mode == 1) s = pthread_create(&tid[i], NULL, thread_bPload, (void*) &bPload_temp_ptr[i]);
				else s = pthread_create(&tid[i], NULL, thread_bPload_2blooms, (void*) &bPload_temp_ptr[i]);
				pthread_detach(tid[i]);
				if (s != 0) {
					fprintf(stderr, "[E] Failed to create bPload thread %d\n", i);
				}
				BASE += THREADBPWORKLOAD;
				THREADCOUNTER++;
			}
		}


		if (OLDFINISHED_ITEMS != FINISHED_ITEMS) {
			printf("\r[+] processing bP points %lu/%lu (%d%%)",
				FINISHED_ITEMS, total_points,
				(int)(((double)FINISHED_ITEMS/(double)total_points)*100));
			fflush(stdout);
			OLDFINISHED_ITEMS = FINISHED_ITEMS;
		}

		for (i = 0; i < NTHREADS; i++) {
			pthread_mutex_lock(&bPload_mutex[i]);
			finished = bPload_temp_ptr[i].finished;
			pthread_mutex_unlock(&bPload_mutex[i]);

			if (finished) {
				bPload_temp_ptr[i].finished = 0;
				bPload_threads_available[i] = 1;
				FINISHED_THREADS_COUNTER++;
				FINISHED_ITEMS += bPload_temp_ptr[i].workload;
			}
		}
	} while (FINISHED_THREADS_COUNTER < THREADCYCLES);

	printf("\r[+] processing bP points : Done\n");

	free(tid);
	free(bPload_mutex);
	free(bPload_temp_ptr);
	free(bPload_threads_available);
}
static void ProcessBloom() {
	char buffer_bloom_file[1024];

	if (SafeBloom) {
		snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
			"BabyBloom_4_%" PRIu64 ".blm", BSGS_m);
		ReadBloom1 = LoadBloom(buffer_bloom_file, bloom_bP, bloom_bP_checksums, 4);

		if (!ReadBloom1) {
			snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
				"BabyBloom_3_%" PRIu64 ".blm", BSGS_m);
			ReadBloom1 = LoadBloom(buffer_bloom_file, bloom_bP, bloom_bP_checksums, 3);
			if (ReadBloom1) UpdateBloom = 1;
		}

		snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
			"BabyBloom_6_%" PRIu64 ".blm", BSGS_m2);
		ReadBloom2 = LoadBloom(buffer_bloom_file, bloom_bPx2nd, bloom_bPx2nd_checksums, 4);

		snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
			"BabyBloom_2_%" PRIu64 ".tbl", BSGS_m3);
		ReadBloom3 = LoadTable(buffer_bloom_file);

		snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
			"BabyBloom_7_%" PRIu64 ".blm", BSGS_m3);
		ReadBloom4 = LoadBloom(buffer_bloom_file, bloom_bPx3rd, bloom_bPx3rd_checksums, 4);

		CheckBloom(BSGS_m, BSGS_m2);
	}

	if (!ReadBloom1 || !ReadBloom2 || !ReadBloom3 || !ReadBloom4) {
		if (ReadBloom1 == 1) {
			printf("[I] We need to recalculate some files, don't worry this is only 3%% of the previous work\n");
			PointGenerator(2, BSGS_m2);
		} else {
			PointGenerator(1, BSGS_m);
		}
	}

	if (!ReadBloom1 || !ReadBloom2 || !ReadBloom4) CalcChecksum();
	SortTable();

	if (SafeBloom || UpdateBloom) {
		if (!ReadBloom1 || UpdateBloom) {
			snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
				"BabyBloom_4_%" PRIu64 ".blm", BSGS_m);
			if (UpdateBloom) printf("[W] Updating old file into a new one\n");
			SaveBloom(buffer_bloom_file, bloom_bP, bloom_bP_checksums);
		}

		if (!ReadBloom2) {
			snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
				"BabyBloom_6_%" PRIu64 ".blm", BSGS_m2);
			SaveBloom(buffer_bloom_file, bloom_bPx2nd, bloom_bPx2nd_checksums);
		}

		if (!ReadBloom3) {
			snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
				"BabyBloom_2_%" PRIu64 ".tbl", BSGS_m3);
			SaveTable(buffer_bloom_file);
		}

		if (!ReadBloom4) {
			snprintf(buffer_bloom_file, sizeof(buffer_bloom_file),
				"BabyBloom_7_%" PRIu64 ".blm", BSGS_m3);
			SaveBloom(buffer_bloom_file, bloom_bPx3rd, bloom_bPx3rd_checksums);
		}
	}
}

static void ThreadManager() {
	int i,
	s;
	struct tothread *tt;

	tid = (pthread_t *) calloc(NTHREADS, sizeof(pthread_t));
	checkpointer((void *)tid, __FILE__, "calloc", "tid", __LINE__ -1);

	for (i = 0; i < NTHREADS; i++) {
		tt = (tothread *) malloc(sizeof(struct tothread));
		checkpointer((void *)tt, __FILE__, "malloc", "tothread", __LINE__ -1);

		tt->nt = i;
		tt->RangeMin.Set(&n_RangeMin);
		tt->RangeMax.Set(&n_RangeMax);

		s = pthread_create(&tid[i], NULL, thread_BSGS, (void *)tt);

		if (s != 0) {
			fprintf(stderr, "[E] pthread_create failed for thread %d\n", i);
			exit(EXIT_FAILURE);
		}
	}
}

static bool is_directory(const char *path) {
	struct stat st;
	if (stat(path, &st) != 0) return false;
	return S_ISDIR(st.st_mode);
}

void load_pubkeys_from_file(const char *fileName) {
	int fd = open(fileName, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "[E] Can't open %s\n", fileName);
		exit(EXIT_FAILURE);
	}

	struct stat st;
	fstat(fd, &st);
	size_t fsize = st.st_size;

	if (fsize == 0) {
		fprintf(stderr, "[E] File %s is empty\n", fileName);
		exit(EXIT_FAILURE);
	}

	char *mem = (char*)mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		fprintf(stderr, "[E] mmap failed\n");
		exit(EXIT_FAILURE);
	}
	close(fd);

	std::vector < std::string > lines;
	lines.reserve(500000);

	char *p = mem;
	char *end = mem + fsize;

	while (p < end) {
		char *line_start = p;

		while (p < end && *p != '\n' && *p != '\r') p++;

		size_t len = p - line_start;
		if (len == 0) {
			p++;
			continue;
		}

		const char *raw = line_start;

		while (len > 0 && (*raw == ' ' || *raw == '\t')) {
			raw++;
			len--;
		}
		if (len == 0) {
			p++;
			continue;
		}

		const char *hex = raw;
		size_t hex_len = len;

		const char *pipe = (const char*)memchr(raw, '|', len);
		if (pipe) hex_len = pipe - raw;
		else {
			const char *kpos = (const char*)memmem(raw, len, "PUBKEY=", 7);
			if (kpos) {
				hex = kpos + 7;
				hex_len = len - (hex - raw);
			}
		}

		while (hex_len > 0 && (hex[hex_len - 1] == ' ' || hex[hex_len - 1] == '\t')) hex_len--;

		if (hex_len == 66 || hex_len == 130) lines.emplace_back(std::string(hex, hex_len));
		p++;
	}

	munmap(mem, fsize);

	int N = lines.size();
	if (N == 0) {
		fprintf(stderr, "[E] No valid pubkeys found in %s\n", fileName);
		exit(EXIT_FAILURE);
	}

	if (BSGS_found) free(BSGS_found);
	if (BSGSCompPoint) free(BSGSCompPoint);

	BSGS_found = (int*)calloc(N, sizeof(int));
	checkpointer((void*)BSGS_found, __FILE__, "calloc", "BSGS_found", __LINE__);

	BSGSPoint.clear();
	BSGSPoint.resize(N, secp->G);

	BSGSCompPoint = (bool*)malloc(N * sizeof(bool));
	checkpointer((void*)BSGSCompPoint, __FILE__, "malloc", "BSGSCompPoint", __LINE__);

	unsigned int nthreads = std::thread::hardware_concurrency();
	if (nthreads == 0) nthreads = 8;

	std::atomic < int > index(0);
	std::vector < std::thread > workers;
	workers.reserve(nthreads);

	auto worker = [&](int) {
		while (true) {
			int idx = index.fetch_add(1);
			if (idx >= N) break;

			char tempbuf[140];
			strncpy(tempbuf, lines[idx].c_str(), sizeof(tempbuf) - 1);
			tempbuf[sizeof(tempbuf) - 1] = '\0';

			secp->ParsePublicKeyHex(tempbuf, BSGSPoint[idx], BSGSCompPoint[idx]);
		}
	};
	for (unsigned int t = 0; t < nthreads; t++) workers.emplace_back(worker, t);
	for (auto &t: workers) t.join();
	PubkeyNumber = N;

	printf("\033[1;32m[+] Loaded %s | %d pubkeys (%.1f MB) parsed using %u threads.\033[0m\n",
		fileName, N, (double)fsize / 1024 / 1024, nthreads);
	fflush(stdout);

}

bool LoadPub(const char *fileName) {
	if (USEPUBKEY) {
		if (BSGS_found) free(BSGS_found);
		if (BSGSCompPoint) free(BSGSCompPoint);
		BSGSPoint.clear();
		PubkeyNumber = 1;
		BSGS_found = (int*)calloc(1, sizeof(int));
		checkpointer(BSGS_found, __FILE__, "calloc", "BSGS_found", __LINE__);
		BSGSPoint.resize(1, secp->G);
		BSGSCompPoint = (bool*)malloc(sizeof(bool));
		checkpointer(BSGSCompPoint, __FILE__, "malloc", "BSGSCompPoint", __LINE__);
		bool ok = secp->ParsePublicKeyHex(PUBKEYARG, BSGSPoint[0], BSGSCompPoint[0]);

		if (!ok) {
			fprintf(stderr, "[E] Invalid pubkey format: %s\n", PUBKEYARG);
			return false;
		}

		printf("\033[1;32m[+] Using pubkey from -P: %s\033[0m\n", PUBKEYARG);
		fflush(stdout);
		return true;
	}
	load_pubkeys_from_file(fileName);
	if (PubkeyNumber == 0) {
		fprintf(stderr, "[E] No pubkeys loaded from %s\n", fileName);
		return false;
	}

	printf("[+] Parsed %d pubkeys from %s\n", PubkeyNumber, fileName);
	fflush(stdout);
	return true;
}

static bool UseFiles(const char *fileName) {
	printf("\n\033[1;36m[+] Processing pubkey file: %s\033[0m\n", fileName);
	fflush(stdout);

	struct timeval start_time,
	end_time;
	gettimeofday(&start_time, NULL);

	if (!LoadPub(fileName)) {
		printf("[W] Skipped: %s\n", fileName);
		return false;
	}

	BSGS_CURRENT.Set(&n_RangeMin);
	RANGE_CURSOR.Set(&n_RangeMin);

	ThreadManager();

	if (tid != NULL) {
		for (int i = 0; i < NTHREADS; i++) pthread_join(tid[i], NULL);
		free(tid);
		tid = NULL;
	}

	gettimeofday(&end_time, NULL);
	double elapsed = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) * 1e-6;
	int hours = (int)(elapsed / 3600);
	int minutes = (int)((elapsed - hours * 3600) / 60);
	int seconds = (int)(elapsed - hours * 3600 - minutes * 60);

	printf("\r\033[1;32m[√] %s: %02d:%02d:%02d | Pubkeys: %d\033[0m\n", fileName, hours, minutes, seconds, PubkeyNumber);
	return true;
}

static void UseFolders(const char *folder) {
	DIR *dir = opendir(folder);
	if (!dir) {
		fprintf(stderr, "[E] Can't open folder %s\n", folder);
		exit(1);
	}

	struct dirent *ent;
	std::vector < std::string > files;

	while ((ent = readdir(dir)) != NULL) {
		if (ent->d_name[0] == '.') continue;
		std::string name = ent->d_name;
		if (name.size() > 4 && name.substr(name.size() - 4) == ".txt") files.push_back(name);
	}
	closedir(dir);

	if (files.empty()) {
		printf("[W] Folder %s tidak berisi file .txt\n", folder);
		return;
	}

	std::sort(files.begin(), files.end(),
		[](const std::string &a, const std::string &b) {
			auto getnum = [&](const std::string &s) {
				size_t pos = s.find_first_of("0123456789");
				return (pos == std::string::npos) ? 0: atoi(s.c_str() + pos);
			};
			return getnum(a) < getnum(b);
		}
	);

	printf("\n\033[1;35m[FOLDER SCAN] Found %zu pubkey files in folder %s\033[0m\n\n", files.size(), folder);
	fflush(stdout);

	size_t total = files.size();
	size_t processed = 0;
	struct timeval folder_start,
	folder_end;
	gettimeofday(&folder_start, NULL);
	double folder_start_seconds = folder_start.tv_sec + folder_start.tv_usec * 1e-6;

	for (auto &fname: files) {
		processed++;
		int barWidth = 50;
		float progress = (float)processed / (float)total;
		int pos = barWidth * progress;

		printf("\033[1;33m[Progress: %zu/%zu] ", processed, total);
		printf("[");
		for (int i = 0; i < barWidth; ++i) {
			if (i < pos) printf("=");
			else if (i == pos) printf(">");
			else printf(" ");
		}
		printf("] %.1f%%\033[0m\n", progress * 100.0);

		char fullpath[1024];
		snprintf(fullpath, sizeof(fullpath), "%s/%s", folder, fname.c_str());
		printf("\n\033[1;33m[ Batch %zu/%zu ] %s\033[0m\n", processed, total, fullpath);
		fflush(stdout);

		UseFiles(fullpath);
		printf("\033[1;34m---\033[0m\n\n");
	}

	gettimeofday(&folder_end, NULL);
	double folder_end_seconds = folder_end.tv_sec + folder_end.tv_usec * 1e-6;
	double folder_elapsed = folder_end_seconds - folder_start_seconds;

	int folder_hours = (int)(folder_elapsed / 3600);
	int folder_minutes = (int)((folder_elapsed - folder_hours * 3600) / 60);
	int folder_seconds = (int)(folder_elapsed - folder_hours * 3600 - folder_minutes * 60);

	printf("\n\033[1;32m═══════════════════════════════════════════\033[0m\n");
	printf("\033[1;32m[√] SELESAI SEMUA FILE DALAM FOLDER!\033[0m\n");
	printf("\033[1;32m═══════════════════════════════════════════\033[0m\n");
	printf("    Total file diproses: %zu\n", total);
	printf("    Waktu total folder: %02d:%02d:%02d\n", folder_hours, folder_minutes, folder_seconds);
	printf("    (%.0f detik)\n", folder_elapsed);

	if (total > 0) {
		double avg_time = folder_elapsed / total;
		printf("    Rata-rata per file: %.2f detik\n", avg_time);
	}

	printf("\033[1;32m═══════════════════════════════════════════\033[0m\n\n");
	fflush(stdout);
}




int main(int argc, char **argv) {
	char *path = NULL;
	InitMutexSecp();
	ArgParser(argc, argv, &path);
	init_generator();
	if (FLAGFILE == 0) path = (char*) default_fileName;
	InitRange();
	CalcBsgsTable();
	ProcessBloom();
	if (!path) {
		fprintf(stderr, "[E] No file or folder specified\n");
		return 1;
	}
	if (is_directory(path)) UseFolders(path);
	else UseFiles(path);
	printf("\n\033[1;32m[+] SELESAI !\033[0m\n");
	return 0;
}