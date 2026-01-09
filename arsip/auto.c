#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <math.h>
#include <stdint.h>
#include <limits.h>
#include <regex.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <gmp.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <dirent.h>

#define CLR_RED     "\033[1;31m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_GRAY    "\033[2;37m"
#define CLR_RESET   "\033[0m"

typedef struct {
  char name[64];
  char start_hex[128];
  char end_hex[128];
  mpz_t index;
} range_ctx;

typedef struct {
  range_ctx *ranges;
  size_t total;
  FILE *fout;
  pthread_mutex_t *f_lock;
} worker_arg_t;

typedef struct {
  char *buf;
  size_t len;
  size_t cap;
} memout_t;

typedef struct {
  char PUBKEY_TARGET[80];
  char STEP_HEX[32];
  char PUBHASIL_PATH[128];
  char HASILPRIV_PATH[128];
  char KEYHUNT_CMD[512];
  int AutoNumberR;
  mpz_t SubrangeSize;
  int group_size;
  int digit_min;
  char RANGE_MIN_HEX[128];
  char RANGE_MAX_HEX[128];
  mpz_t Number_R;
  mpz_t max_pubkey_per_batch;
  int random_pure;
  unsigned long max_pubhasil_lines;
  mpz_t range_count;
  range_ctx *ranges;
} Config;

typedef struct {
  mpz_t range_min,
  range_max;
  mpz_t number_r,
  done_r,
  worker_r;
  mpz_t batch,
  multiplier;
} Checkpoint;

static pthread_mutex_t pre_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t global_log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t digit_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t range_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rn_lock = PTHREAD_MUTEX_INITIALIZER;
static secp256k1_context *CTX = NULL;
static gmp_randstate_t RNG_STATE;
static Config CFG;
static Checkpoint CP;
static mpz_t *RN_FULL = NULL;
static unsigned long RN_FULL_COUNT = 0;
static size_t GLOBAL_DIGIT_MAX = 0;
static int PRE_READY = 0;
static mpz_t PRE_MIN;
static mpz_t PRE_STEP;
static mpz_t STEP_MPZ;
static int STEP_MPZ_READY = 0;
static secp256k1_pubkey STEP_G;
static unsigned char STEP_PRIV[32];
static bool STEP_READY = false;
static unsigned char PUB_TARGET[33];
static secp256k1_pubkey PUB_TARGET_OBJ;
static unsigned long long PUB_LINE_COUNT = 0;
static int PUB_FILE_INDEX = 1;
static FILE *current_pub_file = NULL;
FILE* open_new_pubfile(void);

static mpz_t CURVE_ORDER;
static int CURVE_ORDER_READY = 0;

static int OVERRIDE_RN = 0;
static int OVERRIDE_ITER = 0;
static mpz_t *OVR_RN_LIST = NULL;
static mpz_t *OVR_ITER_LIST = NULL;
static unsigned long OVR_RN_COUNT = 0;
static unsigned long OVR_ITER_COUNT = 0;
static unsigned long OVR_RN_POS = 0;
static unsigned long OVR_ITER_POS = 0;

static pthread_once_t step_mpz_once = PTHREAD_ONCE_INIT;

typedef enum {
  LOG_INFO,
  LOG_WARN,
  LOG_ERROR,
  LOG_SUCCESS,
  LOG_DEBUG,
  LOG_SECTION
} log_level_t;

static volatile sig_atomic_t g_shutdown_requested = 0;
static volatile int g_threads_should_exit = 0;

static const char *color_for_level(log_level_t l) {
  switch(l) {
    case LOG_INFO: return CLR_CYAN;
    case LOG_WARN: return CLR_YELLOW;
    case LOG_ERROR: return CLR_RED;
    case LOG_SUCCESS: return CLR_GREEN;
    case LOG_DEBUG: return CLR_GRAY;
    case LOG_SECTION: return CLR_CYAN;
  }
  return CLR_RESET;
}

static void fmt_commas(char *out, size_t outsz, const mpz_t v) {
  char *raw = mpz_get_str(NULL, 10, v);
  int len = strlen(raw);
  int commas = (len - 1) / 3;
  int total = len + commas;
  if (total >= outsz) total = outsz - 1;
  int ri = len - 1;
  int oi = total - 1;
  int group = 0;
  while (oi >= 0 && ri >= 0) {
    out[oi--] = raw[ri--];
    if (++group == 3 && ri >= 0) {
      out[oi--] = ',';
      group = 0;
    }
  }
  out[total] = 0;
  free(raw);
}

static void log_msg(log_level_t level, const char *tag, const char *fmt, ...) {
  pthread_mutex_lock(&global_log_lock);
  const char *color = color_for_level(level);
  fprintf(stdout, "%s[ %-9s ] ", color, tag ? tag: "-");
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
  fprintf(stdout, "%s\n", CLR_RESET);
  pthread_mutex_unlock(&global_log_lock);
}

static void log_header(const char *title) {
  pthread_mutex_lock(&global_log_lock);
  fprintf(stdout, "\n\033[1;36m");
  fprintf(stdout,
    "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
  );
  fprintf(stdout,
    "┃  %-55s┃\n", title
  );
  fprintf(stdout,
    "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n"
  );
  fprintf(stdout, "\033[0m");
  pthread_mutex_unlock(&global_log_lock);
}

static void log_mpz(log_level_t lvl, const char*tag, const char*label, const mpz_t v) {
  char *s = mpz_get_str(NULL, 10, v);
  log_msg(lvl, tag, "%s=%s", label, s);
  free(s);
}

void log_progress_bar(double pct, unsigned long long done, unsigned long long total) {
  static const char *blocks[] = {
    " ",
    "▏",
    "▎",
    "▍",
    "▌",
    "▋",
    "▊",
    "▉",
    "█"
  };
  static int spin_idx = 0;
  static const char spinner[] = "|/-\\";
  const int width = 40;
  double ratio = pct / 100.0;
  double fblocks = ratio * width;
  int full = (int)fblocks;
  int partial_idx = (int)((fblocks - full) * 8);
  if (partial_idx > 8) partial_idx = 8;
  if (partial_idx < 0) partial_idx = 0;
  fprintf(stderr, "\r\033[K");
  fprintf(stderr, "\r[ PROGRESS  ] %c [", spinner[spin_idx]);
  spin_idx = (spin_idx + 1) & 3;
  fprintf(stderr, "\033[1;32m");
  for (int i = 0; i < full; i++)
  fprintf(stderr, "█");
  if (full < width)
  fprintf(stderr, "%s", blocks[partial_idx]);
  for (int i = full + 1; i < width; i++)
  fprintf(stderr, " ");
  fprintf(stderr, "\033[0m");
  fprintf(stderr, "] %6.2f%% (%llu/%llu)", pct, done, total);
  if (pct >= 100.0) {
    fprintf(stderr, "\n");
    fflush(stderr);
  }
}

static void trim(char *s) {
  char *p = s;
  while (*p && isspace((unsigned char)*p)) p++;
  memmove(s, p, strlen(p) + 1);
  for (int i = strlen(s) - 1; i >= 0 && isspace((unsigned char)s[i]); i--)
  s[i] = 0;
}

void clean_pubhasil_folder() {
  DIR *d = opendir("pubhasil");
  if (!d) return;
  struct dirent *dir;
  char path[512];
  struct stat st;
  while ((dir = readdir(d)) != NULL) {
    if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
    continue;
    snprintf(path, sizeof(path), "pubhasil/%s", dir->d_name);
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
      if (strstr(dir->d_name, ".txt")) {
        remove(path);
      }
    }
  }
  closedir(d);
}

static void parse_range_line(const char *line, mpz_t **out, unsigned long *count) {
  char buf[256];
  strcpy(buf, line);
  char *dash = strchr(buf, '-');
  if (!dash) {
    (*count)++;
    *out = realloc(*out, sizeof(mpz_t) * (*count));
    mpz_init_set_str((*out)[(*count)-1], buf, 0);
    return;
  }
  *dash = 0;
  char *a = buf;
  char *b = dash + 1;
  mpz_t start,
  end,
  cur;
  mpz_inits(start, end, cur, NULL);
  mpz_set_str(start, a, 10);
  mpz_set_str(end, b, 10);
  for (mpz_set(cur, start); mpz_cmp(cur, end) <= 0; mpz_add_ui(cur, cur, 1)) {
    (*count)++;
    *out = realloc(*out, sizeof(mpz_t) * (*count));
    mpz_init_set((*out)[(*count)-1], cur);
  }
  mpz_clears(start, end, cur, NULL);
}

static void load_override_files(void) {
  FILE *fr = fopen("rnlist.txt", "r");
  if (fr) {
    OVERRIDE_RN = 1;
    char line[256];
    while (fgets(line, sizeof(line), fr)) {
      trim(line);
      if (line[0] == 0) continue;
      parse_range_line(line, &OVR_RN_LIST, &OVR_RN_COUNT);
    }
    fclose(fr);
    log_msg(LOG_WARN, "OVERRIDE", "Loaded %lu Rn entries from rnlist.txt", OVR_RN_COUNT);
  }

  FILE *fi = fopen("iterlist.txt", "r");
  if (fi) {
    OVERRIDE_ITER = 1;
    char line[256];
    while (fgets(line, sizeof(line), fi)) {
      trim(line);
      if (line[0] == 0) continue;
      parse_range_line(line, &OVR_ITER_LIST, &OVR_ITER_COUNT);
    }
    fclose(fi);
    log_msg(LOG_WARN, "OVERRIDE", "Loaded %lu Iter entries from iterlist.txt", OVR_ITER_COUNT);
    if (OVR_ITER_COUNT == 0) {
      OVERRIDE_ITER = 0;
      log_msg(LOG_WARN, "OVERRIDE", "iterlist.txt empty->ITER override disabled");
    }
  }
}

int is_valid_hex(const char *str) {
  if (!str || *str == '\0') return 0;
  if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
    str += 2;
    if (*str == '\0') return 0;
  }
  for (; *str; str++) {
    if (!((*str >= '0' && *str <= '9') || (*str >= 'a' && *str <= 'f') || (*str >= 'A' && *str <= 'F'))) {
      return 0;
    }
  }
  return 1;
}

static inline bool safe_mpz_to_size_t(const mpz_t src, size_t *dest, const char* context) {
  if (!mpz_fits_ulong_p(src)) {
    log_msg(LOG_ERROR, "OVERFLOW", "%s: Value too large for size_t", context);
    return false;
  }
  unsigned long ul_val = mpz_get_ui(src);
  if (sizeof(size_t) < sizeof(unsigned long) && ul_val > SIZE_MAX) {
    log_msg(LOG_ERROR, "OVERFLOW", "%s: Value too large for size_t on this platform", context);
    return false;
  }
  *dest = (size_t)ul_val;
  return true;
}

void load_config(const char *path, Config *cfg) {
  if (!path || !cfg) {
    log_msg(LOG_ERROR, "CONFIG", "Parameter path atau cfg NULL");
    exit(1);
  }
  FILE *f = fopen(path, "r");
  if (!f) {
    perror(path);
    log_msg(LOG_ERROR, "CONFIG", "Gagal membuka file konfigurasi: %s", path);
    exit(1);
  }
  char line[512];
  memset(cfg, 0, sizeof(Config));
  mpz_inits(cfg->Number_R, cfg->max_pubkey_per_batch, cfg->range_count, cfg->SubrangeSize, NULL);

  int has_pubkey_target = 0;
  int has_step_hex = 0;
  int has_range_min = 0;
  int has_range_max = 0;
  int line_number = 0;

  while (fgets(line, sizeof(line), f)) {
    line_number++;
    if (strlen(line) == sizeof(line) - 1 && line[sizeof(line) - 2] != '\n') {
      log_msg(LOG_WARN, "CONFIG", "Line %d terlalu panjang, dipotong", line_number);
      int c;
      while ((c = fgetc(f)) != '\n' && c != EOF);
    }
    trim(line);
    if (line[0] == 0 || line[0] == '#')
    continue;

    char key[128],
    val[384];
    key[0] = val[0] = 0;
    int n = sscanf(line, "%127s %383[^\n]", key, val);
    if (n < 1) {
      log_msg(LOG_WARN, "CONFIG", "Line %d: format tidak valid", line_number);
      continue;
    }
    if (strlen(key) >= sizeof(key) - 1) {
      log_msg(LOG_ERROR, "CONFIG", "Line %d: key terlalu panjang", line_number);
      continue;
    }

    if (!strcasecmp(key, "PubkeyTarget")) {
      if (strlen(val) >= sizeof(cfg->PUBKEY_TARGET)) {
        log_msg(LOG_ERROR, "CONFIG", "PubkeyTarget terlalu panjang (max %zu karakter)", sizeof(cfg->PUBKEY_TARGET) - 1);
        exit(1);
      }
      strncpy(cfg->PUBKEY_TARGET, val, sizeof(cfg->PUBKEY_TARGET)-1);
      cfg->PUBKEY_TARGET[sizeof(cfg->PUBKEY_TARGET)-1] = '\0';
      has_pubkey_target = 1;
    }
    else if (!strcasecmp(key, "StepHex")) {
      if (!is_valid_hex(val)) {
        log_msg(LOG_ERROR, "CONFIG", "StepHex bukan hex string yang valid: %s", val);
        exit(1);
      }
      if (strlen(val) >= sizeof(cfg->STEP_HEX)) {
        log_msg(LOG_ERROR, "CONFIG", "StepHex terlalu panjang");
        exit(1);
      }
      strncpy(cfg->STEP_HEX, val, sizeof(cfg->STEP_HEX)-1);
      cfg->STEP_HEX[sizeof(cfg->STEP_HEX)-1] = '\0';
      has_step_hex = 1;
    }
    else if (!strcasecmp(key, "PubHasilPath")) {
      if (strlen(val) >= sizeof(cfg->PUBHASIL_PATH)) {
        log_msg(LOG_ERROR, "CONFIG", "PubHasilPath terlalu panjang");
        exit(1);
      }
      strncpy(cfg->PUBHASIL_PATH, val, sizeof(cfg->PUBHASIL_PATH)-1);
      cfg->PUBHASIL_PATH[sizeof(cfg->PUBHASIL_PATH)-1] = '\0';
    }
    else if (!strcasecmp(key, "HasilPrivPath")) {
      if (strlen(val) >= sizeof(cfg->HASILPRIV_PATH)) {
        log_msg(LOG_ERROR, "CONFIG", "HasilPrivPath terlalu panjang");
        exit(1);
      }
      strncpy(cfg->HASILPRIV_PATH, val, sizeof(cfg->HASILPRIV_PATH)-1);
      cfg->HASILPRIV_PATH[sizeof(cfg->HASILPRIV_PATH)-1] = '\0';
    }
    else if (!strcasecmp(key, "KeyhuntCmd")) {
      if (strlen(val) >= sizeof(cfg->KEYHUNT_CMD)) {
        log_msg(LOG_ERROR, "CONFIG", "KeyhuntCmd terlalu panjang");
        exit(1);
      }
      strncpy(cfg->KEYHUNT_CMD, val, sizeof(cfg->KEYHUNT_CMD)-1);
      cfg->KEYHUNT_CMD[sizeof(cfg->KEYHUNT_CMD)-1] = '\0';
    }
    else if (!strcasecmp(key, "GroupSize")) {
      int gs = atoi(val);
      if (gs <= 0) {
        log_msg(LOG_ERROR, "CONFIG", "GroupSize harus > 0");
        exit(1);
      }
      cfg->group_size = gs;
    }
    else if (!strcasecmp(key, "DigitMin")) {
      int dm = atoi(val);
      if (dm < 0) {
        log_msg(LOG_ERROR, "CONFIG", "DigitMin tidak boleh negatif");
        exit(1);
      }
      cfg->digit_min = dm;
    }
    else if (!strcasecmp(key, "MaxLinePubhasil")) {
      char *endptr;
      unsigned long long mpl = strtoull(val, &endptr, 10);
      if (*endptr != '\0' || mpl == ULLONG_MAX) {
        log_msg(LOG_ERROR, "CONFIG", "MaxLinePubhasil tidak valid: %s", val);
        exit(1);
      }
      cfg->max_pubhasil_lines = mpl;
    }
    else if (!strcasecmp(key, "RangeMin")) {
      if (!is_valid_hex(val)) {
        log_msg(LOG_ERROR, "CONFIG", "RangeMin bukan hex string yang valid");
        exit(1);
      }
      if (strlen(val) >= sizeof(cfg->RANGE_MIN_HEX)) {
        log_msg(LOG_ERROR, "CONFIG", "RangeMin terlalu panjang");
        exit(1);
      }
      strncpy(cfg->RANGE_MIN_HEX, val, sizeof(cfg->RANGE_MIN_HEX)-1);
      cfg->RANGE_MIN_HEX[sizeof(cfg->RANGE_MIN_HEX)-1] = '\0';
      has_range_min = 1;
    }
    else if (!strcasecmp(key, "RangeMax")) {
      if (!is_valid_hex(val)) {
        log_msg(LOG_ERROR, "CONFIG", "RangeMax bukan hex string yang valid");
        exit(1);
      }
      if (strlen(val) >= sizeof(cfg->RANGE_MAX_HEX)) {
        log_msg(LOG_ERROR, "CONFIG", "RangeMax terlalu panjang");
        exit(1);
      }
      strncpy(cfg->RANGE_MAX_HEX, val, sizeof(cfg->RANGE_MAX_HEX)-1);
      cfg->RANGE_MAX_HEX[sizeof(cfg->RANGE_MAX_HEX)-1] = '\0';
      has_range_max = 1;
    }
    else if (!strcasecmp(key, "NumberR")) {
      if (mpz_set_str(cfg->Number_R, val, 0) == -1) {
        log_msg(LOG_ERROR, "CONFIG", "NumberR bukan angka yang valid: %s", val);
        exit(1);
      }
      if (mpz_cmp_ui(cfg->Number_R, 0) < 0) {
        log_msg(LOG_ERROR, "CONFIG", "NumberR tidak boleh negatif");
        exit(1);
      }
    }
    else if (!strcasecmp(key, "MaxPubkeyPerBatch")) {
      if (mpz_set_str(cfg->max_pubkey_per_batch, val, 0) == -1) {
        log_msg(LOG_ERROR, "CONFIG", "MaxPubkeyPerBatch bukan angka yang valid: %s", val);
        exit(1);
      }
      if (mpz_cmp_ui(cfg->max_pubkey_per_batch, 0) < 0) {
        log_msg(LOG_ERROR, "CONFIG", "MaxPubkeyPerBatch tidak boleh negatif");
        exit(1);
      }
    }
    else if (!strcasecmp(key, "RandomPure")) {
      int rp = atoi(val);
      if (rp != 0 && rp != 1) {
        log_msg(LOG_ERROR, "CONFIG", "RandomPure harus 0 atau 1");
        exit(1);
      }
      cfg->random_pure = rp;
    }
    else if (!strcasecmp(key, "AutoNumberR")) {
      int anr = atoi(val);
      if (anr != 0 && anr != 1) {
        log_msg(LOG_ERROR, "CONFIG", "AutoNumberR harus 0 atau 1");
        exit(1);
      }
      cfg->AutoNumberR = anr;
    }
    else if (!strcasecmp(key, "SubrangeSize")) {
      if (mpz_set_str(cfg->SubrangeSize, val, 0) == -1) {
        log_msg(LOG_ERROR, "CONFIG", "SubrangeSize bukan angka yang valid: %s", val);
        exit(1);
      }
      if (mpz_cmp_ui(cfg->SubrangeSize, 0) <= 0) {
        log_msg(LOG_ERROR, "CONFIG", "SubrangeSize harus > 0");
        exit(1);
      }
    }
    else {
      log_msg(LOG_WARN, "CONFIG", "Parameter tidak dikenali: %s", key);
    }
  }
  fclose(f);

  if (!has_pubkey_target) {
    log_msg(LOG_ERROR, "CONFIG", "PubkeyTarget wajib diisi");
    exit(1);
  }
  if (!has_step_hex) {
    log_msg(LOG_ERROR, "CONFIG", "StepHex wajib diisi");
    exit(1);
  }
  if (!has_range_min || !has_range_max) {
    log_msg(LOG_ERROR, "CONFIG", "RangeMin dan RangeMax wajib diisi");
    exit(1);
  }

  mpz_t range_min,
  range_max;
  mpz_inits(range_min, range_max, NULL);
  mpz_set_str(range_min, cfg->RANGE_MIN_HEX, 16);
  mpz_set_str(range_max, cfg->RANGE_MAX_HEX, 16);
  if (mpz_cmp(range_min, range_max) >= 0) {
    log_msg(LOG_ERROR, "CONFIG", "RangeMin harus < RangeMax");
    mpz_clears(range_min, range_max, NULL);
    exit(1);
  }
  mpz_clears(range_min, range_max, NULL);

  if (cfg->max_pubhasil_lines == 0)
  cfg->max_pubhasil_lines = 2000000ULL;
  if (cfg->group_size <= 0) {
    cfg->group_size = 100;
    log_msg(LOG_INFO, "CONFIG", "GroupSize menggunakan default: 100");
  }
  if (cfg->digit_min < 0) {
    cfg->digit_min = 0;
    log_msg(LOG_INFO, "CONFIG", "DigitMin menggunakan default: 0");
  }
  if (mpz_cmp_ui(cfg->max_pubkey_per_batch, 0) == 0) {
    mpz_set_ui(cfg->max_pubkey_per_batch, 1000000ULL);
    log_msg(LOG_INFO, "CONFIG", "MaxPubkeyPerBatch menggunakan default: 1000000");
  }
  if (cfg->random_pure != 0 && cfg->random_pure != 1) {
    cfg->random_pure = 0;
    log_msg(LOG_INFO, "CONFIG", "RandomPure menggunakan default: 0");
  }

  if (cfg->AutoNumberR == 1) {
    if (mpz_cmp_ui(cfg->SubrangeSize, 0) == 0) {
      log_msg(LOG_ERROR, "CONFIG", "AutoNumberR=1 membutuhkan SubrangeSize > 0");
      exit(1);
    }
    mpz_t min,
    max,
    diff,
    tmp;
    mpz_inits(min, max, diff, tmp, NULL);
    mpz_set_str(min, cfg->RANGE_MIN_HEX, 16);
    mpz_set_str(max, cfg->RANGE_MAX_HEX, 16);
    mpz_sub(diff, max, min);
    mpz_add_ui(diff, diff, 1);
    if (mpz_cmp(cfg->SubrangeSize, diff) > 0) {
      log_msg(LOG_ERROR, "CONFIG", "SubrangeSize tidak boleh lebih besar dari range");
      mpz_clears(min, max, diff, tmp, NULL);
      exit(1);
    }
    mpz_fdiv_q(tmp, diff, cfg->SubrangeSize);
    mpz_set(cfg->Number_R, tmp);
    if (mpz_cmp_ui(cfg->Number_R, 0) == 0) {
      log_msg(LOG_WARN, "CONFIG", "Number_R = 0, di-set ke 1");
      mpz_set_ui(cfg->Number_R, 1);
    }
    char *s = mpz_get_str(NULL, 10, cfg->Number_R);
    size_t digits = mpz_sizeinbase(cfg->Number_R, 10);
    log_msg(LOG_SUCCESS, "AUTOR", "NumberR  = %s (Digits: %zu)", s, digits);
    free(s);
    mpz_t pre_step,
    RANGE_MIN,
    RANGE_MAX,
    RANGE_DIFF;
    mpz_inits(pre_step, RANGE_MIN, RANGE_MAX, RANGE_DIFF, NULL);
    mpz_set_str(RANGE_MIN, cfg->RANGE_MIN_HEX, 16);
    mpz_set_str(RANGE_MAX, cfg->RANGE_MAX_HEX, 16);
    mpz_sub(RANGE_DIFF, RANGE_MAX, RANGE_MIN);
    mpz_add_ui(RANGE_DIFF, RANGE_DIFF, 1);
    mpz_fdiv_q(pre_step, RANGE_DIFF, cfg->Number_R);
    if (mpz_cmp_ui(pre_step, 1) < 0)
    mpz_set_ui(pre_step, 1);
    mpz_t stephex,
    iter_max;
    mpz_inits(stephex, iter_max, NULL);
    mpz_set_str(stephex, cfg->STEP_HEX, 16);
    if (mpz_cmp_ui(stephex, 0) == 0) {
      log_msg(LOG_ERROR, "CONFIG", "StepHex tidak boleh 0");
      mpz_clears(pre_step, RANGE_MIN, RANGE_MAX, RANGE_DIFF, stephex, iter_max, NULL);
      mpz_clears(min, max, diff, tmp, NULL);
      exit(1);
    }
    mpz_fdiv_q(iter_max, pre_step, stephex);
    if (mpz_cmp_ui(iter_max, 1) < 0)
    mpz_set_ui(iter_max, 1);
    char *iter_max_str = mpz_get_str(NULL, 10, iter_max);
    size_t dmax = strlen(iter_max_str);
    log_msg(LOG_INFO, "SUMMARY", "maks iter per subrange: %s | maks iter digit: %zu", iter_max_str, dmax);
    free(iter_max_str);
    mpz_clears(pre_step, RANGE_MIN, RANGE_MAX, RANGE_DIFF, stephex, iter_max, NULL);
    mpz_clears(min, max, diff, tmp, NULL);
  }

  if (mpz_cmp_ui(cfg->Number_R, 0) == 0) {
    log_msg(LOG_ERROR, "CONFIG", "Number_R = 0 (cek SubrangeSize / RangeMin / RangeMax / AutoNumberR)");
    mpz_set_ui(cfg->Number_R, 1);
  }
  if (mpz_cmp_ui(cfg->Number_R, 0) <= 0) {
    log_msg(LOG_ERROR, "CONFIG", "Number_R harus > 0");
    exit(1);
  }

  {
    mpz_t RANGE_MIN,
    RANGE_MAX,
    RANGE_DIFF,
    pre_step,
    stephex,
    iter_max;
    mpz_inits(RANGE_MIN, RANGE_MAX, RANGE_DIFF, pre_step, stephex, iter_max, NULL);
    mpz_set_str(RANGE_MIN, cfg->RANGE_MIN_HEX, 16);
    mpz_set_str(RANGE_MAX, cfg->RANGE_MAX_HEX, 16);
    mpz_sub(RANGE_DIFF, RANGE_MAX, RANGE_MIN);
    mpz_add_ui(RANGE_DIFF, RANGE_DIFF, 1);
    mpz_fdiv_q(pre_step, RANGE_DIFF, cfg->Number_R);
    if (mpz_cmp_ui(pre_step, 0) == 0) {
      mpz_set_ui(pre_step, 1);
    }
    mpz_set_str(stephex, cfg->STEP_HEX, 16);
    if (mpz_cmp_ui(stephex, 0) == 0) {
      log_msg(LOG_ERROR, "CONFIG", "StepHex tidak boleh 0");
      mpz_clears(RANGE_MIN, RANGE_MAX, RANGE_DIFF, pre_step, stephex, iter_max, NULL);
      exit(1);
    }
    mpz_fdiv_q(iter_max, pre_step, stephex);
    if (mpz_cmp_ui(iter_max, 1) < 0) {
      mpz_set_ui(iter_max, 1);
    }
    size_t dmax = mpz_sizeinbase(iter_max, 10);
    char *iter_max_str = mpz_get_str(NULL, 10, iter_max);
    log_msg(LOG_INFO, "SUMMARY", "maks iter per subrange: %s | maks iter digit: %zu", iter_max_str, dmax);
    free(iter_max_str);
    mpz_clears(RANGE_MIN, RANGE_MAX, RANGE_DIFF, pre_step, stephex, iter_max, NULL);
  }

  log_header("AUTO_KEYHUNT");
  char *s_max = mpz_get_str(NULL, 10, cfg->max_pubkey_per_batch);
  char *s_numr = mpz_get_str(NULL, 10, cfg->Number_R);
  log_msg(LOG_INFO, "CONFIG", "GroupSize=%d | DigitMin=%d | MaxPubkeyPerBatch=%s | RandomPure=%d", cfg->group_size, cfg->digit_min, s_max, cfg->random_pure);
  log_msg(LOG_INFO, "RANGE", "%s -> %s", cfg->RANGE_MIN_HEX, cfg->RANGE_MAX_HEX);
  log_mpz(LOG_INFO, "CONFIG", "NumberR", cfg->Number_R);
  free(s_max);
  free(s_numr);
}

bool verify_checkpoint_integrity(const Config *cfg, const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) return false;
  char key[64],
  val[512];
  char rmin[128] = "",
  rmax[128] = "",
  pt[80] = "",
  step[32] = "";
  char numR[256] = "",
  maxpub[256] = "";
  int grp = 0;
  while (fscanf(f, "%63s %511s", key, val) == 2) {
    if (!strcasecmp(key, "RangeMin")) strcpy(rmin, val);
    else if (!strcasecmp(key, "RangeMax")) strcpy(rmax, val);
    else if (!strcasecmp(key, "PubkeyTarget")) strcpy(pt, val);
    else if (!strcasecmp(key, "StepHex")) strcpy(step, val);
    else if (!strcasecmp(key, "NumberR")) strcpy(numR, val);
    else if (!strcasecmp(key, "MaxPubkeyPerBatch")) strcpy(maxpub, val);
    else if (!strcasecmp(key, "GroupSize")) grp = atoi(val);
  }
  fclose(f);
  if (strcasecmp(rmin, cfg->RANGE_MIN_HEX) != 0) return false;
  if (strcasecmp(rmax, cfg->RANGE_MAX_HEX) != 0) return false;
  if (strcasecmp(pt, cfg->PUBKEY_TARGET) != 0) return false;
  if (strcasecmp(step, cfg->STEP_HEX) != 0) return false;
  if (grp != cfg->group_size) return false;

  mpz_t a,
  b;
  mpz_inits(a, b, NULL);
  if (strlen(numR) == 0 || strlen(maxpub) == 0) {
    mpz_clears(a, b, NULL);
    return false;
  }
  mpz_set_str(a, numR, 0);
  if (mpz_cmp(a, cfg->Number_R) != 0) {
    mpz_clears(a, b, NULL);
    return false;
  }
  mpz_set_str(b, maxpub, 0);
  if (mpz_cmp(b, cfg->max_pubkey_per_batch) != 0) {
    mpz_clears(a, b, NULL);
    return false;
  }
  mpz_clears(a, b, NULL);
  return true;
}

void delete_checkpoint_and_rnstate(void) {
  remove("checkpoint.txt");
  remove("rn_state.txt");
  remove("rn_full.txt");
  remove("rn_duplikat.txt");
  log_msg(LOG_WARN, "RESET", "Checkpoint mismatch->deleted old checkpoint + RnState");
}

void save_rn_state(const mpz_t batch, const mpz_t mult, const mpz_t number_r, const mpz_t worker_r, const mpz_t done_r) {
  FILE *f = fopen("rn_state.txt", "w");
  if(!f) {
    log_msg(LOG_ERROR, "RN_STATE", "Cannot write rn_state.txt");
    return;
  }
  gmp_fprintf(f, "Batch %Zd\nMultiplier %Zd\nNumberR %Zd\nWorkerR %Zd\nDoneR %Zd\n", batch, mult, number_r, worker_r, done_r);
  fclose(f);
  log_mpz(LOG_SUCCESS, "RN_STATE", "Saved_Batch", batch);
  log_mpz(LOG_SUCCESS, "RN_STATE", "Saved_Mult", mult);
}

bool load_rn_state(mpz_t batch, mpz_t mult, mpz_t number_r, mpz_t worker_r, mpz_t done_r) {
  FILE *f = fopen("rn_state.txt", "r");
  if (!f) return false;
  char key[64],
  val[512];
  while (fscanf(f, "%63s %511s", key, val) == 2) {
    if (!strcasecmp(key, "Batch")) mpz_set_str(batch, val, 0);
    else if (!strcasecmp(key, "Multiplier")) mpz_set_str(mult, val, 0);
    else if (!strcasecmp(key, "NumberR")) mpz_set_str(number_r, val, 0);
    else if (!strcasecmp(key, "WorkerR")) mpz_set_str(worker_r, val, 0);
    else if (!strcasecmp(key, "DoneR")) mpz_set_str(done_r, val, 0);
  }
  fclose(f);
  log_mpz(LOG_INFO, "RN_STATE", "Loaded_Batch", batch);
  log_mpz(LOG_INFO, "RN_STATE", "Loaded_Mult", mult);
  return true;
}

void save_checkpoint(const Checkpoint *cp) {
  FILE *f = fopen("checkpoint.txt", "w");
  if (!f) {
    log_msg(LOG_ERROR, "CHECKPOINT", "Cannot write checkpoint.txt");
    return;
  }
  gmp_fprintf(f, "RangeMin %Zx\nRangeMax %Zx\nPubkeyTarget %s\nStepHex %s\nNumberR %Zd\nMaxPubkeyPerBatch %Zd\nGroupSize %d\nDoneR %Zd\nWorkerR %Zd\nBatch %Zd\nMultiplier %Zd\nTimestamp %ld\n",
    cp->range_min, cp->range_max, CFG.PUBKEY_TARGET, CFG.STEP_HEX, cp->number_r, CFG.max_pubkey_per_batch, CFG.group_size, cp->done_r, cp->worker_r, cp->batch, cp->multiplier, time(NULL));
  fclose(f);
  save_rn_state(cp->batch, cp->multiplier, cp->number_r, cp->worker_r, cp->done_r);
  log_mpz(LOG_SUCCESS, "CHECKPOINT", "Saved_Batch", cp->batch);
}

void load_checkpoint(const Config *cfg) {
  mpz_inits(CP.range_min, CP.range_max, CP.number_r, CP.done_r, CP.worker_r, CP.batch, CP.multiplier, NULL);

  bool ok = verify_checkpoint_integrity(cfg, "checkpoint.txt");
  if (!ok) {
    delete_checkpoint_and_rnstate();
    mpz_set_str(CP.range_min, cfg->RANGE_MIN_HEX, 16);
    mpz_set_str(CP.range_max, cfg->RANGE_MAX_HEX, 16);
    mpz_set(CP.number_r, cfg->Number_R);
    mpz_set_ui(CP.done_r, 0);
    mpz_fdiv_q_ui(CP.worker_r, cfg->max_pubkey_per_batch, cfg->group_size);
    if (mpz_cmp_ui(CP.worker_r, 1) < 0) mpz_set_ui(CP.worker_r, 1);
    mpz_set_ui(CP.batch, 1);
    mpz_set_ui(CP.multiplier, 2);
    save_checkpoint(&CP);
    log_msg(LOG_INFO, "INIT", "New checkpoint created");
    return;
  }

  FILE *f = fopen("checkpoint.txt", "r");
  if (!f) return;
  char key[64],
  val[512];
  while(fscanf(f, "%63s %511s", key, val) == 2) {
    if (!strcasecmp(key, "RangeMin")) mpz_set_str(CP.range_min, val, 16);
    else if (!strcasecmp(key, "RangeMax")) mpz_set_str(CP.range_max, val, 16);
    else if (!strcasecmp(key, "NumberR")) mpz_set_str(CP.number_r, val, 0);
    else if (!strcasecmp(key, "DoneR")) mpz_set_str(CP.done_r, val, 0);
    else if (!strcasecmp(key, "WorkerR")) mpz_set_str(CP.worker_r, val, 0);
    else if (!strcasecmp(key, "Batch")) mpz_set_str(CP.batch, val, 0);
    else if (!strcasecmp(key, "Multiplier")) mpz_set_str(CP.multiplier, val, 0);
  }
  fclose(f);

  mpz_t b,
  m,
  nR,
  wR,
  dR;
  mpz_inits(b, m, nR, wR, dR, NULL);
  if (load_rn_state(b, m, nR, wR, dR)) {
    mpz_set(CP.batch, b);
    mpz_set(CP.multiplier, m);
    mpz_set(CP.number_r, nR);
    mpz_set(CP.worker_r, wR);
    mpz_set(CP.done_r, dR);
  }
  mpz_clears(b, m, nR, wR, dR, NULL);
  log_mpz(LOG_SUCCESS, "CHECKPOINT", "Loaded_Batch", CP.batch);
  log_mpz(LOG_SUCCESS, "CHECKPOINT", "Loaded_Mult", CP.multiplier);
  log_mpz(LOG_SUCCESS, "CHECKPOINT", "Loaded_DoneR", CP.done_r);
}

static void pubkey_to_hex(const unsigned char pub33[33], char out[67]) {
  static const char *hex = "0123456789abcdef";
  for(int i = 0; i < 33; i++) {
    out[i*2] = hex[(pub33[i]>>4)&0xF];
    out[i*2+1] = hex[(pub33[i])&0xF];
  }
  out[66] = '\0';
}

static void init_curve_order(void) {
  if (CURVE_ORDER_READY) return;
  mpz_init_set_str(CURVE_ORDER, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
  CURVE_ORDER_READY = 1;
}

static void initialize_step_mpz(void) {
  mpz_init_set_str(STEP_MPZ, CFG.STEP_HEX, 16);
  STEP_MPZ_READY = 1;
}

static inline void ensure_step_mpz_ready(void) {
  pthread_once(&step_mpz_once, initialize_step_mpz);
}

static void init_step_precompute() {
  if (STEP_READY) return;
  mpz_t step;
  mpz_init_set_str(step, CFG.STEP_HEX, 16);
  if (!STEP_MPZ_READY) {
    mpz_init_set(STEP_MPZ, step);
    STEP_MPZ_READY = 1;
  }
  memset(STEP_PRIV, 0, 32);
  unsigned char tmp[64] = {
    0
  };
  size_t sz = 0;
  mpz_export(tmp, &sz, 1, 1, 1, 0, step);
  if (sz > 32) sz = 32;
  memcpy(STEP_PRIV + (32 - sz), tmp, sz);

  if (!secp256k1_ec_pubkey_create(CTX, &STEP_G, STEP_PRIV)) {
    log_msg(LOG_ERROR, "ECC", "Failed to precompute STEP_G");
  } else {
    STEP_READY = true;
    log_msg(LOG_SUCCESS, "ECC", "STEP_G precomputed");
  }
  mpz_clear(step);
}

static void scalar_mult(secp256k1_context *ctx, const mpz_t k, unsigned char out33[33]) {
  init_curve_order();
  unsigned char priv[32] = {
    0
  };
  unsigned char tmp[32] = {
    0
  };
  mpz_t kmod;
  mpz_init(kmod);
  mpz_mod(kmod, k, CURVE_ORDER);
  if (mpz_cmp_ui(kmod, 0) == 0) mpz_set_ui(kmod, 1);
  size_t count = 0;
  mpz_export(tmp, &count, 1, 1, 1, 0, kmod);
  if (count > 32) {
    memmove(tmp, tmp + (count - 32), 32);
    count = 32;
  }
  memcpy(priv + (32 - count), tmp, count);

  secp256k1_pubkey pub;
  if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) {
    memset(out33, 0, 33);
    mpz_clear(kmod);
    return;
  }
  size_t outlen = 33;
  secp256k1_ec_pubkey_serialize(ctx, out33, &outlen, &pub, SECP256K1_EC_COMPRESSED);
  mpz_clear(kmod);
}

static void scalar_mult_step_iter(secp256k1_context *ctx, const mpz_t iter, unsigned char out33[33]) {
  if (!STEP_READY) { memset(out33, 0, 33); return; }
  init_curve_order();
  mpz_t iter_mod;
  mpz_init(iter_mod);
  mpz_mod(iter_mod, iter, CURVE_ORDER);
  unsigned char iter_bytes[32] = {0};
  unsigned char tmp[32] = {0};
  size_t count = 0;
  mpz_export(tmp, &count, 1, 1, 1, 0, iter_mod);
  if (count > 32) count = 32; 
  memcpy(iter_bytes + (32 - count), tmp, count);
  secp256k1_pubkey R = STEP_G;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &R, iter_bytes)) {
    memset(out33, 0, 33);
  } else {
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out33, &len, &R, SECP256K1_EC_COMPRESSED);
  }
  mpz_clear(iter_mod);
}

static pthread_once_t pre_once = PTHREAD_ONCE_INIT;

static void initialize_pre_step(void) {
  mpz_t min,
  max,
  diff,
  tmp;
  mpz_inits(min, max, diff, tmp, NULL);
  mpz_init(PRE_MIN);
  mpz_init(PRE_STEP);
  mpz_set_str(min, CFG.RANGE_MIN_HEX, 16);
  mpz_set_str(max, CFG.RANGE_MAX_HEX, 16);
  mpz_sub(diff, max, min);
  mpz_add_ui(diff, diff, 1);
  mpz_fdiv_q(tmp, diff, CFG.Number_R);
  if (mpz_cmp_ui(tmp, 1) < 0) mpz_set_ui(tmp, 1);
  mpz_set(PRE_MIN, min);
  mpz_set(PRE_STEP, tmp);
  PRE_READY = 1;
  log_msg(LOG_SUCCESS, "PRE_STEP", "PRE_STEP initialized safely with pthread_once");
  mpz_clears(min, max, diff, tmp, NULL);
}

static inline void ensure_pre_step_ready(void) {
  pthread_once(&pre_once, initialize_pre_step);
}

void compute_range_by_index(const Config *cfg, const mpz_t idx_raw, range_ctx *out) {
  ensure_pre_step_ready();
  mpz_t idx,
  start,
  end,
  tmp,
  nR_minus1,
  maxval;
  mpz_inits(idx, start, end, tmp, nR_minus1, maxval, NULL);

  if (mpz_cmp_ui(cfg->Number_R, 0) == 0) {
    mpz_set_ui(idx, 0);
  } else {
    if (mpz_sgn(idx_raw) < 0) {
      mpz_set_ui(idx, 0);
    } else {
      mpz_sub_ui(nR_minus1, cfg->Number_R, 1);
      if (mpz_cmp(idx_raw, nR_minus1) > 0) {
        mpz_set(idx, nR_minus1);
      } else {
        mpz_set(idx, idx_raw);
      }
    }
  }

  mpz_mul(tmp, PRE_STEP, idx);
  mpz_add(start, PRE_MIN, tmp);

  mpz_set_str(maxval, cfg->RANGE_MAX_HEX, 16);
  if (mpz_cmp_ui(cfg->Number_R, 0) > 0) {
    mpz_sub_ui(nR_minus1, cfg->Number_R, 1);
    if (mpz_cmp(idx, nR_minus1) == 0) {
      mpz_set(end, maxval);
    } else {
      mpz_add(end, start, PRE_STEP);
      mpz_sub_ui(end, end, 1);
    }
  } else {
    mpz_add(end, start, PRE_STEP);
    mpz_sub_ui(end, end, 1);
  }
  if (mpz_cmp(end, maxval) > 0) mpz_set(end, maxval);

  gmp_snprintf(out->start_hex, sizeof(out->start_hex), "%Zx", start);
  gmp_snprintf(out->end_hex, sizeof(out->end_hex), "%Zx", end);
  mpz_set(out->index, idx);

  char *sidx = mpz_get_str(NULL, 10, idx);
  snprintf(out->name, sizeof(out->name), "R%s", sidx);
  free(sidx);

  mpz_clears(idx, start, end, tmp, nR_minus1, maxval, NULL);
}

static int cmp_mpz(const void *a, const void *b) {
  mpz_t *A = (mpz_t *)a;
  mpz_t *B = (mpz_t *)b;
  return mpz_cmp(*A, *B);
}

void finalize_rnfull_sorted(void) {
  if (RN_FULL_COUNT == 0 || RN_FULL == NULL) return;
  qsort(RN_FULL, RN_FULL_COUNT, sizeof(mpz_t), cmp_mpz);

  FILE *f = fopen("rn_full.txt", "w");
  if (!f) {
    log_msg(LOG_ERROR, "RN_FULL", "Cannot write rn_full.txt");
    return;
  }
  for (unsigned long k = 0; k < RN_FULL_COUNT; k++) {
    mpz_t rn;
    mpz_init_set(rn, RN_FULL[k]);
    range_ctx tmp;
    mpz_init(tmp.index);
    mpz_set(tmp.index, rn);
    compute_range_by_index(&CFG, rn, &tmp);
    char *s_rn = mpz_get_str(NULL, 10, rn);
    fprintf(f, "R%s  %s->%s\n", s_rn, tmp.start_hex, tmp.end_hex);
    free(s_rn);
    mpz_clear(tmp.index);
    mpz_clear(rn);
  }
  fclose(f);
  log_msg(LOG_SUCCESS, "RN_FULL", "Sorted and saved (%lu entries) with subranges", RN_FULL_COUNT);
}

static volatile unsigned long long CUR_IDX = 0;

void generate_rn_parallel(range_ctx *ranges, const mpz_t worker_r_mpz, const mpz_t number_r_mpz, int nthreads) {
  (void)nthreads;
  if (!mpz_fits_ulong_p(worker_r_mpz)) {
    log_msg(LOG_ERROR, "OVERFLOW", "worker_r terlalu besar untuk dialokasikan sebagai array C.");
    return;
  }
  size_t worker_r = (size_t) mpz_get_ui(worker_r_mpz);
  if (worker_r == 0) {
    log_msg(LOG_WARN, "RN_GEN", "worker_r = 0, tidak ada Rn yang digenerate");
    return;
  }
  if (mpz_cmp_ui(number_r_mpz, 0) <= 0) {
    log_msg(LOG_ERROR, "RN_GEN", "Number_R / number_r_mpz harus > 0 (cek config / AutoNumberR)");
    return;
  }

  if (RN_FULL != NULL) {
    for (unsigned long i = 0; i < RN_FULL_COUNT; i++) {
      if (&RN_FULL[i] != NULL) {
        mpz_clear(RN_FULL[i]);
      }
    }
    free(RN_FULL);
    RN_FULL = NULL;
    RN_FULL_COUNT = 0;
  }

  RN_FULL_COUNT = worker_r;
  RN_FULL = calloc(worker_r, sizeof(mpz_t));
  if (!RN_FULL) {
    log_msg(LOG_ERROR, "MEM", "calloc gagal untuk RN_FULL");
    return;
  }
  for (size_t i = 0; i < worker_r; i++) {
    mpz_init(RN_FULL[i]);
  }

  gmp_randstate_t rng;
  gmp_randinit_default(rng);
  gmp_randseed_ui(rng, (unsigned long)time(NULL));

  mpz_t rid,
  idx_mod;
  mpz_inits(rid, idx_mod, NULL);

  if (OVERRIDE_RN && OVR_RN_COUNT > 0) {
    size_t limit = (worker_r < OVR_RN_COUNT) ? worker_r: OVR_RN_COUNT;
    for (size_t i = 0; i < limit; i++) {
      mpz_mod(idx_mod, OVR_RN_LIST[i], number_r_mpz);
      if (mpz_sgn(idx_mod) < 0) {
        mpz_add(idx_mod, idx_mod, number_r_mpz);
      }
      mpz_set(RN_FULL[i], idx_mod);
      compute_range_by_index(&CFG, idx_mod, &ranges[i]);
    }
    for (size_t i = limit; i < worker_r; i++) {
      mpz_urandomm(idx_mod, rng, number_r_mpz);
      if (mpz_sgn(idx_mod) < 0) {
        mpz_add(idx_mod, idx_mod, number_r_mpz);
      }
      mpz_set(RN_FULL[i], idx_mod);
      compute_range_by_index(&CFG, idx_mod, &ranges[i]);
    }
    finalize_rnfull_sorted();
    mpz_clears(rid, idx_mod, NULL);
    gmp_randclear(rng);
    return;
  }

  uint64_t last_u64 = 0;
  for (size_t k = 0; k < worker_r; k++) {
    mpz_urandomm(rid, rng, number_r_mpz);
    if (mpz_sgn(rid) < 0) {
      mpz_add(rid, rid, number_r_mpz);
    }
    uint64_t h = mpz_get_ui(rid);
    if (h == last_u64 && mpz_cmp_ui(number_r_mpz, 1) > 0) {
      mpz_add_ui(rid, rid, (k + 1) % 17);
      mpz_mod(rid, rid, number_r_mpz);
      if (mpz_sgn(rid) < 0) {
        mpz_add(rid, rid, number_r_mpz);
      }
      h = mpz_get_ui(rid);
    }
    last_u64 = h;
    mpz_set(RN_FULL[k], rid);
    compute_range_by_index(&CFG, rid, &ranges[k]);
  }
  finalize_rnfull_sorted();
  mpz_clears(rid, idx_mod, NULL);
  gmp_randclear(rng);

  size_t mem_usage = worker_r * sizeof(mpz_t) + worker_r * sizeof(range_ctx);
  log_msg(LOG_INFO, "MEMORY", "Allocated %zu bytes for RN_FULL and ranges", mem_usage);
}

static bool is_pub_zero(const unsigned char p[33]) {
  for (int i = 0; i < 33; i++) if (p[i] != 0) return false;
  return true;
}

static bool is_pub_prefix_valid(const unsigned char p[33]) {
  return (p[0] == 0x02 || p[0] == 0x03);
}

static inline bool parse_range_and_step(range_ctx *ctx, mpz_t start, mpz_t end, mpz_t step, mpz_t nmax, size_t *dmax_out) {
  ensure_step_mpz_ready();
  mpz_set(step, STEP_MPZ);
  mpz_set_str(start, ctx->start_hex, 16);
  mpz_set_str(end, ctx->end_hex, 16);

  mpz_t diff;
  mpz_init(diff);
  mpz_sub(diff, end, start);
  mpz_fdiv_q(nmax, diff, step);
  if (mpz_cmp_ui(nmax, 1) < 0) {
    mpz_clear(diff);
    return false;
  }
  *dmax_out = mpz_sizeinbase(nmax, 10);
  mpz_clear(diff);
  return true;
}

static inline void update_global_digit_max(size_t dmax) {
  pthread_mutex_lock(&digit_lock);
  if (dmax > GLOBAL_DIGIT_MAX) GLOBAL_DIGIT_MAX = dmax;
  pthread_mutex_unlock(&digit_lock);
}

static inline void compute_iter_bounds(mpz_t iter_min, mpz_t iter_max, const mpz_t nmax, int digit_min) {
  size_t digit_nmax = mpz_sizeinbase(nmax, 10);
  if (digit_min > 0) {
    if (digit_min > (int)digit_nmax) {
      mpz_set(iter_min, nmax);
    } else {
      mpz_ui_pow_ui(iter_min, 10, digit_min - 1);
      if (mpz_cmp(iter_min, nmax) > 0) {
        mpz_set(iter_min, nmax);
      }
    }
  } else {
    if (digit_nmax > 0) {
      mpz_ui_pow_ui(iter_min, 10, digit_nmax - 1);
      if (mpz_cmp(iter_min, nmax) > 0) {
        if (mpz_cmp_ui(nmax, 1) < 0) {
          mpz_set_ui(iter_min, 1);
        } else {
          mpz_set(iter_min, nmax);
        }
      }
    } else {
      mpz_set_ui(iter_min, 0);
    }
  }
  mpz_set(iter_max, nmax);
  if (mpz_cmp(iter_min, iter_max) > 0) {
    mpz_set(iter_min, iter_max);
  }
}

static inline memout_t *init_output_buffer() {
  memout_t *out = calloc(1, sizeof(memout_t));
  out->cap = CFG.group_size * 128; // Asumsi ukuran rata-rata per record
  out->buf = malloc(out->cap);
  return out;
}

static inline void compute_pub_start_and_ref(secp256k1_context *ctx_local, const mpz_t start, unsigned char pub_start[33], unsigned char pub_ref[33]) {
  scalar_mult(ctx_local, start, pub_start);
  secp256k1_pubkey P1,
  P2,
  N2,
  R;
  if (!secp256k1_ec_pubkey_parse(ctx_local, &P1, PUB_TARGET, 33) || !secp256k1_ec_pubkey_parse(ctx_local, &P2, pub_start, 33)) {
    memset(pub_ref, 0, 33);
    return;
  }
  memcpy(&N2, &P2, sizeof(P2));
  secp256k1_ec_pubkey_negate(ctx_local, &N2);
  const secp256k1_pubkey *arr[2] = {
    &P1,
    &N2
  };
  if (!secp256k1_ec_pubkey_combine(ctx_local, &R, arr, 2)) {
    memset(pub_ref, 0, 33);
    return;
  }
  size_t len = 33;
  secp256k1_ec_pubkey_serialize(ctx_local, pub_ref, &len, &R, SECP256K1_EC_COMPRESSED);
}

static inline unsigned long *make_shuffle_order(unsigned long total, gmp_randstate_t rng) {
  unsigned long *order = malloc(sizeof(unsigned long) * total);
  for (unsigned long i = 0; i < total; i++) order[i] = i;
  for (unsigned long i = total - 1; i > 0; i--) {
    unsigned long j = gmp_urandomb_ui(rng, 32) % (i + 1);
    unsigned long tmp = order[i];
    order[i] = order[j];
    order[j] = tmp;
  }
  return order;
}

static inline bool compute_iter_step(mpz_t iter_min, mpz_t iter_max, mpz_t step_iter, mpz_t range_span, unsigned long total) {
  mpz_sub(range_span, iter_max, iter_min);
  mpz_fdiv_q_ui(step_iter, range_span, total);
  if (mpz_cmp_ui(step_iter, 1) < 0) {
    mpz_set_ui(step_iter, 1);
  }
  return true;
}

static inline void append_record(memout_t *out, const char *hex, const char *rn, const char *s_iter) {
  int need = snprintf(NULL, 0, "%s|%s|%s\n", hex, rn, s_iter);
  if (out->len + need + 1 >= out->cap) {
    out->cap *= 2;
    out->buf = realloc(out->buf, out->cap);
  }
  snprintf(out->buf + out->len, out->cap - out->len, "%s|%s|%s\n", hex, rn, s_iter);
  out->len += need;
}

// --- FUNGSI UTAMA YANG DIPERBAIKI ---
static void calc_mpz(memout_t *out, secp256k1_context *ctx_local, gmp_randstate_t rng, unsigned long total, unsigned long *order, const mpz_t iter_min, const mpz_t iter_max, const mpz_t step_iter, const unsigned char pub_ref[33], const char *s_rn) {
  mpz_t it,
  offset,
  actual_max,
  range_size; // Tambahkan range_size
  mpz_inits(it, offset, actual_max, range_size, NULL);

  // Tentukan batas iterasi maksimum yang digunakan
  mpz_set(actual_max, iter_max);
  if (mpz_cmp(iter_min, actual_max) > 0) {
    mpz_set(actual_max, iter_min);
  }

  // Hitung ukuran rentang untuk pick_random_iter
  mpz_sub(range_size, actual_max, iter_min);
  mpz_add_ui(range_size, range_size, 1);

  unsigned char pub_d[33],
  pub_res[33];
  char hex[67];
  char s_iter[64];

  for (unsigned long k = 0; k < total; k++) {
    if (OVERRIDE_ITER && OVR_ITER_COUNT > 0) {
      // Gunakan nilai dari daftar override jika ada
      mpz_set(it, OVR_ITER_LIST[k % OVR_ITER_COUNT]);
      if (mpz_cmp(it, actual_max) > 0) {
        char *s_it = mpz_get_str(NULL, 10, it);
        char *s_max = mpz_get_str(NULL, 10, actual_max);
        log_msg(LOG_WARN, "OVERRIDE", "Iteration %s exceeds max %s, clamping", s_it, s_max);
        free(s_it);
        free(s_max);
        mpz_set(it, actual_max);
      }
    } else {
      // --- PERUBAHAN UTAMA ---
      // Pilih iter secara acak dalam rentang [iter_min, actual_max]
      // Hasilkan angka acak dalam rentang [0, range_size - 1]
      mpz_urandomm(it, rng, range_size);
      // Tambahkan iter_min untuk mendapatkan nilai dalam [iter_min, actual_max]
      mpz_add(it, it, iter_min);

      // Pastikan hasilnya >= 1 (hindari scalar_mult_step_iter dengan iter 0)
      if (mpz_sgn(it) <= 0) {
        mpz_set_ui(it, 1);
        log_msg(LOG_WARN, "ITER", "Random iter <= 0, set to 1");
      }
      // --- AKHIR PERUBAHAN ---
    }

    // Proses pembuatan pubkey seperti sebelumnya
    scalar_mult_step_iter(ctx_local, it, pub_d);
    if (is_pub_zero(pub_d)) continue;

    secp256k1_pubkey P1,
    P2,
    N2,
    R;
    if (!secp256k1_ec_pubkey_parse(ctx_local, &P1, pub_ref, 33) || !secp256k1_ec_pubkey_parse(ctx_local, &P2, pub_d, 33)) {
      continue;
    }
    memcpy(&N2, &P2, sizeof(P2));
    secp256k1_ec_pubkey_negate(ctx_local, &N2);
    const secp256k1_pubkey *arr[2] = {
      &P1,
      &N2
    };
    if (!secp256k1_ec_pubkey_combine(ctx_local, &R, arr, 2)) {
      continue;
    }
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx_local, pub_res, &len, &R, SECP256K1_EC_COMPRESSED);
    if (is_pub_zero(pub_res)) continue;

    pubkey_to_hex(pub_res, hex);
    mpz_get_str(s_iter, 10, it); // Konversi iter ke string
    append_record(out, hex, s_rn, s_iter);
  }

  mpz_clears(it, offset, actual_max, range_size, NULL);
}
// --- AKHIR FUNGSI YANG DIPERBAIKI ---

void *Worker_generator(range_ctx *ctx, secp256k1_context *ctx_local, gmp_randstate_t rng) {
  mpz_t step,
  start,
  end,
  nmax;
  mpz_inits(step, start, end, nmax, NULL);

  size_t dmax = 0;
  if (!parse_range_and_step(ctx, start, end, step, nmax, &dmax)) {
    log_msg(LOG_WARN, ctx->name, "Invalid range");
    mpz_clears(step, start, end, nmax, NULL);
    return NULL;
  }
  update_global_digit_max(dmax);

  mpz_t iter_min,
  iter_max;
  mpz_inits(iter_min, iter_max, NULL);
  compute_iter_bounds(iter_min, iter_max, nmax, CFG.digit_min);

  if (CFG.digit_min <= 0 && dmax > 0) {
    mpz_t min_by_dmax;
    mpz_init(min_by_dmax);
    mpz_ui_pow_ui(min_by_dmax, 10, dmax - 1);
    if (mpz_cmp(iter_min, min_by_dmax) < 0) {
      if (mpz_cmp(min_by_dmax, nmax) <= 0) {
        char *old_min = mpz_get_str(NULL, 10, iter_min);
        char *new_min = mpz_get_str(NULL, 10, min_by_dmax);
        log_msg(LOG_INFO, ctx->name, "Adjusting iter_min from %s to %s (digit_max=%zu)", old_min, new_min, dmax);
        free(old_min);
        free(new_min);
        mpz_set(iter_min, min_by_dmax);
      }
    }
    mpz_clear(min_by_dmax);
  }

  if (mpz_cmp(iter_min, iter_max) > 0) {
    char *s_min = mpz_get_str(NULL, 10, iter_min);
    char *s_max = mpz_get_str(NULL, 10, iter_max);
    log_msg(LOG_WARN, ctx->name, "iter_min(%s) > iter_max(%s), clamping to iter_max", s_min, s_max);
    free(s_min);
    free(s_max);
    mpz_set(iter_min, iter_max);
  }

  memout_t *out = init_output_buffer();
  if (!out) {
    log_msg(LOG_ERROR, ctx->name, "Failed to allocate output buffer");
    mpz_clears(step, start, end, nmax, iter_min, iter_max, NULL);
    return NULL;
  }

  unsigned char pub_start[33],
  pub_ref[33];
  compute_pub_start_and_ref(ctx_local, start, pub_start, pub_ref);

  unsigned long total = CFG.group_size;
  unsigned long *order = make_shuffle_order(total, rng);
  if (!order) {
    log_msg(LOG_ERROR, ctx->name, "Failed to create shuffle order");
    free(out->buf);
    free(out);
    mpz_clears(step, start, end, nmax, iter_min, iter_max, NULL);
    return NULL;
  }

  mpz_t step_iter,
  range_span;
  mpz_inits(step_iter, range_span, NULL);
  compute_iter_step(iter_min, iter_max, step_iter, range_span, total);

  char s_rn[64];
  snprintf(s_rn, sizeof(s_rn) - 1, "%s", ctx->name + 1);
  s_rn[sizeof(s_rn) - 1] = '\0';

  calc_mpz(out, ctx_local, rng, total, order, iter_min, iter_max, step_iter, pub_ref, s_rn);

  free(order);
  mpz_clears(step, start, end, nmax, iter_min, iter_max, step_iter, range_span, NULL);
  return out;
}

void *worker_thread(void *arg) {
  worker_arg_t *wa = (worker_arg_t *)arg;

  secp256k1_context *ctx_local = secp256k1_context_clone(CTX);
  gmp_randstate_t rng;
  gmp_randinit_default(rng);
  gmp_randseed_ui(rng, (unsigned long)(time(NULL) ^ (uintptr_t)pthread_self()));

  size_t total = wa->total;
  size_t idx;
  while (1) {
    if (g_shutdown_requested || g_threads_should_exit) {
      log_msg(LOG_WARN, "WORKER", "Thread exiting due to shutdown request");
      break;
    }
    unsigned long long next = __sync_fetch_and_add(&CUR_IDX, 1);
    if (next >= total || next == ULLONG_MAX) {
      break;
    }
    idx = (size_t)next;

    memout_t *res = Worker_generator(&wa->ranges[idx], ctx_local, rng);
    if (!res || res->len == 0) {
      if (res) {
        free(res->buf);
        free(res);
      }
      continue;
    }

    pthread_mutex_lock(wa->f_lock);
    char *ptr = res->buf;
    char *end = res->buf + res->len;
    while (ptr < end) {
      char *nl = memchr(ptr, '\n', end - ptr);
      if (!nl) break;
      size_t len = nl - ptr + 1;
      fwrite(ptr, 1, len, wa->fout);
      PUB_LINE_COUNT++;
      if (PUB_LINE_COUNT >= CFG.max_pubhasil_lines) {
        fclose(wa->fout);
        wa->fout = open_new_pubfile();
      }
      ptr = nl + 1;
    }
    pthread_mutex_unlock(wa->f_lock);

    free(res->buf);
    free(res);
  }

  gmp_randclear(rng);
  secp256k1_context_destroy(ctx_local);
  return NULL;
}

FILE* open_new_pubfile(void) {
  char fname[256];
  snprintf(fname, sizeof(fname), "pubhasil/%s_%d.txt", CFG.PUBHASIL_PATH, PUB_FILE_INDEX);
  PUB_FILE_INDEX++;
  FILE *f = fopen(fname, "w");
  if (!f) {
    perror("open pubhasil split");
    exit(1);
  }
  PUB_LINE_COUNT = 0;
  return f;
}

static void signal_handler(int signum) {
  if (g_shutdown_requested == 0) {
    g_shutdown_requested = 1;
    g_threads_should_exit = 1;
    pthread_mutex_lock(&global_log_lock);
    fprintf(stderr, "\n%s[ SIGNAL    ] Received signal %d. Shutting down gracefully...%s\n", CLR_YELLOW, signum, CLR_RESET);
    pthread_mutex_unlock(&global_log_lock);
    save_checkpoint(&CP);
    __atomic_store_n(&CUR_IDX, ULLONG_MAX, __ATOMIC_SEQ_CST);
  }
  static int force_exit_count = 0;
  force_exit_count++;
  if (force_exit_count >= 2) {
    pthread_mutex_lock(&global_log_lock);
    fprintf(stderr, "%s[ FORCE     ] Force exiting...%s\n", CLR_RED, CLR_RESET);
    pthread_mutex_unlock(&global_log_lock);
    exit(1);
  }
}

void generate_pubhasil(range_ctx *ranges, const mpz_t count_mpz) {
  struct sigaction sa;
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  mkdir("pubhasil", 0777);
  clean_pubhasil_folder();

  PUB_FILE_INDEX = 1;
  if (!mpz_fits_ulong_p(count_mpz)) {
    log_msg(LOG_ERROR, "OVERFLOW", "count_mpz terlalu besar untuk dialokasikan sebagai array.");
    return;
  }
  size_t total = (size_t) mpz_get_ui(count_mpz);
  if (total == 0) {
    log_msg(LOG_WARN, "PUBHASIL", "Total ranges = 0, nothing to generate");
    return;
  }

  int cores = sysconf(_SC_NPROCESSORS_ONLN);
  if (cores < 2) cores = 2;
  if (cores > 16) cores = 16;

  current_pub_file = open_new_pubfile();
  if (!current_pub_file) {
    log_msg(LOG_ERROR, "FILE", "Failed to open pubhasil file");
    return;
  }
  setvbuf(current_pub_file, NULL, _IOFBF, 64 * 1024 * 1024);

  CUR_IDX = 0;
  pthread_t *th = malloc(sizeof(pthread_t) * cores);
  if (!th) {
    log_msg(LOG_ERROR, "MEM", "Failed to allocate thread pool");
    fclose(current_pub_file);
    return;
  }

  pthread_mutex_t f_lock;
  if (pthread_mutex_init(&f_lock, NULL) != 0) {
    log_msg(LOG_ERROR, "THREAD", "Failed to init mutex");
    free(th);
    fclose(current_pub_file);
    return;
  }

  worker_arg_t wa = {
    ranges,
    total,
    current_pub_file,
    &f_lock
  };

  log_msg(LOG_SECTION, "THREADPOOL", "Launching %d threads for %zu ranges", cores, total);
  for (int i = 0; i < cores; i++) {
    if (pthread_create(&th[i], NULL, worker_thread, &wa) != 0) {
      log_msg(LOG_ERROR, "THREAD", "Failed to create thread %d", i);
      cores = i;
      break;
    }
  }

  size_t last = 0;
  size_t step = (total / 50);
  if (step < 1) step = 1;
  while (!g_shutdown_requested) {
    size_t cur = __atomic_load_n(&CUR_IDX, __ATOMIC_SEQ_CST);
    if (cur >= total) break;
    if (cur - last >= step) {
      double pct = (100.0 * cur) / (double) total;
      log_progress_bar(pct, cur, total);
      last = cur;
    }
    usleep(100000);
  }

  if (g_shutdown_requested) {
    log_msg(LOG_WARN, "SHUTDOWN", "Shutdown requested. Saving checkpoint...");
    save_checkpoint(&CP);
  }

  size_t timeout = 0;
  while (__atomic_load_n(&CUR_IDX, __ATOMIC_SEQ_CST) < total && timeout < 30) {
    usleep(1000000);
    timeout++;
    if (timeout >= 30) {
      log_msg(LOG_WARN, "TIMEOUT", "Timeout waiting for threads to complete");
      break;
    }
  }

  log_progress_bar(100.0, total, total);

  for (int i = 0; i < cores; i++) {
    if (th[i]) {
      pthread_join(th[i], NULL);
    }
  }
  fprintf(stderr, "\n");
  fflush(stderr);
  fflush(stdout);

  pthread_mutex_destroy(&f_lock);
  if (current_pub_file) {
    fclose(current_pub_file);
    current_pub_file = NULL;
  }
  free(th);

  log_msg(LOG_SUCCESS, "PUBHASIL", "Generated %zu ranges", total);
}

bool run_keyhunt_and_monitor(void) {
  log_msg(LOG_INFO, "KEYHUNT", "Starting external keyhunt process...");
  FILE *pipe = popen(CFG.KEYHUNT_CMD, "r");
  if (!pipe) {
    log_msg(LOG_ERROR, "KEYHUNT", "Failed to start keyhunt command!");
    return false;
  }

  regex_t re_kf;
  regcomp(&re_kf, "\\[KF\\] PRIV=([0-9A-Fa-f]+) PUB=([0-9A-Fa-f]+)", REG_EXTENDED | REG_ICASE);
  regex_t re_file;
  regcomp(&re_file, "\\] ([^ ]+\\.txt)", REG_EXTENDED);

  static char current_pubhasil_file[256] = {
    0
  };

  FILE *logfound = fopen("foundkey.txt", "a");
  FILE *privout = fopen(CFG.HASILPRIV_PATH, "a");

  char line[1024];
  while (fgets(line, sizeof(line), pipe)) {
    fputs(line, stdout);

    regmatch_t fm[2];
    if (regexec(&re_file, line, 2, fm, 0) == 0) {
      int len = fm[1].rm_eo - fm[1].rm_so;
      snprintf(current_pubhasil_file, sizeof(current_pubhasil_file), "%.*s", len, line + fm[1].rm_so);
      log_msg(LOG_INFO, "KEYHUNT", "Active pubhasil: %s", current_pubhasil_file);
      continue;
    }

    regmatch_t km[3];
    if (regexec(&re_kf, line, 3, km, 0) != 0) continue;

    char priv_small_hex[128] = {
      0
    };
    char pub_hex_in[128] = {
      0
    };
    snprintf(priv_small_hex, sizeof(priv_small_hex), "%.*s", (int)(km[1].rm_eo - km[1].rm_so), line + km[1].rm_so);
    snprintf(pub_hex_in, sizeof(pub_hex_in), "%.*s", (int)(km[2].rm_eo - km[2].rm_so), line + km[2].rm_so);

    if (current_pubhasil_file[0] == 0) {
      log_msg(LOG_WARN, "KEYHUNT", "Cannot reconstruct — no active pubhasil detected!");
      continue;
    }

    FILE *f = fopen(current_pubhasil_file, "r");
    if (!f) {
      log_msg(LOG_WARN, "FILE", "Cannot open pubhasil: %s", current_pubhasil_file);
      continue;
    }

    char buf[512];
    char pubhex[128],
    rn_str[128],
    iter_str[128];
    while (fgets(buf, sizeof(buf), f)) {
      if (!strchr(buf, '|')) continue;
      int n = sscanf(buf, "%127[^|]|%127[^|]|%127s", pubhex, rn_str, iter_str);
      if (n != 3) continue;
      if (strcasestr(pubhex, pub_hex_in) == NULL) continue;

      char range_name[128];
      snprintf(range_name, sizeof(range_name), "R%s", rn_str);
      const char *start_hex = NULL;
      unsigned long total = mpz_get_ui(CFG.range_count);
      for (unsigned long i = 0; i < total; i++) {
        if (!strcasecmp(CFG.ranges[i].name, range_name)) {
          start_hex = CFG.ranges[i].start_hex;
          break;
        }
      }

      mpz_t start,
      iter_bn,
      priv_small,
      k_target,
      tmp;
      mpz_inits(start, iter_bn, priv_small, k_target, tmp, NULL);

      ensure_step_mpz_ready();
      init_curve_order();

      mpz_set_str(iter_bn, iter_str, 10);
      mpz_set_str(priv_small, priv_small_hex, 16);
      if (!start_hex) mpz_set_ui(start, 0); else mpz_set_str(start, start_hex, 16);

      mpz_mul(tmp, STEP_MPZ, iter_bn);
      mpz_add(k_target, start, tmp);
      mpz_add(k_target, k_target, priv_small);
      mpz_mod(k_target, k_target, CURVE_ORDER);

      if (logfound) {
        gmp_fprintf(logfound, "[FOUND] PRIV=%Zx PUB=%s RANGE=%s ITER=%s STEP=%s\n", k_target, pub_hex_in, range_name, iter_str, CFG.STEP_HEX);
        fflush(logfound);
      }
      if (privout) {
        gmp_fprintf(privout, "[PRIVKEY] %Zx | PUB=%s | RANGE=%s | ITER=%s | STEP=%s\n", k_target, pub_hex_in, range_name, iter_str, CFG.STEP_HEX);
        fflush(privout);
      }

      pthread_mutex_lock(&global_log_lock);
      gmp_printf("\n");
      printf("┌────────────────────────────── FOUND ───────────────────────────────┐\n");
      gmp_printf("│ ✓ PRIV=%Zx | Rn=%s | iter=%s\n", k_target, rn_str, iter_str);
      printf("└────────────────────────────────────────────────────────────────────┘\n");
      pthread_mutex_unlock(&global_log_lock);

      mpz_clears(start, iter_bn, priv_small, k_target, tmp, NULL);
      break;
    }
    fclose(f);
  }
  pclose(pipe);

  if (logfound) fclose(logfound);
  if (privout) fclose(privout);

  regfree(&re_kf);
  regfree(&re_file);
  log_msg(LOG_SUCCESS, "KEYHUNT", "Process completed & all results saved.");
  return true;
}

static void init_global_context(void) {
  CTX = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  gmp_randinit_default(RNG_STATE);
  gmp_randseed_ui(RNG_STATE, (unsigned long)(time(NULL) ^ getpid()));
  srand((unsigned int)(time(NULL) ^ getpid()));

  load_config("config.txt", &CFG);
  clean_pubhasil_folder();
  load_override_files();
  init_step_precompute();
  init_curve_order();
  ensure_step_mpz_ready();
}

static int validate_Pub_Target(void) {
  size_t len = strlen(CFG.PUBKEY_TARGET);
  if (len != 66) {
    log_msg(LOG_ERROR, "MAIN", "PUBKEY_TARGET harus 66 karakter hex. Panjang saat ini: %zu", len);
    return 0;
  }
  for (int i = 0; i < 33; i++) {
    if (sscanf(CFG.PUBKEY_TARGET + 2*i, "%2hhx", &PUB_TARGET[i]) != 1) {
      log_msg(LOG_ERROR, "MAIN", "Invalid hex format at byte %d", i);
      return 0;
    }
  }
  if (!secp256k1_ec_pubkey_parse(CTX, &PUB_TARGET_OBJ, PUB_TARGET, 33)) {
    log_msg(LOG_ERROR, "MAIN", "Invalid PubkeyTarget!");
    return 0;
  }
  return 1;
}

static void preview_range_split(void) {
  log_header("RANGE SPLIT PREVIEW");
  gmp_printf(CLR_CYAN "Total Subrange (virtual): %Zd\n" CLR_RESET, CFG.Number_R);
  range_ctx demo;
  mpz_init(demo.index);
  mpz_set_ui(demo.index, 0);
  compute_range_by_index(&CFG, demo.index, &demo);
  log_msg(LOG_INFO, "RANGE", "%s: %s → %s", demo.name, demo.start_hex, demo.end_hex);
  mpz_clear(demo.index);
}

void log_batch_info_pure(mpz_t batch, mpz_t worker_r) {
  mpz_t mult;
  mpz_init(mult);
  mpz_add_ui(mult, batch, 3);
  char *s_b = mpz_get_str(NULL, 10, batch);
  char *s_wr = mpz_get_str(NULL, 10, worker_r);
  char *s_m = mpz_get_str(NULL, 10, mult);
  log_msg(LOG_INFO, "BATCH", "Batch=%s | worker_r=%s | mult=%s", s_b, s_wr, s_m);
  free(s_b);
  free(s_wr);
  free(s_m);
  mpz_clear(mult);
}

void update_batch_and_multiplier_pure(mpz_t batch) {
  mpz_t mult;
  mpz_init(mult);
  mpz_add_ui(mult, batch, 3);
  mpz_add_ui(CP.done_r, CP.done_r, (size_t)mpz_get_ui(CP.worker_r));
  mpz_add_ui(batch, batch, 1);
  mpz_set(CP.batch, batch);
  mpz_set(CP.multiplier, mult);
  save_checkpoint(&CP);
  mpz_clear(mult);
}

void cleanup_ranges(range_ctx* ranges, size_t count) {
  for (size_t i = 0; i < count; i++) {
    mpz_clear(ranges[i].index);
  }
  free(ranges);
}

static void run_pure_random_mode(void) {
  log_msg(LOG_INFO, "MODE", "PureRandom Mode Active");
  mpz_t batch;
  mpz_init_set(batch, CP.batch);

  while (!g_shutdown_requested) {
    if (!mpz_fits_ulong_p(CP.worker_r)) {
      log_msg(LOG_ERROR, "OVERFLOW", "worker_r terlalu besar.");
      exit(1);
    }
    size_t worker_count = (size_t)mpz_get_ui(CP.worker_r);

    log_batch_info_pure(batch, CP.worker_r);

    if (g_shutdown_requested) break;

    range_ctx *ranges = calloc(worker_count, sizeof(range_ctx));
    for (size_t i = 0; i < worker_count; i++) mpz_init(ranges[i].index);

    generate_rn_parallel(ranges, CP.worker_r, CFG.Number_R, 8);

    if (g_shutdown_requested) {
      cleanup_ranges(ranges, worker_count);
      break;
    }

    mpz_set_ui(CFG.range_count, worker_count);
    CFG.ranges = ranges;

    generate_pubhasil(ranges, CP.worker_r);
    if (!g_shutdown_requested) run_keyhunt_and_monitor();

    if (RN_FULL) {
      for (size_t i = 0; i < RN_FULL_COUNT; i++) mpz_clear(RN_FULL[i]);
      free(RN_FULL);
      RN_FULL = NULL;
      RN_FULL_COUNT = 0;
    }

    if (!g_shutdown_requested) {
      update_batch_and_multiplier_pure(batch);
    }

    cleanup_ranges(ranges, worker_count);

    if (!g_shutdown_requested) {
      for (int i = 0; i < 10 && !g_shutdown_requested; i++) {
        usleep(100000);
      }
    }
  }
  mpz_clear(batch);
  if (g_shutdown_requested) {
    log_msg(LOG_WARN, "EXIT", "PureRandom mode terminated by user");
  }
}

void handle_sequential_cycle_reset(mpz_t batch) {
  log_msg(LOG_INFO, "SEQ", "Finished one full cycle. Resetting done_r to 0.");
  mpz_set_ui(CP.done_r, 0);
  mpz_add_ui(batch, batch, 1);
  mpz_set(CP.batch, batch);
  if (!g_shutdown_requested) save_checkpoint(&CP);
}

void log_batch_info_seq(mpz_t batch, mpz_t start_r, mpz_t end_r, mpz_t total_r) {
  char *b = mpz_get_str(NULL, 10, batch);
  char *s1 = mpz_get_str(NULL, 10, start_r);
  char *s2 = mpz_get_str(NULL, 10, end_r);
  char *t = mpz_get_str(NULL, 10, total_r);
  log_msg(LOG_INFO, "BATCH", "Sequential batch=%s | startIdx=%s | endIdx=%s | total=%s", b, s1, s2, t);
  free(b); free(s1); free(s2); free(t);
}

void update_batch_and_multiplier_seq(mpz_t batch, size_t idx) {
  mpz_add_ui(CP.done_r, CP.done_r, idx);
  mpz_add_ui(batch, batch, 1);
  mpz_set(CP.batch, batch);
  mpz_set_ui(CP.multiplier, 1);
  save_checkpoint(&CP);
}

static void run_sequential_mode(void) {
  log_msg(LOG_INFO, "MODE", "Sequential Mode used (Looping Infinite)");
  mpz_t batch;
  mpz_init_set(batch, CP.batch);

  while (!g_shutdown_requested) {
    mpz_t start_r,
    end_r,
    total_r,
    total_minus1;
    mpz_inits(start_r, end_r, total_r, total_minus1, NULL);

    mpz_set(total_r, CP.number_r);
    mpz_set(start_r, CP.done_r);

    if (mpz_cmp(start_r, total_r) >= 0) {
      handle_sequential_cycle_reset(batch);
      mpz_clears(start_r, end_r, total_r, total_minus1, NULL);
      if (g_shutdown_requested) break;
      continue;
    }

    mpz_add(end_r, start_r, CP.worker_r);
    mpz_sub_ui(end_r, end_r, 1);
    mpz_sub_ui(total_minus1, total_r, 1);
    if (mpz_cmp(end_r, total_minus1) > 0) mpz_set(end_r, total_minus1);

    if (!mpz_fits_ulong_p(CP.worker_r)) {
      log_msg(LOG_ERROR, "OVERFLOW", "CP.worker_r terlalu besar.");
      exit(1);
    }
    size_t worker_count = (size_t) mpz_get_ui(CP.worker_r);

    log_batch_info_seq(batch, start_r, end_r, total_r);

    if (g_shutdown_requested) {
      mpz_clears(start_r, end_r, total_r, total_minus1, NULL);
      break;
    }

    range_ctx *ranges = calloc(worker_count, sizeof(range_ctx));
    for (size_t i = 0; i < worker_count; i++) mpz_init(ranges[i].index);

    mpz_t cur;
    mpz_init_set(cur, start_r);
    size_t idx = 0;
    while (mpz_cmp(cur, end_r) <= 0 && idx < worker_count && !g_shutdown_requested) {
      compute_range_by_index(&CFG, cur, &ranges[idx]);
      mpz_add_ui(cur, cur, 1);
      idx++;
    }
    mpz_clear(cur);

    mpz_set_ui(CFG.range_count, idx);
    CFG.ranges = ranges;

    if (g_shutdown_requested) {
      cleanup_ranges(ranges, worker_count);
      mpz_clears(start_r, end_r, total_r, total_minus1, NULL);
      break;
    }

    generate_pubhasil(ranges, CFG.range_count);
    if (!g_shutdown_requested) run_keyhunt_and_monitor();

    if (RN_FULL) {
      for (size_t i = 0; i < RN_FULL_COUNT; i++) mpz_clear(RN_FULL[i]);
      free(RN_FULL);
      RN_FULL = NULL;
      RN_FULL_COUNT = 0;
    }

    if (!g_shutdown_requested) {
      update_batch_and_multiplier_seq(batch, idx);
    }

    cleanup_ranges(ranges, worker_count);

    mpz_clears(start_r, end_r, total_r, total_minus1, NULL);

    if (!g_shutdown_requested) {
      for (int i = 0; i < 10 && !g_shutdown_requested; i++) {
        usleep(100000);
      }
    }
  }
  mpz_clear(batch);
  if (g_shutdown_requested) {
    log_msg(LOG_WARN, "EXIT", "Sequential mode terminated by user");
  }
}

static void cleanup_all(void) {
  secp256k1_context_destroy(CTX);
  gmp_randclear(RNG_STATE);

  if (OVERRIDE_RN) {
    for (unsigned long i = 0; i < OVR_RN_COUNT; i++) mpz_clear(OVR_RN_LIST[i]);
    free(OVR_RN_LIST);
  }
  if (OVERRIDE_ITER) {
    for (unsigned long i = 0; i < OVR_ITER_COUNT; i++) mpz_clear(OVR_ITER_LIST[i]);
    free(OVR_ITER_LIST);
  }

  mpz_clears(CP.range_min, CP.range_max, CP.number_r, CP.done_r, CP.worker_r, CP.batch, CP.multiplier, NULL);
  log_header("EXIT");
  log_msg(LOG_SUCCESS, "MAIN", "Program finished");
}

int main() {
  struct sigaction sa_int,
  sa_term;
  memset(&sa_int, 0, sizeof(sa_int));
  sa_int.sa_handler = signal_handler;
  sigemptyset(&sa_int.sa_mask);
  sa_int.sa_flags = SA_RESTART;
  sigaction(SIGINT, &sa_int, NULL);

  memset(&sa_term, 0, sizeof(sa_term));
  sa_term.sa_handler = signal_handler;
  sigemptyset(&sa_term.sa_mask);
  sa_term.sa_flags = SA_RESTART;
  sigaction(SIGTERM, &sa_term, NULL);

  signal(SIGPIPE, SIG_IGN);

  init_global_context();
  if (!validate_Pub_Target()) return 1;

  load_checkpoint(&CFG);
  preview_range_split();

  if (g_shutdown_requested) {
    log_msg(LOG_WARN, "MAIN", "Shutdown requested before starting work");
    cleanup_all();
    return 0;
  }

  if (CFG.random_pure) {
    run_pure_random_mode();
  } else {
    run_sequential_mode();
  }

  cleanup_all();
  log_msg(LOG_SUCCESS, "MAIN", "Program completed %s", g_shutdown_requested ? " (user interrupted)": "successfully");
  return g_shutdown_requested ? 130: 0;
}