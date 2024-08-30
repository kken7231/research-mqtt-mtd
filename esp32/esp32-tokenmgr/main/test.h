#include "tokenmgr.h"

int plain_none(long start_time, int num_tokens_divided_by_multiplier, int iter);
int plain_aead(long start_time, int num_tokens_divided_by_multiplier, int iter);
int tls(long start_time, int iter);
