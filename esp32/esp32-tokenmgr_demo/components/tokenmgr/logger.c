#include "tokenmgr.h"

int permit_time_logging = 0;
static const char *TAG = "tokenmgr_logger";

#ifdef COMPILEROPT_INCLUDE_TIME_LOG

extern tokenmgr_state_t current_state;
#define TIME_RECORD_STORE_MAX 1024
static time_record_t time_record_store[TIME_RECORD_STORE_MAX];
static int time_record_store_count = 0;
#define HIER_INDENT 4

void log_time(time_record_type_t record_type, const char *label) {
	if (current_state != TOKENMGR_STATE_OPERTATIONAL || permit_time_logging == 0) return;
	if (time_record_store_count < TIME_RECORD_STORE_MAX) {
		time_record_store[time_record_store_count].record_type = record_type;
		gettimeofday(&time_record_store[time_record_store_count].timestamp, NULL);
		time_record_store[time_record_store_count].label = strdup(label);
		if (time_record_store[time_record_store_count].label == NULL) {
			fprintf(stderr, "Memory allocation failed\n");
			exit(1);
		}
		time_record_store_count++;
	} else {
		fprintf(stderr, "Time logging failed due to insufficient space in time_record_store\n");
	}
}

void print_time_record_summary(void) {
	printf("Time Record Summary:\n");
	printf("====================\n");
	char time_string[26];
	int hier_prefix_len = 0;
	const int hier_prefix_indent = 4;
	time_t ts_sec;
	long ts_usec;
	struct tm *tm_info;
	for (int i = 0; i < time_record_store_count; i++) {
		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_ENDED && hier_prefix_len > 0) {
			hier_prefix_len -= hier_prefix_indent;
		}
		ts_sec = time_record_store[i].timestamp.tv_sec;
		ts_usec = time_record_store[i].timestamp.tv_usec;

		tm_info = localtime(&ts_sec);
		strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", tm_info);

		const char *suffix = "";
		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_STARTED) {
			suffix = " started";
		} else if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_ENDED) {
			suffix = " ended";
		}

		int indent_len = time_record_store[i].record_type == TIME_RECORD_TYPE_UNDEFINED ? 0 : hier_prefix_len;
		printf("%s.%06ld %*s%s%s",
			   time_string, ts_usec,
			   indent_len, "",
			   time_record_store[i].label, suffix);

		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_ENDED) {
			for (int j = i - 1; j >= 0; j--) {
				if (time_record_store[j].record_type == TIME_RECORD_TYPE_FUNC_STARTED &&
					strcmp(time_record_store[j].label, time_record_store[i].label) == 0) {
					long elapsed_sec = time_record_store[i].timestamp.tv_sec - time_record_store[j].timestamp.tv_sec;
					long elapsed_usec = time_record_store[i].timestamp.tv_usec - time_record_store[j].timestamp.tv_usec;
					if (elapsed_usec < 0) {
						elapsed_sec -= 1;
						elapsed_usec += 1000000;
					}
					printf(" (%ld.%06ld seconds)", elapsed_sec, elapsed_usec);
					break;
				}
			}
		}
		printf("\n");

		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_STARTED) {
			hier_prefix_len += hier_prefix_indent;
		}
	}
	printf("====================\n");
}

void reset_time_record_store(void) {
	for (int i = 0; i < time_record_store_count; i++) {
		if (time_record_store[i].label) {
			free((void *)time_record_store[i].label);
			time_record_store[i].label = NULL;
		}
	}
	time_record_store_count = 0;
}
#else
void print_time_record_summary(void) {};
void reset_time_record_store(void) {};
#endif
