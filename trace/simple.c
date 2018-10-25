/*
 * Simple trace backend
 *
 * Copyright IBM, Corp. 2010
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#ifndef _WIN32
#include <pthread.h>
#endif
#include "qemu/timer.h"
#include "trace/control.h"
#include "trace/simple.h"
#include "qemu/error-report.h"

/** Trace file header event ID, picked to avoid conflict with real event IDs */
#define HEADER_EVENT_ID (~(uint64_t)0)

/** Trace file magic number */
#define HEADER_MAGIC 0xf2b177cb0aa429b4ULL

/** Trace file version number, bump if format changes */
#define HEADER_VERSION 4

/** Records were dropped event ID */
#define DROPPED_EVENT_ID (~(uint64_t)0 - 1)

/** Trace record is valid */
#define TRACE_RECORD_VALID ((uint64_t)1 << 63)

/*
 * Trace records are written out by a dedicated thread.  The thread waits for
 * records to become available, writes them out, and then waits again.
 */
static GMutex trace_lock;
// static GMutex orenmn_monitor_cmds_lock;
static GCond trace_available_cond;
static GCond trace_empty_cond;

static bool trace_available;
static bool trace_writeout_enabled;

enum {
    TRACE_BUF_LEN = 4096 * 64,
    TRACE_BUF_FLUSH_THRESHOLD = TRACE_BUF_LEN / 4,
};

uint8_t trace_buf[TRACE_BUF_LEN];
static volatile gint trace_idx;
static unsigned int writeout_idx;
static volatile gint dropped_events;
static uint32_t trace_pid;
static FILE *trace_fp;
static FILE *sanity_fp;
static char *trace_file_name;

static uint32_t orenmn_num_of_GMBEs_to_our_buf_not_written_to_trace_file = 0;
// SEO = Single Event Optimization
static volatile gint orenmn_SEO_num_of_events_written_to_trace_file = 0;
static volatile gint orenmn_num_of_events_written_to_trace_buf_since_SEO_enabled = 0;
static bool orenmn_single_event_optimization = false;
static bool orenmn_trace_only_user_code_GMBE = false;
static int orenmn_log_of_GMBE_block_len = 0;
static int orenmn_log_of_GMBE_tracing_ratio = 0;
static volatile gpointer orenmn_GMBE_idx = 0;
static uint64_t orenmn_mask_of_GMBE_idx_in_GMBE_block = 0;
static uint64_t orenmn_mask_of_GMBE_block_idx = 0;
static uint32_t orenmn_SEO_trace_record_size = 0;
static int * orenmn_our_buf_addr = 0;

#define TRACE_RECORD_TYPE_MAPPING 0
#define TRACE_RECORD_TYPE_EVENT   1

/* * Trace buffer entry */
typedef struct {
    uint64_t event; /* event ID value */
    uint64_t timestamp_ns;
    uint32_t length;   /*    in bytes */
    uint32_t pid;
    uint64_t arguments[];
} TraceRecord;

/* * orenmn: Trace buffer entry in case of single_event_optimization */
typedef struct {
    uint64_t event; /* event ID value */
    uint64_t padding; /* because the size of the struct must be a power of 2 */
    uint64_t arguments[];
} orenmn_OptimizedTraceRecord;

typedef struct {
    uint64_t header_event_id; /* HEADER_EVENT_ID */
    uint64_t header_magic;    /* HEADER_MAGIC    */
    uint64_t header_version;  /* HEADER_VERSION  */
} TraceLogHeader;


static void read_from_buffer(unsigned int idx, void *dataptr, size_t size);
static unsigned int write_to_buffer(unsigned int idx, void *dataptr, size_t size);

static void clear_buffer_range(unsigned int idx, size_t len)
{
    uint32_t num = 0;
    while (num < len) {
        if (idx >= TRACE_BUF_LEN) {
            idx = idx % TRACE_BUF_LEN;
        }
        trace_buf[idx++] = 0;
        num++;
    }
}
/**
 * Read a trace record from the trace buffer
 *
 * @idx         Trace buffer index
 * @record      Trace record to fill
 *
 * Returns false if the record is not valid.
 */
static bool get_trace_record(unsigned int idx, TraceRecord **recordptr)
{
    uint64_t event_flag = 0;
    TraceRecord record;
    /* read the event flag to see if its a valid record */
    read_from_buffer(idx, &record, sizeof(event_flag));

    if (!(record.event & TRACE_RECORD_VALID)) {
        return false;
    }

    smp_rmb(); /* read memory barrier before accessing record */
    /* read the record header to know record length */
    read_from_buffer(idx, &record, sizeof(TraceRecord));
    *recordptr = malloc(record.length); /* don't use g_malloc, can deadlock when traced */
    /* make a copy of record to avoid being overwritten */
    read_from_buffer(idx, *recordptr, record.length);
    smp_rmb(); /* memory barrier before clearing valid flag */
    (*recordptr)->event &= ~TRACE_RECORD_VALID;
    /* clear the trace buffer range for consumed record otherwise any byte
     * with its MSB set may be considered as a valid event id when the writer
     * thread crosses this range of buffer again.
     */
    clear_buffer_range(idx, record.length);
    return true;
}

/**
 * Kick writeout thread
 *
 * @wait        Whether to wait for writeout thread to complete
 */
static void flush_trace_file(bool wait)
{
    g_mutex_lock(&trace_lock);
    trace_available = true;
    g_cond_signal(&trace_available_cond);

    if (wait) {
        g_cond_wait(&trace_empty_cond, &trace_lock);
        printf("flush_trace_file(true)\n");
    }


    g_mutex_unlock(&trace_lock);
}

static void wait_for_trace_records_available(void)
{
    g_mutex_lock(&trace_lock);
    while (!(trace_available && trace_writeout_enabled)) {
        g_cond_signal(&trace_empty_cond);
        g_cond_wait(&trace_available_cond, &trace_lock);
    }
    trace_available = false;
    g_mutex_unlock(&trace_lock);
}

void orenmn_set_our_buf_address(int *buf_addr) {
    // g_mutex_lock(&orenmn_monitor_cmds_lock);

    orenmn_our_buf_addr = buf_addr;

    // g_mutex_unlock(&orenmn_monitor_cmds_lock);
}

void orenmn_update_trace_only_user_code_GMBE(bool flag) {
    // g_mutex_lock(&orenmn_monitor_cmds_lock);

    orenmn_trace_only_user_code_GMBE = flag;

    // g_mutex_unlock(&orenmn_monitor_cmds_lock);
}

/* Assumes that both log_of_GMBE_block_len and log_of_GMBE_tracing_ratio are
   in [0, 64]. */
static void orenmn_set_log_of_GMBE_block_len_and_log_of_GMBE_tracing_ratio(
    int log_of_GMBE_block_len, int log_of_GMBE_tracing_ratio)
{
    orenmn_log_of_GMBE_block_len = log_of_GMBE_block_len;
    orenmn_log_of_GMBE_tracing_ratio = log_of_GMBE_tracing_ratio;
    if (log_of_GMBE_block_len + log_of_GMBE_tracing_ratio > 64) {
        error_report("log_of_GMBE_block_len + log_of_GMBE_tracing_ratio must "
                     "be in [0, 64].");
        return;
    }
    orenmn_mask_of_GMBE_idx_in_GMBE_block = (1 << log_of_GMBE_block_len) - 1;
    orenmn_mask_of_GMBE_block_idx = ((1 << log_of_GMBE_tracing_ratio) - 1) <<
                                    log_of_GMBE_block_len;
    g_atomic_pointer_set(&orenmn_GMBE_idx, 0);

    info_report("orenmn_mask_of_GMBE_idx_in_GMBE_block: %016lx\n"
                "orenmn_mask_of_GMBE_block_idx: %016lx",
                orenmn_mask_of_GMBE_idx_in_GMBE_block,
                orenmn_mask_of_GMBE_block_idx);
}

/* Assumes that log_of_GMBE_block_len is in [0, 64]. */
void orenmn_set_log_of_GMBE_block_len(int log_of_GMBE_block_len) {
    // g_mutex_lock(&orenmn_monitor_cmds_lock);

    orenmn_set_log_of_GMBE_block_len_and_log_of_GMBE_tracing_ratio(
        log_of_GMBE_block_len, orenmn_log_of_GMBE_tracing_ratio);

    // g_mutex_unlock(&orenmn_monitor_cmds_lock);
}

/* Assumes that log_of_GMBE_tracing_ratio is in [0, 64]. */
void orenmn_set_log_of_GMBE_tracing_ratio(int log_of_GMBE_tracing_ratio) {
    // g_mutex_lock(&orenmn_monitor_cmds_lock);

    orenmn_set_log_of_GMBE_block_len_and_log_of_GMBE_tracing_ratio(
        orenmn_log_of_GMBE_block_len, log_of_GMBE_tracing_ratio);

    // g_mutex_unlock(&orenmn_monitor_cmds_lock);
}

void orenmn_print_trace_results(void)
{
    // g_mutex_lock(&orenmn_monitor_cmds_lock);

    uint64_t num_of_GMBE_events = (uint64_t)g_atomic_pointer_get(&orenmn_GMBE_idx);
    info_report("num_of_GMBE_events: %lu", num_of_GMBE_events);

    if (orenmn_single_event_optimization) {
        unsigned int SEO_num_of_events_written_to_trace_buf =
            (uint32_t)g_atomic_int_get(&trace_idx) / orenmn_SEO_trace_record_size;
        if (g_atomic_int_get(&orenmn_num_of_events_written_to_trace_buf_since_SEO_enabled) !=
            SEO_num_of_events_written_to_trace_buf)
        {
            error_report("- - - - - - - - - - ATTENTION - - - - - - - - - -: "
                         "SEO_num_of_events_written_to_trace_buf (%u) != num of events "
                         "orenmn_num_of_events_written_to_trace_buf_since_SEO_enabled (%d). "
                         "smells like a bug.",
                         SEO_num_of_events_written_to_trace_buf,
                         g_atomic_int_get(&orenmn_num_of_events_written_to_trace_buf_since_SEO_enabled));
        }
        unsigned int num_of_events_waiting_in_trace_buf = 0;
        for (unsigned int i = 0; i < TRACE_BUF_LEN; i += orenmn_SEO_trace_record_size) {
            if (((orenmn_OptimizedTraceRecord *)&trace_buf[i])->event &
                TRACE_RECORD_VALID)
            {
                uint64_t virt_addr =
                    ((orenmn_OptimizedTraceRecord *)&trace_buf[i])->arguments[0];
                if (virt_addr >= (uint64_t)orenmn_our_buf_addr &&
                    virt_addr < (uint64_t)orenmn_our_buf_addr + 20000 * sizeof(int))
                {
                    ++orenmn_num_of_GMBEs_to_our_buf_not_written_to_trace_file;
                }
                ++num_of_events_waiting_in_trace_buf;
                // info_report("%u", i);
            }
        }
        info_report("num_of_events_waiting_in_trace_buf: %u",
                    num_of_events_waiting_in_trace_buf);
        unsigned int num_of_missing_events =
            SEO_num_of_events_written_to_trace_buf -
            g_atomic_int_get(&orenmn_SEO_num_of_events_written_to_trace_file) -
            num_of_events_waiting_in_trace_buf;
        if (num_of_missing_events != 0) {
            error_report("- - - - - - - - - - ATTENTION - - - - - - - - - -: "
                         "num_of_missing_events (i.e. "
                         "SEO_num_of_events_written_to_trace_buf - "
                         "orenmn_SEO_num_of_events_written_to_trace_file - "
                         "num_of_events_waiting_in_trace_buf): %u.",
                         num_of_missing_events);
        }
        info_report("SEO_num_of_events_written_to_trace_buf: %d",
                    SEO_num_of_events_written_to_trace_buf);
        if (SEO_num_of_events_written_to_trace_buf != 0) {
            info_report("num_of_GMBE_events / SEO_num_of_events_written_to_trace_buf: %lf",
                        (double)num_of_GMBE_events / SEO_num_of_events_written_to_trace_buf);
        }
    }
    if (orenmn_num_of_GMBEs_to_our_buf_not_written_to_trace_file != 0) {
        info_report("orenmn_num_of_GMBEs_to_our_buf_not_written_to_trace_file: %u",
                    orenmn_num_of_GMBEs_to_our_buf_not_written_to_trace_file);
    }

    int num_of_dropped_events = g_atomic_int_get(&dropped_events);
    if (num_of_dropped_events != 0) {
        warn_report("- - - - - - - - - - ATTENTION - - - - - - - - - -: "
                    "%d events were dropped.", num_of_dropped_events);
    }
    printf("\n"); // orenmn: for my own convenience. shouldn't be here.

    // g_mutex_unlock(&orenmn_monitor_cmds_lock);
}

static gpointer writeout_thread(gpointer opaque)
{
    TraceRecord *recordptr;
    union {
        TraceRecord rec;
        uint8_t bytes[sizeof(TraceRecord) + sizeof(uint64_t)];
    } dropped;
    unsigned int idx = 0;
    int dropped_count;
    size_t unused __attribute__ ((unused));
    uint64_t type = TRACE_RECORD_TYPE_EVENT;

    for (;;) {
        wait_for_trace_records_available();

        if (orenmn_single_event_optimization) {
            /* Just let dropped_events count the number dropped events. */

            uint32_t orenmn_record_size = orenmn_SEO_trace_record_size;
            assert(idx % orenmn_record_size == 0);

            /* We can't call fwrite once for both the end and the beginning of
               trace_buf, so we add this while loop, to prevent a case in which
               TRACE_BUF_FLUSH_THRESHOLD was reached, but there is only a small
               number of trace records at the end of trace_buf, and many at its
               beginning. (recall that trace_buf is a cyclic buffer.) */
            while (((unsigned int)g_atomic_int_get(&trace_idx) - writeout_idx) >
                   TRACE_BUF_FLUSH_THRESHOLD) {
                /* Find the first invalid trace record. We would write all
                   of the records until that one. */
                unsigned int temp_idx = idx;
                /* Dereferencing to get the event field is OK because it is
                   guaranteed that
                   `TRACE_BUF_LEN % orenmn_SEO_trace_record_size == 0`.
                   This also guarantees that when the loop ends,
                   `temp_idx <= TRACE_BUF_LEN`. */
                while (temp_idx < TRACE_BUF_LEN &&
                       (((orenmn_OptimizedTraceRecord *)&trace_buf[temp_idx])->event &
                        TRACE_RECORD_VALID)) {
                    g_atomic_int_inc(&orenmn_SEO_num_of_events_written_to_trace_file);
                    temp_idx += orenmn_record_size;
                }

                unsigned int orenmn_num_of_bytes_to_write = temp_idx - idx;
                size_t fwrite_res;
                // fwrite_res = 1;
                fwrite_res = fwrite(&trace_buf[idx], orenmn_num_of_bytes_to_write,
                                    1, trace_fp);
                if (fwrite_res != 1) {
                    error_report("\nfwrite error! file: %s, line: %u\n\n",
                                 __FILE__, __LINE__);
                    exit(1);
                }
                // Instead of calling `clear_buffer_range`
                // fprintf(sanity_fp, "%p,orenmn_num_of_bytes_to_write\n", &trace_buf[idx]
                //                errno);
                if (idx + orenmn_num_of_bytes_to_write > TRACE_BUF_LEN) {
                    fprintf(sanity_fp, "%p,%u\n", &trace_buf[idx], orenmn_num_of_bytes_to_write);
                }
                assert(idx + orenmn_num_of_bytes_to_write <= TRACE_BUF_LEN);
                memset(&trace_buf[idx], 0, orenmn_num_of_bytes_to_write);

                writeout_idx += orenmn_num_of_bytes_to_write;
                idx = writeout_idx % TRACE_BUF_LEN;
            }
        }
        else {
            assert(!orenmn_single_event_optimization);

            if (g_atomic_int_get(&dropped_events)) {
                dropped.rec.event = DROPPED_EVENT_ID,
                dropped.rec.timestamp_ns = get_clock();
                dropped.rec.length = sizeof(TraceRecord) + sizeof(uint64_t);
                dropped.rec.pid = trace_pid;
                do {
                    dropped_count = g_atomic_int_get(&dropped_events);
                } while (!g_atomic_int_compare_and_exchange(&dropped_events,
                                                            dropped_count, 0));
                dropped.rec.arguments[0] = dropped_count;
                // if (false){
                unused = fwrite(&type, sizeof(type), 1, trace_fp);
                unused = fwrite(&dropped.rec, dropped.rec.length, 1, trace_fp);
                // }
            }

            while (get_trace_record(idx, &recordptr)) {
                unused = fwrite(&type, sizeof(type), 1, trace_fp);
                unused = fwrite(recordptr, recordptr->length, 1, trace_fp);
                writeout_idx += recordptr->length;
                free(recordptr); /* don't use g_free, can deadlock when traced */
                idx = writeout_idx % TRACE_BUF_LEN;
            }
        }

        fflush(trace_fp);
    }
    return NULL;
}

void trace_record_write_u64(TraceBufferRecord *rec, uint64_t val)
{
    // if (val >= (uint64_t)orenmn_our_buf_addr &&
    //     val < (uint64_t)orenmn_our_buf_addr + 20000 * sizeof(int))
    // {
    //     g_atomic_int_inc(&orenmn_num_of_GMBEs_to_our_buf_not_written_to_trace_file);
    // }
    rec->rec_off = write_to_buffer(rec->rec_off, &val, sizeof(uint64_t));
}

void trace_record_write_str(TraceBufferRecord *rec, const char *s, uint32_t slen)
{
    /* Write string length first */
    rec->rec_off = write_to_buffer(rec->rec_off, &slen, sizeof(slen));
    /* Write actual string now */
    rec->rec_off = write_to_buffer(rec->rec_off, (void*)s, slen);
}

int trace_record_start(TraceBufferRecord *rec, uint32_t event, size_t datasize)
{
    unsigned int idx, rec_off, old_idx, new_idx;
    uint32_t rec_len;
    if (orenmn_single_event_optimization) {
        rec_len = orenmn_SEO_trace_record_size;
        assert(rec_len == sizeof(orenmn_OptimizedTraceRecord) + datasize);
    }
    else {
        rec_len = sizeof(TraceRecord) + datasize;
    }
    uint64_t event_u64 = event;

    do {
        old_idx = g_atomic_int_get(&trace_idx);
        smp_rmb();
        new_idx = old_idx + rec_len;

        if (new_idx - writeout_idx > TRACE_BUF_LEN) {
            /* Trace Buffer Full, Event dropped ! */
            g_atomic_int_inc(&dropped_events);
            return -ENOSPC;
        }
    } while (!g_atomic_int_compare_and_exchange(&trace_idx, old_idx, new_idx));

    idx = old_idx % TRACE_BUF_LEN;

    rec_off = idx;
    rec_off = write_to_buffer(rec_off, &event_u64, sizeof(event_u64));
    if (!orenmn_single_event_optimization) {
        uint64_t timestamp_ns = get_clock();
        rec_off = write_to_buffer(rec_off, &timestamp_ns, sizeof(timestamp_ns));
        rec_off = write_to_buffer(rec_off, &rec_len, sizeof(rec_len));
        rec_off = write_to_buffer(rec_off, &trace_pid, sizeof(trace_pid));
    }

    rec->tbuf_idx = idx;
    if (orenmn_single_event_optimization) {
        rec->rec_off  = (idx + sizeof(orenmn_OptimizedTraceRecord)) % TRACE_BUF_LEN;
    }
    else {
        rec->rec_off  = (idx + sizeof(TraceRecord)) % TRACE_BUF_LEN;
    }
    return 0;
}

static void read_from_buffer(unsigned int idx, void *dataptr, size_t size)
{
    uint8_t *data_ptr = dataptr;
    uint32_t x = 0;
    while (x < size) {
        if (idx >= TRACE_BUF_LEN) {
            idx = idx % TRACE_BUF_LEN;
        }
        data_ptr[x++] = trace_buf[idx++];
    }
}

static unsigned int write_to_buffer(unsigned int idx, void *dataptr, size_t size)
{
    uint8_t *data_ptr = dataptr;
    uint32_t x = 0;
    while (x < size) {
        if (idx >= TRACE_BUF_LEN) {
            idx = idx % TRACE_BUF_LEN;
        }
        trace_buf[idx++] = data_ptr[x++];
    }
    return idx; /* most callers wants to know where to write next */
}

void trace_record_finish(TraceBufferRecord *rec)
{
    if (orenmn_single_event_optimization) {
        orenmn_OptimizedTraceRecord record;
        read_from_buffer(rec->tbuf_idx, &record, sizeof(orenmn_OptimizedTraceRecord));
        smp_wmb(); /* write barrier before marking as valid */
        record.event |= TRACE_RECORD_VALID;
        write_to_buffer(rec->tbuf_idx, &record, sizeof(orenmn_OptimizedTraceRecord));
    }
    else {
        TraceRecord record;
        read_from_buffer(rec->tbuf_idx, &record, sizeof(TraceRecord));
        smp_wmb(); /* write barrier before marking as valid */
        record.event |= TRACE_RECORD_VALID;
        write_to_buffer(rec->tbuf_idx, &record, sizeof(TraceRecord));
    }

    g_atomic_int_inc(&orenmn_num_of_events_written_to_trace_buf_since_SEO_enabled);
    if (((unsigned int)g_atomic_int_get(&trace_idx) - writeout_idx)
        > TRACE_BUF_FLUSH_THRESHOLD) {
        flush_trace_file(false);
    }
}

static int st_write_event_mapping(void)
{
    uint64_t type = TRACE_RECORD_TYPE_MAPPING;
    TraceEventIter iter;
    TraceEvent *ev;

    trace_event_iter_init(&iter, NULL);
    while ((ev = trace_event_iter_next(&iter)) != NULL) {
        uint64_t id = trace_event_get_id(ev);
        const char *name = trace_event_get_name(ev);
        uint32_t len = strlen(name);
        if (fwrite(&type, sizeof(type), 1, trace_fp) != 1 ||
            fwrite(&id, sizeof(id), 1, trace_fp) != 1 ||
            fwrite(&len, sizeof(len), 1, trace_fp) != 1 ||
            fwrite(name, len, 1, trace_fp) != 1) {
            return -1;
        }
    }

    return 0;
}

void st_set_trace_file_enabled(bool enable)
{
    if (enable == !!trace_fp) {
        return; /* no change */
    }

    /* Halt trace writeout */
    flush_trace_file(true);
    trace_writeout_enabled = false;
    flush_trace_file(true);

    if (enable) {
        static const TraceLogHeader header = {
            .header_event_id = HEADER_EVENT_ID,
            .header_magic = HEADER_MAGIC,
            /* Older log readers will check for version at next location */
            .header_version = HEADER_VERSION,
        };

        trace_fp = fopen(trace_file_name, "wb");
        if (!trace_fp) {
            return;
        }
        sanity_fp = fopen("sanity.txt", "w");
        if (!sanity_fp) {
            return;
        }

        if (fwrite(&header, sizeof header, 1, trace_fp) != 1 ||
            st_write_event_mapping() < 0) {
            fclose(trace_fp);
            trace_fp = NULL;
            return;
        }

        /* Resume trace writeout */
        trace_writeout_enabled = true;
        flush_trace_file(false);
    } else {
        fclose(trace_fp);
        trace_fp = NULL;
    }
}

/**
 * Set the name of a trace file
 *
 * @file        The trace file name or NULL for the default name-<pid> set at
 *              config time
 */
void st_set_trace_file(const char *file)
{
    st_set_trace_file_enabled(false);

    g_free(trace_file_name);

    if (!file) {
        /* Type cast needed for Windows where getpid() returns an int. */
        trace_file_name = g_strdup_printf(CONFIG_TRACE_FILE, (pid_t)getpid());
    } else {
        trace_file_name = g_strdup_printf("%s", file);
    }

    st_set_trace_file_enabled(true);
}

void orenmn_enable_tracing_single_event_optimization(uint64_t num_of_arguments_of_event)
{
    // g_mutex_lock(&orenmn_monitor_cmds_lock);
    
    uint32_t record_size = sizeof(orenmn_OptimizedTraceRecord) +
                           num_of_arguments_of_event * sizeof(uint64_t);
    assert(record_size > 0);
    if (TRACE_BUF_LEN % record_size != 0) {
        error_report("    single_event_optimization requires that TRACE_BUF_LEN "
                     "is a multiple of the size of a trace record (%u). "
                     "Unfortunately, TRACE_BUF_LEN %% record_size == %u. "
                     "If you wish to use single_event_optimization, recompile "
                     "qemu so that TRACE_BUF_LEN fits the size of a trace "
                     "record.", record_size, TRACE_BUF_LEN % record_size);
    }
    else {
        orenmn_single_event_optimization = true;
        orenmn_SEO_trace_record_size = record_size;
        info_report("    single_event_optimization is on. "
                    "trace record size: %u", orenmn_SEO_trace_record_size);
    }
    g_atomic_int_set(&orenmn_num_of_events_written_to_trace_buf_since_SEO_enabled, 0);
    g_atomic_pointer_set(&orenmn_GMBE_idx, 0);

    // g_mutex_unlock(&orenmn_monitor_cmds_lock);
}

void st_print_trace_file_status(FILE *stream, int (*stream_printf)(FILE *stream, const char *fmt, ...))
{
    stream_printf(stream, "Trace file \"%s\" %s.\n",
                  trace_file_name, trace_fp ? "on" : "off");
}

void st_flush_trace_buffer(void)
{
    flush_trace_file(true);
}

/* Helper function to create a thread with signals blocked.  Use glib's
 * portable threads since QEMU abstractions cannot be used due to reentrancy in
 * the tracer.  Also note the signal masking on POSIX hosts so that the thread
 * does not steal signals when the rest of the program wants them blocked.
 */
static GThread *trace_thread_create(GThreadFunc fn)
{
    GThread *thread;
#ifndef _WIN32
    sigset_t set, oldset;

    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &oldset);
#endif

    thread = g_thread_new("trace-thread", fn, NULL);

#ifndef _WIN32
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
#endif

    return thread;
}

bool st_init(void)
{
    /* orenmn: TRACE_BUF_LEN must be a divisor of 1 << 32, because we do
       `idx = writeout_idx % TRACE_BUF_LEN;`, and `writeout_idx` might
       overflow. */
    assert(0x100000000 % TRACE_BUF_LEN == 0);

    GThread *thread;

    trace_pid = getpid();

    thread = trace_thread_create(writeout_thread);
    if (!thread) {
        warn_report("unable to initialize simple trace backend");
        return false;
    }

    atexit(st_flush_trace_buffer);
    return true;
}

bool orenmn_should_trace_this_GMBE(void) {
    uint64_t GMBE_idx = (uint64_t)g_atomic_pointer_add(&orenmn_GMBE_idx, 1);
    return (GMBE_idx & orenmn_mask_of_GMBE_block_idx) == 0;
    // for (int i = 0; i < 100; ++i) {
    //     GMBE_idx++;
    // }
    // return false;
}

/* Return true if should trace, according to
   orenmn_trace_only_user_code_GMBE. Otherwise, return false. */
bool orenmn_add_cpl_to_GMBE_info_if_should_trace(uint8_t *info, uint8_t *env) {
    // orenmn: This is CPUX86State's definition in target/i386/cpu.h,
    // which I didn't manage to include here. Thus I couldn't do
    // `((struct CPUX86State *)__cpu->env_ptr)->hflags`, and thus this very
    // ugly solution.
    // Please replace this ugliness with something beautiful if you can.
    // A less ugly solution would be to add something to the makefile that uses
    // offsetof(struct CPUX86State, hflags), and then run a Python script to
    // patch the code in this function to do
    // `env[offsetof(struct CPUX86State, hflags)]`.
    // 
    // typedef struct CPUX86State {
    //     /* standard registers */
    //     target_ulong regs[CPU_NB_REGS];
    //     target_ulong eip;
    //     target_ulong eflags; /* eflags register. During CPU emulation, CC
    //                         flags and DF are set to zero because they are
    //                         stored elsewhere */
    // 
    //     /* emulator internal eflags handling */
    //     target_ulong cc_dst;
    //     target_ulong cc_src;
    //     target_ulong cc_src2;
    //     uint32_t cc_op;
    //     int32_t df; /* D flag : 1 if D = 0, -1 if D = 1 */
    //     uint32_t hflags; /* TB flags, see HF_xxx constants. These flags
    //                         are known at translation time. */
    int cpu_nb_regs = 16;
    int offset_of_hflags = sizeof(unsigned long) * (cpu_nb_regs + 5) + 
                           sizeof(uint32_t) + sizeof(int32_t);
    uint8_t cpl = env[offset_of_hflags] & 3;
    // cpl < 3 means that the guest is not in ring 3, i.e. not in user code.
    if (orenmn_trace_only_user_code_GMBE && cpl < 3) {
        return false;
    }
    *info |= cpl << 6;
    return true;
}

