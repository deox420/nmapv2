
/***************************************************************************
 * output_json.h -- Functions for writing native JSON scan output (-oJ).   *
 *                                                                         *
 * This file is part of the nmapv2 enhanced fork (proposal P05). It is a   *
 * derivative work added on top of upstream Nmap and is distributed under  *
 * the same Nmap Public Source License (NPSL) terms as the rest of Nmap.   *
 * See the LICENSE file and https://nmap.org/npsl/ for details.            *
 ***************************************************************************/

#ifndef OUTPUT_JSON_H
#define OUTPUT_JSON_H

#include <time.h>

class Target;

/* Open the JSON output file. filename "-" means stdout. Returns 0 on success,
 * -1 on failure. append selects append vs. truncate. */
int json_open_output(const char *filename, bool append);

/* True if JSON output is currently active (a file is open). */
bool json_output_active(void);

/* Write the run-open envelope: { "nmaprun": { ... "hosts": [
 * Safe to call more than once; only the first call has effect. */
void json_run_open(const char *args, time_t start, const char *startstr,
                   const char *version);

/* Emit one host object into the hosts array. */
void json_host(const Target *currenths);

/* Close the hosts array and write runstats, then close the document. */
void json_run_close(unsigned int up, unsigned int down, unsigned int total,
                    double elapsed, time_t endtime, const char *endstr,
                    const char *exitstatus);

/* Flush and close the JSON output file. */
void json_close_output(void);

#endif /* OUTPUT_JSON_H */
