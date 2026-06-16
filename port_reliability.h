
/***************************************************************************
 * port_reliability.h -- Confidence scoring for port-state determinations. *
 *                                                                         *
 * This file is part of the nmapv2 enhanced fork (proposal P14). It is a   *
 * derivative work added on top of upstream Nmap and is distributed under  *
 * the same Nmap Public Source License (NPSL) terms as the rest of Nmap.   *
 * See the LICENSE file and https://nmap.org/npsl/ for details.            *
 ***************************************************************************/

#ifndef PORT_RELIABILITY_H
#define PORT_RELIABILITY_H

#include "portreasons.h"

struct serviceDeductions;

/* Returns a 0-10 score expressing how reliable the reported port STATE is,
 * based on the evidence that produced it (the state_reason) plus any service
 * evidence. A state proven by an actual response from the target scores high;
 * a state inferred only from silence (no-response) scores low.
 *
 *   state : PORT_OPEN / PORT_CLOSED / PORT_FILTERED / PORT_OPENFILTERED / ...
 *   reason: how the state was determined (may be NULL)
 *   sd    : service deductions for the port (may be NULL)
 */
int compute_port_state_reliability(int state, const state_reason_t *reason,
                                   const struct serviceDeductions *sd);

/* Coarse label for a 0-10 reliability score: "high", "medium" or "low". */
const char *reliability_level(int score);

#endif /* PORT_RELIABILITY_H */
