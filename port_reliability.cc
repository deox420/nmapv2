
/***************************************************************************
 * port_reliability.cc -- Confidence scoring for port-state determinations.*
 *                                                                         *
 * This file is part of the nmapv2 enhanced fork (proposal P14). It is a   *
 * derivative work added on top of upstream Nmap and is distributed under  *
 * the same Nmap Public Source License (NPSL) terms as the rest of Nmap.   *
 * See the LICENSE file and https://nmap.org/npsl/ for details.            *
 *                                                                         *
 * The score answers: "how much should we trust this port-state result?"   *
 * A state proven by an actual packet from the target (SYN-ACK, RST, an    *
 * ICMP error, or a real service banner) is high-confidence. A state that  *
 * was inferred only because nothing came back (no-response) is low: it is  *
 * indistinguishable, on its own, from a dropped probe, rate-limiting, or a *
 * filtering middlebox -- which is exactly what later proposals (P24/P25)   *
 * use this signal to investigate.                                          *
 ***************************************************************************/

#include "port_reliability.h"
#include "portlist.h"

/* Base reliability of a state determination given the reason it was reached. */
static int reason_base_reliability(reason_t reason_id) {
  switch (reason_id) {
    /* Direct, active responses from the target: the state is proven. */
    case ER_RESETPEER:
    case ER_CONREFUSED:
    case ER_CONACCEPT:
    case ER_SYNACK:
    case ER_SYN:
    case ER_UDPRESPONSE:
    case ER_PROTORESPONSE:
    case ER_TCPRESPONSE:
    case ER_PORTUNREACH:
    case ER_ECHOREPLY:
    case ER_ARPRESPONSE:
    case ER_NDRESPONSE:
    case ER_INITACK:
    case ER_LOCALHOST:
      return 10;

    /* ICMP errors / administrative rejections: filtering is confirmed by a
     * returned error packet, not merely by silence. Strong, but the exact
     * port state behind the filter is not directly observable. */
    case ER_NETUNREACH:
    case ER_HOSTUNREACH:
    case ER_PROTOUNREACH:
    case ER_DESTUNREACH:
    case ER_SOURCEQUENCH:
    case ER_NETPROHIBITED:
    case ER_HOSTPROHIBITED:
    case ER_ADMINPROHIBITED:
    case ER_TIMEEXCEEDED:
    case ER_REJECTROUTE:
    case ER_NOROUTE:
    case ER_BEYONDSCOPE:
    case ER_PARAMPROBLEM:
    case ER_ABORT:
      return 8;

    case ER_ACCES:
      return 7;

    /* Inference from indirect signals or set by script/user. */
    case ER_NOIPIDCHANGE:
    case ER_IPIDCHANGE:
    case ER_SCRIPT:
    case ER_USER:
      return 6;

    /* State inferred purely from the absence of a reply: weakest evidence. */
    case ER_NORESPONSE:
      return 3;

    default:
      return 5;
  }
}

int compute_port_state_reliability(int state, const state_reason_t *reason,
                                   const struct serviceDeductions *sd) {
  int score = (reason != NULL) ? reason_base_reliability(reason->reason_id) : 5;

  /* An open port whose service was actively probed and matched (we read a real
   * banner) is about as certain as it gets, regardless of the scan reason. */
  if (state == PORT_OPEN && sd != NULL &&
      sd->dtype == SERVICE_DETECTION_PROBED && sd->name != NULL)
    score = 10;

  if (score < 0) score = 0;
  if (score > 10) score = 10;
  return score;
}

const char *reliability_level(int score) {
  if (score >= 8) return "high";
  if (score >= 5) return "medium";
  return "low";
}
