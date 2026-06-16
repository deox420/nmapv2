
/***************************************************************************
 * output_json.cc -- Native JSON scan output for Nmap (-oJ).               *
 *                                                                         *
 * This file is part of the nmapv2 enhanced fork (proposal P05). It is a   *
 * derivative work added on top of upstream Nmap and is distributed under  *
 * the same Nmap Public Source License (NPSL) terms as the rest of Nmap.   *
 * See the LICENSE file and https://nmap.org/npsl/ for details.            *
 *                                                                         *
 * Design: rather than threading a JSON channel through every inline       *
 * emission site, this is a self-contained writer that reads from the      *
 * already-populated in-memory structures (Target, PortList,              *
 * serviceDeductions, FingerPrintResults) at three points: run-open,       *
 * per-host, and run-close. All network-derived strings (banners, version  *
 * info, hostnames, CPEs) are passed through json_escape_into(), which     *
 * neutralizes quotes, backslashes and control characters so untrusted     *
 * input cannot break or inject into the JSON document.                    *
 ***************************************************************************/

#include "nmap.h"
#include "nmap_error.h"
#include "output_json.h"
#include "output.h"
#include "NmapOps.h"
#include "Target.h"
#include "portlist.h"
#include "portreasons.h"
#include "port_reliability.h"
#include "protocols.h"
#include "FingerPrintResults.h"

#include <string>
#include <map>

extern NmapOps o;

static FILE *jf = NULL;          /* JSON output stream */
static bool jf_is_stdout = false;
static bool g_run_open = false;  /* run envelope written */
static bool g_first_host = true; /* comma handling for hosts array */

/* Append s to out, escaping it as a JSON string body (without surrounding
 * quotes). NULL is treated as empty. Bytes >= 0x80 are passed through (as the
 * XML writer does) to preserve valid UTF-8; control bytes are \u-escaped. */
static void json_escape_into(std::string &out, const char *s) {
  if (s == NULL)
    return;
  for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
    unsigned char c = *p;
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b";  break;
      case '\f': out += "\\f";  break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          Snprintf(buf, sizeof(buf), "\\u%04x", (unsigned) c);
          out += buf;
        } else {
          out += (char) c;
        }
    }
  }
}

static void jputs_escaped(const char *s) {
  std::string e;
  json_escape_into(e, s);
  fputs(e.c_str(), jf);
}

/* Emit "key":"value", omitting the field entirely if value is NULL. *first
 * tracks whether a comma separator is needed within the current object. */
static void jkey_str(bool *first, const char *k, const char *v) {
  if (v == NULL)
    return;
  if (!*first)
    fputc(',', jf);
  *first = false;
  fputc('"', jf);
  fputs(k, jf);
  fputs("\":\"", jf);
  jputs_escaped(v);
  fputc('"', jf);
}

static void jkey_int(bool *first, const char *k, long long v) {
  if (!*first)
    fputc(',', jf);
  *first = false;
  fprintf(jf, "\"%s\":%lld", k, v);
}

int json_open_output(const char *filename, bool append) {
  if (filename == NULL)
    return -1;
  if (strcmp(filename, "-") == 0) {
    jf = stdout;
    jf_is_stdout = true;
    return 0;
  }
  jf = fopen(filename, append ? "a" : "w");
  if (jf == NULL) {
    error("Failed to open JSON output file %s for writing: %s",
          filename, strerror(errno));
    return -1;
  }
  return 0;
}

bool json_output_active(void) {
  return jf != NULL;
}

void json_run_open(const char *args, time_t start, const char *startstr,
                   const char *version) {
  if (jf == NULL || g_run_open)
    return;
  g_run_open = true;
  fputs("{\n\"nmaprun\":{", jf);
  bool f = true;
  jkey_str(&f, "scanner", "nmap");
  jkey_str(&f, "args", args);
  jkey_int(&f, "start", (long long) start);
  jkey_str(&f, "startstr", startstr);
  jkey_str(&f, "version", version);
  if (!f)
    fputc(',', jf);
  fputs("\"hosts\":[", jf);
}

void json_host(const Target *t) {
  if (jf == NULL)
    return;
  /* Lazily ensure the envelope exists even if json_run_open was skipped. */
  if (!g_run_open) {
    g_run_open = true;
    fputs("{\n\"nmaprun\":{\"hosts\":[", jf);
  }
  if (!g_first_host)
    fputc(',', jf);
  g_first_host = false;
  fputs("\n", jf);

  bool f = true;
  fputc('{', jf);

  /* status */
  if (!f) fputc(',', jf);
  f = false;
  fputs("\"status\":{", jf);
  {
    bool sf = true;
    const char *state = (t->flags & HOST_UP) ? "up" :
                        ((t->flags & HOST_DOWN) ? "down" : "unknown");
    jkey_str(&sf, "state", state);
    jkey_str(&sf, "reason", target_reason_str(t));
  }
  fputc('}', jf);

  /* addresses */
  fputs(",\"addresses\":[", jf);
  {
    bool fa = true;
    if (!fa) fputc(',', jf);
    fa = false;
    fputc('{', jf);
    { bool x = true;
      jkey_str(&x, "addr", t->targetipstr());
      jkey_str(&x, "addrtype", t->af() == AF_INET6 ? "ipv6" : "ipv4");
    }
    fputc('}', jf);

    const u8 *mac = t->MACAddress();
    if (mac != NULL) {
      char macstr[24];
      Snprintf(macstr, sizeof(macstr), "%02X:%02X:%02X:%02X:%02X:%02X",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
      fputc(',', jf);
      fputc('{', jf);
      { bool x = true;
        jkey_str(&x, "addr", macstr);
        jkey_str(&x, "addrtype", "mac");
      }
      fputc('}', jf);
    }
  }
  fputc(']', jf);

  /* hostnames */
  fputs(",\"hostnames\":[", jf);
  {
    bool fh = true;
    const char *hn = t->HostName();
    const char *tn = t->TargetName();
    if (hn != NULL && hn[0] != '\0') {
      fputc('{', jf);
      { bool x = true; jkey_str(&x, "name", hn); jkey_str(&x, "type", "PTR"); }
      fputc('}', jf);
      fh = false;
    }
    if (tn != NULL && tn[0] != '\0' && (hn == NULL || strcmp(tn, hn) != 0)) {
      if (!fh) fputc(',', jf);
      fputc('{', jf);
      { bool x = true; jkey_str(&x, "name", tn); jkey_str(&x, "type", "user"); }
      fputc('}', jf);
      fh = false;
    }
  }
  fputc(']', jf);

  /* ports */
  fputs(",\"ports\":[", jf);
  {
    const PortList *plist = &t->ports;
    Port *current = NULL;
    Port port;
    struct serviceDeductions sd;
    bool fp = true;
    while ((current = plist->nextPort(current, &port, TCPANDUDPANDSCTP, 0)) != NULL) {
      if (plist->isIgnoredState(current->state, NULL))
        continue;
      if (!fp) fputc(',', jf);
      fp = false;
      fputc('{', jf);
      bool pf = true;
      jkey_str(&pf, "protocol", IPPROTO2STR(current->proto));
      jkey_int(&pf, "portid", current->portno);
      jkey_str(&pf, "state", statenum2str(current->state));
      jkey_str(&pf, "reason", reason_str(current->reason.reason_id, SINGULAR));
      jkey_int(&pf, "reason_ttl", current->reason.ttl);

      plist->getServiceDeductions(current->portno, current->proto, &sd);

      /* P14: per-port state-reliability score (how trustworthy this state is). */
      int rel = compute_port_state_reliability(current->state, &current->reason, &sd);
      jkey_int(&pf, "reliability", rel);
      jkey_str(&pf, "reliability_level", reliability_level(rel));

      if (sd.name || sd.service_fp || sd.service_tunnel != SERVICE_TUNNEL_NONE) {
        if (!pf) fputc(',', jf);
        pf = false;
        fputs("\"service\":{", jf);
        bool sf = true;
        jkey_str(&sf, "name", sd.name);
        jkey_str(&sf, "product", sd.product);
        jkey_str(&sf, "version", sd.version);
        jkey_str(&sf, "extrainfo", sd.extrainfo);
        jkey_str(&sf, "ostype", sd.ostype);
        jkey_str(&sf, "devicetype", sd.devicetype);
        jkey_str(&sf, "hostname", sd.hostname);
        jkey_int(&sf, "conf", sd.name_confidence);
        jkey_str(&sf, "method",
                 sd.dtype == SERVICE_DETECTION_TABLE ? "table" : "probed");
        if (sd.service_tunnel == SERVICE_TUNNEL_SSL)
          jkey_str(&sf, "tunnel", "ssl");
        if (!sd.cpe.empty()) {
          if (!sf) fputc(',', jf);
          sf = false;
          fputs("\"cpe\":[", jf);
          for (size_t ci = 0; ci < sd.cpe.size(); ci++) {
            if (ci) fputc(',', jf);
            fputc('"', jf);
            jputs_escaped(sd.cpe[ci]);
            fputc('"', jf);
          }
          fputc(']', jf);
        }
        fputc('}', jf);
      }
      fputc('}', jf); /* port */
    }
  }
  fputc(']', jf);

  /* P15: per-host scan diagnostics -- aggregate WHY the results look as they do,
   * across all ports (including consolidated ignored states). Explains result
   * quality and surfaces probable filtering/blackholing. */
  {
    const PortList *plist = &t->ports;
    std::map<std::string, int> state_counts, reason_counts;
    int rel_high = 0, rel_med = 0, rel_low = 0, total = 0, no_response = 0;
    Port *cur = NULL;
    Port pt;
    while ((cur = plist->nextPort(cur, &pt, TCPANDUDPANDSCTP, 0)) != NULL) {
      total++;
      const char *st = statenum2str(cur->state);
      state_counts[st ? st : "unknown"]++;
      const char *rs = reason_str(cur->reason.reason_id, SINGULAR);
      reason_counts[rs ? rs : "unknown"]++;
      if (cur->reason.reason_id == ER_NORESPONSE)
        no_response++;
      int r = compute_port_state_reliability(cur->state, &cur->reason, NULL);
      const char *lv = reliability_level(r);
      if (lv[0] == 'h') rel_high++;
      else if (lv[0] == 'm') rel_med++;
      else rel_low++;
    }
    if (total > 0) {
      fputs(",\"diagnostics\":{", jf);
      fputs("\"state_counts\":{", jf);
      bool f1 = true;
      for (std::map<std::string, int>::const_iterator it = state_counts.begin();
           it != state_counts.end(); ++it) {
        if (!f1) fputc(',', jf);
        f1 = false;
        fputc('"', jf); jputs_escaped(it->first.c_str());
        fprintf(jf, "\":%d", it->second);
      }
      fputs("},\"reason_counts\":{", jf);
      bool f2 = true;
      for (std::map<std::string, int>::const_iterator it = reason_counts.begin();
           it != reason_counts.end(); ++it) {
        if (!f2) fputc(',', jf);
        f2 = false;
        fputc('"', jf); jputs_escaped(it->first.c_str());
        fprintf(jf, "\":%d", it->second);
      }
      fputs("}", jf);
      fprintf(jf, ",\"reliability\":{\"high\":%d,\"medium\":%d,\"low\":%d}",
              rel_high, rel_med, rel_low);
      /* Derived note: probes overwhelmingly unanswered => probable filtering. */
      fputs(",\"notes\":[", jf);
      bool fn = true;
      if (no_response * 2 >= total && no_response > 0) {
        fputc('"', jf);
        jputs_escaped("majority of probed ports gave no response; host may be "
                      "filtering, rate-limiting or blackholing probes");
        fputc('"', jf);
        fn = false;
      }
      if (rel_low > rel_high && rel_low > 0) {
        if (!fn) fputc(',', jf);
        fputc('"', jf);
        jputs_escaped("more low-reliability than high-reliability port states; "
                      "results should be treated with caution");
        fputc('"', jf);
        fn = false;
      }
      fputc(']', jf);
      fputc('}', jf); /* diagnostics */
    }
  }

  /* os (best matches, if any) */
  if (t->FPR != NULL && t->FPR->num_matches > 0) {
    fputs(",\"os\":{\"matches\":[", jf);
    int lim = t->FPR->num_matches < 5 ? t->FPR->num_matches : 5;
    for (int i = 0; i < lim; i++) {
      if (i) fputc(',', jf);
      fputc('{', jf);
      bool x = true;
      jkey_str(&x, "name", t->FPR->matches[i]->OS_name);
      jkey_int(&x, "accuracy", (long long) (t->FPR->accuracy[i] * 100.0 + 0.5));
      fputc('}', jf);
    }
    fputs("]}", jf);
  }

  fputc('}', jf); /* host */
}

void json_run_close(unsigned int up, unsigned int down, unsigned int total,
                    double elapsed, time_t endtime, const char *endstr,
                    const char *exitstatus) {
  if (jf == NULL)
    return;
  if (!g_run_open) {
    g_run_open = true;
    fputs("{\n\"nmaprun\":{\"hosts\":[", jf);
  }
  fputs("\n],", jf); /* close hosts array */
  fputs("\"runstats\":{", jf);
  fputs("\"finished\":{", jf);
  {
    bool ff = true;
    jkey_int(&ff, "time", (long long) endtime);
    jkey_str(&ff, "timestr", endstr);
    if (!ff) fputc(',', jf);
    fprintf(jf, "\"elapsed\":%.2f", elapsed);
    ff = false;
    jkey_str(&ff, "exit", exitstatus);
  }
  fputc('}', jf);
  fputs(",\"hosts\":{", jf);
  {
    bool hf = true;
    jkey_int(&hf, "up", (long long) up);
    jkey_int(&hf, "down", (long long) down);
    jkey_int(&hf, "total", (long long) total);
  }
  fputc('}', jf);
  fputc('}', jf); /* runstats */
  fputs("}\n}\n", jf); /* close nmaprun + root */
}

void json_close_output(void) {
  if (jf == NULL)
    return;
  fflush(jf);
  if (!jf_is_stdout)
    fclose(jf);
  jf = NULL;
}
