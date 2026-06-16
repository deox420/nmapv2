local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Flags hosts that appear to falsify scan responses -- honeypots, TCP tarpits, and
deceptive firewalls/middleboxes.

Such hosts typically betray themselves by making an implausible number of TCP
ports look "open" and/or by returning identical (or empty) service banners on all
of them. This host script inspects the results Nmap already gathered and reports a
verdict with the concrete indicators it found:

* Excessive open ports -- far more open TCP ports than a real host would expose.
* Uniform banners -- a large fraction of open ports sharing one identical service
  signature (including the "all open, no banner" tarpit/blackhole-accept pattern).

It is most effective combined with service detection (-sV), which populates the
per-port banners used for the uniformity check. Thresholds are tunable.

This is the host-level companion to the per-port reliability score (fork proposal
P14): where P14 rates how trustworthy a single port state is, this script looks
across all ports for the collective signature of a host that fabricates openness.
]]

---
-- @usage nmap -sV --script honeypot-detect <target>
-- @usage nmap -sV --script honeypot-detect --script-args honeypot-detect.minopen=50 <target>
--
-- @args honeypot-detect.minopen  Minimum number of open TCP ports to consider
--       "excessive" (default 30).
-- @args honeypot-detect.uniform  Minimum number of open ports sharing one identical
--       service signature to flag uniform banners (default 10).
--
-- @output
-- Host script results:
-- | honeypot-detect:
-- |   verdict: LIKELY honeypot / fake-response host
-- |   open_ports: 40
-- |   indicators:
-- |     excessive open TCP ports (40)
-- |_    40 ports share an identical service signature (tcpwrapped///)

author = "nmapv2 enhanced fork (proposal P24)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

hostrule = function(host)
  return nmap.get_ports(host, nil, "tcp", "open") ~= nil
end

action = function(host)
  local minopen = tonumber(stdnse.get_script_args("honeypot-detect.minopen")) or 30
  local uniform_min = tonumber(stdnse.get_script_args("honeypot-detect.uniform")) or 10

  -- Collect all open TCP ports.
  local open_ports = {}
  local p = nil
  repeat
    p = nmap.get_ports(host, p, "tcp", "open")
    if p then open_ports[#open_ports + 1] = p end
  until not p

  local n = #open_ports
  if n == 0 then return nil end

  local indicators = {}
  local score = 0

  -- Signal 1: excessive open ports.
  if n >= minopen then
    indicators[#indicators + 1] = string.format("excessive open TCP ports (%d)", n)
    score = score + 2
  end

  -- Signal 2: uniform service signatures across ports.
  local sig_count = {}
  for _, pt in ipairs(open_ports) do
    local v = pt.version or {}
    local key = string.format("%s/%s/%s", v.name or "?", v.product or "", v.version or "")
    sig_count[key] = (sig_count[key] or 0) + 1
  end
  local top_key, top_n = nil, 0
  for k, c in pairs(sig_count) do
    if c > top_n then top_n, top_key = c, k end
  end
  if top_n >= uniform_min and top_n * 2 >= n then
    indicators[#indicators + 1] =
      string.format("%d ports share an identical service signature (%s)", top_n, top_key)
    score = score + 2
  end

  if #indicators == 0 then return nil end

  local verdict
  if score >= 4 then
    verdict = "LIKELY honeypot / fake-response host"
  else
    verdict = "POSSIBLE honeypot / middlebox"
  end

  local out = stdnse.output_table()
  out.verdict = verdict
  out.open_ports = n
  out.indicators = indicators
  return out
end
