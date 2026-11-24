"""Helpers for building Lua source safely, plus the support code the client
installs in the target once per session."""

_SAFE = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b" !#$%&'()*+,-./:;<=>?@[]^_`{|}~"
)


def quote(value):
    """Returns ``value`` (str or bytes) as a Lua string literal.

    Everything outside a conservative printable set is written as a decimal
    escape (``\\ddd``), so quotes, backslashes, newlines, NUL bytes and
    non-ASCII data cannot break out of - or alter - the literal. This is
    what replaces the old f-string interpolation of paths and names into
    Lua source.
    """
    if isinstance(value, str):
        data = value.encode("utf-8", "surrogateescape")
    else:
        data = bytes(value)
    parts = ['"']
    for b in data:
        if b in _SAFE:
            parts.append(chr(b))
        else:
            parts.append("\\%03d" % b)
    parts.append('"')
    return "".join(parts)


def to_lua(value):
    """Converts a Python value to a Lua expression."""
    # Imported lazily: client imports this module.
    from .client import JavaObject, LuaExpr

    if value is None:
        return "nil"
    if isinstance(value, LuaExpr):
        return value.source
    if isinstance(value, JavaObject):
        return "__renef_py.objs[%d]" % value.handle
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if value >= 1 << 63:
            # Lua integers are signed 64-bit; a hex literal wraps around to
            # the same bit pattern, a decimal one would become a float.
            return "0x%x" % (value & 0xFFFFFFFFFFFFFFFF)
        return str(value)
    if isinstance(value, float):
        if value != value:
            return "(0/0)"
        if value in (float("inf"), float("-inf")):
            return "math.huge" if value > 0 else "-math.huge"
        return repr(value)
    if isinstance(value, (str, bytes, bytearray)):
        return quote(value)
    if isinstance(value, (list, tuple)):
        return "{" + ", ".join(to_lua(v) for v in value) + "}"
    if isinstance(value, dict):
        items = []
        for k, v in value.items():
            items.append("[%s] = %s" % (to_lua(k), to_lua(v)))
        return "{" + ", ".join(items) + "}"
    raise TypeError("cannot convert %r to a Lua value" % type(value).__name__)


# Installed once per session (idempotent). Everything the client needs on
# the Lua side lives in the single global `__renef_py`.
PRELUDE = r"""
if not __renef_py then
  __renef_py = { objs = {}, next_obj = 1, nf = {}, ranges = nil, hooks = {} }
  local P = __renef_py

  local FMT = {}
  local function fmt(n)
    local f = FMT[n]
    if not f then f = string.rep("%02x", n); FMT[n] = f end
    return f
  end

  -- bytes -> hex, 2048 bytes per string.format call
  function P.hex(s)
    local n = #s
    local out, k = {}, 0
    for i = 1, n, 2048 do
      local j = math.min(i + 2047, n)
      k = k + 1
      out[k] = string.format(fmt(j - i + 1), s:byte(i, j))
    end
    return table.concat(out)
  end

  function P.unhex(h)
    return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end))
  end

  local function load_ranges()
    local r = Process.enumerateRanges() or {}
    table.sort(r, function(a, b) return a.start < b.start end)
    P.ranges = r
  end

  -- Unsigned comparison: tagged heap pointers have the top bit set.
  local function ult(a, b) return math.ult(a, b) end

  local function covered(addr, size, need)
    local r = P.ranges
    local cur, last = addr, addr + size
    local lo, hi = 1, #r
    while lo <= hi do
      local mid = (lo + hi) // 2
      if not ult(cur, r[mid]["end"]) then lo = mid + 1 else hi = mid - 1 end
    end
    local i = lo
    while ult(cur, last) do
      local m = r[i]
      if not m or ult(cur, m.start) then return false end
      if not m.perms:find(need, 1, true) then return false end
      cur = m["end"]
      i = i + 1
    end
    return true
  end

  -- True if [addr, addr+size) is mapped with permission `need` ("r"/"w").
  -- Memory.read/write dereference the address directly, so an unmapped one
  -- would crash the target; this turns that into a Lua error.
  function P.check(addr, size, need)
    if size <= 0 then return true end
    local a = addr & 0x00FFFFFFFFFFFFFF      -- drop the MTE/TBI tag byte
    if not P.ranges then load_ranges() end
    if covered(a, size, need) then return true end
    load_ranges()                            -- mappings change; look again once
    return covered(a, size, need)
  end

  function P.read(addr, size)
    if not P.check(addr, size, "r") then
      error(string.format("memory range 0x%x+%d is not readable", addr, size), 0)
    end
    return P.hex(Memory.read(addr, size))
  end

  function P.write(addr, hexdata)
    local data = P.unhex(hexdata)
    if P.check(addr, #data, "w") then
      Memory.write(addr, data)
      return true
    end
    if not P.check(addr, #data, "r") then
      error(string.format("memory range 0x%x+%d is not mapped", addr, #data), 0)
    end
    local ok, err = Memory.patch(addr, data)   -- read-only/executable page
    if not ok then error("Memory.patch failed: " .. tostring(err), 0) end
    return true
  end

  function P.readstr(addr, maxlen)
    if addr == 0 then return nil end
    if not P.check(addr, 1, "r") then
      error(string.format("address 0x%x is not readable", addr), 0)
    end
    return Memory.readStr(addr, maxlen)
  end

  -- Loaded files as {path, name, base, size}: one entry per mapped file,
  -- spanning its lowest to highest mapping.
  function P.modules()
    local by, order = {}, {}
    for _, m in ipairs(Process.enumerateRanges() or {}) do
      local p = m.path
      if p and p:sub(1, 1) == "/" then
        local e = by[p]
        if not e then
          e = { path = p, name = p:match("([^/]+)$") or p, base = m.start, last = m["end"] }
          by[p] = e
          order[#order + 1] = e
        else
          if ult(m.start, e.base) then e.base = m.start end
          if ult(e.last, m["end"]) then e.last = m["end"] end
        end
      end
    end
    for _, e in ipairs(order) do e.size = e.last - e.base; e.last = nil end
    return order
  end

  -- Userdata (Java objects) cannot cross the wire: keep them here and hand
  -- out a handle instead.
  function P.box(v)
    if type(v) == "userdata" then
      local id = P.next_obj
      P.next_obj = id + 1
      P.objs[id] = v
      return { __py_obj = id }
    end
    return v
  end

  function P.release(id) P.objs[id] = nil end

  function P.emit(id, phase, payload)
    payload.__py_hook = id
    payload.phase = phase
    payload.tid = Thread.id()
    send(payload)
  end
end
"""
