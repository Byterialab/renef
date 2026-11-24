-- NativeFunction v2 -- float/double (v0-v7) argument and
-- return support test. Uses libm.so's sinf/sin/cosf/pow (always present,
-- stable, well-known semantics -- easy to assert exact expected values).
--
-- Positive: sinf(float)->float, sin(double)->double, pow(double,double)->
-- double (two float-register args, proving independent register
-- counting), and a MIXED case strtod(pointer,pointer)->double just to
-- confirm a float-returning call with integer/pointer args still works.
-- Negative: calling with a wildly out-of-domain value (e.g. a huge
-- exponent to pow) must return a normal float value (inf), not crash --
-- and a bad argType string should fall back to integer marshalling
-- instead of crashing (robustness check for a mistyped argType).

print("=== NativeFunction v2 (float/double) test ===")

local base = Module.find("libm.so")
assert(base and base ~= 0, "libm.so not found")

local function resolve(name)
    for _, e in ipairs(Module.exports("libm.so")) do
        if e.name == name then return base + e.offset end
    end
    return nil
end

-- (1) sinf(float) -> float
local a_sinf = assert(resolve("sinf"), "sinf not found")
local sinf = NativeFunction(a_sinf, "float", {"float"})
local r1 = sinf(1.5707963) -- ~pi/2
print(string.format("sinf(pi/2) = %.6f (expect ~1.0)", r1))
assert(math.abs(r1 - 1.0) < 0.001, "sinf result out of tolerance: " .. tostring(r1))

-- (2) sin(double) -> double
local a_sin = assert(resolve("sin"), "sin not found")
local sin_fn = NativeFunction(a_sin, "double", {"double"})
local r2 = sin_fn(0.0)
print(string.format("sin(0.0) = %.6f (expect 0.0)", r2))
assert(math.abs(r2 - 0.0) < 1e-9, "sin(0) result out of tolerance: " .. tostring(r2))

-- (3) pow(double, double) -> double -- two float-register args, proving
-- the independent x0-x7/d0-d7 counters (no integer args at all here).
local a_pow = assert(resolve("pow"), "pow not found")
local pow_fn = NativeFunction(a_pow, "double", {"double", "double"})
local r3 = pow_fn(2.0, 10.0)
print(string.format("pow(2.0, 10.0) = %.6f (expect 1024.0)", r3))
assert(math.abs(r3 - 1024.0) < 1e-6, "pow result out of tolerance: " .. tostring(r3))

-- (4) MIXED: strtod(const char*, char**) -> double. strtod is libc, not
-- libm -- integer/pointer arg (x0) + a float return (d0) in the same
-- call, proving the two register files really are independent in both
-- directions.
local libc_base = assert(Module.find("libc.so"), "libc.so not found")
local a_strtod = nil
for _, e in ipairs(Module.exports("libc.so")) do
    if e.name == "strtod" then a_strtod = libc_base + e.offset; break end
end
assert(a_strtod, "strtod not found")
local strtod_fn = NativeFunction(a_strtod, "double", {"pointer", "pointer"})
local r4 = strtod_fn("3.1415", nil)
print(string.format("strtod(\"3.1415\") = %.4f (expect 3.1415)", r4))
assert(math.abs(r4 - 3.1415) < 1e-4, "strtod result out of tolerance: " .. tostring(r4))

print("[OK] all 4 positive float/double NativeFunction calls within tolerance")

-- NEGATIVE 1: out-of-domain-ish but IEEE-754-legal input (huge exponent)
-- must come back as +inf, not crash the process.
local r5 = pow_fn(10.0, 1000.0)
print("pow(10.0, 1000.0) = " .. tostring(r5) .. " (expect inf, no crash)")
assert(r5 == math.huge, "expected +inf for pow(10,1000), got " .. tostring(r5))
print("[OK] out-of-range float call returned inf cleanly, no crash")

-- NEGATIVE 2: a bogus argType string ("flaot", typo) must NOT crash --
-- is_float_argtype() only recognizes exact "float"/"double", so a typo
-- silently falls back to integer marshalling (wrong result, not a
-- crash -- the contract this test checks).
local sinf_typo = NativeFunction(a_sinf, "float", {"flaot"})
local ok, r6 = pcall(sinf_typo, 1.5707963)
print("[OK] typo'd argType did not crash the process (ok=" .. tostring(ok) ..
      ", result=" .. tostring(r6) .. ")")

print("=== test done ===")
