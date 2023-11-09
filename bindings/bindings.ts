// Auto-generated with deno_bindgen
function encode(v: string | Uint8Array): Uint8Array {
  if (typeof v !== "string") return v
  return new TextEncoder().encode(v)
}

function decode(v: Uint8Array): string {
  return new TextDecoder().decode(v)
}

// deno-lint-ignore no-explicit-any
function readPointer(v: any): Uint8Array {
  const ptr = new Deno.UnsafePointerView(v)
  const lengthBe = new Uint8Array(4)
  const view = new DataView(lengthBe.buffer)
  ptr.copyInto(lengthBe, 0)
  const buf = new Uint8Array(view.getUint32(0))
  ptr.copyInto(buf, 4)
  return buf
}

const url = new URL("../target/release", import.meta.url)

let uri = url.pathname
if (!uri.endsWith("/")) uri += "/"

// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya#parameters
if (Deno.build.os === "windows") {
  uri = uri.replace(/\//g, "\\")
  // Remove leading slash
  if (uri.startsWith("\\")) {
    uri = uri.slice(1)
  }
}

const { symbols } = Deno.dlopen(
  {
    darwin: uri + "libblst_deno.dylib",
    windows: uri + "blst_deno.dll",
    linux: uri + "libblst_deno.so",
    freebsd: uri + "libblst_deno.so",
    netbsd: uri + "libblst_deno.so",
    aix: uri + "libblst_deno.so",
    solaris: uri + "libblst_deno.so",
    illumos: uri + "libblst_deno.so",
  }[Deno.build.os],
  {
    generate_private_key_random: {
      parameters: [],
      result: "buffer",
      nonblocking: true,
    },
    generate_private_key_seed: {
      parameters: ["buffer", "usize"],
      result: "buffer",
      nonblocking: true,
    },
    get_public_key: {
      parameters: ["buffer", "usize"],
      result: "buffer",
      nonblocking: true,
    },
    get_random: { parameters: ["usize"], result: "buffer", nonblocking: true },
    sign: {
      parameters: ["buffer", "usize", "buffer", "usize"],
      result: "buffer",
      nonblocking: true,
    },
    verify: {
      parameters: ["buffer", "usize", "buffer", "usize", "buffer", "usize"],
      result: "u8",
      nonblocking: true,
    },
  },
)

export function generate_private_key_random() {
  const rawResult = symbols.generate_private_key_random()
  const result = rawResult.then(readPointer)
  return result
}
export function generate_private_key_seed(a0: Uint8Array) {
  const a0_buf = encode(a0)

  const rawResult = symbols.generate_private_key_seed(a0_buf, a0_buf.byteLength)
  const result = rawResult.then(readPointer)
  return result
}
export function get_public_key(a0: Uint8Array) {
  const a0_buf = encode(a0)

  const rawResult = symbols.get_public_key(a0_buf, a0_buf.byteLength)
  const result = rawResult.then(readPointer)
  return result
}
export function get_random(a0: bigint) {
  const rawResult = symbols.get_random(a0)
  const result = rawResult.then(readPointer)
  return result
}
export function sign(a0: Uint8Array, a1: Uint8Array) {
  const a0_buf = encode(a0)
  const a1_buf = encode(a1)

  const rawResult = symbols.sign(
    a0_buf,
    a0_buf.byteLength,
    a1_buf,
    a1_buf.byteLength,
  )
  const result = rawResult.then(readPointer)
  return result
}
export function verify(a0: Uint8Array, a1: Uint8Array, a2: Uint8Array) {
  const a0_buf = encode(a0)
  const a1_buf = encode(a1)
  const a2_buf = encode(a2)

  const rawResult = symbols.verify(
    a0_buf,
    a0_buf.byteLength,
    a1_buf,
    a1_buf.byteLength,
    a2_buf,
    a2_buf.byteLength,
  )
  const result = rawResult
  return result
}
