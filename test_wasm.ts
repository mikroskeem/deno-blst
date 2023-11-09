import { encodeHex } from "https://deno.land/std@0.205.0/encoding/hex.ts";
import { instantiate } from "./lib/blst_deno.generated.js";

const mod = await instantiate();
console.log(mod);
const {
  get_random,
  generate_private_key_random,
  generate_private_key_seed,
  get_public_key,
  sign,
  verify,
} = mod;

const privateKey = await generate_private_key_random();
const publicKey = await get_public_key(privateKey);

console.log(
  "private key",
  encodeHex(privateKey),
);

console.log(
  "public key",
  encodeHex(publicKey),
);

const msg = new TextEncoder().encode("foo bar baz");
const signature = await sign(privateKey, msg);
console.log("signature", encodeHex(signature));
console.log("verified", await verify(publicKey, signature, msg) === 1);

function measure<T>(fn: () => T): [T, number] {
  const start = performance.now();
  let end: number;
  let res: T;
  try {
    res = fn();
  } finally {
    end = performance.now();
  }
  return [res, end - start];
}

for (let i = 0; i < 100; i++) {
  const [b, t] = measure(() => {
    return get_random(32);
  });
  const [b2, t2] = measure(() => {
    return crypto.getRandomValues(new Uint8Array(32));
  });

  console.log(b.length);
  console.log(b2.length);

  const k = await generate_private_key_seed(b);
  const k2 = await generate_private_key_seed(b2);
  console.log(t, t2);
}
