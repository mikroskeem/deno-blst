import { encodeHex } from "https://deno.land/std@0.205.0/encoding/hex.ts";
import {
  generate_private_key_random,
  get_public_key,
  sign,
  verify,
} from "./bindings/bindings.ts";

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
