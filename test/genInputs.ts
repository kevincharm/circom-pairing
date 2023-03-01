import * as bls from "@noble/bls12-381";
import { Fp2, PointG1, utils, PointG2, verify } from "./index";

function bigint_to_array(n: number, k: number, x: bigint) {
  let mod: bigint = 1n;
  for (var idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret: string[] = [];
  var x_temp: bigint = x;
  for (var idx = 0; idx < k; idx++) {
    ret.push((x_temp % mod).toString());
    x_temp = x_temp / mod;
  }
  return ret;
}

function Fp2_to_array(n: number, k: number, x: Fp2) {
  let { c0, c1 } = x;
  return [bigint_to_array(n, k, c0.value), bigint_to_array(n, k, c1.value)];
}

function formatHex(str: string): string {
  if (str.startsWith("0x")) {
    str = str.slice(2);
  }
  return str;
}

function hexToBytes(hex: string, endian: string = "big"): Uint8Array {
  if (typeof hex !== "string") {
    throw new TypeError("hexToBytes: expected string, got " + typeof hex);
  }
  hex = formatHex(hex);
  if (hex.length % 2)
    throw new Error("hexToBytes: received invalid unpadded hex");
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    let j = 0;
    if (endian === "big") j = i * 2;
    else j = (array.length - 1 - i) * 2;

    const hexByte = hex.slice(j, j + 2);
    if (hexByte.length !== 2) throw new Error("Invalid byte sequence");
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0)
      throw new Error("Invalid byte sequence");
    array[i] = byte;
  }
  return array;
}

async function genInputs(
  msg: Uint8Array,
  publicKeyHex: Uint8Array,
  sigHex: Uint8Array
) {
  let u = await utils.hashToField(msg, 2);

  console.log(
    "u[0] = 0x" + u[0][0].toString(16) + "\n + I * 0x" + u[0][1].toString(16)
  );
  console.log(
    "u[1] = 0x" + u[1][0].toString(16) + "\n + I * 0x" + u[1][1].toString(16)
  );

  let u_array = [
    Fp2_to_array(55, 7, Fp2.fromBigTuple(u[0])),
    Fp2_to_array(55, 7, Fp2.fromBigTuple(u[1])),
  ];
  console.log("u_array : ");
  console.log(JSON.stringify(u_array, null, 2));

  let Hm = await PointG2.hashToCurve(msg);
  console.log(Hm.toAffine()[0].c0.value.toString(16));

  console.log("MapToG2 out:");
  console.log(
    JSON.stringify(
      [
        Fp2_to_array(55, 7, Hm.toAffine()[0]),
        Fp2_to_array(55, 7, Hm.toAffine()[1]),
      ],
      null,
      2
    )
  );

  const signature = PointG2.fromSignature(sigHex);
  let publicKey = PointG1.fromHex(publicKeyHex);
  const isCorrect = await verify(signature, Hm, publicKey);
  console.log("valid signature? " + isCorrect);

  console.log("publicKey:");
  console.log("x = 0x" + publicKey.toAffine()[0].value.toString(16));
  console.log("y = 0x" + publicKey.toAffine()[1].value.toString(16));
  const pubkeyInput = [
    bigint_to_array(55, 7, publicKey.toAffine()[0].value),
    bigint_to_array(55, 7, publicKey.toAffine()[1].value),
  ];
  console.log(JSON.stringify(pubkeyInput, null, 2));

  console.log("signature:");
  console.log(
    "x = 0x" +
      signature.toAffine()[0].c0.value.toString(16) +
      "\n + I * 0x" +
      signature.toAffine()[0].c1.value.toString(16)
  );
  console.log(
    "y = 0x" +
      signature.toAffine()[1].c0.value.toString(16) +
      "\n + I * 0x" +
      signature.toAffine()[1].c1.value.toString(16)
  );
  const signatureInput = [
    Fp2_to_array(55, 7, signature.toAffine()[0]),
    Fp2_to_array(55, 7, signature.toAffine()[1]),
  ];
  console.log(JSON.stringify(signatureInput, null, 2));

  const input = {
    pubkey: pubkeyInput,
    signature: signatureInput,
    hash: u_array,
  };
  console.log(JSON.stringify(input, null, 2));
}

/**
 * Usage:
 *      yarn ts-node test/genInputs.ts <round number (decimal)> <pubkey (48B hexstring)> <signature (96B hexstring)>
 */
async function main() {
  const args = process.argv.slice(2);
  console.log(`args:`, args);

  // Encode round buffer into message
  const round = Number(args[0]);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(round));
  const message = await bls.utils.sha256(buffer);
  console.log(
    `message:`,
    Array.from(message)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("")
  );
  // Public key
  const pubKey = hexToBytes(args[1]);
  console.log(
    `pubKey:`,
    Array.from(pubKey)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("")
  );
  // Signature
  const sig = hexToBytes(args[2]);
  console.log(
    `sig:`,
    Array.from(sig)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("")
  );

  // verify with bls
  console.log(`noble bls verify:`, await bls.verify(sig, message, pubKey));

  await genInputs(message, pubKey, sig);
}

main()
  .then(() => {
    console.log("Done");
  })
  .catch((err) => {
    console.error(err);
  });
