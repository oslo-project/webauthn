import { sha256 } from "@oslojs/crypto/sha2";
import {
	ASN1BitString,
	ASN1Integer,
	ASN1ObjectIdentifier,
	ASN1Sequence,
	decodeASN1NoLeftoverBytes,
	encodeASN1,
	encodeObjectIdentifier
} from "@oslojs/asn1";
import { Hash, EllipticCurve } from "./crypto.js";
import { bigIntBytes } from "@oslojs/binary";

import type { ECDSAPublicKey, RSAPublicKey } from "./crypto.js";

export async function verifyECDSASignature(
	hash: Hash,
	publicKey: ECDSAPublicKey,
	derSignature: Uint8Array,
	authenticatorData: Uint8Array,
	clientDataJSON: Uint8Array
): Promise<boolean> {
	let webCryptoHash: string;
	if (hash === Hash.SHA1) {
		webCryptoHash = "SHA-1";
	} else if (hash === Hash.SHA256) {
		webCryptoHash = "SHA-256";
	} else if (hash === Hash.SHA384) {
		webCryptoHash = "SHA-384";
	} else if (hash === Hash.SHA512) {
		webCryptoHash = "SHA-512";
	} else {
		throw new TypeError("Unsupported hash");
	}

	let webCryptoCurve: string;
	if (publicKey.curve === EllipticCurve.P256) {
		webCryptoCurve = "P-256";
	} else if (publicKey.curve === EllipticCurve.P384) {
		webCryptoCurve = "P-384";
	} else if (publicKey.curve === EllipticCurve.P521) {
		webCryptoCurve = "P-521";
	} else {
		throw new TypeError("Unsupported curve");
	}

	const uncompressedPublicKey = new Uint8Array(65);
	uncompressedPublicKey[0] = 0x04;
	uncompressedPublicKey.set(bigIntBytes(publicKey.x), 1);
	uncompressedPublicKey.set(bigIntBytes(publicKey.y), 33);
	const webCryptoPublicKey = await crypto.subtle.importKey(
		"raw",
		uncompressedPublicKey,
		{
			name: "ECDSA",
			namedCurve: webCryptoCurve
		},
		true,
		["verify"]
	);

	const message = createSignatureMessage(authenticatorData, clientDataJSON);
	let derParsedSignature: unknown;
	try {
		derParsedSignature = decodeASN1NoLeftoverBytes(derSignature, 2);
	} catch {
		return false;
	}
	if (!(derParsedSignature instanceof ASN1Sequence) || derParsedSignature.items.length !== 2) {
		return false;
	}
	const rASN1 = derParsedSignature.items[0];
	const sASN1 = derParsedSignature.items[1];
	if (!(rASN1 instanceof ASN1Integer) || !(sASN1 instanceof ASN1Integer)) {
		return false;
	}
	const r = rASN1.value;
	const s = sASN1.value;
	if (r < 1n || s < 1n) {
		return false;
	}
	const rBytes = bigIntBytes(r);
	const sBytes = bigIntBytes(s);
	const signature = new Uint8Array(Math.max(rBytes.byteLength, sBytes.byteLength) * 2);
	signature.set(rBytes, signature.byteLength / 2 - rBytes.byteLength);
	signature.set(sBytes, signature.byteLength - sBytes.byteLength);
	const result = await crypto.subtle.verify(
		{
			name: "ECDSA",
			hash: webCryptoHash
		},
		webCryptoPublicKey,
		signature,
		message
	);
	return result;
}

export async function verifyRSASSAPKCS1v1_5Signature(
	hash: Hash,
	publicKey: RSAPublicKey,
	signature: Uint8Array,
	authenticatorData: Uint8Array,
	clientDataJSON: Uint8Array
): Promise<boolean> {
	let webCryptoHash: string;
	if (hash === Hash.SHA1) {
		webCryptoHash = "SHA-1";
	} else if (hash === Hash.SHA256) {
		webCryptoHash = "SHA-256";
	} else if (hash === Hash.SHA384) {
		webCryptoHash = "SHA-384";
	} else if (hash === Hash.SHA512) {
		webCryptoHash = "SHA-512";
	} else {
		throw new TypeError("Unsupported hash");
	}

	const encodedPublicKey = encodeASN1(new ASN1Sequence([new ASN1Integer(publicKey.n), new ASN1Integer(publicKey.e)]));
	const spki = encodeASN1(
		new ASN1Sequence([
			new ASN1Sequence([new ASN1ObjectIdentifier(encodeObjectIdentifier("1.2.840.113549.1.1.1"))]),
			new ASN1BitString(encodedPublicKey, encodedPublicKey.byteLength * 8)
		])
	);
	const webCryptoKey = await crypto.subtle.importKey(
		"spki",
		spki,
		{
			name: "RSASSA-PKCS1-v1_5",
			hash: webCryptoHash
		},
		false,
		["verify"]
	);
	const message = createSignatureMessage(authenticatorData, clientDataJSON);
	const result = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", webCryptoKey, signature, message);
	return result;
}

export async function verifyRSASSAPSSSignature(
	hash: Hash,
	publicKey: RSAPublicKey,
	signature: Uint8Array,
	authenticatorData: Uint8Array,
	clientDataJSON: Uint8Array
): Promise<boolean> {
	let webCryptoHash: string;
	let saltLength: number;
	if (hash === Hash.SHA1) {
		webCryptoHash = "SHA-1";
		saltLength = 20;
	} else if (hash === Hash.SHA256) {
		webCryptoHash = "SHA-256";
		saltLength = 32;
	} else if (hash === Hash.SHA384) {
		webCryptoHash = "SHA-384";
		saltLength = 48;
	} else if (hash === Hash.SHA512) {
		webCryptoHash = "SHA-512";
		saltLength = 64;
	} else {
		throw new TypeError("Unsupported hash");
	}

	const encodedPublicKey = encodeASN1(new ASN1Sequence([new ASN1Integer(publicKey.n), new ASN1Integer(publicKey.e)]));
	const spki = encodeASN1(
		new ASN1Sequence([
			new ASN1Sequence([new ASN1ObjectIdentifier(encodeObjectIdentifier("1.2.840.113549.1.1.1"))]),
			new ASN1BitString(encodedPublicKey, encodedPublicKey.byteLength * 8)
		])
	);
	const webCryptoKey = await crypto.subtle.importKey(
		"spki",
		spki,
		{
			name: "RSA-PSS",
			hash: webCryptoHash
		},
		false,
		["verify"]
	);
	const message = createSignatureMessage(authenticatorData, clientDataJSON);
	const result = await crypto.subtle.verify(
		{
			name: "RSA-PSS",
			saltLength
		},
		webCryptoKey,
		signature,
		message
	);
	return result;
}

export function createSignatureMessage(authenticatorData: Uint8Array, clientDataJSON: Uint8Array): Uint8Array {
	const hash = sha256(clientDataJSON);
	const message = new Uint8Array(authenticatorData.byteLength + hash.byteLength);
	message.set(authenticatorData);
	message.set(hash, authenticatorData.byteLength);
	return message;
}
