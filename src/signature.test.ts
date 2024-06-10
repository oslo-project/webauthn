import { test, expect } from "vitest";
import {
	createSignatureMessage,
	verifyECDSASignature,
	verifyRSASSAPKCS1v1_5Signature,
	verifyRSASSAPSSSignature
} from "./signature.js";
import { EllipticCurve, Hash } from "./crypto.js";
import { ASN1BitString, ASN1Integer, ASN1Sequence, decodeASN1NoLeftoverBytes, encodeASN1 } from "@oslojs/asn1";
import { bigIntFromBytes } from "@oslojs/binary";

import type { ECDSAPublicKey, RSAPublicKey } from "./crypto.js";

test("verifyECDSASignature()", async () => {
	const authenticatorData = new Uint8Array([0x01]);
	const clientDataJSON = new Uint8Array([0x02]);
	const webCryptoKeys = await crypto.subtle.generateKey(
		{
			name: "ECDSA",
			namedCurve: "P-256"
		},
		false,
		["sign", "verify"]
	);
	const message = createSignatureMessage(authenticatorData, clientDataJSON);
	const signature = new Uint8Array(
		await crypto.subtle.sign(
			{
				name: "ECDSA",
				hash: "SHA-256"
			},
			webCryptoKeys.privateKey,
			message
		)
	);
	const encodedPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", webCryptoKeys.publicKey));
	const r = bigIntFromBytes(signature.slice(0, signature.byteLength / 2));
	const s = bigIntFromBytes(signature.slice(signature.byteLength / 2));
	const derSignature = encodeASN1(new ASN1Sequence([new ASN1Integer(r), new ASN1Integer(s)]));

	const publicKey: ECDSAPublicKey = {
		curve: EllipticCurve.P256,
		x: bigIntFromBytes(encodedPublicKey.slice(1, 33)),
		y: bigIntFromBytes(encodedPublicKey.slice(33))
	};
	await expect(
		verifyECDSASignature(Hash.SHA256, publicKey, derSignature, authenticatorData, clientDataJSON)
	).to.resolves.toBe(true);
});

test("verifyRSASSAPKCS1v1_5Signature()", async () => {
	const authenticatorData = new Uint8Array([0x01]);
	const clientDataJSON = new Uint8Array([0x02]);
	const webCryptoKeys = await crypto.subtle.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			modulusLength: 2048,
			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
			hash: "SHA-256"
		},
		false,
		["sign", "verify"]
	);
	const message = createSignatureMessage(authenticatorData, clientDataJSON);
	const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", webCryptoKeys.privateKey, message));
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", webCryptoKeys.publicKey));
	const decodedSPKI = decodeASN1NoLeftoverBytes(spki, 10);
	if (!(decodedSPKI instanceof ASN1Sequence) || decodedSPKI.items.length !== 2) {
		throw new Error("Invalid SPKI");
	}
	const encodedPublicKey = decodedSPKI.items[1];
	if (!(encodedPublicKey instanceof ASN1BitString)) {
		throw new Error("Invalid SPKI public key");
	}
	const decodedPublicKey = decodeASN1NoLeftoverBytes(encodedPublicKey.bytes, 10);
	if (!(decodedPublicKey instanceof ASN1Sequence) || decodedPublicKey.items.length !== 2) {
		throw new Error("Invalid SPKI");
	}
	const nASN1 = decodedPublicKey.items[0];
	const eASN1 = decodedPublicKey.items[1];
	if (!(nASN1 instanceof ASN1Integer) || !(eASN1 instanceof ASN1Integer)) {
		throw new Error("Invalid public key");
	}
	const publicKey: RSAPublicKey = {
		n: nASN1.value,
		e: eASN1.value
	};
	await expect(
		verifyRSASSAPKCS1v1_5Signature(Hash.SHA256, publicKey, signature, authenticatorData, clientDataJSON)
	).to.resolves.toBe(true);
});

test("verifyRSASSAPSSSignature()", async () => {
	const authenticatorData = new Uint8Array([0x01]);
	const clientDataJSON = new Uint8Array([0x02]);
	const webCryptoKeys = await crypto.subtle.generateKey(
		{
			name: "RSA-PSS",
			modulusLength: 2048,
			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
			hash: "SHA-256"
		},
		false,
		["sign", "verify"]
	);
	const message = createSignatureMessage(authenticatorData, clientDataJSON);
	const signature = new Uint8Array(
		await crypto.subtle.sign(
			{
				name: "RSA-PSS",
				saltLength: 32
			},
			webCryptoKeys.privateKey,
			message
		)
	);
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", webCryptoKeys.publicKey));
	const decodedSPKI = decodeASN1NoLeftoverBytes(spki, 10);
	if (!(decodedSPKI instanceof ASN1Sequence) || decodedSPKI.items.length !== 2) {
		throw new Error("Invalid SPKI");
	}
	const encodedPublicKey = decodedSPKI.items[1];
	if (!(encodedPublicKey instanceof ASN1BitString)) {
		throw new Error("Invalid SPKI public key");
	}
	const decodedPublicKey = decodeASN1NoLeftoverBytes(encodedPublicKey.bytes, 10);
	if (!(decodedPublicKey instanceof ASN1Sequence) || decodedPublicKey.items.length !== 2) {
		throw new Error("Invalid SPKI");
	}
	const nASN1 = decodedPublicKey.items[0];
	const eASN1 = decodedPublicKey.items[1];
	if (!(nASN1 instanceof ASN1Integer) || !(eASN1 instanceof ASN1Integer)) {
		throw new Error("Invalid public key");
	}
	const publicKey: RSAPublicKey = {
		n: nASN1.value,
		e: eASN1.value
	};
	await expect(
		verifyRSASSAPSSSignature(Hash.SHA256, publicKey, signature, authenticatorData, clientDataJSON)
	).to.resolves.toBe(true);
});
