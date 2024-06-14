import { test, expect } from "vitest";
import { createAssertionSignatureMessage } from "./signature.js";

test("createAssertionSignatureMessage()", async () => {
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
	const message = createAssertionSignatureMessage(authenticatorData, clientDataJSON);
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
	await expect(
		crypto.subtle.verify(
			{
				name: "ECDSA",
				hash: "SHA-256"
			},
			webCryptoKeys.publicKey,
			signature,
			message
		)
	).to.resolves.toBe(true);
});
