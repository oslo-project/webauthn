import { describe, test, expect } from "vitest";
import { COSEEllipticCurve, COSEPublicKey } from "./cose.js";

import type { COSEEC2PublicKey, COSEOKPPublicKey, COSERSAPublicKey } from "./cose.js";

describe("COSEPublicKey", () => {
	test("COSEPublicKey.ec2()", () => {
		const decoded = {
			1: 2,
			"-1": 1,
			"-2": new Uint8Array([...new Uint8Array(29), 0x00, 0x01, 0x00]),
			"-3": new Uint8Array([...new Uint8Array(29), 0x01, 0x00, 0x00])
		};
		const key = new COSEPublicKey(decoded);
		expect(key.ec2()).toStrictEqual({
			curve: COSEEllipticCurve.P256,
			x: 1n << 8n,
			y: 1n << 16n
		} satisfies COSEEC2PublicKey);
	});

	test("COSEPublicKey.rsa()", () => {
		const decoded = {
			1: 3,
			"-1": new Uint8Array([...new Uint8Array(253), 0x00, 0x01, 0x00]),
			"-2": new Uint8Array([0x01, 0x00, 0x00])
		};
		const key = new COSEPublicKey(decoded);
		expect(key.rsa()).toStrictEqual({
			n: 1n << 8n,
			e: 1n << 16n
		} satisfies COSERSAPublicKey);
	});

	test("COSEPublicKey.okp()", () => {
		const decoded = {
			1: 1,
			"-1": 4,
			"-2": new Uint8Array([0x01, 0x02, 0x03])
		};
		const key = new COSEPublicKey(decoded);
		expect(key.okp()).toStrictEqual({
			curve: COSEEllipticCurve.X25519,
			x: new Uint8Array([0x01, 0x02, 0x03])
		} satisfies COSEOKPPublicKey);
	});

	test("COSEPublicKey.symmetric()", () => {
		const decoded = {
			1: 4,
			"-1": new Uint8Array([0x01, 0x02, 0x03])
		};
		const key = new COSEPublicKey(decoded);
		expect(key.symmetric()).toStrictEqual(new Uint8Array([0x01, 0x02, 0x03]));
	});
});
