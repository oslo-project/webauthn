import { decodeCBORIntoNative } from "@oslojs/cbor";
import { EllipticCurve } from "./crypto.js";
import {bigIntFromBytes} from "@oslojs/binary"

import type { ECDSAPublicKey, RSAPublicKey } from "./crypto.js";

export function parseCOSEPublicKey(data: Uint8Array): [publicKey: COSEPublicKey, size: number] {
	const [decodedRaw, size] = decodeCBORIntoNative(data, 4);
	if (typeof decodedRaw !== "object" || decodedRaw === null) {
		throw new Error();
	}
	if (!(1 in decodedRaw) || typeof decodedRaw[1] !== "number") {
		throw new Error();
	}
	if (!(3 in decodedRaw) || typeof decodedRaw[3] !== "number") {
		throw new Error();
	}
	const decoded: DecodedCOSEPublicKey = {
		1: decodedRaw[1],
		3: decodedRaw[3]
	};
	return [new COSEPublicKey(decoded), size];
}

export class COSEPublicKey {
	public decoded: DecodedCOSEPublicKey;

	constructor(decoded: DecodedCOSEPublicKey) {
		this.decoded = decoded;
	}

	public algorithm(): COSEAlgorithm {
		if (this.decoded[3] in COSE_ALGORITHM_ID_MAP) {
			return COSE_ALGORITHM_ID_MAP[this.decoded[3]];
		}
		throw new Error();
	}

	public ecdsa(): ECDSAPublicKey {
		if (!("-1" in this.decoded) || typeof this.decoded["-1"] !== "number") {
			throw new Error();
		}
		let curve: EllipticCurve;
		if (this.decoded["-1"] === 1) {
			curve = EllipticCurve.P256;
		} else if (this.decoded["-1"] === 2) {
			curve = EllipticCurve.P384;
		} else if (this.decoded["-1"] === 3) {
			curve = EllipticCurve.P521;
		} else if (this.decoded["-1"] === 8) {
			curve = EllipticCurve.P521;
		} else {
			throw new Error("Unknown elliptic curve");
		}
		if (!("-2" in this.decoded) || !(this.decoded["-2"] instanceof Uint8Array)) {
			throw new Error();
		}
		if (!("-3" in this.decoded) || !(this.decoded["-3"] instanceof Uint8Array)) {
			throw new Error();
		}
		if (this.decoded["-2"].length !== 32 || this.decoded["-3"].length !== 32) {
			throw new Error();
		}
		const publicKey: ECDSAPublicKey = {
			curve,
			x: bigIntFromBytes(this.decoded["-2"]),
			y: bigIntFromBytes(this.decoded["-3"])
		};
		return publicKey;
	}

	public rsa(): RSAPublicKey {
		if (!("-1" in this.decoded) || !(this.decoded["-1"] instanceof Uint8Array)) {
			throw new Error();
		}
		if (this.decoded["-1"].length !== 256) {
			throw new Error();
		}
		if (!("-2" in this.decoded) || !(this.decoded["-2"] instanceof Uint8Array)) {
			throw new Error();
		}
		if (this.decoded["-2"].length !== 3) {
			throw new Error();
		}
		const publicKey: RSAPublicKey = {
			n: bigIntFromBytes(this.decoded["-1"]),
			e: bigIntFromBytes(this.decoded["-2"])
		};
		return publicKey;
	}
}

export interface DecodedCOSEPublicKey {
	1: number;
	3: number;
}

export enum COSEAlgorithm {
	RS1 = 0,
	A128CTR,
	A192CTR,
	A256CTR,
	A128CBC,
	A192CBC,
	A256CBC,
	WalnutDSA,
	RS512,
	RS384,
	RS256,
	ES256K,
	HSSLMS,
	SHAKE256,
	SHA512,
	SHA384,
	RSAESOAEP_SHA512,
	RSAESOAEP_SHA256,
	RSAESOAEP_RFC8017Default,
	PS512,
	PS384,
	PS256,
	ES512,
	ES384,
	ECDHSS_A256KW,
	ECDHSS_A192KW,
	ECDHSS_A128KW,
	ECDHES_A256KW,
	ECDHES_A192KW,
	ECDHES_A128KW,
	ECDHSS_HKDF512,
	ECDHSS_HKDF256,
	ECDHES_HKDF512,
	ECDHES_HKDF256,
	SHAKE128,
	SHA512_256,
	SHA256,
	SHA256_64,
	SHA1,
	Direct_HKDFAES256,
	Direct_HKDFAES128,
	Direct_HKDFSHA512,
	Direct_HKDFSHA256,
	EdDSA,
	ES256,
	Direct,
	A256KW,
	A192KW,
	A128KW,
	A128GCM,
	A192GCM,
	A256GCM,
	HMAC256_64,
	HMAC256_256,
	HMAC384_384,
	HMAC512_512,
	AESCCM_16_64_128,
	AESCCM_16_64_256,
	AESCCM_64_64_128,
	AESCCM_64_64_256,
	AESMAC128_64,
	AESMAC256_64,
	ChaCha20_Poly1305,
	AESMAC128_128,
	AESMAC256_128,
	AESCCM_16_128_128,
	AESCCM_16_128_256,
	AESCCM_64_128_128,
	AESCCM_64_128_256
}

export const COSE_ALGORITHM_ID_MAP: Record<number, COSEAlgorithm> = {
	"-65535": COSEAlgorithm.RS1,
	"-65534": COSEAlgorithm.A128CTR,
	"-65533": COSEAlgorithm.A192CTR,
	"-65532": COSEAlgorithm.A256CTR,
	"-65531": COSEAlgorithm.A128CBC,
	"-65530": COSEAlgorithm.A192CBC,
	"-65529": COSEAlgorithm.A256CBC,
	"-260": COSEAlgorithm.WalnutDSA,
	"-259": COSEAlgorithm.RS512,
	"-258": COSEAlgorithm.RS384,
	"-257": COSEAlgorithm.RS256,
	"-47": COSEAlgorithm.ES256K,
	"-46": COSEAlgorithm.HSSLMS,
	"-45": COSEAlgorithm.SHAKE256,
	"-44": COSEAlgorithm.SHA512,
	"-43": COSEAlgorithm.SHA384,
	"-42": COSEAlgorithm.RSAESOAEP_SHA512,
	"-41": COSEAlgorithm.RSAESOAEP_SHA256,
	"-40": COSEAlgorithm.RSAESOAEP_RFC8017Default,
	"-39": COSEAlgorithm.PS512,
	"-38": COSEAlgorithm.PS384,
	"-37": COSEAlgorithm.PS256,
	"-36": COSEAlgorithm.ES512,
	"-35": COSEAlgorithm.ES384,
	"-34": COSEAlgorithm.ECDHSS_A256KW,
	"-33": COSEAlgorithm.ECDHSS_A192KW,
	"-32": COSEAlgorithm.ECDHSS_A128KW,
	"-31": COSEAlgorithm.ECDHES_A256KW,
	"-30": COSEAlgorithm.ECDHES_A192KW,
	"-29": COSEAlgorithm.ECDHES_A128KW,
	"-28": COSEAlgorithm.ECDHSS_HKDF512,
	"-27": COSEAlgorithm.ECDHSS_HKDF256,
	"-26": COSEAlgorithm.ECDHES_HKDF512,
	"-25": COSEAlgorithm.ECDHES_HKDF256,
	"-18": COSEAlgorithm.SHAKE128,
	"-17": COSEAlgorithm.SHA512_256,
	"-16": COSEAlgorithm.SHA256,
	"-15": COSEAlgorithm.SHA256_64,
	"-14": COSEAlgorithm.SHA1,
	"-13": COSEAlgorithm.Direct_HKDFAES256,
	"-12": COSEAlgorithm.Direct_HKDFAES128,
	"-11": COSEAlgorithm.Direct_HKDFSHA512,
	"-10": COSEAlgorithm.Direct_HKDFSHA256,
	"-8": COSEAlgorithm.EdDSA,
	"-7": COSEAlgorithm.ES256,
	"-6": COSEAlgorithm.Direct,
	"-5": COSEAlgorithm.A256KW,
	"-4": COSEAlgorithm.A192KW,
	"-3": COSEAlgorithm.A128KW,
	1: COSEAlgorithm.A128GCM,
	2: COSEAlgorithm.A192GCM,
	3: COSEAlgorithm.A256GCM,
	4: COSEAlgorithm.HMAC256_64,
	5: COSEAlgorithm.HMAC256_256,
	6: COSEAlgorithm.HMAC384_384,
	7: COSEAlgorithm.HMAC512_512,
	10: COSEAlgorithm.AESCCM_16_64_128,
	11: COSEAlgorithm.AESCCM_16_64_256,
	12: COSEAlgorithm.AESCCM_64_64_128,
	13: COSEAlgorithm.AESCCM_64_64_256,
	14: COSEAlgorithm.AESMAC128_64,
	15: COSEAlgorithm.AESMAC256_64,
	24: COSEAlgorithm.ChaCha20_Poly1305,
	25: COSEAlgorithm.AESMAC128_128,
	26: COSEAlgorithm.AESMAC256_128,
	30: COSEAlgorithm.AESCCM_16_128_128,
	31: COSEAlgorithm.AESCCM_16_128_256,
	32: COSEAlgorithm.AESCCM_64_128_128,
	33: COSEAlgorithm.AESCCM_64_128_256
};
