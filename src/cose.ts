import { decodeCBORIntoNative } from "@oslojs/cbor";
import { bigIntFromBytes } from "@oslojs/binary";

export function decodeCOSEPublicKey(data: Uint8Array): [publicKey: COSEPublicKey, size: number] {
	let decoded: unknown;
	let size: number;
	try {
		[decoded, size] = decodeCBORIntoNative(data, 4);
	} catch {
		throw new COSEParseError("Failed to decode CBOR");
	}
	if (typeof decoded !== "object" || decoded === null) {
		throw new COSEParseError("Failed to parse object");
	}
	return [new COSEPublicKey(decoded), size];
}

export class COSEPublicKey {
	public decoded: object;

	constructor(decoded: object) {
		this.decoded = decoded;
	}

	public type(): COSEKeyType {
		if (!(1 in this.decoded) || typeof this.decoded[1] !== "number") {
			throw new COSEParseError("Invalid or missing parameter 'kty'");
		}
		const typeId = this.decoded[1];
		if (typeId in COSE_KEY_ID_MAP) {
			return COSE_KEY_ID_MAP[typeId];
		}
		throw new COSEParseError(`Unknown 'kty' value '${typeId}'`);
	}

	public isAlgorithmDefined(): boolean {
		if (!(3 in this.decoded)) {
			return false;
		}
		if (typeof this.decoded[3] !== "number") {
			throw new COSEParseError("Invalid parameter 'alg'");
		}
		return true;
	}

	public algorithm(): COSEAlgorithm {
		if (!(3 in this.decoded) || typeof this.decoded[3] !== "number") {
			throw new COSEParseError("Invalid or missing parameter 'alg'");
		}
		const algorithmId = this.decoded[3];
		if (algorithmId in COSE_ALGORITHM_ID_MAP) {
			return COSE_ALGORITHM_ID_MAP[algorithmId];
		}
		throw new COSEParseError(`Unknown 'alg' value '${algorithmId}'`);
	}

	public ec2(): COSEEC2PublicKey {
		if (this.type() !== COSEKeyType.EC2) {
			throw new COSEParseError("Expected an elliptic curve public key");
		}

		if (!("-1" in this.decoded) || typeof this.decoded["-1"] !== "number") {
			throw new COSEParseError("Invalid or missing parameter 'crv'");
		}
		if (!(this.decoded["-1"] in COSE_ELLIPTIC_CURVE_MAP)) {
			throw new COSEParseError(`Unknown 'crv' value '${this.decoded["-1"]}'`);
		}
		const curve = COSE_ELLIPTIC_CURVE_MAP[this.decoded["-1"]];

		if (!("-2" in this.decoded) || !(this.decoded["-2"] instanceof Uint8Array)) {
			throw new COSEParseError("Invalid or missing parameter 'x'");
		}
		const xBytes = this.decoded["-2"];
		if (xBytes.byteLength !== 32) {
			throw new COSEParseError("Invalid or missing parameter 'x'");
		}

		if (!("-3" in this.decoded) || !(this.decoded["-3"] instanceof Uint8Array)) {
			throw new COSEParseError("Invalid or missing parameter 'y'");
		}
		const yBytes = this.decoded["-3"];
		if (yBytes.byteLength !== 32) {
			throw new COSEParseError("Invalid or missing parameter 'y'");
		}

		const publicKey: COSEEC2PublicKey = {
			curve,
			x: bigIntFromBytes(xBytes),
			y: bigIntFromBytes(yBytes)
		};
		return publicKey;
	}

	public rsa(): COSERSAPublicKey {
		if (this.type() !== COSEKeyType.RSA) {
			throw new COSEParseError("Expected an RSA public key");
		}

		if (!("-1" in this.decoded) || !(this.decoded["-1"] instanceof Uint8Array)) {
			throw new COSEParseError("Invalid or missing parameter 'n'");
		}
		const nBytes = this.decoded["-1"];
		if (nBytes.byteLength !== 256) {
			throw new COSEParseError("Invalid or missing parameter 'n'");
		}

		if (!("-2" in this.decoded) || !(this.decoded["-2"] instanceof Uint8Array)) {
			throw new COSEParseError("Invalid or missing parameter 'e'");
		}
		const eBytes = this.decoded["-2"];
		if (eBytes.byteLength !== 3) {
			throw new COSEParseError("Invalid or missing parameter 'e'");
		}

		const publicKey: COSERSAPublicKey = {
			n: bigIntFromBytes(nBytes),
			e: bigIntFromBytes(eBytes)
		};
		return publicKey;
	}

	public okp(): COSEOKPPublicKey {
		if (this.type() !== COSEKeyType.OKP) {
			throw new COSEParseError("Expected an octet key pair public key");
		}

		if (!("-1" in this.decoded) || typeof this.decoded["-1"] !== "number") {
			throw new COSEParseError("Invalid or missing parameter 'curve'");
		}
		if (!(this.decoded["-1"] in COSE_ELLIPTIC_CURVE_MAP)) {
			throw new COSEParseError("Unknown elliptic curve");
		}
		const curve = COSE_ELLIPTIC_CURVE_MAP[this.decoded["-1"]];

		if (!("-2" in this.decoded) || !(this.decoded["-2"] instanceof Uint8Array)) {
			throw new COSEParseError("Invalid or missing parameter 'x'");
		}
		const x = this.decoded["-2"];

		if ("-4" in this.decoded) {
			throw new COSEParseError("Unexpected parameter 'd'");
		}

		const publicKey: COSEOKPPublicKey = {
			curve,
			x
		};
		return publicKey;
	}

	public symmetric(): Uint8Array {
		if (this.type() !== COSEKeyType.Symmetric) {
			throw new COSEParseError("Expected an symmetric key");
		}
		if (!("-1" in this.decoded) || !(this.decoded["-1"] instanceof Uint8Array)) {
			throw new COSEParseError("Invalid or missing parameter 'k'");
		}
		const k = this.decoded["-1"];
		return k;
	}
}
export interface COSEEC2PublicKey {
	curve: COSEEllipticCurve;
	x: bigint;
	y: bigint;
}

export interface COSERSAPublicKey {
	n: bigint;
	e: bigint;
}

export interface COSEOKPPublicKey {
	curve: COSEEllipticCurve;
	x: Uint8Array;
}

export class COSEParseError extends Error {
	constructor(message: string) {
		super(`Failed to parse COSE public key: ${message}`);
	}
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

export enum COSEEllipticCurve {
	P256 = 0,
	P384,
	P521,
	X25519,
	X448,
	Ed25519,
	Ed448,
	SECP256k1,
	BrainpoolP256r1,
	BrainpoolP320r1,
	BrainpoolP384r1,
	BrainpoolP512r1
}

export enum COSEKeyType {
	OKP = 0,
	EC2,
	RSA,
	Symmetric,
	HSSLMS,
	WalnutDSA
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

export const COSE_KEY_ID_MAP: Record<number, COSEKeyType> = {
	1: COSEKeyType.OKP,
	2: COSEKeyType.EC2,
	3: COSEKeyType.RSA,
	4: COSEKeyType.Symmetric,
	5: COSEKeyType.HSSLMS,
	6: COSEKeyType.WalnutDSA
};

export const COSE_ELLIPTIC_CURVE_MAP: Record<number, COSEEllipticCurve> = {
	1: COSEEllipticCurve.P256,
	2: COSEEllipticCurve.P384,
	3: COSEEllipticCurve.P521,
	4: COSEEllipticCurve.X25519,
	5: COSEEllipticCurve.X448,
	6: COSEEllipticCurve.Ed25519,
	7: COSEEllipticCurve.Ed448,
	8: COSEEllipticCurve.SECP256k1,
	256: COSEEllipticCurve.BrainpoolP256r1,
	257: COSEEllipticCurve.BrainpoolP320r1,
	258: COSEEllipticCurve.BrainpoolP384r1,
	259: COSEEllipticCurve.BrainpoolP512r1
};
