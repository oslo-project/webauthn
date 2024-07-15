import { decodeCBORToNativeValue } from "@oslojs/cbor";
import { bigIntFromBytes } from "@oslojs/binary";

export function decodeCOSEPublicKey(data: Uint8Array): [publicKey: COSEPublicKey, size: number] {
	let decoded: unknown;
	let size: number;
	try {
		[decoded, size] = decodeCBORToNativeValue(data, 4);
	} catch {
		throw new Error("Failed to decode CBOR");
	}
	if (typeof decoded !== "object" || decoded === null) {
		throw new Error("Invalid CBOR map");
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
			throw new Error("Invalid or missing parameter 'kty'");
		}
		const typeId = this.decoded[1];
		if (typeId in COSE_KEY_ID_MAP) {
			return COSE_KEY_ID_MAP[typeId];
		}
		throw new Error(`Unknown 'kty' value '${typeId}'`);
	}

	public isAlgorithmDefined(): boolean {
		if (!(3 in this.decoded)) {
			return false;
		}
		if (typeof this.decoded[3] !== "number") {
			throw new Error("Invalid parameter 'alg'");
		}
		return true;
	}

	public algorithm(): number {
		if (!(3 in this.decoded) || typeof this.decoded[3] !== "number") {
			throw new Error("Invalid or missing parameter 'alg'");
		}
		return this.decoded[3];
	}

	public ec2(): COSEEC2PublicKey {
		if (this.type() !== COSEKeyType.EC2) {
			throw new Error("Expected an elliptic curve public key");
		}

		if (!("-1" in this.decoded) || typeof this.decoded["-1"] !== "number") {
			throw new Error("Invalid or missing parameter 'crv'");
		}

		const curve = this.decoded["-1"];

		if (!("-2" in this.decoded) || !(this.decoded["-2"] instanceof Uint8Array)) {
			throw new Error("Invalid or missing parameter 'x'");
		}
		const xBytes = this.decoded["-2"];
		if (xBytes.byteLength !== 32) {
			throw new Error("Invalid or missing parameter 'x'");
		}

		if (!("-3" in this.decoded) || !(this.decoded["-3"] instanceof Uint8Array)) {
			throw new Error("Invalid or missing parameter 'y'");
		}
		const yBytes = this.decoded["-3"];
		if (yBytes.byteLength !== 32) {
			throw new Error("Invalid or missing parameter 'y'");
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
			throw new Error("Expected an RSA public key");
		}

		if (!("-1" in this.decoded) || !(this.decoded["-1"] instanceof Uint8Array)) {
			throw new Error("Invalid or missing parameter 'n'");
		}
		const nBytes = this.decoded["-1"];
		if (nBytes.byteLength !== 256) {
			throw new Error("Invalid or missing parameter 'n'");
		}

		if (!("-2" in this.decoded) || !(this.decoded["-2"] instanceof Uint8Array)) {
			throw new Error("Invalid or missing parameter 'e'");
		}
		const eBytes = this.decoded["-2"];
		if (eBytes.byteLength !== 3) {
			throw new Error("Invalid or missing parameter 'e'");
		}

		const publicKey: COSERSAPublicKey = {
			n: bigIntFromBytes(nBytes),
			e: bigIntFromBytes(eBytes)
		};
		return publicKey;
	}

	public okp(): COSEOKPPublicKey {
		if (this.type() !== COSEKeyType.OKP) {
			throw new Error("Expected an octet key pair public key");
		}

		if (!("-1" in this.decoded) || typeof this.decoded["-1"] !== "number") {
			throw new Error("Invalid or missing parameter 'curve'");
		}
		const curve = this.decoded["-1"];

		if (!("-2" in this.decoded) || !(this.decoded["-2"] instanceof Uint8Array)) {
			throw new Error("Invalid or missing parameter 'x'");
		}
		const x = this.decoded["-2"];

		if ("-4" in this.decoded) {
			throw new Error("Unexpected parameter 'd'");
		}

		const publicKey: COSEOKPPublicKey = {
			curve,
			x
		};
		return publicKey;
	}

	public symmetric(): Uint8Array {
		if (this.type() !== COSEKeyType.Symmetric) {
			throw new Error("Expected an symmetric key");
		}
		if (!("-1" in this.decoded) || !(this.decoded["-1"] instanceof Uint8Array)) {
			throw new Error("Invalid or missing parameter 'k'");
		}
		const k = this.decoded["-1"];
		return k;
	}
}
export interface COSEEC2PublicKey {
	curve: number;
	x: bigint;
	y: bigint;
}

export interface COSERSAPublicKey {
	n: bigint;
	e: bigint;
}

export interface COSEOKPPublicKey {
	curve: number;
	x: Uint8Array;
}

export const coseAlgorithmES256 = -7;
export const coseAlgorithmRS256 = -257;
export const coseAlgorithmEdDSA = -8;

export const coseEllipticCurveP256 = 1;
export const coseEllipticCurveEd25519 = 6;

export enum COSEKeyType {
	OKP = 0,
	EC2,
	RSA,
	Symmetric,
	HSSLMS,
	WalnutDSA
}

const COSE_KEY_ID_MAP: Record<number, COSEKeyType> = {
	1: COSEKeyType.OKP,
	2: COSEKeyType.EC2,
	3: COSEKeyType.RSA,
	4: COSEKeyType.Symmetric,
	5: COSEKeyType.HSSLMS,
	6: COSEKeyType.WalnutDSA
};
