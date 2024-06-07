export enum Hash {
	SHA1 = 0,
	SHA224,
	SHA256,
	SHA384,
	SHA512
}

export enum EllipticCurve {
	P256 = 0,
	P384,
	P521,
	Secp256k1,
	Curve25519,
	Curve448
}

export interface ECDSAPublicKey {
	curve: EllipticCurve;
	x: bigint;
	y: bigint;
}

export interface RSAPublicKey {
	e: bigint;
	n: bigint;
}
