import { decodeCBORToNativeValueNoLeftoverBytes } from "@oslojs/cbor";
import { parseAuthenticatorData } from "./auth.js";

import type { AuthenticatorData } from "./auth.js";
import { getCOSEAlgorithmFromId, type COSEAlgorithm } from "./cose.js";

export function parseAttestationObject(encoded: Uint8Array): AttestationObject {
	let decoded: unknown;
	try {
		decoded = decodeCBORToNativeValueNoLeftoverBytes(encoded, 4);
	} catch {
		throw new AttestationObjectParseError("Invalid CBOR data");
	}
	if (typeof decoded !== "object" || decoded === null) {
		throw new AttestationObjectParseError("Invalid CBOR data");
	}
	if (!("fmt" in decoded) || typeof decoded.fmt !== "string") {
		throw new AttestationObjectParseError("Invalid or missing property 'fmt'");
	}
	if (!("attStmt" in decoded) || typeof decoded.attStmt !== "object" || decoded.attStmt === null) {
		throw new AttestationObjectParseError("Invalid or missing property 'attStmt'");
	}
	if (!("authData" in decoded) || !(decoded.authData instanceof Uint8Array)) {
		throw new AttestationObjectParseError("Invalid or missing property 'authData'");
	}
	let attestationFormat: AttestationStatementFormat;
	if (decoded.fmt === "packed") {
		attestationFormat = AttestationStatementFormat.Packed;
	} else if (decoded.fmt === "tpm") {
		attestationFormat = AttestationStatementFormat.TPM;
	} else if (decoded.fmt === "android-key") {
		attestationFormat = AttestationStatementFormat.AndroidKey;
	} else if (decoded.fmt === "android-safetynet") {
		attestationFormat = AttestationStatementFormat.AndroidSafetyNet;
	} else if (decoded.fmt === "fido-u2f") {
		attestationFormat = AttestationStatementFormat.FIDOU2F;
	} else if (decoded.fmt === "none") {
		attestationFormat = AttestationStatementFormat.None;
	} else if (decoded.fmt === "apple") {
		attestationFormat = AttestationStatementFormat.AppleAnonymous;
	} else {
		throw new AttestationObjectParseError(`Unsupported attestation statement format '${decoded.fmt}'`);
	}
	const attestationObject: AttestationObject = {
		authenticatorData: parseAuthenticatorData(decoded.authData),
		attestationStatement: new AttestationStatement(attestationFormat, decoded.attStmt)
	};
	return attestationObject;
}

export class AttestationObjectParseError extends Error {
	constructor(message: string) {
		super(`Failed to parse attestation object: ${message}`);
	}
}

export interface AttestationObject {
	attestationStatement: AttestationStatement;
	authenticatorData: AuthenticatorData;
}

export class AttestationStatement {
	public format: AttestationStatementFormat;
	public decoded: object;

	constructor(format: AttestationStatementFormat, decoded: object) {
		this.format = format;
		this.decoded = decoded;
	}

	public packed(): PackedAttestationStatement {
		if (this.format !== AttestationStatementFormat.Packed) {
			throw new AttestationStatementParseError("Invalid format");
		}
		if (!("alg" in this.decoded) || typeof this.decoded.alg !== "number") {
			throw new AttestationStatementParseError("Invalid or missing property 'alg'");
		}
		const algorithm = getCOSEAlgorithmFromId(this.decoded.alg);
		if (algorithm === null) {
			throw new AttestationStatementParseError(`Unknown algorithm ID ${this.decoded.alg}`);
		}

		if (!("sig" in this.decoded) || !(this.decoded.sig instanceof Uint8Array)) {
			throw new AttestationStatementParseError("Invalid or missing property 'sig'");
		}
		let certificates: Uint8Array[] | null = null;
		if ("x5c" in this.decoded) {
			if (!Array.isArray(this.decoded.x5c)) {
				throw new AttestationStatementParseError("Invalid property 'x5c'");
			}
			if (this.decoded.x5c.length < 1) {
				throw new AttestationStatementParseError("Invalid property 'x5c'");
			}
			certificates = [];
			for (const certificate of this.decoded.x5c) {
				if (!(certificate instanceof Uint8Array)) {
					throw new AttestationStatementParseError("Invalid property 'x5c'");
				}
				certificates.push(certificate);
			}
		}

		const statement: PackedAttestationStatement = {
			algorithm,
			signature: this.decoded.sig,
			certificates
		};
		return statement;
	}

	public tpm(): TPMAttestationStatement {
		if (this.format !== AttestationStatementFormat.TPM) {
			throw new AttestationStatementParseError("Invalid format");
		}
		if (!("alg" in this.decoded) || typeof this.decoded.alg !== "number") {
			throw new AttestationStatementParseError("Invalid or missing property 'alg'");
		}
		const algorithm = getCOSEAlgorithmFromId(this.decoded.alg);
		if (algorithm === null) {
			throw new AttestationStatementParseError(`Unknown algorithm ID ${this.decoded.alg}`);
		}
		if (!("sig" in this.decoded) || !(this.decoded.sig instanceof Uint8Array)) {
			throw new AttestationStatementParseError("Invalid or missing property 'sig'");
		}
		if (!("x5c" in this.decoded) || !Array.isArray(this.decoded.x5c)) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}
		if (this.decoded.x5c.length < 1) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}
		const certificates: Uint8Array[] = [];
		for (const certificate of this.decoded.x5c) {
			if (!(certificate instanceof Uint8Array)) {
				throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
			}
			certificates.push(certificate);
		}

		if (!("certInfo" in this.decoded) || !(this.decoded.certInfo instanceof Uint8Array)) {
			throw new AttestationStatementParseError("Invalid or missing property 'certInfo'");
		}
		if (!("pubArea" in this.decoded) || !(this.decoded.pubArea instanceof Uint8Array)) {
			throw new AttestationStatementParseError("Invalid or missing property 'pubArea'");
		}

		const statement: TPMAttestationStatement = {
			algorithm: algorithm,
			signature: this.decoded.sig,
			certificates,
			attestation: this.decoded.certInfo,
			publicKey: this.decoded.pubArea
		};
		return statement;
	}

	public androidKey(): AndroidKeyAttestationStatement {
		if (this.format !== AttestationStatementFormat.AndroidKey) {
			throw new AttestationStatementParseError("Invalid format");
		}
		if (!("alg" in this.decoded) || typeof this.decoded.alg !== "number") {
			throw new AttestationStatementParseError("Invalid or missing property 'alg'");
		}
		const algorithm = getCOSEAlgorithmFromId(this.decoded.alg);
		if (algorithm === null) {
			throw new AttestationStatementParseError(`Unknown algorithm ID ${this.decoded.alg}`);
		}
		if (!("sig" in this.decoded) || !(this.decoded.sig instanceof Uint8Array)) {
			throw new AttestationStatementParseError("Invalid or missing property 'sig'");
		}
		if (!("x5c" in this.decoded) || !Array.isArray(this.decoded.x5c)) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}
		if (this.decoded.x5c.length < 1) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}
		const certificates: Uint8Array[] = [];
		for (const certificate of this.decoded.x5c) {
			if (!(certificate instanceof Uint8Array)) {
				throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
			}
			certificates.push(certificate);
		}

		const statement: AndroidKeyAttestationStatement = {
			algorithm: algorithm,
			signature: this.decoded.sig,
			certificates
		};
		return statement;
	}

	public androidSafetyNet(): AndroidSafetyNetAttestationStatement {
		if (this.format !== AttestationStatementFormat.AndroidKey) {
			throw new AttestationStatementParseError("Invalid format");
		}
		if (!("ver" in this.decoded) || typeof this.decoded.ver !== "string") {
			throw new AttestationStatementParseError("Invalid or missing property 'ver'");
		}
		if (!("response" in this.decoded) || !(this.decoded.response instanceof Uint8Array)) {
			throw new AttestationStatementParseError("Invalid or missing property 'response'");
		}

		const statement: AndroidSafetyNetAttestationStatement = {
			version: this.decoded.ver,
			response: this.decoded.response
		};
		return statement;
	}

	public fidoU2F(): FIDOU2FAttestationStatement {
		if (this.format !== AttestationStatementFormat.FIDOU2F) {
			throw new AttestationStatementParseError("Invalid format");
		}
		if (!("sig" in this.decoded) || !(this.decoded.sig instanceof Uint8Array)) {
			throw new AttestationStatementParseError("Invalid or missing property 'sig'");
		}
		if (!("x5c" in this.decoded) || !Array.isArray(this.decoded.x5c)) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}
		if (this.decoded.x5c.length !== 1) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}
		const certificate = this.decoded.x5c[0];
		if (!(certificate instanceof Uint8Array)) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}

		const statement: FIDOU2FAttestationStatement = {
			signature: this.decoded.sig,
			certificate
		};
		return statement;
	}

	public appleAnonymous(): AppleAnonymousAttestationStatement {
		if (this.format !== AttestationStatementFormat.AppleAnonymous) {
			throw new AttestationStatementParseError("Invalid format");
		}
		if (!("x5c" in this.decoded) || !Array.isArray(this.decoded.x5c)) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}
		if (this.decoded.x5c.length < 1) {
			throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
		}
		const certificates: Uint8Array[] = [];
		for (const certificate of this.decoded.x5c) {
			if (!(certificate instanceof Uint8Array)) {
				throw new AttestationStatementParseError("Invalid or missing property 'x5c'");
			}
			certificates.push(certificate);
		}

		const statement: AppleAnonymousAttestationStatement = { certificates };
		return statement;
	}
}

export class AttestationStatementParseError extends Error {
	constructor(message: string) {
		super(`Failed to parse attestation statement: ${message}`);
	}
}

export interface PackedAttestationStatement {
	algorithm: COSEAlgorithm;
	signature: Uint8Array;
	certificates: Uint8Array[] | null;
}

export interface TPMAttestationStatement {
	algorithm: COSEAlgorithm;
	signature: Uint8Array;
	certificates: Uint8Array[];
	attestation: Uint8Array;
	publicKey: Uint8Array;
}

export interface AndroidKeyAttestationStatement {
	algorithm: COSEAlgorithm;
	signature: Uint8Array;
	certificates: Uint8Array[];
}

export interface AndroidSafetyNetAttestationStatement {
	version: string;
	response: Uint8Array;
}

export interface FIDOU2FAttestationStatement {
	signature: Uint8Array;
	certificate: Uint8Array;
}

export interface AppleAnonymousAttestationStatement {
	certificates: Uint8Array[];
}

export enum AttestationStatementFormat {
	Packed = 0,
	TPM,
	AndroidKey,
	AndroidSafetyNet,
	FIDOU2F,
	AppleAnonymous,
	None
}
