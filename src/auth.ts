import { bigEndian } from "@oslojs/binary";
import { base64url } from "@oslojs/encoding";
import { COSEPublicKey, decodeCOSEPublicKey } from "./cose.js";

export function parseClientDataJSON(encoded: Uint8Array): ClientData {
	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder().decode(encoded));
	} catch {
		throw new ClientDataParseError("Invalid client data JSON");
	}
	if (parsed === null || typeof parsed !== "object") {
		throw new ClientDataParseError("Invalid client data JSON");
	}
	if (!("type" in parsed)) {
		throw new ClientDataParseError("Missing or invalid property 'type'");
	}
	let type: ClientDataType;
	if (parsed.type === "webauthn.get") {
		type = ClientDataType.Get;
	} else if (parsed.type === "webauthn.create") {
		type = ClientDataType.Create;
	} else {
		throw new ClientDataParseError("Missing or invalid property 'type'");
	}
	if (!("challenge" in parsed) || typeof parsed.challenge !== "string") {
		throw new ClientDataParseError("Missing or invalid property 'challenge'");
	}
	let challenge: Uint8Array;
	try {
		challenge = base64url.decodeIgnorePadding(parsed.challenge);
	} catch {
		throw new ClientDataParseError("Missing or invalid property 'challenge'");
	}

	if (!("origin" in parsed) || typeof parsed.origin !== "string") {
		throw new ClientDataParseError("Missing or invalid property 'origin'");
	}
	let crossOrigin: boolean = false;
	if ("crossOrigin" in parsed) {
		if (typeof parsed.crossOrigin !== "boolean") {
			throw new ClientDataParseError("Invalid property 'crossOrigin'");
		}
		crossOrigin = parsed.crossOrigin;
	}
	let tokenBinding: TokenBinding | null = null;
	if ("tokenBinding" in parsed) {
		if (parsed.tokenBinding === null || typeof parsed.tokenBinding !== "object") {
			throw new ClientDataParseError("Invalid property 'tokenBinding'");
		}
		if (!("id" in parsed.tokenBinding) || typeof parsed.tokenBinding.id !== "string") {
			throw new ClientDataParseError("Missing or invalid property 'tokenBinding.id'");
		}
		if (!("status" in parsed.tokenBinding)) {
			throw new ClientDataParseError("Missing or invalid property 'tokenBinding.status'");
		}

		let tokenBindingId: Uint8Array;
		try {
			tokenBindingId = base64url.decodeIgnorePadding(parsed.tokenBinding.id);
		} catch {
			throw new ClientDataParseError("Missing or invalid property 'tokenBinding.id'");
		}

		let status: TokenBindingStatus;
		if (parsed.tokenBinding.status === "present") {
			status = TokenBindingStatus.Present;
		} else if (parsed.tokenBinding.status === "supported") {
			status = TokenBindingStatus.Supported;
		} else {
			throw new ClientDataParseError("Missing or invalid property 'tokenBinding.status'");
		}
		tokenBinding = {
			id: tokenBindingId,
			status
		};
	}
	const clientData: ClientData = {
		type,
		challenge,
		origin: parsed.origin,
		crossOrigin,
		tokenBinding
	};
	return clientData;
}

export interface ClientData {
	type: ClientDataType;
	challenge: Uint8Array;
	origin: string;
	crossOrigin: boolean | null;
	tokenBinding: TokenBinding | null;
}

export enum ClientDataType {
	Get = 0,
	Create
}

export interface TokenBinding {
	id: Uint8Array;
	status: TokenBindingStatus;
}

export enum TokenBindingStatus {
	Supported = 0,
	Present
}

export class ClientDataParseError extends Error {
	constructor(message: string) {
		super(`Failed to parse client data: ${message}`);
	}
}

export function parseAuthenticatorData(encoded: Uint8Array): AuthenticatorData {
	if (encoded.byteLength < 37) {
		throw new AuthenticatorDataParseError("Insufficient bytes");
	}
	const relyingPartyIdHash = encoded.slice(0, 32);
	const userPresent = (encoded[32] & 0x01) === 1;
	const userVerified = ((encoded[32] >> 2) & 0x01) === 1;
	const signatureCounter = bigEndian.uint32(encoded.slice(33, 37));
	const includesAttestedCredentialData = ((encoded[32] >> 6) & 0x01) === 1;
	let credential: WebAuthnCredential | null = null;
	if (includesAttestedCredentialData) {
		if (encoded.byteLength < 37 + 18) {
			throw new AuthenticatorDataParseError("");
		}
		const aaguid = encoded.slice(37, 53);
		const credentialIdLength = bigEndian.uint16(encoded.slice(53, 55));
		if (encoded.byteLength < 37 + 18 + credentialIdLength) {
			throw new AuthenticatorDataParseError("Insufficient bytes");
		}
		const credentialId = encoded.slice(55, 55 + credentialIdLength);
		let credentialPublicKey: COSEPublicKey;
		try {
			[credentialPublicKey] = decodeCOSEPublicKey(encoded.slice(55 + credentialIdLength));
		} catch {
			throw new AuthenticatorDataParseError("Failed to parse public key");
		}
		credential = {
			authenticatorAAGUID: aaguid,
			id: credentialId,
			publicKey: credentialPublicKey
		};
	}
	const authenticatorData: AuthenticatorData = {
		relyingPartyIdHash,
		userPresent,
		userVerified,
		signatureCounter,
		credential,
		extensions: null
	};
	return authenticatorData;
}

export interface AuthenticatorData {
	relyingPartyIdHash: Uint8Array;
	userPresent: boolean;
	userVerified: boolean;
	signatureCounter: number;
	credential: WebAuthnCredential | null;
	extensions: null;
}

export class AuthenticatorDataParseError extends Error {
	constructor(message: string) {
		super(`Failed to parse authenticator data: ${message}`);
	}
}

export interface WebAuthnCredential {
	authenticatorAAGUID: Uint8Array;
	id: Uint8Array;
	publicKey: COSEPublicKey;
}
