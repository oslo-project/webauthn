export {
	AttestationStatementFormat,
	parseAttestationObject,
	AttestationObjectParseError
} from "./attestation.js";
export {
	AuthenticatorDataParseError,
	ClientDataType,
	ClientDataParseError,
	parseAuthenticatorData,
	parseClientDataJSON,
	TokenBindingStatus
} from "./auth.js";
export { COSEAlgorithm, COSEPublicKey } from "./cose.js";
export { EllipticCurve, Hash } from "./crypto.js";
export {
	createSignatureMessage,
	verifyECDSASignature,
	verifyRSASSAPKCS1v1_5Signature,
	verifyRSASSAPSSSignature
} from "./signature.js";

export type {
	AttestationObject,
	AndroidKeyAttestationStatement,
	AndroidSafetyNetAttestationStatement,
	AppleAnonymousAttestationStatement,
	FIDOU2FAttestationStatement,
	PackedAttestationStatement,
	TPMAttestationStatement
} from "./attestation.js";
export type { AuthenticatorData, WebAuthnCredential, ClientData, TokenBinding } from "./auth.js";
export type { DecodedCOSEPublicKey } from "./cose.js";
export type { ECDSAPublicKey, RSAPublicKey } from "./crypto.js";
