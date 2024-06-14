export { AttestationStatementFormat, parseAttestationObject, AttestationObjectParseError } from "./attestation.js";
export {
	AuthenticatorDataParseError,
	ClientDataType,
	ClientDataParseError,
	parseAuthenticatorData,
	parseClientDataJSON,
	TokenBindingStatus
} from "./auth.js";
export { COSEAlgorithm, COSEPublicKey, COSEEllipticCurve, COSEKeyType, COSEParseError } from "./cose.js";
export { createAssertionSignatureMessage } from "./signature.js";

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
export type { COSEEC2PublicKey, COSEOKPPublicKey, COSERSAPublicKey } from "./cose.js";
