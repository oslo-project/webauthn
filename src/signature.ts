import { sha256 } from "@oslojs/crypto/sha2";

export function createAssertionSignatureMessage(authenticatorData: Uint8Array, clientDataJSON: Uint8Array): Uint8Array {
	const hash = sha256(clientDataJSON);
	const message = new Uint8Array(authenticatorData.byteLength + hash.byteLength);
	message.set(authenticatorData);
	message.set(hash, authenticatorData.byteLength);
	return message;
}
