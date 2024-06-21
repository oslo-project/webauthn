# @oslojs/webauthn

## 0.5.0

- [Breaking] `AuthenticatorData` is now a class

## 0.4.0

- [Breaking] Remove `verifyECDSASignature()`, `verifyRSASSAPKCS1v1_5Signature()`, `verifyRSASSAPSSSignature()`
- [Breaking] Remove `Hash`
- [Breaking] Remove `EllipticCurve`
- [Breaking] Remove `ECDSAPublicKey`, `RSAPublicKey`
- [Breaking] Remove `DecodedCOSEPublicKey`
- [Breaking] Rename `createSignatureMessage()` to `createAssertionSignatureMessage()`
- [Breaking] Remove `COSEPublicKey.ecdsa()`
- [Breaking] Update `COSEPublicKey.rsa()`
- [Breaking] Update `COSEPublicKey.algorithm()`
- Add `COSEEllipticCurve`, `COSEKeyType`
- Add `COSEEC2PublicKey`, `COSEOKPPublicKey`
- Add `COSEPublicKey.isAlgorithmDefined()`, `COSEPublicKey.keyType()`, `COSEPublicKey.ec2()`, `COSEPublicKey.okp()`, `COSEPublicKey.symmetric()`
- Add `COSEParseError`
- No longer requires the Web Crypto API

## 0.3.0

- [Breaking] Rename `AttestationFormat.Apple` to `AttestationFormat.AppleAnonymous`

## 0.2.1

- Update dependencies

## 0.2.0

- [Breaking] `PackedAttestationStatement.certificates` can be `null`.
- Update dependencies
