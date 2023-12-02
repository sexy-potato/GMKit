# Data structure

```
SM2Cipher {
  C1 ( byte[], byte[] ), // Tuple
  C2 byte[],
  C3 byte[],
}
```

`SM2Cipher` represents cipher context

- `C1` is Generator adds itself by `k` times (`[k]G`)
- `C2` is CipherText
- `C3` is Hash

```
SM2Signature {
  R byte[],
  S byte[],
}
```

`SM2Signature` isn't message digest, it represents an random point with a proof

- `R` is an value based-on x-coordinate of random point
- `S` is signature proof

```
SM2PublicKey (byte[], byte[]) // Tuple
```

SM2 is one of elliptic curve cryptography, so it's public key can represent in compression (starts with `0x02` or `0x03`) or not (starts with `0x04`), you must decompress it before use if necessary.

```
SM2Key {
  P SM2PublicKey,
  d byte[],
}
```

`SM2Key` represents a pair of public key & private key.

# Functions

__Signer defaults to `1234567812345678`__

- `gmkit_xor(X byte[], Y byte[]) byte[]`
- `gmkit_sm2_verify(P SM2PublicKey, message byte[], signature SM2Signature, signer? string) boolean`
- `gmkit_sm2_sign(dP SM2Key, message byte[], signer? string) SM2Signature`
- `gmkit_sm2_encrypt(P SM2PublicKey, message byte[]) SM2Cipher`
- `gmkit_sm2_decrypt(d byte[], cipher SM2Cipher) byte[]`
- `gmkit_sm2_key() SM2Key` 
- `gmkit_sm4(key byte[], message byte[]) byte[]` 


