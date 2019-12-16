# SHA algorithms

### Algorithms

Table showing details of the SHA algorithms:

| algorithm      | mnemonic | type-code    | width | extension | builtin      | gcrypt | OpenSSL| EVP    |
|:---------------|:---------|:-------------|------:|----------:|:-------------|:-------|:-------|:-------|
| `sha1`         | `sha1`   | `0x73686131` | 160   | yes       | `sha/sha1`   | yes    | yes    | -      |
| `sha256`       | `s256`   | `0x73323536` | 256   | yes       | `sha/sha256` | yes    | yes    | -      |
| `sha224`       | `s224`   | `0x73323234` | 224   | no        | `sha/sha256` | yes    | yes    | -      |
| `sha512`       | `s512`   | `0x73353132` | 512   | yes       | `sha/sha512` | yes    | yes    | yes    |
| `sha512/224`   | `s226`   | `0x73323236` | 224   | no        | `sha/sha512` | yes    | yes    | yes    |
| `sha512/256`   | `s228`   | `0x73323238` | 256   | no        | `sha/sha512` | yes    | yes    | yes    |
| `sha3-224`     | `s388`   | `0x73333838` | 224   | no        | `sha/sha3`   | yes    | -      | yes    |
| `sha3-256`     | `s398`   | `0x73333938` | 256   | no        | `sha/sha3`   | yes    | -      | yes    |
| `sha3-384`     | `s3a8`   | `0x73336138` | 384   | no        | `sha/sha3`   | yes    | -      | yes    |
| `sha3-512`     | `s3b8`   | `0x73336238` | 512   | no        | `sha/sha3`   | yes    | -      | yes    |

#### Notes

- The _'extension'_ column refers to whether the algorithm is vulnerable to the
 [length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack).