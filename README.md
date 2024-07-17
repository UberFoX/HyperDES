# HyperDES Cipher

HyperDES is a 256-bit block cipher with a 672-bit key size. It uses 12 main rounds, each containing 16 sub-rounds, for a total of 192 rounds of encryption.

## Features

- Block size: 256 bits
- Key size: 672 bits
- Total rounds: 192

## Shuffling Process

The HyperDES cipher uses a complex shuffling process:

1. Block Division: Each 256-bit block is divided into four 64-bit sub-blocks.

2. Sub-block Shuffling: Each sub-block is further split into high and low 32-bit parts (highHi, highLo, lowHi, lowLo).

3. Internal Shuffling: The cipher applies DES operations to shuffle each sub-block internally.

4. Cross-Section Shuffling: After internal shuffling, the cipher performs cross-section shuffling between sub-blocks.

5. Iteration: This process is repeated for multiple rounds, alternating between internal and cross-section shuffling.

The combination of high/low part manipulation and cross-section shuffling aims to create a strong diffusion effect, making the cipher resistant to various cryptanalytic attacks.

This intricate shuffling process ensures that the entire 256-bit block must be cracked as a whole, as no individual part of it can be decoded independently, significantly increasing the cipher's resistance to partial decryption attacks.

## Motivation

HyperDES was created with the goal of improving upon the 3DES (Triple DES) algorithm. The primary objectives were:

1. Increased Block Size: HyperDES operates on 256-bit blocks, a significant increase from the 64-bit blocks used in 3DES. This larger block size allows for more data to be encrypted at once and provides better resistance against certain types of attacks.

2. Expanded Key Space: With a 672-bit key, HyperDES offers a vastly larger key space compared to 3DES. This expansion aims to make the cipher resistant to brute-force attacks, even with potential future advancements in computing power.

3. Future-Proofing: The combination of larger block size and expanded key space is designed to make HyperDES resilient against both current and anticipated future cryptographic attacks, aiming for long-term security in an evolving technological landscape.

These enhancements seek to address some of the limitations of 3DES while maintaining a similar structural approach, resulting in a more robust and future-oriented cipher.

## Usage Example

```csharp
const String s = "The quick brown fox jumps over the lazy dog";
var p = UCryptoUtils.GenerateHyperDesKey("password");
var d = Encoding.UTF8.GetBytes(s);
var c = UCryptoUtils.EncryptHyperDes(d, p);
var t = UCryptoUtils.DecryptHyperDes(c, p);
var e = Encoding.UTF8.GetString(t);
```

## Sample Output
```
CipherText
81 F8 F0 51 EC B3 6D F6 7B 4A CF D5 CB 9B 57 B6 .odQì.mö{JIOE.W¶
34 40 C0 4F 81 67 70 AC 78 08 A4 C6 08 40 1C F2 4@AO.gp¬x.☼Æ.@.ò
BF B1 1F BA 50 80 7F F4 57 46 CC DB DE 41 92 02 ¿±.ºP..ôWFIU_A..
D2 4C EF 36 3F 9D 98 10 9A AF 84 C8 97 9C 5E 0C OLï6?...._.E..^.
PlainText
The quick brown fox jumps over the lazy dog
```

## Security Note
The security of this cipher relies on the secrecy of the key, not the algorithm. The source code can be published without weakening the cipher's security.

## Final Note
HyperDES was based off the 3DES source code found within the Bouncy Castle library, so all credit goes to them for creating the original sources. HyperDES is simply an improvement on that system.
