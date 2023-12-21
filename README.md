#   slh-dsa-py

2023-11-27  Markku-Juhani O. Saarinen  mjos@iki.fi

A simple Python implementation of the SLH-DSA ("Stateless Hash-Based Digital Signature Standard") as described in [FIPS 205 Initial Public Draft](https://doi.org/10.6028/NIST.FIPS.205.ipd) from August 2023. SLH-DSA is derived from the SPHINCS+ submission to the NIST PQC Competition, with minor modifications.

This single-file ([slh_dsa.py](slh_dsa.py)) implementation covers all 12 parameter sets contained in FIPS 205 IPD (Table 1, Section 10.) Note that NIST is standardizing only the "small simple" (s) and "fast simple" (f) variants using SHA2 and SHAKE hashes. The following table also includes the PQ Security Categories and byte sizes of the public keys, secret keys, and signatures with each variant.

| FIPS 205 Name      | Reference KAT Filename    | Cat | PK |  SK |   Sig |
|--------------------|---------------------------|-----|----|-----|-------|
| SLH-DSA-SHA2-128s  | sphincs-sha2-128s-simple  |  1  | 32 |  64 |  7856 |
| SLH-DSA-SHAKE-128s | sphincs-shake-128s-simple |  1  | 32 |  64 |  7856 |
| SLH-DSA-SHA2-128f  | sphincs-sha2-128f-simple  |  1  | 32 |  64 | 17088 |
| SLH-DSA-SHAKE-128f | sphincs-shake-128f-simple |  1  | 32 |  64 | 17088 |
| SLH-DSA-SHA2-192s  | sphincs-sha2-192s-simple  |  3  | 48 |  96 | 16224 |
| SLH-DSA-SHAKE-192s | sphincs-shake-192s-simple |  3  | 48 |  96 | 16224 |
| SLH-DSA-SHA2-192f  | sphincs-sha2-192f-simple  |  3  | 48 |  96 | 35664 |
| SLH-DSA-SHAKE-192f | sphincs-shake-192f-simple |  3  | 48 |  96 | 35664 |
| SLH-DSA-SHA2-256s  | sphincs-sha2-256s-simple  |  5  | 64 | 128 | 29792 |
| SLH-DSA-SHAKE-256s | sphincs-shake-256s-simple |  5  | 64 | 128 | 29792 |
| SLH-DSA-SHA2-256f  | sphincs-sha2-256f-simple  |  5  | 64 | 128 | 49856 |
| SLH-DSA-SHAKE-256f | sphincs-shake-256f-simple |  5  | 64 | 128 | 49856 |

The code output matches the Known Answer Tests of the reference implementation (["consistent-basew" branch, commit c8116bc](https://github.com/sphincs/sphincsplus/tree/consistent-basew).) That branch implements the changes in FIPS 205 IPD in relation to SPHINCS+ 3.1, which are documented in Section 1.3 of FIPS 205 IPD.


##  Comments on the Initial Public Draft

In general, FIPS 205 IPD has a sufficient level of detail to serve as an engineering specification.

I wrote this implementation "looking at the specification" and had to peek at the reference code only for some minor things; for example, I discovered the seed for key generation is actually obtained with a single call to the RBG rather than with three calls (Lines 1-3 of Algorithm 17, slh_keygen); I adopted the behavior of the reference code in order to match the KAT output.

Another minor aspect that required peeking at the reference code were with the "(ADRS) Member Functions" of type `ADRS.getX()` and `ADRS.setX(Y)` that are very briefly discussed in Section 4.3 of the specification. While Figures 5--8 helped me to decipher these, the spec would benefit from an explicit table for the functions. The member functions and the compressed serialization used by SHA2 variants are implemented by a helper class `ADSR` in the implementation ([slh_dsa.py](slh_dsa.py)).


##  Running Known Answer Tests

The known answer testbench ([kat_test.py](kat_test.py)) can be executed via `python3 kat_test.py` and check against the provided. You will need Python3 and hash functions; try `pip3 install pycryptodome` if those are not installed.

It takes one or two minutes to print just the KAT checksum for the first vector for each variant, but you may modify the `katnum` variable in [kat_test.py](kat_test.py) to produce hashes of more vectors.
```
$ python3 kat_test.py
# 0/1 SLH-DSA-SHA2-128f
d3df72bb154abaef53cc5d0dd5b4fde46a797e90e30805fff7c3e31041ab4c67 SLH-DSA-SHA2-128f (1)
# 0/1 SLH-DSA-SHA2-128s
a316908dec0998861b647f40213bf37cbfc2b3634b8a0a52e4503dba59bad441 SLH-DSA-SHA2-128s (1)
# 0/1 SLH-DSA-SHA2-192f
f525b6569082b4335593eab8257364a5754932b2a209fc194c09ffce12bfbb16 SLH-DSA-SHA2-192f (1)
# 0/1 SLH-DSA-SHA2-192s
601be3028bf69f6c7aecfd709b95c9c778e2420b976967771203e2e824a86321 SLH-DSA-SHA2-192s (1)
# 0/1 SLH-DSA-SHA2-256f
1aab628d922a489f6879e29b55e5a474c3b9d4c52b166a52e7504f69bf85057a SLH-DSA-SHA2-256f (1)
# 0/1 SLH-DSA-SHA2-256s
2b23b59d31969dbb91fb5465d26637448c53658631d9c218664e2ad1a2cb69e0 SLH-DSA-SHA2-256s (1)
# 0/1 SLH-DSA-SHAKE-128f
6452ae18c387c7816d1396b0919c824479d0ab02f91010f59d26cd405fe309b4 SLH-DSA-SHAKE-128f (1)
# 0/1 SLH-DSA-SHAKE-128s
d36999edc06c0daeaae9e6346b4b5a5ea9503387fb343bfe869c5ccd0a90c51c SLH-DSA-SHAKE-128s (1)
# 0/1 SLH-DSA-SHAKE-192f
7cf1ae6803f24d2fabcc2f98e77ab703fc223b6d5ddd5091658d03c13c3045b2 SLH-DSA-SHAKE-192f (1)
# 0/1 SLH-DSA-SHAKE-192s
84644ef3f842f5939f48179bcbc1f8c0e494f5a76585c71a176547e6ef297517 SLH-DSA-SHAKE-192s (1)
# 0/1 SLH-DSA-SHAKE-256f
049ff342c967ee43f586052249ba3313297e6630c1095d2af869853a717f0acd SLH-DSA-SHAKE-256f (1)
# 0/1 SLH-DSA-SHAKE-256s
b399077b5c53daffd830df98dd3953b9db1903a151bc679adff314a93cf808d0 SLH-DSA-SHAKE-256s (1)
```

The known answer tests are quite big, so I'm including just SHA256 hashes for [1](kat/kat1-sha256.txt), [10](kat/kat10-sha256.txt), and [100](kat/kat100-sha256.txt) first ones. The [kat](kat) subdirectory also contains full text of the first vector of each response file.

