# minigma
So this is a wrapper for BouncyCastle OpenPGP. Because while BouncyCastle is good and secure and tested and everything
it's a bit of a dog to use. I mean to sign something, say, you have to instantiate a signature generator, and a PBEKeyDecryptor, 
and there's no chance I will be able to remember (or can be arsed) to do all those things just when I want to
digitally-sign a Tweet or something.
It is a new, simplified API for OpenPGP. And because it is a bugbear of mine, it doesn't refer to public or private keys,
but Locks (public) and Keys (private). If you want to encrypt, say, a String, you just get a Lock and call its lock method. 
Then, if you happen to have the corresponding Key to that Lock, you can call the key.unlock method.
For signing, you use the key; to verify a signature, use its corresponding Lock.
It's not yet complete and doesn't support the full range of OpenPGP algorithms. But it does do encryption/decryption, sign/verify,
key (Lock) certification, certificate revocation and it supports designated revokers.
Plus it supports NotationData - adding signed name-value pairs to signatures - which are part of my long-term plan to use OpenPGP
to sort out all this fake news nonsense going down in the world. Messrs Putin, Trump and Farridge: you have been warned.
