# SP network implementation + KPA

**DISCLAIMER:** This is project is for a homework assignment of my uni cryptography class.

This project is an implementation of a 64-bit Substitution-Permutation network written in C#. It also features known plaintext attack functionalities for determining the keys that were used for encrypting message-ciphertext pairs with SP nets (for two rounds max).

## Program.cs

The main logic inside Program.cs right now has a couple of hard-coded task inputs that made up the assignment, but they can be removed or replaced and the rest of the supporting classes can be used for any purpose as they were written to be as flexible as possible.

The task inputs were left in there to provide a demonstration for the usage of the SubPermNet64, KPA and Utils classes.

## SP net

The implementation of the SP network can be found inside **SubPermNet64** class. It supports any number of rounds, as the key list can be provided both as an array or as an enumerator that can represent arbitrarily complicated keystream generators.

## KPA

The methods that can be used for known plaintext attacks are inside the **KPA** class. These support breaking the encryption of an SP net that ran for one or two rounds. Note, however, that more than one message-ciphertext pairs are needed for determining the keys in the case of two-round KPAs.

The logic used by the two round KPA could be more or less generalized into a "break n-rounds" method, but it would quickly start getting exponentially slower in runtime (unrealistically so for a viable attack).
