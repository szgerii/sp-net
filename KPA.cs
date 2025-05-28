using System.Diagnostics;

namespace SP_KPA;

/// <summary>
/// Known plaintext attacks against SP networks
/// </summary>
public static class KPA {
	/// <summary>
	/// Whether to output info about the inner state of the algorithms
	/// </summary>
	public static bool Verbose { get; set; } = false;

	/// <summary>
	/// Performs a known plaintext attack on a message-ciphertext pair that were encrypted using a single round of an SP network
	/// </summary>
	/// <param name="perm">The permutation used by the SP net</param>
	/// <param name="sbox">The S-Box used by the SP net</param>
	/// <param name="message">The plaintext that was encrypted using the SP net</param>
	/// <param name="ciphertext">The ciphertext that was the result of the encryption</param>
	/// <returns>The key that was used for the encryption</returns>
	public static ulong BreakOneRound(byte[] perm, byte[] sbox, ulong message, ulong ciphertext) {
		// get the inverses for the perms and the S-Box
		byte[] permInv = Utils.GetPermutationInverse(perm);
		byte[] sboxInv = Utils.GetSBoxInverse(sbox);

		// reverse permutation
		ulong unperm = Utils.Permutate(permInv, ciphertext);

		// apply S-Box inverse
		ulong result = Utils.Substitute(sboxInv, unperm);

		// at this point:
		// result == m XOR k  <==>  k = result XOR m

		return result ^ message;
	}

	/// <summary>
	/// Performs a known plaintext attack on message-ciphertext pairs that were encrypted with two rounds of an SP network
	/// </summary>
	/// <param name="perm">The permutation used by the SP net</param>
	/// <param name="sbox">The S-Box used by the SP net</param>
	/// <param name="messages">The plaintexts that were encrypted using the SP net (index aligned with <paramref name="ciphertexts"/>)</param>
	/// <param name="ciphertexts">The ciphertexts that were the results of the encryption (index aligned with <paramref name="messages"/>)</param>
	/// <returns>A tuple of the two keys that were used for the encryption</returns>
	public static (ulong k1, ulong k2) BreakTwoRounds(byte[] perm, byte[] sbox, ulong[] messages, ulong[] ciphertexts) {
		if (messages.Length != ciphertexts.Length) {
			throw new ArgumentException("Message-Ciphertext array dimension mismatch");
		}

		byte[] permInv = Utils.GetPermutationInverse(perm);
		byte[] sboxInv = Utils.GetSBoxInverse(sbox);

		ulong k1 = 0, k2 = 0;

		// for all 4-bit chunks of k1...
		for (int i = 0; i < 64; i += 4) {
			PrintHeader($"NEW CHUNK: [{i}-{i+3}]");

			// bitwise operands needed to extract 4-bit region from 64-bit ulongs
			int shift = 60 - i;
			ulong mask = ((1UL << 4) - 1) << shift;
			Print($"Bitmask: {Utils.BinStr(mask)}");
			Print($"Shift:   {shift}\n");

			// ...try all possible 0-1 combinations... (2^4 => 16)
			for (byte k1Chunk = 0; k1Chunk < 16; k1Chunk++) {
				// invert permutation and substitution
				// t == P(S(m XOR k1)) XOR k2
				ulong k1Masked = (ulong)k1Chunk << shift;
				ulong k2Masked = 0;
				
				Print($"Current guess:	 {Utils.BinStr(k1Chunk, padLen: 4)}");
				Print($"Masked guess:	 {Utils.BinStr(k1Masked)}");
				if (Verbose) Console.ReadLine();

				// ...and all message-ciphertext pairs
				bool worksForAll = true;
				for (int j = 0; j < messages.Length && worksForAll; j++) {
					Print($"Active k2 guess: {Utils.BinStr(k2Masked)}\n");

					ulong mMasked = messages[j] & mask;

					Print($"Current m/c: {Utils.HexStr(messages[j])} / {Utils.HexStr(ciphertexts[j])}");
					Print($"m masked:    {Utils.HexStr(mMasked)}\n");
					
					// calculate what s-box would do with guessed k1
					ulong sMasked = mMasked ^ k1Masked;
					// shift to lsb4 -> sbox -> shift back to original position
					byte sIn = (byte)(sMasked >> shift);
					ulong sOut = (ulong)sbox[sIn] << shift;
					
					Print($"SIn masked:  {Utils.HexStr(sMasked)}");
					Print($"SIn:         {Utils.HexStr(sIn)}");
					Print($"SOut:        {Utils.HexStr(sOut)}\n");

					// create alternative permutation that only
					// moves around the "currently inspected" bits
					byte[] altPerm = new byte[perm.Length];
					string altPermStr = "[ ";
					for (byte pIdx = 0; pIdx < altPerm.Length; pIdx++) {
						if (pIdx - i >= 0 && pIdx - i < 4) {
							altPerm[pIdx] = perm[pIdx];
						} else {
							altPerm[pIdx] = pIdx;
						}

						altPermStr += $"({pIdx};{altPerm[pIdx]}), ";
					}
					altPermStr = altPermStr.Substring(0, altPermStr.Length - 2) + " ]";
					Print($"altperm: {altPermStr}");
					ulong pOut = Utils.Permutate(altPerm, sOut);

					// t := SInv(MInv(c))
					ulong t = Utils.Substitute(sboxInv, Utils.Permutate(permInv, ciphertexts[j]));
					Print($"t:          {Utils.BinStr(t)}");
					// mask t
					t &= Utils.Permutate(altPerm, mask);
					Print($"t masked:   {Utils.BinStr(t)}");

					// calculate k2's "remainder part" for t, aka
					// let  w := P(S(m XOR k1))
					// then t == w XOR k2 -> k2 == t XOR w
					ulong w = pOut;

					Print($"pOut == w:  {Utils.BinStr(w)}\n");

					ulong newK2Masked = w ^ t;
					Print($"k2 guess:   {Utils.BinStr(k2Masked)}");
					Print($"w XOR t:    {Utils.BinStr(newK2Masked)}\n");

					if (k2Masked == 0) {
						k2Masked = newK2Masked;
						Print($"No k2 guess, setting (w XOR t)\n");
					} else if (newK2Masked != k2Masked) {
						Print($"(w XOR t) didnt match previous k2 guess, aborting k1 guess\n");
						worksForAll = false;
					} else {
						Print($"(w XOR t) matched previous k2 guess, keeping k1 for now\n");
					}
				}

				if (worksForAll) {
					k1 |= k1Masked;
					k2 |= k2Masked;
					Print("found (w XOR t) match, adding it to keys");
					Print($"new k1: {Utils.HexStr(k1)}");
					Print($"new k2: {Utils.HexStr(k2)}\n");
					break;
				}
			}
		}

		return (k1, k2);
	}

	[Conditional("DEBUG")]
	private static void PrintHeader(string headerTxt) {
		if (!Verbose) return;

		int n = headerTxt.Length;

		Console.WriteLine();
		Console.WriteLine(new String('-', n + 6));
		Console.WriteLine($"|  {headerTxt}  |");
		Console.WriteLine(new String('-', n + 6));
		Console.WriteLine();
	}

	[Conditional("DEBUG")]
	private static void Print(string txt) {
		if (!Verbose) return;

		Console.WriteLine(txt);
	}
}
