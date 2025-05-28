namespace SP_KPA;

public static class Utils {
	public const ulong MsbMask = 1UL << 63;
	public const ulong Msb4Mask = 0xfUL << (15 * 4);

	public static ulong Permutate(byte[] perm, ulong data) {
		ulong result = 0;
		
		for (int i = 0; i < 64; i++) {
			ulong msb = data & MsbMask;
			msb >>= perm[i];
			result |= msb;
			data <<= 1;
		}

		return result;
	}

	public static ulong Substitute(byte[] sbox, ulong data) {
		ulong result = 0;
		
		for (int i = 0; i < 16; i++) {
			byte chunk = (byte)((data & Msb4Mask) >> (15 * 4));
			byte sub = sbox[chunk];
			result <<= 4;
			result += sub;
			data <<= 4;
		}

		return result;
	}

	public static string HexStr(ulong val, bool applyPad = true, int padLen = 16) {
		string formatCode = applyPad ? ("0x{0:X" + padLen + "}") : "0x{0:X}";

		return String.Format(formatCode, val);
	}

	public static string BinStr(ulong val, bool applyPad = true, int padLen = 64) {
		string formatCode = applyPad ? ("0b{0:B" + padLen + "}") : "0b{0:B}";

		return String.Format(formatCode, val);
	}

	public static byte[] GetPermutationInverse(byte[] perm) {
		if (perm.Length != 64) {
			throw new ArgumentException("The provided permutation function is not a 64-bit permutation");
		}

		for (byte i = 0; i < perm.Length; i++) {
			if (perm.Where(x => x == i).Count() != 1) {
				throw new ArgumentException("The provided permutation function does not represent a proper permutation");
			}
		}

		byte[] permInv = new byte[perm.Length];

		for (byte i = 0; i < perm.Length; i++) {
			permInv[perm[i]] = i;
		}

		return permInv;
	}

	public static byte[] GetSBoxInverse(byte[] sbox) {
		if (sbox.Length != 16) {
			throw new ArgumentException("The provided sbox function is not a 16-bit substitution");
		}

		byte[] sboxInv = new byte[sbox.Length];

		for (byte i = 0; i < sbox.Length; i++) {
			sboxInv[sbox[i]] = i;
		}

		return sboxInv;
	}

	public static void KpaVerify(SubPermNet64 spNet, ulong[] crackedKeys, ulong[] knownMessages, ulong[] knownCiphers) {
		spNet.KeyGenerator = GetEnumeratorFromArray(crackedKeys);
		for (int i = 0; i < knownMessages.Length; i++) {
			spNet.Message = knownMessages[i];

			for (int j = 0; j < crackedKeys.Length; j++) {
				spNet.DoRound();
			}

			Console.WriteLine($"input m-c #{i + 1}: {Utils.HexStr(knownMessages[i])} - {Utils.HexStr(knownCiphers[i])}");
			Console.WriteLine($"c' with cracked keypair: {Utils.HexStr(spNet.Ciphertext)}");

			if (knownCiphers[i] == spNet.Ciphertext) {
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine($"c <-> c' match verified for m-c pair #{i + 1}");
			} else {
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine($"c <-> c' mismatch for m-c pair #{i + 1}");
			}
			Console.ForegroundColor = ConsoleColor.White;
			Console.WriteLine();
		}
	}

	public static IEnumerator<T> GetEnumeratorFromArray<T>(T[] array) {
		// have to cast first to get the proper generic for IEnumerator
		return array.Cast<T>().GetEnumerator();
	}
}
