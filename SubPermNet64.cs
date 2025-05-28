using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace SP_KPA;

/// <summary>
/// 64-bit Substitution-Permutation Network with 4-bit S-boxes
/// </summary>
public sealed class SubPermNet64 {
	public byte[] Permutation { get; private init; }
	public byte[] SBox { get; private init; }

	private ulong message;
	public ulong Message {
		get => message;
		set {
			message = value;
			Reset();
		}
	}

	private IEnumerator<ulong> keyGenerator;
	/// <summary>
	/// The enumerator that is used for retrieving a unique key for every encryption round <br/>
	/// This can be as simple as an array of ulongs (if you know the # of rounds you want to perform in advance)
	/// or a keystream that can generate new pseudo-random keys endlessly
	/// </summary>
	public IEnumerator<ulong> KeyGenerator {
		get => keyGenerator;
		[MemberNotNull(nameof(keyGenerator))]
		set {
			if (value == null) 
				throw new ArgumentNullException(nameof(value), "KeyGenerator cannot be null");

			keyGenerator = value;
			Reset();
		}
	}

	public ulong Ciphertext { get; private set; }
	public int CurrentRound { get; private set; } = 0;

	public bool Verbose { get; set; } = false;

	public SubPermNet64(byte[] permutations, string sbox, ulong message, IEnumerator<ulong> keyGenerator) {
		if (permutations.Length != 64) {
			throw new ArgumentException("Invalid perm array length", nameof(permutations));
		}

		if (sbox.Length != 16) {
			throw new ArgumentException("Invalid s-box ruleset length", nameof(sbox));
		}

		Permutation = permutations;

		SBox = new byte[16];
		for (int i = 0; i < sbox.Length; i++) {
			string rule = sbox[i].ToString();
			bool isValid = byte.TryParse(rule, NumberStyles.HexNumber, null, out SBox[i]);

			if (!isValid) {
				throw new ArgumentException("Invalid character in s-box ruleset", nameof(sbox));
			}
		}

		Message = message;
		KeyGenerator = keyGenerator;
	}

	public SubPermNet64(byte[] permutations, string sbox, ulong message, IEnumerable<ulong> keyGenerator)
		: this(permutations, sbox, message, keyGenerator.GetEnumerator()) { }

	public void DoRound() {
		bool couldGen = KeyGenerator.MoveNext();
		ulong key = KeyGenerator.Current;
		if (!couldGen) {
			KeyGenerator.Reset();
			KeyGenerator.MoveNext();
		}

		CurrentRound++;
		ulong buffer = CurrentRound == 1 ? Message : Ciphertext;

		VPrintHeader($"Round {CurrentRound}");
        VPrint("Performing one round of the SP network on:");
        VPrint($"m: {Utils.HexStr(buffer)}");
        VPrint($"k: {Utils.HexStr(key)}\n");

		VPrintHeader("KEY MIXING");
		buffer = buffer ^ key;
		VPrint($"Key mixing result: {Utils.HexStr(buffer)}");

		VPrintHeader("SUBSTITUTION");
		buffer = Substitute(buffer);
		VPrint($"Substitution result: {Utils.HexStr(buffer)}");
		
		VPrintHeader("PERMUTATION");
		buffer = Permutate(buffer);
		VPrint($"Permutation result: {Utils.HexStr(buffer)}");

		VPrintHeader("RESULT");
		Ciphertext = buffer;
		VPrint($"Ciphertext: {Utils.HexStr(Ciphertext)}");
	}

	public ulong Substitute(ulong data) {
		ulong result = 0;

		VPrint($"Initial data state: {Utils.HexStr(data)}");
		VPrint($"Initial result state: {Utils.HexStr(result)}\n");

		// run all 64 bits of data through 4-bit s-boxes ( => 16 iterations in total )
		for (int i = 0; i < 16; i++) {
			VPrint($"Performing substitution on chunk #{i + 1}");

			byte chunk = (byte)((data & Utils.Msb4Mask) >> (15 * 4));
			VPrint($"Chunk value:      {Utils.HexStr(chunk, false)}");

			byte sub = SBox[chunk];
			VPrint($"Subbed for:       {Utils.HexStr(sub, false)}");

			result <<= 4;
			result += sub;
			VPrint($"New result state: {Utils.HexStr(result)}");

			data <<= 4;
			VPrint($"New data state:   {Utils.HexStr(data)}\n");
		}

		return result;
	}

	public ulong Permutate(ulong data) {
		ulong result = 0;

		VPrint($"Initial data state: {Utils.BinStr(data)}\n");

		// permutate all 64 bits
		for (int i = 0; i < 64; i++) {
			VPrint($"Incoming data state:     {Utils.BinStr(data)}");

			ulong msb = data & Utils.MsbMask;
			VPrint($"Separated msb:           {Utils.BinStr(msb)}");

			data <<= 1;
			VPrint($"New data state:          {Utils.BinStr(data)}");
			
			// minor optimization
			if (msb == 0) {
				VPrint("Skipping 0 bit, result stays the same\n");
				continue;
			}

			msb >>= Permutation[i];
			VPrint($"Shifted via permutation: {Utils.BinStr(msb)}");
				
			result |= msb;
			VPrint($"New result state:        {Utils.BinStr(result)}\n");
		}

		return result;
	}

	public void Reset() {
		Ciphertext = 0;
		CurrentRound = 0;
		KeyGenerator?.Reset();
	}

	/// <summary>
	/// Prints header info to stdout if the net is running in verbose mode
	/// </summary>
	/// <param name="headerTxt">The header text to print</param>
	[Conditional("DEBUG")]
	private void VPrintHeader(string headerTxt) {
		if (!Verbose) return;

		int n = headerTxt.Length;

		Console.WriteLine();
		Console.WriteLine(new String('-', n + 6));
        Console.WriteLine($"|  {headerTxt}  |");
		Console.WriteLine(new String('-', n + 6));
        Console.WriteLine();
	}

	/// <summary>
	/// Print a line of text to stdout if the net is running in Verbose mode
	/// </summary>
	/// <param name="txt">The line to print</param>
	[Conditional("DEBUG")]
	private void VPrint(string txt) {
		if (!Verbose) return;

        Console.WriteLine(txt);
	}
}
