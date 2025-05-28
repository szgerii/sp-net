using SP_KPA;

byte[] perms = [
	41, 32, 28, 7, 60, 62, 38, 35, 5, 24, 61, 40, 12, 53, 55, 56, 50, 34, 54, 22, 39, 8, 51,
	33, 20, 26, 30, 10, 31, 19, 42, 16, 47, 48, 13, 9, 63, 6, 4, 45, 29, 36, 15, 0, 46, 11,
	21, 58, 2, 57, 3, 37, 1, 17, 27, 18, 25, 52, 14, 44, 43, 49, 23, 59
];
string sboxRuleset = "c56b90ad3ef84712";

ulong exampleM     = 0x99776bb932a5dd75;
ulong exampleK     = 0x23a68d38d22f3af5;
ulong exampleC     = 0xc273f68217da54af;

ulong tOneM        = 0x5a07124e452f4d55;
ulong tOneK        = 0x60a3b4d693a65e5a;

ulong tTwoM        = 0x4b6a342141dc35b2;
ulong tTwoC        = 0xeed96cc0c26a7be9;

ulong[] tThreeMArr = [0x1368d429a9b82f3f, 0xd75926d22b46a843, 0xf133c57117382514, 0x91e5a3c972781d18, 0x3c51af1147862aae, 0xb0ed20c40d97994d];
ulong[] tThreeCArr = [0xf3e9c6e6d30a2b1e, 0x731060771b00516d, 0xe1860548ce87b5e0, 0x185935d9d34180c2, 0xb57261fca027a68d, 0xb30839e941ccf052];

SubPermNet64 spNet = new(perms, sboxRuleset, exampleM, [exampleK]) {
	// Verbose = true,
};

spNet.DoRound();

if (spNet.Ciphertext == exampleC) {
	Console.ForegroundColor = ConsoleColor.Green;
	Console.WriteLine("");
	Console.ForegroundColor = ConsoleColor.White;
}

spNet.Reset();
spNet.Message = tOneM;
spNet.KeyGenerator = Utils.GetEnumeratorFromArray([tOneK]);
spNet.DoRound();

Console.WriteLine($"T1 cipher: {Utils.HexStr(spNet.Ciphertext)}");

// KPA.Verbose = true;

ulong tTwoK = KPA.BreakOneRound(spNet.Permutation, spNet.SBox, tTwoM, tTwoC);
Console.WriteLine($"\nT2 key: {Utils.HexStr(tTwoK)}");

Console.WriteLine("\nT2 verify:");
Utils.KpaVerify(spNet, [tTwoK], [tTwoM], [tTwoC]);

(ulong tThreeK1, ulong tThreeK2) = KPA.BreakTwoRounds(spNet.Permutation, spNet.SBox, tThreeMArr, tThreeCArr);

Console.WriteLine($"\nT3 results:");
Console.WriteLine($"k1: {Utils.HexStr(tThreeK1)}");
Console.WriteLine($"k2: {Utils.HexStr(tThreeK2)}");

Console.WriteLine("\nKPA T3 verify:");
Utils.KpaVerify(spNet, [tThreeK1, tThreeK2], tThreeMArr, tThreeCArr);
