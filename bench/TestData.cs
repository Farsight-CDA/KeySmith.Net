using Keysmith.Net.BIP;

namespace Keysmith.Net.Bench;
public static class TestData
{
    public const string Mnemonics_12_Words = "donkey food slam vague mesh joy length ride sting kid media expand";
    public static readonly byte[] Seed_12_Words = BIP39.MnemonicToSeed(Mnemonics_12_Words);
    public const string Mnemonics_18_Words = "doctor laptop cube chair future furnace wrong biology sphere minimum monster torch yard outside surprise desk news twist";
    public static readonly byte[] Seed_18_Words = BIP39.MnemonicToSeed(Mnemonics_18_Words);
    public const string Mnemonics_24_Words = "trim answer dentist loud blur expand juice blade summer early catch gentle panel veteran another find emotion puzzle excite gentle sock dune desert multiply";
    public static readonly byte[] Seed_24_Words = BIP39.MnemonicToSeed(Mnemonics_24_Words);
}
