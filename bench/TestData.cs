using Keysmith.Net.BIP;

namespace Keysmith.Net.Bench;
public static class TestData
{
    public const string Mnemonics_12_Words = "donkey food slam vague mesh joy length ride sting kid media expand";
    public const string Mnemonics_18_Words = "doctor laptop cube chair future furnace wrong biology sphere minimum monster torch yard outside surprise desk news twist";
    public const string Mnemonics_24_Words = "trim answer dentist loud blur expand juice blade summer early catch gentle panel veteran another find emotion puzzle excite gentle sock dune desert multiply";

    public static readonly byte[] Seed_512B = BIP39.MnemonicToSeed(Mnemonics_12_Words);
}
