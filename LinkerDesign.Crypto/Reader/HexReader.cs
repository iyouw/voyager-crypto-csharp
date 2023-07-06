namespace LinkerDesign.Crypto;

public class HexReader : ByteArrayReader
{
  public override byte[] Source { get; protected set; }

  public HexReader(string text)
  {
    Source = new Hex().Decode(text);
  }
}