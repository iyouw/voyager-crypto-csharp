namespace LinkerDesign.Crypto;

public class Utf8Reader : ByteArrayReader
{
  public override byte[] Source { get; protected set; }

  public Utf8Reader(string text)
  {
    Source = new Utf8().Decode(text);
  }
}