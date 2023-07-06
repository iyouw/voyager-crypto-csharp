namespace LinkerDesign.Crypto;

public class Base64Reader : ByteArrayReader
{
  public override byte[] Source { get; protected set; }

  public Base64Reader(string text)
  {
    Source = new Base64().Decode(text);
  }
}