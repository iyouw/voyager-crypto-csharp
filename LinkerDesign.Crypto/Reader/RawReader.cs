namespace LinkerDesign.Crypto;

public class RawReader : ByteArrayReader
{
  public override byte[] Source { get; protected set; }

  public RawReader(byte[] bytes)
  {
    Source = bytes;
  }
}