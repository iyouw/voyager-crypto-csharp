namespace LinkerDesign.Crypto;

public class BinaryDecodeStrategy: IBinaryDecoder
{
  public readonly IBinaryDecoder _decoder;

  public BinaryDecodeStrategy(EncodingType exportType)
  {
    switch(exportType)
    {
      case EncodingType.Base64:
        _decoder = new Base64();
        break;
      case EncodingType.Hex:
        _decoder = new Hex();
        break;
      case EncodingType.UTF8:
        _decoder = new Utf8();
        break;
      default:
        throw new NotSupportedException();
    }
  }

  public byte[] Decode(string text)
  {
    return _decoder.Decode(text);
  }
}