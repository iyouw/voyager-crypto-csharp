namespace LinkerDesign.Crypto;

public class BinaryEncodeStrategy : IBinaryEncoder
{
  private readonly IBinaryEncoder _encoder;

  public BinaryEncodeStrategy(EncodingType exportType)
  {
    switch(exportType)
    {
      case EncodingType.Base64:
        _encoder = new Base64();
        break;
      case EncodingType.Hex:
        _encoder = new Hex();
        break;
      case EncodingType.UTF8:
        _encoder = new Utf8();
        break;
      default:
        throw new NotSupportedException();
    }
  }

  public string Encode(byte[] bytes)
  {
    return _encoder.Encode(bytes);
  }
}