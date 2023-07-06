namespace LinkerDesign.Crypto;

public class BinaryEncodeStrategy : IBinaryEncoder
{
  private readonly IBinaryEncoder _encoder;

  public BinaryEncodeStrategy(ExportType exportType)
  {
    switch(exportType)
    {
      case ExportType.Base64:
        _encoder = new Base64();
        break;
      case ExportType.Hex:
        _encoder = new Hex();
        break;
      case ExportType.UTF8:
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