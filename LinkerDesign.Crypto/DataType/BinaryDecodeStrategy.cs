namespace LinkerDesign.Crypto;

public class BinaryDecodeStrategy: IBinaryDecoder
{
  public readonly IBinaryDecoder _decoder;

  public BinaryDecodeStrategy(ExportType exportType)
  {
    switch(exportType)
    {
      case ExportType.Base64:
        _decoder = new Base64();
        break;
      case ExportType.Hex:
        _decoder = new Hex();
        break;
      case ExportType.UTF8:
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