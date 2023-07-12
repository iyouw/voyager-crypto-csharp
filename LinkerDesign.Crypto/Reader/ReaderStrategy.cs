namespace LinkerDesign.Crypto;

public class ReaderStrategy: IReader
{
  private readonly IReader _reader;

  public ReaderStrategy(string text, EncodingType EncodingType)
  {
    switch(EncodingType)
    {
      case EncodingType.Base64:
        _reader = new Base64Reader(text);
        break;
      case EncodingType.Hex:
        _reader = new HexReader(text);
        break;
      case EncodingType.UTF8:
        _reader = new Utf8Reader(text);
        break;
      default:
        throw new NotSupportedException();
    }
  }

  public ReaderStrategy(Stream stream)
  {
    _reader = new StreamReader(stream);
  }

  public ReaderStrategy(byte[] bytes)
  {
    _reader = new RawReader(bytes);
  }

  public byte[]? read(int length)
  {
    return _reader.read(length);
  }
}