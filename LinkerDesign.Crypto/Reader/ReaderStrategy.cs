namespace LinkerDesign.Crypto;

public class ReaderStrategy: IReader
{
  private IReader _reader;

  public long Length => _reader.Length;

  public ReaderStrategy(string text, ExportType exportType)
  {
    switch(exportType)
    {
      case ExportType.Base64:
        _reader = new Base64Reader(text);
        break;
      case ExportType.Hex:
        _reader = new HexReader(text);
        break;
      case ExportType.UTF8:
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