namespace LinkerDesign.Crypto;

public class StreamReader: IReader
{
  public Stream Stream {get; private set;}

  public StreamReader(Stream stream)
  {
    Stream = stream;
  }

  public long Length => Stream.Length;

  public byte[]? read(int length)
  {
    var size = (int)Math.Min(Stream.Length - Stream.Position, length);
    if (size == 0) return null;
    var res = new byte[size];
    Stream.Read(res, 0, size);
    return res;
  }
}