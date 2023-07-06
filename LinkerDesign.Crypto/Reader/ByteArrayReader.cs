namespace LinkerDesign.Crypto;

public abstract class ByteArrayReader : IReader
{
  public long ReadedLength { get; protected set;} = 0;

  public long Length => Source.Length;

  public long Available  => Length - ReadedLength;

  public abstract byte[] Source { get; protected set; }

  public byte[]? read(int length)
  {
    var size = (int)Math.Min(length, Available);
    if (size == 0) return null;
    var res = new byte[size];
    for (long i = 0; i < size; i++)
    {
      res[i] = Source[ReadedLength + i];
    }
    ReadedLength += size;
    return res;
  }
}