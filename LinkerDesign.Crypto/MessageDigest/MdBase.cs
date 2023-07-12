namespace LinkerDesign.Crypto;

public abstract class MdBase: CryptoBase
{
  public abstract MdAlgorithm GetAlgorithm();

  public byte[] Digest(string message, EncodingType msgType = EncodingType.Base64, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = GetAlgorithm();
    return DigestCore(message, algorithm, msgType, bufferSize);
  }

  public string Digest(string message,  EncodingType msgType = EncodingType.Base64, EncodingType EncodingType = EncodingType.Base64, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = GetAlgorithm();
    return DigestCore(message, algorithm, msgType, EncodingType, bufferSize);
  }

  public byte[] Digest(byte[] bytes, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = GetAlgorithm();
    return DigestCore(bytes, algorithm, bufferSize);
  }

  public string Digest(byte[] bytes, EncodingType EncodingType = EncodingType.Base64, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = GetAlgorithm();
    return DigestCore(bytes, algorithm, EncodingType, bufferSize);
  }

  public byte[] Digest(Stream stream, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = GetAlgorithm();
    return DigestCore(stream, algorithm, bufferSize);
  }

  public string Digest(Stream stream, EncodingType EncodingType = EncodingType.Base64, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = GetAlgorithm();
    return DigestCore(stream, algorithm, EncodingType, bufferSize);
  }

  protected byte[] DigestCore(IReader reader, MdAlgorithm algorithm, int bufferSize)
  {
    byte[]? res = null;

    ReadCallback readCallback = (IntPtr ptr, int length) => 
    {
      var data = reader.read(length);
      return data != null ? this.WriteNativeMemroy(ptr, data) : 0;
    };

    WriteCallback writeCallback = (IntPtr ptr, int length) => 
    {
      if (length < 0) throw new Exception("Could not digest the data");
      res = this.ReadNativeMemory(ptr, length);
    };

    Native.Digest(bufferSize, ((int)algorithm), readCallback, writeCallback);
    if (res == null) throw new Exception("Could not digest the data");
    return res;
  }

  protected byte[] DigestCore(byte[] msg, MdAlgorithm algorithm, int bufferSize)
  {
    var reader = new ReaderStrategy(msg);
    return DigestCore(reader, algorithm, bufferSize);
  }

  protected string DigestCore(byte[] msg, MdAlgorithm algorithm, EncodingType EncodingType , int bufferSize)
  {
    var bytes = DigestCore(msg, algorithm, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(bytes);
  }

  protected byte[] DigestCore(string msg, MdAlgorithm algorithm, EncodingType msgType, int bufferSize)
  {
    var reader = new ReaderStrategy(msg, msgType);
    return DigestCore(reader, algorithm, bufferSize);
  }

  protected string DigestCore(string msg, MdAlgorithm algorithm, EncodingType msgType, EncodingType EncodingType, int bufferSize)
  {
    var bytes = DigestCore(msg, algorithm, msgType, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(bytes);
  }

  protected byte[] DigestCore(Stream stream, MdAlgorithm algorithm, int bufferSize)
  {
    var reader = new ReaderStrategy(stream);
    return DigestCore(reader, algorithm, bufferSize);
  }

  protected string DigestCore(Stream stream, MdAlgorithm algorithm, EncodingType EncodingType, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var bytes = DigestCore(stream, algorithm, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(bytes);
  }
}


