namespace LinkerDesign.Crypto;

public class MdBase: CryptoBase
{
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

  protected string DigestCore(byte[] msg, MdAlgorithm algorithm, ExportType exportType , int bufferSize)
  {
    var bytes = DigestCore(msg, algorithm, bufferSize);
    var strategy = new BinaryEncodeStrategy(exportType);
    return strategy.Encode(bytes);
  }

  protected byte[] DigestCore(string msg, MdAlgorithm algorithm, ExportType msgType, int bufferSize)
  {
    var reader = new ReaderStrategy(msg, msgType);
    return DigestCore(reader, algorithm, bufferSize);
  }

  protected string DigestCore(string msg, MdAlgorithm algorithm, ExportType msgType, ExportType exportType, int bufferSize)
  {
    var bytes = DigestCore(msg, algorithm, msgType, bufferSize);
    var strategy = new BinaryEncodeStrategy(exportType);
    return strategy.Encode(bytes);
  }

  protected byte[] DigestCore(Stream stream, MdAlgorithm algorithm, int bufferSize)
  {
    var reader = new ReaderStrategy(stream);
    return DigestCore(reader, algorithm, bufferSize);
  }

  protected string DigestCore(Stream stream, MdAlgorithm algorithm, ExportType exportType, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var bytes = DigestCore(stream, algorithm, bufferSize);
    var strategy = new BinaryEncodeStrategy(exportType);
    return strategy.Encode(bytes);
  }
}


