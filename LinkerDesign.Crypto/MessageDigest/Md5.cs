namespace LinkerDesign.Crypto;

public class Md5: MdBase
{
  public byte[] Digest(string message, ExportType msgType = ExportType.Base64, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = MdAlgorithm.MD5;
    return DigestCore(message, algorithm, msgType, bufferSize);
  }

  public string Digest(string message,  ExportType msgType = ExportType.Base64, ExportType exportType = ExportType.Base64, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = MdAlgorithm.MD5;
    return DigestCore(message, algorithm, msgType, exportType, bufferSize);
  }

  public byte[] Digest(byte[] bytes, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = MdAlgorithm.MD5;
    return DigestCore(bytes, algorithm, bufferSize);
  }

  public string Digest(byte[] bytes, ExportType exportType = ExportType.Base64, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = MdAlgorithm.MD5;
    return DigestCore(bytes, algorithm, exportType, bufferSize);
  }

  public byte[] Digest(Stream stream, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = MdAlgorithm.MD5;
    return DigestCore(stream, algorithm, bufferSize);
  }

  public string Digest(Stream stream, ExportType exportType = ExportType.Base64, int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var algorithm = MdAlgorithm.MD5;
    return DigestCore(stream, algorithm, exportType, bufferSize);
  }
}


