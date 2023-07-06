namespace LinkerDesign.Crypto;

public class Aes: AesBase
{
  public byte[] EncryptCBC(
    string key, 
    string iv, 
    byte[] data, 
    ExportType keyType = ExportType.Base64, 
    ExportType ivType = ExportType.Base64, 
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return EncryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
  }

  public byte[] DecryptCBC(
    string key,
    string iv,
    byte[] data,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return DecryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
  }

  public byte[] EncryptCBCWithUTF8(
    string key,
    string iv,
    string data,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return EncryptCore(data, ExportType.UTF8, key, keyType, iv, ivType, mode, bufferSize);
  }

  public string EncryptCBCWithUTF8(
    string key,
    string iv,
    string data,
    ExportType exportType = ExportType.Base64,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return EncryptCore(data, ExportType.UTF8, key, keyType, iv, ivType, mode, exportType, bufferSize);
  }

  public string DecryptCBCWithUTF8(
    string key,
    string iv,
    byte[] data,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return DecryptCore(data, key, keyType, iv, ivType, mode, ExportType.UTF8, bufferSize);
  }

  public string DecryptCBCWithUTF8(
    string key,
    string iv,
    string data,
    ExportType dataType = ExportType.Base64,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return DecryptCore(data, dataType, key, keyType, iv, ivType, mode, ExportType.UTF8, bufferSize);
  }

  public byte[] EncryptCTR(
    string key, 
    string iv, 
    byte[] data, 
    ExportType keyType = ExportType.Base64, 
    ExportType ivType = ExportType.Base64, 
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return EncryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
  }

  public byte[] DecryptCTR(
    string key,
    string iv,
    byte[] data,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return DecryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
  }

  public byte[] EncryptCTRWithUTF8(
    string key,
    string iv,
    string data,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return EncryptCore(data, ExportType.UTF8, key, keyType, iv, ivType, mode, bufferSize);
  }

  public string EncryptCTRWithUTF8(
    string key,
    string iv,
    string data,
    ExportType exportType = ExportType.Base64,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return EncryptCore(data, ExportType.UTF8, key, keyType, iv, ivType, mode, exportType, bufferSize);
  }

  public string DecryptCTRWithUTF8(
    string key,
    string iv,
    byte[] data,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return DecryptCore(data, key, keyType, iv, ivType, mode, ExportType.UTF8, bufferSize);
  }

  public string DecryptCTRWithUTF8(
    string key,
    string iv,
    string data,
    ExportType dataType = ExportType.Base64,
    ExportType keyType = ExportType.Base64,
    ExportType ivType = ExportType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return DecryptCore(data, dataType, key, keyType, iv, ivType, mode, ExportType.UTF8, bufferSize);
  }

  public byte[] GenerateKey(AesKeySize size = AesKeySize.KS256)
  {
    return GenerateAesKeyCore(size);
  }

  public string GenerateKey(ExportType exportType = ExportType.Base64, AesKeySize size = AesKeySize.KS256)
  {
    return GenerateAesKeyCore(size, exportType);
  }

  public byte[] GenerateIV()
  {
    return GenerateAesIVCore();
  }

  public string GenerateIV(ExportType exportType = ExportType.Base64)
  {
    return GenerateAesIVCore(exportType);
  }
}