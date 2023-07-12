namespace LinkerDesign.Crypto;

public class Aes: AesBase
{
  public byte[] EncryptCBC(
    string key, 
    string iv, 
    byte[] data, 
    EncodingType keyType = EncodingType.Base64, 
    EncodingType ivType = EncodingType.Base64, 
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return EncryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
  }

  public byte[] DecryptCBC(
    string key,
    string iv,
    byte[] data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return DecryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
  }

  public byte[] EncryptCBCWithUTF8(
    string key,
    string iv,
    string data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return EncryptCore(data, EncodingType.UTF8, key, keyType, iv, ivType, mode, bufferSize);
  }

  public string EncryptCBCWithUTF8(
    string key,
    string iv,
    string data,
    EncodingType EncodingType = EncodingType.Base64,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return EncryptCore(data, EncodingType.UTF8, key, keyType, iv, ivType, mode, EncodingType, bufferSize);
  }

  public string DecryptCBCWithUTF8(
    string key,
    string iv,
    byte[] data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return DecryptCore(data, key, keyType, iv, ivType, mode, EncodingType.UTF8, bufferSize);
  }

  public string DecryptCBCWithUTF8(
    string key,
    string iv,
    string data,
    EncodingType dataType = EncodingType.Base64,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CBC;
    return DecryptCore(data, dataType, key, keyType, iv, ivType, mode, EncodingType.UTF8, bufferSize);
  }

  public byte[] EncryptCTR(
    string key, 
    string iv, 
    byte[] data, 
    EncodingType keyType = EncodingType.Base64, 
    EncodingType ivType = EncodingType.Base64, 
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return EncryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
  }

  public byte[] DecryptCTR(
    string key,
    string iv,
    byte[] data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return DecryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
  }

  public byte[] EncryptCTRWithUTF8(
    string key,
    string iv,
    string data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return EncryptCore(data, EncodingType.UTF8, key, keyType, iv, ivType, mode, bufferSize);
  }

  public string EncryptCTRWithUTF8(
    string key,
    string iv,
    string data,
    EncodingType EncodingType = EncodingType.Base64,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return EncryptCore(data, EncodingType.UTF8, key, keyType, iv, ivType, mode, EncodingType, bufferSize);
  }

  public string DecryptCTRWithUTF8(
    string key,
    string iv,
    byte[] data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return DecryptCore(data, key, keyType, iv, ivType, mode, EncodingType.UTF8, bufferSize);
  }

  public string DecryptCTRWithUTF8(
    string key,
    string iv,
    string data,
    EncodingType dataType = EncodingType.Base64,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    var mode = AesMode.CTR;
    return DecryptCore(data, dataType, key, keyType, iv, ivType, mode, EncodingType.UTF8, bufferSize);
  }

  public byte[] GenerateKey(AesKeySize size = AesKeySize.KS256)
  {
    return GenerateAesKeyCore(size);
  }

  public string GenerateKey(EncodingType EncodingType = EncodingType.Base64, AesKeySize size = AesKeySize.KS256)
  {
    return GenerateAesKeyCore(size, EncodingType);
  }

  public byte[] GenerateIV()
  {
    return GenerateAesIVCore();
  }

  public string GenerateIV(EncodingType EncodingType = EncodingType.Base64)
  {
    return GenerateAesIVCore(EncodingType);
  }
}