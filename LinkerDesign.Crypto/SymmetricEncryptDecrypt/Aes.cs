namespace LinkerDesign.Crypto;

public class Aes: AesBase
{
  public AesMode Mode { get; private set; }

  public Aes(): this(AesMode.CBC)
  {

  }

  public Aes(AesMode mode)
  {
    Mode = mode;
  }

  public byte[] Encrypt(
    string key, 
    string iv, 
    byte[] data, 
    EncodingType keyType = EncodingType.Base64, 
    EncodingType ivType = EncodingType.Base64, 
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    return EncryptCore(data, key, keyType, iv, ivType, Mode, bufferSize);
  }

  public byte[] Encrypt(
    string key, 
    string iv, 
    string data,
    EncodingType dataType, 
    EncodingType keyType = EncodingType.Base64, 
    EncodingType ivType = EncodingType.Base64, 
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    return EncryptCore(data, dataType, key, keyType, iv, ivType, Mode, bufferSize);
  }

  public byte[] Encrypt(
    string key, 
    string iv, 
    Stream data,
    EncodingType keyType = EncodingType.Base64, 
    EncodingType ivType = EncodingType.Base64, 
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    return EncryptCore(data, key, keyType, iv, ivType, Mode, bufferSize);
  }

  public void Encrypt(
    Stream output,
    string key, 
    string iv, 
    Stream data,
    EncodingType keyType = EncodingType.Base64, 
    EncodingType ivType = EncodingType.Base64, 
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    EncryptCore(output, data, key, keyType, iv, ivType, Mode, bufferSize);
  }


  public byte[] Decrypt(
    string key,
    string iv,
    byte[] data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    return DecryptCore(data, key, keyType, iv, ivType, Mode, bufferSize);
  }

  public byte[] Decrypt(
    string key,
    string iv,
    string data,
    EncodingType dataType,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    return DecryptCore(data, dataType, key, keyType, iv, ivType, Mode, bufferSize);
  }

  public byte[] Decrypt(
    string key,
    string iv,
    Stream data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    return DecryptCore(data, key, keyType, iv, ivType, Mode, bufferSize);
  }

  public void Decrypt(
    Stream output,
    string key,
    string iv,
    Stream data,
    EncodingType keyType = EncodingType.Base64,
    EncodingType ivType = EncodingType.Base64,
    int bufferSize = CryptoBase.DefaultBufferSize)
  {
    DecryptCore(output, data, key, keyType, iv, ivType, Mode, bufferSize);
  }

  public byte[] GenerateKey(AesKeySize size = AesKeySize.KS256)
  {
    return GenerateAesKeyCore(size);
  }

  public string GenerateKey(EncodingType encodingType = EncodingType.Base64, AesKeySize size = AesKeySize.KS256)
  {
    return GenerateAesKeyCore(size, encodingType);
  }

  public byte[] GenerateIV()
  {
    return GenerateAesIVCore();
  }

  public string GenerateIV(EncodingType encodingType = EncodingType.Base64)
  {
    return GenerateAesIVCore(encodingType);
  }
}