namespace LinkerDesign.Crypto;

public class AesBase: CryptoBase
{
  public byte[] EncryptCore(IReader reader, byte[] key, byte[] iv,  AesMode mode,  int bufferSize)
  {
    byte[]? res = null;

    var keyPtr = ImportAesKey(key);
    var ivPtr = ImportAesIV(iv);

    ReadCallback readCallback = (IntPtr ptr, int length) =>
    {
      var data = reader.read(length);
      return data != null ? WriteNativeMemroy(ptr, data) : 0;
    };

    WriteCallback writeCallback = (IntPtr ptr, int length) =>
    {
      if (length < 0) throw new Exception("Could encrypt the data");
      res = ReadNativeMemory(ptr, length);
    };

    AesEncryptNative(bufferSize, keyPtr, ivPtr, (int)mode, key.Length << 3, readCallback, writeCallback);

    FreeAesKey(keyPtr);
    FreeAesIV(ivPtr);

    if (res == null) throw new Exception("Could encrypt the data");
    return res;
  }

  public byte[] EncryptCore(byte[] data, byte[] key, byte[] iv, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data);
    return EncryptCore(reader,key, iv, mode, bufferSize);
  }

  public byte[] EncryptCore(byte[] data, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data);

    var strategy = new BinaryDecodeStrategy(keyType);
    var keyData = strategy.Decode(key);

    strategy = new BinaryDecodeStrategy(ivType);
    var ivData = strategy.Decode(iv);

    return EncryptCore(reader, keyData, ivData, mode, bufferSize);
  }

  public string EncryptCore(byte[] data, byte[] key, byte[] iv, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = EncryptCore(data, key, iv, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public string EncryptCore(byte[] data, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = EncryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public byte[] EncryptCore(string data, EncodingType dataType, byte[] key, byte[] iv, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data, dataType);
    return EncryptCore(reader, key, iv, mode, bufferSize);
  }

  public byte[] EncryptCore(string data, EncodingType dataType, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data, dataType);

    var strategy = new BinaryDecodeStrategy(keyType);
    var keyData = strategy.Decode(key);

    strategy = new BinaryDecodeStrategy(ivType);
    var ivData = strategy.Decode(iv);

    return EncryptCore(reader, keyData, ivData, mode, bufferSize);
  }

  public string EncryptCore(string data, EncodingType dataType, byte[] key, byte[] iv, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = EncryptCore(data, dataType, key, iv, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public string EncryptCore(string data, EncodingType dataType, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = EncryptCore(data, dataType, key, keyType, iv, ivType, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public byte[] EncryptCore(Stream data, byte[] key, byte[] iv, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data);
    return EncryptCore(reader, key, iv, mode, bufferSize);
  }

  public byte[] EncryptCore(Stream data, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data);

    var strategy = new BinaryDecodeStrategy(keyType);
    var keyData = strategy.Decode(key);

    strategy = new BinaryDecodeStrategy(ivType);
    var ivData = strategy.Decode(iv);

    return EncryptCore(reader, keyData, ivData, mode, bufferSize);
  }

  public string EncryptCore(Stream data, byte[] key, byte[] iv, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = EncryptCore(data, key, iv, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public string EncryptCore(Stream data, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = EncryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public byte[] DecryptCore(IReader reader, byte[] key, byte[] iv, AesMode mode, int bufferSize)
  {
    byte[]? res = null;

    var keyPtr = ImportAesKey(key);
    var ivPtr = ImportAesIV(iv);

    ReadCallback readCallback = (IntPtr ptr, int length) =>
    {
      var data = reader.read(length);
      return data != null ? WriteNativeMemroy(ptr, data) : 0;
    };

    WriteCallback writeCallback = (IntPtr ptr, int length) =>
    {
      if (length < 0) throw new Exception("Could decrypt the data");
      res = ReadNativeMemory(ptr, length);
    };

    AesDecryptNative(bufferSize, keyPtr, ivPtr, (int)mode, key.Length << 3, readCallback, writeCallback);

    FreeAesKey(keyPtr);
    FreeAesIV(ivPtr);

    if (res == null) throw new Exception("Could decrypt the data");
    return res;
  }

  public byte[] DecryptCore(byte[] data, byte[] key, byte[] iv, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data);
    return DecryptCore(reader, key, iv, mode, bufferSize);
  }

  public byte[] DecryptCore(byte[] data, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data);

    var strategy = new BinaryDecodeStrategy(keyType);
    var keyData = strategy.Decode(key);

    strategy = new BinaryDecodeStrategy(ivType);
    var ivData = strategy.Decode(iv);

    return DecryptCore(reader, keyData, ivData, mode, bufferSize);
  }

  public string DecryptCore(byte[] data, byte[] key, byte[] iv, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = DecryptCore(data, key, iv, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public string DecryptCore(byte[] data, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = DecryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public byte[] DecryptCore(string data, EncodingType dataType, byte[] key, byte[] iv, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data, dataType);
    return DecryptCore(reader, key, iv, mode, bufferSize);
  }

  public byte[] DecryptCore(string data, EncodingType dataType, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data, dataType);
    
    var strategy = new BinaryDecodeStrategy(keyType);
    var keyData = strategy.Decode(key);

    strategy = new BinaryDecodeStrategy(ivType);
    var ivData = strategy.Decode(iv);

    return DecryptCore(reader, keyData, ivData, mode, bufferSize);
  }

  public string DecryptCore(string data, EncodingType dataType, byte[] key, byte[] iv, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = DecryptCore(data, dataType, key, iv, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public string DecryptCore(string data, EncodingType dataType, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = DecryptCore(data, dataType, key, keyType, iv, ivType, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public byte[] DecryptCore(Stream data, byte[] key, byte[] iv, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data);
    return DecryptCore(reader, key, iv, mode, bufferSize);
  }

  public byte[] DecryptCore(Stream data, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, int bufferSize)
  {
    var reader = new ReaderStrategy(data);

    var strategy = new BinaryDecodeStrategy(keyType);
    var keyData = strategy.Decode(key);

    strategy = new BinaryDecodeStrategy(ivType);
    var ivData = strategy.Decode(iv);

    return DecryptCore(reader, keyData, ivData, mode, bufferSize);
  }

  public string DecryptCore(Stream data, byte[] key, byte[] iv, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = DecryptCore(data, key, iv, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  public string DecryptCore(Stream data, string key, EncodingType keyType, string iv, EncodingType ivType, AesMode mode, EncodingType EncodingType, int bufferSize)
  {
    var res = DecryptCore(data, key, keyType, iv, ivType, mode, bufferSize);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  protected byte[] GenerateAesKeyCore(AesKeySize size)
  {
    byte[]? res = null;

    WriteCallback callback = (IntPtr ptr, int length) =>
    {
      if (length < 0) throw new Exception("Could generate aes key");
      res = ReadNativeMemory(ptr, length);
    };

    Native.GenerateAesKey((int)size, callback);

    if (res == null) throw new Exception("Could generate aes key");
    return res;
  }

  protected string GenerateAesKeyCore(AesKeySize size, EncodingType EncodingType)
  {
    var res = GenerateAesKeyCore(size);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  protected byte[] GenerateAesIVCore(int size = 16)
  {
    byte[]? res = null;

    WriteCallback callback = (IntPtr ptr, int length) =>
    {
      if (length < 0) throw new Exception("Could not generate aes IV");
      res = ReadNativeMemory(ptr, length);
    };

    Native.GenerateAesIV(callback);

    if (res == null) throw new Exception("Could not generate aes IV");
    return res;
  }

  protected string GenerateAesIVCore(EncodingType EncodingType, int size = 16)
  {
    var res = GenerateAesIVCore(size);
    var strategy = new BinaryEncodeStrategy(EncodingType);
    return strategy.Encode(res);
  }

  protected IntPtr ImportAesKey(byte[] key)
  {
    var keyPtr = ImportAesKeyNative(key.Length);
    WriteNativeMemroy(keyPtr, key);
    return keyPtr;
  }

  protected void FreeAesKey(IntPtr key)
  {
    FreeAesKeyNative(key);
  }

  protected IntPtr ImportAesIV(byte[] iv)
  {
    var ivPtr = ImportAesIVNative();
    WriteNativeMemroy(ivPtr, iv);
    return ivPtr;
  }

  protected void FreeAesIV(IntPtr iv)
  {
    FreeAesIVNative(iv);
  }
}


