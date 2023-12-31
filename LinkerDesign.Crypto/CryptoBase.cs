namespace LinkerDesign.Crypto;

using System.Runtime.InteropServices;

public class CryptoBase
{
  public const int DefaultBufferSize = 8092;

  protected byte[] ReadNativeMemory(IntPtr ptr, int length)
  {
    byte[] bytes = new byte[length];
    Marshal.Copy(ptr, bytes, 0, length);
    return bytes;
  }

  protected int WriteNativeMemroy(IntPtr ptr, byte[] bytes)
  {
    Marshal.Copy(bytes, 0, ptr, bytes.Length);
    return bytes.Length;
  }

  protected int DigestNative(int bufferLength, int algorithm, ReadCallback readCallback, WriteCallback writeCallback)
  {
    return Native.Digest(bufferLength, algorithm, readCallback, writeCallback);
  }

  protected int GenerateAesKeyNative(int length, WriteCallback writeCallback)
  {
    return Native.GenerateAesKey(length, writeCallback);
  }

  protected IntPtr ImportAesKeyNative(int length)
  {
    return Native.ImportAesKey(length);
  }

  protected void FreeAesKeyNative(IntPtr key)
  {
    Native.FreeAesKey(key);
  }

  protected int GenerateAesIVNative( WriteCallback writeCallback)
  {
    return Native.GenerateAesIV(writeCallback);
  }

  protected IntPtr ImportAesIVNative()
  {
    return Native.ImportAesIV();
  }

  protected void FreeAesIVNative(IntPtr iv)
  {
    Native.FreeAesIV(iv);
  }

  protected int AesEncryptNative(int bufferLength, IntPtr key, IntPtr iv, int aesMode, int blockSize, ReadCallback readCallback, WriteCallback writeCallback)
  {
    return Native.AesEncrypt(bufferLength, key, iv, aesMode, blockSize, readCallback, writeCallback);
  }

  protected int AesDecryptNative(int bufferLength, IntPtr key, IntPtr iv, int aesMode, int blockSize, ReadCallback readCallback, WriteCallback writeCallback)
  {
    return Native.AesDecrypt(bufferLength, key, iv, aesMode, blockSize, readCallback, writeCallback);
  }
}




