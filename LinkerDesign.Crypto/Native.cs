namespace LinkerDesign.Crypto;

using System.Runtime.InteropServices;

public delegate int ReadCallback(IntPtr ptr, int length);

public delegate void WriteCallback(IntPtr ptr, int length);

class Native
{
  [DllImport("kcrypto", EntryPoint="digest")]
  public static extern int Digest(int bufferLength, int algorithm, ReadCallback readCallback, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="generate_aes_key")]
  public static extern int GenerateAesKey(int length, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="import_aes_key")]
  public static extern IntPtr ImportAesKey(int length);

  [DllImport("kcrypto", EntryPoint="free_aes_key")]
  public static extern void FreeAesKey(IntPtr key);

  [DllImport("kcrypto", EntryPoint="generate_aes_iv")]
  public static extern int GenerateAesIV(int length, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="import_aes_iv")]
  public static extern IntPtr ImportAesIV(int length);

  [DllImport("kcrypto", EntryPoint="free_aes_iv")]
  public static extern void FreeAesIV(IntPtr iv);

  [DllImport("kcrypto", EntryPoint="encrypt")]
  public static extern int Encrypt(int bufferLength, IntPtr key, IntPtr iv, int aesMode, int blockSize, ReadCallback readCallback, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="decrypt")]
  public static extern int Decrypt(int bufferLength, IntPtr key, IntPtr iv, int aesMode, int blockSize, ReadCallback readCallback, WriteCallback writeCallback);
}





