namespace LinkerDesign.Crypto;

using System.Runtime.InteropServices;

public delegate int ReadCallback(IntPtr ptr, int length);

public delegate void WriteCallback(IntPtr ptr, int length);

class Native
{
  // message digest
  [DllImport("kcrypto", EntryPoint="digest")]
  public static extern int Digest(int bufferLength, int algorithm, ReadCallback readCallback, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="md_context_create")]
  public static extern IntPtr CreateMdContext(int algorithm, int bufferLength);

  [DllImport("kcrypto", EntryPoint="md_context_update")]
  public static extern int UpdateMdContext(IntPtr mdContext, ReadCallback readCallback);

  [DllImport("kcrypto", EntryPoint="md_context_final")]
  public static extern int FinalMdContext(IntPtr mdContext, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="md_context_free")]
  public static extern void FreeMdContext(IntPtr mdContext);

  // aes encrypt decrypt
  [DllImport("kcrypto", EntryPoint="generate_aes_key")]
  public static extern int GenerateAesKey(int length, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="import_aes_key")]
  public static extern IntPtr ImportAesKey(int length);

  [DllImport("kcrypto", EntryPoint="free_aes_key")]
  public static extern void FreeAesKey(IntPtr key);

  [DllImport("kcrypto", EntryPoint="generate_aes_iv")]
  public static extern int GenerateAesIV(WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="import_aes_iv")]
  public static extern IntPtr ImportAesIV();

  [DllImport("kcrypto", EntryPoint="free_aes_iv")]
  public static extern void FreeAesIV(IntPtr iv);

  [DllImport("kcrypto", EntryPoint="aes_encrypt")]
  public static extern int AesEncrypt(int bufferLength, IntPtr key, IntPtr iv, int aesMode, int blockSize, ReadCallback readCallback, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="aes_decrypt")]
  public static extern int AesDecrypt(int bufferLength, IntPtr key, IntPtr iv, int aesMode, int blockSize, ReadCallback readCallback, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="aes_context_create")]
  public static extern IntPtr CreateAesContext(int aesMode, int key_size, int bufferLength);

  [DllImport("kcrypto", EntryPoint="aes_context_get_block_size")]
  public static extern int GetAesContextBufferSize(IntPtr aesContext);

  [DllImport("kcrypto", EntryPoint="aes_context_encrypt_init")]
  public static extern int InitEncryptAesContext(IntPtr aesContext, IntPtr key, IntPtr iv);

  [DllImport("kcrypto", EntryPoint="aes_context_encrypt_update")]
  public static extern int UpdateEncryptAesContext(IntPtr aesContext, ReadCallback readCallback, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="aes_context_encrypt_final")]
  public static extern int FinalEncryptAesContext(IntPtr aesContext, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="aes_context_decrypt_init")]
  public static extern int InitDecryptAesContext(IntPtr aesContext, IntPtr key, IntPtr iv);

  [DllImport("kcrypto", EntryPoint="aes_context_decrypt_update")]
  public static extern int UpdateDecryptAesContext(IntPtr aesContext, ReadCallback readCallback, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="aes_context_decrypt_final")]
  public static extern int FinalDecryptAesContext(IntPtr aesContext, WriteCallback writeCallback);

  [DllImport("kcrypto", EntryPoint="aes_context_free")]
  public static extern void FreeAesContext(IntPtr aesContext);

}





