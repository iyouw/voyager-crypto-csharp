namespace LinkerDesign.Crypto;

public interface IReader
{
  byte[]? read(int length);
}