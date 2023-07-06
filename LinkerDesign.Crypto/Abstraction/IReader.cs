namespace LinkerDesign.Crypto;

public interface IReader
{
  long Length { get; }
  byte[]? read(int length);
}