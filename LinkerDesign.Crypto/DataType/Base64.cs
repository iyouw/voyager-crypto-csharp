namespace LinkerDesign.Crypto;

public class Base64: IBinaryEncoder, IBinaryDecoder
{
  public byte[] Decode(string text)
  {
    return Convert.FromBase64String(text);
  }

  public string Encode(byte[] bytes)
  {
    return Convert.ToBase64String(bytes);
  }
}