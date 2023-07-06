namespace LinkerDesign.Crypto;

using System.Text;

public class Utf8: IBinaryEncoder, IBinaryDecoder
{
  public byte[] Decode(string text)
  {
    return Encoding.UTF8.GetBytes(text);
  }

  public string Encode(byte[] bytes)
  {
    return Encoding.UTF8.GetString(bytes);
  }
}


