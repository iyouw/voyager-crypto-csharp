namespace LinkerDesign.Crypto;

public class Hex: IBinaryEncoder, IBinaryDecoder
{
  public byte[] Decode(string text)
  {
    var len = text.Length;
    var bytes = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
    {
      bytes[i / 2] = Convert.ToByte(text.Substring(i, 2), 16);
    }
    return bytes;
  }

  public string Encode(byte[] bytes)
  {
    return BitConverter.ToString(bytes).Replace("-","").ToLower();
  }
}