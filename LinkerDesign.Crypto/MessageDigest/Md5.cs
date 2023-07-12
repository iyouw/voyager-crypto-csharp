namespace LinkerDesign.Crypto;

public class Md5: MdBase
{
  protected override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.MD5;
  }
}


