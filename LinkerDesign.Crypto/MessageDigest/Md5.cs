namespace LinkerDesign.Crypto;

public class Md5: MdBase
{
  public override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.MD5;
  }
}


