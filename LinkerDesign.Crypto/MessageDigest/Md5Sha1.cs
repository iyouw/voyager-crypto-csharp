namespace LinkerDesign.Crypto;

public class Md5Sha1: MdBase
{
  public override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.MD5_SHA1;
  }
}