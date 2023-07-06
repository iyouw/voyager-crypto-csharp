namespace LinkerDesign.Crypto;

public class Sha1: MdBase
{
  public override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.SHA1;
  }
}