namespace LinkerDesign.Crypto;

public class Sha1: MdBase
{
  protected override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.SHA1;
  }
}