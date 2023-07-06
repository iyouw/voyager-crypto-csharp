namespace LinkerDesign.Crypto;

public class Sha512: MdBase
{
  public override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.SHA512;
  }
}