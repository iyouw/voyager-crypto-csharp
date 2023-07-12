namespace LinkerDesign.Crypto;

public class Sha512: MdBase
{
  protected override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.SHA512;
  }
}