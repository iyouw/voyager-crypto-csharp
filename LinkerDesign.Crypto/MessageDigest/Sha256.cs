namespace LinkerDesign.Crypto;

public class Sha256: MdBase
{
  protected override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.SHA256;
  }
}