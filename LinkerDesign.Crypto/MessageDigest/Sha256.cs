namespace LinkerDesign.Crypto;

public class Sha256: MdBase
{
  public override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.SHA256;
  }
}