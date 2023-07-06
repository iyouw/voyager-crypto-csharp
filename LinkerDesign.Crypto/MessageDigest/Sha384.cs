namespace LinkerDesign.Crypto;

public class Sha384: MdBase
{
  public override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.SHA384;
  }
}