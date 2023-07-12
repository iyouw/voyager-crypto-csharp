namespace LinkerDesign.Crypto;

public class Sha384: MdBase
{
  protected override MdAlgorithm GetAlgorithm()
  {
    return MdAlgorithm.SHA384;
  }
}