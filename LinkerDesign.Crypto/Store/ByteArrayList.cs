namespace LinkerDesign.Crypto;

public class ByteArrayList
{
  private List<byte[]> _items;

  public ByteArrayList()
  {
    this._items = new List<byte[]>();
  }

  public ByteArrayList Add(byte[] bytes)
  {
    this._items.Add(bytes);
    return this;
  }

  public long Count => this._items.Count;

  public byte[] ToArray()
  {
    return this._items.Aggregate((byte[] ret, byte[] item)=>ret.Concat(item).ToArray());
  }
}