# LinkerDesign.Crypto

a lightweight crypto library for dotnet, which can run on linux-x64 and windows-x64 platform.

## Features

1. Symmetric Encryt Decrypt
  + AES-CBC
  + AES-CTR
2. Message Digest
  + Sha1
  + Sha256
  + Sha384
  + Sha512
  + Md5
  + Md5Sha1

more features will come soon!

## Setup

```
dotnet add reference LinkerDesign.Crypto
```

## usages

1. AES-CBC

We can use AES-CBC to encryt a string who's encoding is utf8 to a base64 string.

Additional, we can AES-CBS to decrypt a base64 string to it's original utf8 string 

```c#
using LinkerDesign.Crypto;

var msg = "《青溪》是唐代诗人王维创作的一首五言古诗。此诗描写了一条青溪的幽秀景色，诗人用多彩的画笔，绘出青溪流经不同地方时呈现的不同画面。其中“声喧乱石中，色静深松里”两句，以喧响的声音和幽冷的色调形成闹与静的强烈对比，如同一幅“有声画”。诗的末四句写出诗人心境的闲谈正如清川的闲淡，把自己的精神和自然的精神融和起来，意味隽永。全诗自然清淡素雅，写景抒情皆轻轻松松，然而韵味却隽永醇厚。诗人笔下的青溪是喧闹与沉郁的统一，活泼与安详的揉合，幽深与素静的融和。";

var aes = new Aes();

string key = aes.GenerateKey(ExportType.Base64);
string iv = aes.GenerateIV(ExportType.Base64);

var enc = aes.EncryptCBCWithUTF8(key, iv, msg, exportType: ExportType.Base64);
var dec = aes.DecryptCBCWithUTF8(key, iv, enc);
Console.WriteLine($"{dec}:::equals:{msg == dec}");
```

2. Message Digest

support regular message digest algorith, like `sha1`, `sha256`, `md5` etc...

```c#
using LinkerDesign.Crypto;

const msg = '《青溪》是唐代诗人王维创作的一首五言古诗。此诗描写了一条青溪的幽秀景色，诗人用多彩的画笔，绘出青溪流经不同地方时呈现的不同画面。其中“声喧乱石中，色静深松里”两句，以喧响的声音和幽冷的色调形成闹与静的强烈对比，如同一幅“有声画”。诗的末四句写出诗人心境的闲谈正如清川的闲淡，把自己的精神和自然的精神融和起来，意味隽永。全诗自然清淡素雅，写景抒情皆轻轻松松，然而韵味却隽永醇厚。诗人笔下的青溪是喧闹与沉郁的统一，活泼与安详的揉合，幽深与素静的融和。';

var sha1 = new Sha1();
var hash = sha1.Digest(msg, ExportType.UTF8, ExportType.Base64);
Console.WriteLine($"{hash}:::{hash.Length}");

var sha256 = new Sha256();
hash = sha256.Digest(msg, ExportType.UTF8, ExportType.Hex);
Console.WriteLine($"{hash}:::{hash.Length}");

var sha384 = new Sha384();
hash = sha384.Digest(msg, ExportType.UTF8, ExportType.Hex);
Console.WriteLine($"{hash}:::{hash.Length}");

var sha512 = new Sha512();
hash = sha512.Digest(msg, ExportType.UTF8, ExportType.Hex);
Console.WriteLine($"{hash}:::{hash.Length}");

var md5 = new Md5();
var hashWeb = "51dac0da1863951d696e027892bdc177";
hash = md5.Digest(msg, ExportType.UTF8, ExportType.Hex);
Console.WriteLine($"{hash}:::{hash.Length}:::equals: {hash == hashWeb}");

var md5Sha1 = new Md5Sha1();
hash = md5Sha1.Digest(msg, ExportType.UTF8, ExportType.Hex);
Console.WriteLine($"{hash}:::{hash.Length}");

Console.WriteLine("Hello, World!");
```