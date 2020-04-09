using static TACTLib.Core.Product.Tank.CMFCryptHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF
{
  [CMFMetadataAttribute(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
  public class ProCMF_66607 : ICMFEncryptionProc
  {
    public byte[] Key(CMFHeader header, int length)
    {
      byte[] buffer = new byte[length];
      uint kidx, okidx;
      kidx = okidx = Keytable[SignedMod(length * Keytable[0], 512)];
      for (uint i = 0; i != length; ++i)
      {
        buffer[i] = Keytable[SignedMod(kidx, 512)];
        kidx -= header.BuildVersion & 511;
      }
     return buffer;
    }

    public byte[] IV(CMFHeader header, byte[] digest, int length)
    {
      byte[] buffer = new byte[length];
      uint kidx, okidx;
      kidx = okidx = Keytable[(uint)header.DataCount & 511];
      for (int i = 0; i != length; ++i)
      {
        buffer[i] = Keytable[SignedMod(kidx, 512)];
        kidx -= header.BuildVersion & 511;
        buffer[i] ^= digest[SignedMod(kidx + header.BuildVersion, SHA1_DIGESTSIZE)];
      }
      return buffer;
    }

    private static readonly byte[] Keytable =
    {
      0x42, 0xFF, 0x31, 0x78, 0xE8, 0xCF, 0xE4, 0xCD, 0xF8, 0xD2, 0x5C, 0x4B, 0x26, 0xA3, 0xCA, 0x9F, 
      0x91, 0x86, 0x34, 0xBE, 0xA7, 0x80, 0x5B, 0xE9, 0x9C, 0x32, 0xBC, 0x8C, 0x70, 0x86, 0x54, 0x28, 
      0x79, 0x13, 0xE9, 0x70, 0xE8, 0x5E, 0xAD, 0x37, 0x32, 0x85, 0xCE, 0x3A, 0x8F, 0x0B, 0x7F, 0x6A, 
      0x9D, 0x02, 0xBB, 0x3D, 0x90, 0x7B, 0xA6, 0x1B, 0xE8, 0x04, 0xDF, 0xF2, 0xA8, 0x35, 0x7D, 0xC7, 
      0x1A, 0xF9, 0xF2, 0x0D, 0xC0, 0x50, 0x75, 0xA2, 0x89, 0xB1, 0xB4, 0xD3, 0x66, 0x28, 0xD1, 0x86, 
      0x2C, 0xC3, 0x33, 0xAA, 0x7E, 0xD4, 0x89, 0x43, 0xD3, 0x62, 0x1C, 0x84, 0x81, 0x0E, 0x07, 0xAD, 
      0x03, 0xAF, 0x11, 0xB6, 0xED, 0xD7, 0x9F, 0x1A, 0xFF, 0xCF, 0x94, 0x18, 0xBC, 0xB7, 0x22, 0x5A, 
      0xDD, 0xDD, 0xC2, 0xAA, 0x0A, 0x60, 0xEF, 0x17, 0x8C, 0x39, 0x15, 0x04, 0x96, 0x05, 0xCB, 0x25, 
      0xFE, 0xBC, 0x56, 0x87, 0x57, 0x02, 0x7E, 0xAD, 0x47, 0x43, 0xA7, 0x73, 0x54, 0xC5, 0xBB, 0xA3, 
      0xDB, 0x39, 0x13, 0x64, 0xA9, 0x3A, 0x34, 0x18, 0x72, 0x45, 0x0B, 0x48, 0xF1, 0x78, 0xF3, 0x7F, 
      0x2C, 0xB4, 0x3A, 0x4F, 0x59, 0xCE, 0x44, 0xD4, 0x5F, 0x39, 0x42, 0x6C, 0xED, 0x10, 0x11, 0xE3, 
      0xDD, 0xF8, 0x3B, 0x00, 0x67, 0x0E, 0xF3, 0x8E, 0x77, 0xD0, 0x4D, 0x5F, 0xFB, 0xF1, 0x37, 0x6E, 
      0x84, 0x07, 0x32, 0x34, 0xA8, 0x0C, 0x91, 0xF3, 0x27, 0xFE, 0x78, 0xCF, 0x9E, 0x0C, 0x3D, 0x80, 
      0xCF, 0xBC, 0x4A, 0xDA, 0x61, 0x49, 0xA8, 0xBF, 0x5E, 0x19, 0x75, 0xF1, 0xAE, 0xF7, 0xDA, 0x5F, 
      0x75, 0x77, 0x4C, 0xED, 0xFF, 0xA3, 0x1D, 0x2A, 0xB1, 0xA9, 0x11, 0xC0, 0x93, 0xD6, 0x3D, 0x99, 
      0x4C, 0x73, 0x81, 0x94, 0x43, 0x36, 0x8F, 0xF3, 0xB1, 0x65, 0xD0, 0x3C, 0x4F, 0x0A, 0xC0, 0xB2, 
      0x2E, 0xFF, 0x88, 0x5A, 0x0D, 0x7D, 0xDF, 0x4B, 0x4E, 0xC4, 0x46, 0xDB, 0xF3, 0x67, 0x80, 0x1F, 
      0xF2, 0xB5, 0xC6, 0xBC, 0x6F, 0x2F, 0xC9, 0x5B, 0x18, 0x88, 0x29, 0xA1, 0xF3, 0x0D, 0x68, 0x84, 
      0xC7, 0x1A, 0x21, 0x54, 0xA8, 0x85, 0x73, 0x2C, 0x30, 0x61, 0x17, 0x1E, 0x6F, 0xAE, 0x28, 0x39, 
      0xB1, 0x06, 0x58, 0xB2, 0xEA, 0x91, 0x10, 0x8A, 0x5B, 0x9A, 0x07, 0xC0, 0xD2, 0xCA, 0xAA, 0x65, 
      0x61, 0xE0, 0x5B, 0xB2, 0xDF, 0x4D, 0xF3, 0x2E, 0xD3, 0xD4, 0x7C, 0x79, 0xFA, 0x44, 0x27, 0x15, 
      0xA3, 0x73, 0x2A, 0xAB, 0x90, 0x42, 0x5D, 0xFD, 0x47, 0xBC, 0x9F, 0x9C, 0x04, 0x9C, 0x8D, 0xE0, 
      0xF6, 0xA5, 0x12, 0xC7, 0x51, 0x50, 0xDC, 0x93, 0xE7, 0xD2, 0xE8, 0x13, 0x59, 0x90, 0x28, 0xA5, 
      0xFF, 0x8A, 0x7F, 0x47, 0x50, 0x69, 0x4F, 0xF2, 0x71, 0x98, 0x04, 0x1B, 0xFC, 0x78, 0x0B, 0x38, 
      0x00, 0x1A, 0x3E, 0x5B, 0xD2, 0x4C, 0xF9, 0xB7, 0x6A, 0x68, 0x10, 0xF3, 0x84, 0x36, 0x14, 0xD9, 
      0x15, 0x6E, 0x4A, 0x7A, 0xDA, 0xAD, 0xDB, 0x06, 0x9D, 0x8C, 0xA7, 0x37, 0x5B, 0x9A, 0x36, 0xC6, 
      0xA7, 0x5E, 0xAB, 0xB8, 0xFE, 0x3F, 0x7B, 0x5D, 0x3C, 0xF4, 0x06, 0x15, 0xAD, 0x9D, 0xCC, 0x53, 
      0x5A, 0x3B, 0x8D, 0x42, 0x9D, 0xD0, 0xF1, 0x43, 0x2F, 0x28, 0x9F, 0xC7, 0x3E, 0x75, 0x2B, 0xAD, 
      0xA8, 0xA3, 0x6E, 0x4F, 0x39, 0xCF, 0xDD, 0xAF, 0xDA, 0x32, 0x36, 0x73, 0xF9, 0x39, 0x46, 0x8A, 
      0xC3, 0xAB, 0x2F, 0x57, 0x74, 0x3A, 0x25, 0x61, 0xCA, 0x94, 0x11, 0xA4, 0xD0, 0xB9, 0x0F, 0xED, 
      0xD5, 0x92, 0x14, 0x94, 0x9B, 0xCB, 0xAD, 0x6E, 0x4B, 0xB8, 0x3B, 0xA1, 0x9F, 0x7E, 0x07, 0xC3, 
      0x8D, 0xAB, 0xB0, 0x11, 0x34, 0x2E, 0xE4, 0x39, 0x5E, 0x25, 0x46, 0x64, 0x2E, 0x4E, 0xCF, 0xA9
    };
  }
}