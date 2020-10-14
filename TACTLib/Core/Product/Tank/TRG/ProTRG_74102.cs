using static TACTLib.Core.Product.Tank.ManifestCryptoHandler;
using static TACTLib.Core.Product.Tank.ResourceGraph;

namespace TACTLib.Core.Product.Tank.TRG
{
	[ManifestCrypto(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
	public class ProTRG_74102 : ITRGEncryptionProc
	{
		public byte[] Key(TRGHeader header, int length)
		{
			byte[] buffer = new byte[length];
			uint kidx, okidx;
			kidx = okidx = Keytable[(length * Keytable[0]) & 511];
			for (uint i = 0; i != length; ++i)
			{
				buffer[i] = Keytable[SignedMod(kidx, 512)];
				kidx += 3;
			}
			return buffer;
		}

		public byte[] IV(TRGHeader header, byte[] digest, int length)
		{
			byte[] buffer = new byte[length];
			uint kidx, okidx;
			kidx = okidx = length * header.m_buildVersion;
			for (int i = 0; i != length; ++i)
			{
				buffer[i] = Keytable[SignedMod(kidx, 512)];
				kidx += okidx % 61;
				buffer[i] ^= digest[SignedMod(kidx - i, SHA1_DIGESTSIZE)];
			}
			return buffer;
		}

		private static readonly byte[] Keytable =
		{
			0x7A, 0x6A, 0xE9, 0xCF, 0xC7, 0xCB, 0x7B, 0x5F, 0xB1, 0x2B, 0x10, 0xC0, 0x7B, 0x3E, 0x02, 0xF5, 
			0xF7, 0xFD, 0xD3, 0x6B, 0x86, 0x1F, 0x98, 0xC7, 0xAC, 0x22, 0x0B, 0x50, 0xF8, 0x11, 0x75, 0x46, 
			0x77, 0xC7, 0xF7, 0x89, 0x08, 0xC1, 0x71, 0x7E, 0x4E, 0x06, 0x3D, 0x78, 0x9D, 0x21, 0x6B, 0x22, 
			0x20, 0x40, 0x1B, 0x76, 0x85, 0x3D, 0xD8, 0x3B, 0xC6, 0x7F, 0x42, 0xF7, 0xA5, 0xF6, 0x29, 0x12, 
			0xEE, 0x25, 0x96, 0x25, 0x90, 0x2A, 0xC7, 0x1C, 0x0A, 0x4D, 0xB9, 0xB2, 0x17, 0xED, 0x69, 0xB1, 
			0xE4, 0x35, 0x6E, 0x97, 0x49, 0x93, 0xF4, 0x0D, 0x01, 0x94, 0x75, 0x03, 0x57, 0xDC, 0x14, 0xE6, 
			0xE6, 0xF2, 0x20, 0x4D, 0x90, 0x6D, 0x10, 0x06, 0x71, 0x2D, 0x67, 0xFE, 0x75, 0x00, 0xAF, 0xE6, 
			0x31, 0xE0, 0x64, 0x31, 0xF8, 0x94, 0xA6, 0xC8, 0x34, 0x73, 0xB0, 0x61, 0x20, 0x28, 0x54, 0x8A, 
			0x52, 0x3E, 0xF9, 0x63, 0x39, 0x6C, 0xD1, 0xA8, 0xCC, 0x84, 0xF4, 0xA0, 0xFF, 0xAD, 0xC9, 0xBF, 
			0xEE, 0x36, 0x08, 0xBE, 0x7A, 0x62, 0xA0, 0x64, 0x35, 0x27, 0x71, 0xFF, 0x50, 0x8B, 0x3E, 0x31, 
			0xCF, 0xF9, 0x7D, 0xA3, 0xA0, 0x21, 0xEF, 0x40, 0xAC, 0x81, 0x1A, 0x29, 0x8F, 0x03, 0x70, 0x35, 
			0x3D, 0x95, 0xB3, 0xBA, 0x52, 0x49, 0x25, 0x70, 0xB7, 0xBF, 0xF9, 0x9E, 0xB8, 0x6A, 0xF3, 0xDB, 
			0x55, 0x39, 0xA4, 0x15, 0x97, 0x80, 0x9A, 0xED, 0x3C, 0x9D, 0xB6, 0xAB, 0x85, 0xA7, 0x3A, 0x56, 
			0x6F, 0x6B, 0x06, 0xF3, 0xCE, 0xFE, 0xBE, 0x24, 0x33, 0x33, 0x30, 0x0E, 0x72, 0xBD, 0x26, 0xCF, 
			0xE8, 0x30, 0x99, 0x2F, 0xC1, 0xEB, 0x1E, 0x83, 0x00, 0x83, 0x5B, 0xEF, 0xD6, 0x8F, 0x1F, 0xBE, 
			0x2B, 0x04, 0xE9, 0x6F, 0xB7, 0x90, 0xC9, 0x28, 0xB9, 0x2F, 0x10, 0x86, 0xA0, 0xF2, 0x65, 0x5F, 
			0xD7, 0xA4, 0xF3, 0x6E, 0x2F, 0xBB, 0xA4, 0x7C, 0xF6, 0x56, 0x2D, 0x6F, 0x68, 0xB0, 0xE0, 0xFE, 
			0xD9, 0x94, 0xA0, 0x49, 0x11, 0x01, 0x9B, 0x64, 0xD9, 0x5B, 0x4B, 0xDD, 0x55, 0x3E, 0xE5, 0x71, 
			0x1F, 0x0F, 0x14, 0x7E, 0x89, 0x76, 0x8E, 0xEF, 0x1B, 0x7B, 0xA4, 0x1B, 0x83, 0xA6, 0xE0, 0xCE, 
			0x02, 0x55, 0xCB, 0x40, 0xAB, 0xEA, 0x45, 0xE5, 0x12, 0x28, 0x89, 0xF7, 0x02, 0xA2, 0xCD, 0x74, 
			0x27, 0x66, 0x76, 0x69, 0x84, 0x1B, 0x81, 0xB6, 0xCF, 0x41, 0x44, 0x52, 0xAA, 0xE2, 0x45, 0x1C, 
			0x6C, 0x6F, 0x61, 0x45, 0xD9, 0x1F, 0x99, 0xE3, 0x35, 0x18, 0x8B, 0x92, 0xFF, 0xA0, 0xCC, 0x72, 
			0x6D, 0x61, 0xC9, 0x70, 0xF0, 0xCF, 0xCB, 0xE1, 0xF4, 0xA1, 0xBD, 0x41, 0x96, 0x89, 0x8B, 0xA4, 
			0x87, 0x15, 0xA5, 0xD4, 0xE4, 0x45, 0x6C, 0x51, 0xBF, 0xA2, 0xA8, 0x2F, 0xD5, 0x6E, 0xD4, 0x43, 
			0x06, 0x0A, 0x6D, 0x9F, 0x76, 0x13, 0x49, 0x9F, 0x06, 0xA7, 0x57, 0x7F, 0xDD, 0xF8, 0x5B, 0x2B, 
			0x42, 0xD0, 0xA0, 0x23, 0x45, 0x57, 0xAF, 0x74, 0x91, 0x69, 0x32, 0xF5, 0x44, 0xE2, 0x89, 0x15, 
			0x88, 0xFB, 0x74, 0xC1, 0x7E, 0xB0, 0x92, 0xE8, 0xF0, 0xFB, 0x51, 0x6B, 0xD3, 0x00, 0xE2, 0xE3, 
			0x0A, 0xD5, 0x01, 0x4D, 0xB9, 0xCF, 0x81, 0xF6, 0x14, 0x2A, 0xFE, 0xFB, 0x42, 0x88, 0x17, 0xA0, 
			0x15, 0xBD, 0x54, 0x78, 0x28, 0x57, 0x41, 0xD3, 0x1C, 0x6F, 0x3C, 0xD3, 0xD3, 0x9B, 0x62, 0xA3, 
			0x7B, 0x4E, 0x12, 0xE0, 0xED, 0x13, 0x57, 0x43, 0x14, 0xC9, 0xCA, 0x6D, 0x96, 0xFE, 0x30, 0x71, 
			0x19, 0xAA, 0xB6, 0x18, 0xF5, 0x23, 0x6D, 0x8F, 0x89, 0x79, 0xE8, 0xAF, 0xB1, 0xA2, 0x33, 0x27, 
			0x6D, 0x78, 0xA3, 0x70, 0x32, 0x02, 0x41, 0xCE, 0xEF, 0x79, 0xB3, 0xF1, 0x3F, 0x3A, 0x57, 0x91
		};
	}
}
