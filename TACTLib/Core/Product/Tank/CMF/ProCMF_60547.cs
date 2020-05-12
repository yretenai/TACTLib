using static TACTLib.Core.Product.Tank.ManifestCryptoHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [ManifestCryptoAttribute(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_60547 : ICMFEncryptionProc
    {
        public byte[] Key(CMFHeader header, int length)
        {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[SignedMod(length * Keytable[0], 512)];
            for (uint i = 0; i != length; ++i)
            {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx += (uint)(header.m_buildVersion * header.m_dataCount) % 7;
            }
            
            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length)
        {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[digest[7] * Keytable[0] & 511];
            for (int i = 0; i != length; ++i)
            {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx = header.m_buildVersion - kidx;
                buffer[i] ^= digest[SignedMod(kidx + i, SHA1_DIGESTSIZE)];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0x90, 0x7B, 0x7B, 0x12, 0x86, 0x3A, 0xE2, 0x80, 0x39, 0xCD, 0x45, 0xF0, 0x81, 0x6D, 0x65, 0x8D,
            0xBF, 0x98, 0x50, 0x8C, 0xE4, 0x63, 0xBD, 0x15, 0x03, 0x74, 0xE3, 0xD3, 0x27, 0x58, 0x3E, 0xC5,
            0x6A, 0xF5, 0x4C, 0x6F, 0x95, 0x98, 0xE1, 0x22, 0x0E, 0x63, 0x93, 0xBC, 0xE3, 0xBA, 0x32, 0x94,
            0x3A, 0x72, 0xBC, 0x41, 0x60, 0x44, 0x29, 0x5D, 0xC7, 0x71, 0xCB, 0xC4, 0x37, 0x8D, 0x08, 0x96,
            0x06, 0xB2, 0xCD, 0x03, 0xFE, 0x01, 0x65, 0x3A, 0x1C, 0xA5, 0x4F, 0x37, 0xFB, 0xB9, 0x45, 0x48,
            0x7A, 0x55, 0xAA, 0xDB, 0xBB, 0x70, 0x91, 0x3B, 0x63, 0xD6, 0x27, 0x4C, 0x1E, 0x9C, 0xBB, 0xD5,
            0x6F, 0x12, 0x97, 0xA5, 0x29, 0x06, 0xC1, 0xF2, 0x69, 0x70, 0x03, 0xA0, 0xCD, 0x24, 0x5A, 0xCE,
            0x3B, 0x59, 0x04, 0x17, 0xDA, 0x93, 0xDC, 0x22, 0x37, 0x9C, 0x41, 0xDE, 0x9A, 0xE4, 0xCB, 0xDA,
            0x6F, 0xCF, 0xF0, 0x18, 0xCB, 0xE1, 0xC2, 0x51, 0x6E, 0x3D, 0xA4, 0x61, 0x5A, 0xB5, 0x16, 0x13,
            0x33, 0x11, 0x8D, 0x28, 0x2F, 0xB1, 0x78, 0x57, 0xD1, 0x02, 0xBF, 0x00, 0xE5, 0x3F, 0x22, 0x94,
            0x87, 0x97, 0x39, 0x01, 0xC1, 0x3F, 0x06, 0x21, 0xDB, 0x6D, 0xF9, 0x70, 0x41, 0x9C, 0x33, 0xF9,
            0x94, 0x32, 0x3C, 0x77, 0x5B, 0x77, 0x88, 0x6C, 0x97, 0x03, 0x4D, 0x50, 0x94, 0xF4, 0x70, 0xA7,
            0xAC, 0xBA, 0x6A, 0x89, 0x81, 0x9C, 0xF0, 0xA9, 0xA4, 0x8A, 0x92, 0xB7, 0x9B, 0x6E, 0xB9, 0xE7,
            0x72, 0x72, 0x70, 0xCB, 0x4C, 0x41, 0x7D, 0xF8, 0x7C, 0xA2, 0x12, 0x8C, 0xCA, 0xE5, 0x39, 0x32,
            0x59, 0x34, 0xC4, 0xA2, 0xE5, 0x87, 0xD3, 0x97, 0xA1, 0xD5, 0x27, 0x62, 0x72, 0x6C, 0xD6, 0xE1,
            0x2F, 0xEF, 0xAB, 0x9B, 0x4A, 0x70, 0xF3, 0xC9, 0x11, 0xA8, 0x69, 0xE3, 0x72, 0x0A, 0x35, 0x55,
            0x29, 0x0B, 0x0D, 0x8B, 0xED, 0x4A, 0xDF, 0xBC, 0x2A, 0x6F, 0x3F, 0x79, 0xE7, 0xB5, 0x92, 0x38,
            0xE1, 0xD8, 0xB3, 0xEC, 0x64, 0x3B, 0xCA, 0x2D, 0xF1, 0x26, 0x82, 0x4D, 0xA6, 0x17, 0x77, 0x4D,
            0x38, 0x1B, 0xE6, 0x0A, 0x3F, 0xA7, 0x8C, 0x88, 0x72, 0x99, 0x21, 0x82, 0xD0, 0x98, 0x88, 0x4B,
            0x7B, 0x54, 0x3C, 0x75, 0xF8, 0xDF, 0xF3, 0xC8, 0xC2, 0x40, 0x63, 0xB8, 0xD2, 0x39, 0x70, 0xBA,
            0x7F, 0x77, 0x11, 0x89, 0xFA, 0x4F, 0x96, 0xDC, 0x7A, 0xB8, 0x03, 0x6A, 0x78, 0x95, 0x24, 0x81,
            0xD3, 0x89, 0xB5, 0x16, 0x4B, 0x6C, 0xC6, 0xE2, 0xED, 0x95, 0xB8, 0x1F, 0x3A, 0x72, 0x85, 0x89,
            0x5C, 0x5A, 0xCA, 0x22, 0x7C, 0x8A, 0x39, 0xA1, 0xD6, 0x49, 0x30, 0x0C, 0xFB, 0x43, 0x6D, 0x02,
            0x38, 0x7B, 0xB9, 0x4F, 0x04, 0x96, 0xC6, 0xEB, 0xE8, 0x9F, 0x0E, 0x58, 0x48, 0x85, 0x15, 0xE0,
            0x84, 0xB3, 0xFB, 0xA4, 0xF3, 0x4E, 0x02, 0x32, 0x30, 0xBF, 0xC5, 0xE1, 0x7E, 0x53, 0xEB, 0xAF,
            0x1A, 0xDC, 0x5C, 0xB2, 0xC5, 0xA2, 0x8C, 0xEA, 0xB0, 0x06, 0x6D, 0xB9, 0xCB, 0xE2, 0x9F, 0x60,
            0x96, 0xE4, 0x1E, 0x31, 0xEB, 0x3C, 0xC3, 0x2B, 0x01, 0x8E, 0x1E, 0x11, 0x1E, 0x16, 0x97, 0x75,
            0x2A, 0x7C, 0xD8, 0xB1, 0x03, 0x9F, 0x79, 0xCF, 0x31, 0x6B, 0x76, 0x5C, 0x48, 0x60, 0xB6, 0x4E,
            0xF1, 0x33, 0xB3, 0x41, 0xD9, 0x08, 0x23, 0x6B, 0x13, 0xD3, 0x51, 0x53, 0x16, 0x2A, 0x28, 0x58,
            0x47, 0x6C, 0xBE, 0xB1, 0x98, 0x45, 0x38, 0xB5, 0xDA, 0x24, 0x03, 0xEA, 0x7A, 0x59, 0x8B, 0x46,
            0x59, 0x7B, 0x99, 0x04, 0xE0, 0x94, 0x39, 0xF3, 0x1B, 0x65, 0x3C, 0x22, 0x7C, 0x6D, 0x9B, 0x87,
            0x0B, 0x48, 0xE6, 0xD6, 0x4A, 0x0C, 0x26, 0x4D, 0x01, 0x4B, 0x35, 0x83, 0x0D, 0x86, 0x37, 0x68
        };
    }
}
