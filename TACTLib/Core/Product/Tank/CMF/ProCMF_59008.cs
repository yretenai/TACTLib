using static TACTLib.Core.Product.Tank.CMFCryptHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [CMFMetadataAttribute(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_59008 : ICMFEncryptionProc
    {
        public byte[] Key(CMFHeader header, int length)
        {
            byte[] buffer = new byte[length];

            uint kidx = header.BuildVersion * (uint)length;
            for (uint i = 0; i != length; ++i)
            {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                switch (SignedMod(kidx, 3))
                {
                    case 0:
                        kidx += 103;
                        break;
                    case 1:
                        kidx = (uint)SignedMod(4 * kidx, header.BuildVersion);
                        break;
                    case 2:
                        --kidx;
                        break;
                }
            }
            
            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length)
        {
            byte[] buffer = new byte[length];

            uint kidx = 2u * digest[5];
            for (int i = 0; i != length; ++i)
            {
                buffer[i] = Keytable[SignedMod(kidx, 512)];

                kidx += header.BuildVersion * (uint)header.DataCount % 7u;

                buffer[i] ^= digest[SignedMod(kidx - 73, SHA1_DIGESTSIZE)];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0x3B, 0x2F, 0x20, 0x3A, 0xAF, 0x14, 0xEE, 0x7F, 0x06, 0x32, 0xD4, 0xC2, 0x82, 0x28, 0xCC, 0xDB,
            0xF5, 0xCD, 0xBF, 0x6A, 0x4A, 0x8A, 0xB9, 0x38, 0xDF, 0x53, 0x01, 0x2F, 0xE0, 0xDB, 0x93, 0x7E,
            0x56, 0x17, 0x13, 0x70, 0xA1, 0xC7, 0x8D, 0xF9, 0x91, 0x5D, 0x1A, 0x1C, 0xA0, 0x18, 0xED, 0xE8,
            0x9C, 0x05, 0xC6, 0xE2, 0x09, 0x6C, 0xC1, 0x25, 0xC7, 0xB6, 0x70, 0xDD, 0x95, 0xEB, 0x53, 0x68,
            0xD8, 0xAE, 0x35, 0x30, 0x73, 0x25, 0x90, 0x9F, 0xEF, 0xCB, 0xD6, 0x24, 0xC4, 0xB5, 0x9B, 0x35,
            0x94, 0x4C, 0xC5, 0xD7, 0xA4, 0x1F, 0xB2, 0x42, 0x72, 0x53, 0x29, 0x8C, 0x08, 0x19, 0x02, 0x1C,
            0xD0, 0x01, 0x10, 0x5B, 0xD6, 0x4A, 0xBA, 0xE8, 0x33, 0xC8, 0x3A, 0x94, 0xD6, 0xE0, 0x8A, 0x23,
            0x1B, 0xA1, 0x1D, 0x3A, 0xD9, 0x0E, 0xE6, 0x02, 0xA1, 0xDB, 0x69, 0x13, 0x21, 0x09, 0xB7, 0x98,
            0xB2, 0xDA, 0x77, 0x31, 0x2B, 0x54, 0xA5, 0x1D, 0x40, 0x4A, 0x8A, 0x41, 0xC8, 0xEE, 0x8D, 0xF5,
            0xFF, 0x15, 0xAF, 0xF6, 0xCA, 0xCF, 0x46, 0x89, 0x31, 0xCC, 0xA8, 0x96, 0x47, 0x59, 0xB2, 0x78,
            0xF6, 0xAE, 0x0B, 0x3D, 0xF7, 0x07, 0x42, 0x8C, 0xAF, 0x42, 0x28, 0x67, 0x27, 0x59, 0x10, 0xC5,
            0x8D, 0x23, 0x93, 0x36, 0x8F, 0x32, 0x7F, 0x64, 0x8E, 0x21, 0x83, 0x0F, 0x15, 0xC4, 0x31, 0x04,
            0x1D, 0xF7, 0xF6, 0xA5, 0x5A, 0xAD, 0xFC, 0x5A, 0x4A, 0x70, 0xFD, 0xDD, 0x78, 0x48, 0x7C, 0x11,
            0x86, 0x13, 0xE3, 0x9B, 0xD4, 0x2A, 0x20, 0x30, 0xCF, 0xA1, 0xAC, 0xE1, 0x35, 0x5D, 0x86, 0xB6,
            0xBE, 0xDB, 0xDB, 0x3A, 0x1B, 0x29, 0xEA, 0x52, 0x6D, 0x16, 0xF1, 0xD8, 0x45, 0xA9, 0x95, 0xFB,
            0xA9, 0x64, 0x45, 0xD5, 0x3E, 0xAC, 0x09, 0xAF, 0x22, 0xE9, 0x77, 0x4A, 0x28, 0x52, 0x19, 0xAD,
            0x8D, 0xFD, 0x34, 0x6C, 0x12, 0xDD, 0x26, 0xBE, 0xB1, 0xA4, 0x62, 0xC0, 0xFB, 0x48, 0xFB, 0x03,
            0xD6, 0x4A, 0x96, 0x46, 0x97, 0xAD, 0xA7, 0xAC, 0x17, 0x3C, 0xFA, 0x25, 0xE6, 0xC3, 0xFC, 0x01,
            0x9F, 0xA3, 0xDD, 0xEE, 0x35, 0xFF, 0x50, 0x38, 0x51, 0x01, 0x59, 0xF0, 0x24, 0x30, 0x54, 0xEA,
            0x96, 0x11, 0x02, 0x02, 0x9D, 0xBD, 0x7F, 0x48, 0x52, 0x52, 0x0B, 0xFC, 0xF5, 0xD3, 0xA0, 0x35,
            0x13, 0x35, 0x2D, 0x04, 0x43, 0x43, 0x32, 0xF4, 0x86, 0x8A, 0xA3, 0xD1, 0x2E, 0x51, 0x60, 0x19,
            0x25, 0xA3, 0x39, 0x15, 0x62, 0xEA, 0x20, 0x57, 0x0D, 0x60, 0x32, 0xA6, 0x28, 0x56, 0xBD, 0x91,
            0xC7, 0x2F, 0xBD, 0x55, 0xBC, 0x1A, 0x66, 0xD2, 0x0A, 0x7E, 0xAA, 0x78, 0xA9, 0x93, 0xBC, 0x84,
            0x1F, 0xB6, 0x35, 0x7E, 0xEF, 0xC3, 0x10, 0xB4, 0x60, 0x45, 0xB4, 0xE0, 0xB8, 0xB8, 0x97, 0x2D,
            0xD7, 0xF9, 0xB4, 0x58, 0x92, 0xBF, 0x91, 0xDA, 0x01, 0x07, 0xC7, 0x08, 0x38, 0xBE, 0xF9, 0x44,
            0xE6, 0x47, 0x47, 0xE7, 0xE0, 0x65, 0x3F, 0xE7, 0x0A, 0xBE, 0x74, 0x58, 0x6B, 0x8D, 0xDF, 0x23,
            0x37, 0x15, 0x79, 0xFF, 0x9B, 0x1D, 0x9B, 0x66, 0x87, 0x91, 0xD4, 0xC3, 0x84, 0x5F, 0xBB, 0xC1,
            0x0C, 0x3E, 0xB7, 0xDA, 0x2A, 0xCD, 0x5F, 0x5A, 0xE7, 0x45, 0x71, 0x99, 0xCA, 0x62, 0x43, 0x07,
            0xD8, 0x9F, 0x9F, 0x36, 0xF6, 0x54, 0xBA, 0x84, 0x0F, 0xAB, 0xF8, 0x66, 0xDC, 0x84, 0xBA, 0x2B,
            0xC3, 0x49, 0x74, 0x7A, 0x19, 0x93, 0xC2, 0x0E, 0x88, 0xC5, 0x80, 0x4C, 0xE4, 0xB4, 0x85, 0xA8,
            0xF0, 0x08, 0x35, 0x0B, 0xDF, 0x68, 0x6A, 0xE0, 0x5F, 0x69, 0x7B, 0xAA, 0xA3, 0x41, 0x7F, 0xA4,
            0xBA, 0x77, 0x7C, 0xAD, 0x9F, 0xC2, 0x03, 0x00, 0xDE, 0x6C, 0x39, 0x19, 0x1C, 0xDA, 0xC7, 0x0A
        };
    }
}