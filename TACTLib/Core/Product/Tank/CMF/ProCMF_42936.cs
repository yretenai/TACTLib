// <TACT xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" HASH="01F879ECA68F6A07F7F6114605CB8C37CF48F7B7" NAME="TACTLib.ProCMF_42936.dll" xmlns="https://chomp.gg/types/tactheader" />
using static TACTLib.Core.Product.Tank.CMFCryptHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [CMFMetadata(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_42936 : ICMFEncryptionProc {
        public byte[] Key(CMFHeader header, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[header.DataCount & 511];
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                switch (SignedMod(kidx, 3)) {
                    case 0:
                        kidx += 103;
                        break;
                    case 1:
                        kidx = (uint) SignedMod(kidx * 4, header.BuildVersion);
                        break;
                    case 2:
                        --kidx;
                        break;
                }
            }

            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length) {
            byte[] buffer = new byte[length];
            uint kidx = (uint) (2 * digest[5]);
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx = header.BuildVersion - kidx;
                buffer[i] ^= digest[SignedMod(kidx + i, SHA1_DIGESTSIZE)];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0x76, 0x1C, 0xE5, 0x6F, 0x6A, 0x38, 0x33, 0x54, 0xF8, 0xF6, 0x78, 0xB6, 0x1F, 0x5F, 0xC9, 0x30,
            0x82, 0x90, 0x84, 0xFB, 0xFD, 0x54, 0x13, 0x20, 0x0A, 0x9F, 0x9B, 0x61, 0xB5, 0xE4, 0x89, 0x65,
            0x9C, 0x46, 0xF0, 0x75, 0x93, 0xC1, 0xC9, 0x63, 0x18, 0x04, 0xB1, 0x4C, 0x45, 0xF8, 0x1D, 0xCD,
            0xC6, 0xCE, 0x22, 0x24, 0xC9, 0x9C, 0x4F, 0x3E, 0x9A, 0x22, 0xF8, 0xCF, 0xD3, 0xA6, 0x16, 0xC5,
            0x72, 0x8D, 0x05, 0x02, 0x14, 0x2D, 0x04, 0x50, 0x41, 0xE1, 0x41, 0x5F, 0x57, 0x88, 0xEF, 0xA8,
            0x37, 0x06, 0xA6, 0x66, 0xD7, 0x89, 0xD5, 0x4A, 0xAE, 0x49, 0x16, 0x4A, 0xE9, 0x20, 0x05, 0x85,
            0xA8, 0xE8, 0x11, 0x22, 0x6D, 0x7D, 0x04, 0xDD, 0xCD, 0x6C, 0xBD, 0x02, 0xBB, 0xF2, 0x74, 0xB8,
            0xFF, 0x41, 0x14, 0x98, 0xE9, 0x39, 0x2B, 0x75, 0xF2, 0x9F, 0x36, 0xF0, 0xD5, 0xAB, 0x05, 0x89,
            0x39, 0x0F, 0x28, 0x6B, 0x68, 0x79, 0x09, 0xC8, 0x58, 0xC9, 0xA3, 0xAE, 0xDA, 0x18, 0xA9, 0x37,
            0xB9, 0x46, 0x71, 0x8A, 0x79, 0xBC, 0xC7, 0xD0, 0xA2, 0x31, 0xD7, 0x1F, 0x2F, 0x2D, 0x8C, 0xC0,
            0x6E, 0x08, 0xBC, 0xAE, 0x5C, 0x6A, 0xB8, 0xA3, 0x63, 0x6A, 0xE8, 0x17, 0xE7, 0x77, 0x5C, 0x28,
            0x77, 0x14, 0x89, 0xFE, 0x41, 0xA2, 0x9F, 0xB2, 0x0D, 0x5E, 0x61, 0x4D, 0x70, 0x70, 0x18, 0x04,
            0x68, 0xC5, 0x6C, 0x88, 0xF8, 0x2C, 0xEB, 0xDD, 0x9F, 0x96, 0xE6, 0x1F, 0x2B, 0xD0, 0xC6, 0x73,
            0x80, 0x5E, 0x27, 0xE9, 0x01, 0xDB, 0x3E, 0xD5, 0x4B, 0xA1, 0x1C, 0x48, 0xBC, 0x0A, 0x73, 0x66,
            0x9F, 0x75, 0x87, 0x55, 0x85, 0xF4, 0x2F, 0x62, 0xF2, 0x4C, 0xA1, 0x23, 0x21, 0x83, 0xAD, 0xF5,
            0x3E, 0x4E, 0xE7, 0x34, 0xAB, 0x7D, 0x31, 0xAA, 0x57, 0xCB, 0x43, 0x5E, 0x12, 0x48, 0xAD, 0x08,
            0x6B, 0x01, 0xBE, 0x04, 0x7D, 0x64, 0x09, 0x30, 0x33, 0x2A, 0x60, 0xE8, 0xEA, 0x08, 0x05, 0x31,
            0xC2, 0xF5, 0xAF, 0xCA, 0x20, 0xFE, 0x6F, 0x77, 0x4F, 0x1C, 0x65, 0x3B, 0x42, 0xE4, 0x6F, 0x29,
            0xFF, 0xAE, 0xA7, 0x7E, 0xD8, 0xA5, 0xB7, 0x3A, 0x4D, 0x83, 0x0D, 0x64, 0xF1, 0x5D, 0x8A, 0x45,
            0x6C, 0xF7, 0xF4, 0x47, 0xBF, 0xEC, 0x0A, 0x59, 0xB9, 0x59, 0x70, 0x46, 0x5E, 0x9D, 0x2C, 0xD0,
            0x11, 0x44, 0xCC, 0xAA, 0x10, 0x57, 0xAF, 0xFB, 0x2E, 0xD3, 0x4D, 0x89, 0x86, 0x1C, 0xE9, 0x88,
            0x01, 0x59, 0x05, 0xF2, 0xA9, 0x25, 0xEE, 0x23, 0x0A, 0x6E, 0xC9, 0x41, 0x2F, 0x17, 0x72, 0xBB,
            0xAE, 0xA5, 0x02, 0xFD, 0x7B, 0x70, 0x93, 0x76, 0x3D, 0xE4, 0xCF, 0xCC, 0xC0, 0x35, 0x72, 0x71,
            0x33, 0x83, 0x5D, 0xAA, 0x21, 0xA3, 0xB8, 0x50, 0x06, 0xF7, 0xF3, 0xE9, 0xB8, 0x40, 0x87, 0x29,
            0x98, 0xE9, 0x22, 0xF9, 0xAA, 0x6E, 0xFF, 0xA0, 0x1E, 0xD3, 0x5D, 0xD8, 0xF1, 0x29, 0xCE, 0x81,
            0x92, 0x04, 0x48, 0xD8, 0x67, 0xF3, 0x6D, 0x06, 0x98, 0xED, 0x7C, 0xB6, 0x5A, 0xCE, 0x6F, 0x78,
            0x61, 0xA8, 0x5D, 0x4B, 0xF0, 0xA7, 0x1D, 0x74, 0xD1, 0x6F, 0x1D, 0xAB, 0x76, 0xF4, 0x26, 0xAD,
            0xBC, 0x97, 0xE4, 0xDA, 0xD8, 0xC6, 0x91, 0x98, 0x85, 0xAC, 0x61, 0x8C, 0x3F, 0xC8, 0x29, 0xBE,
            0x49, 0xE3, 0x90, 0xB3, 0xEB, 0x39, 0x2D, 0x0A, 0xD8, 0xB0, 0xF6, 0x35, 0x74, 0x03, 0x2B, 0x9B,
            0x4A, 0x82, 0xF2, 0xAD, 0xC3, 0xB2, 0x7A, 0x4C, 0x70, 0x78, 0xCA, 0xCE, 0xC9, 0x78, 0xA8, 0x8E,
            0x56, 0x93, 0x3B, 0x33, 0xD4, 0x59, 0xA6, 0xB4, 0x59, 0xBF, 0xC0, 0x8E, 0x32, 0xB5, 0x9A, 0x17,
            0x02, 0x2E, 0xDF, 0xE1, 0x65, 0x1E, 0xA0, 0xD7, 0xAC, 0xCE, 0x63, 0x70, 0x22, 0x33, 0xE3, 0x96
        };
    }
}
