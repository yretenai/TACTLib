using static TACTLib.Core.Product.Tank.CMFCryptHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [CMFMetadataAttribute(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_61542 : ICMFEncryptionProc {
        public byte[] Key(CMFHeader header, int length) {
            byte[] buffer = new byte[length];
            uint kidx = Keytable[SignedMod(length * Keytable[0], 512)];
            for (uint i = 0; i != length; ++i) {
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
            uint kidx, okidx;
            kidx = okidx = (uint) (2 * digest[5]);
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx += okidx % 29;
                buffer[i] ^= (byte)(digest[SignedMod(kidx + header.EntryCount, SHA1_DIGESTSIZE)] + 1);
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0xC4, 0x3E, 0x25, 0x41, 0x84, 0x5F, 0x19, 0x0D, 0xCC, 0x10, 0x44, 0x7D, 0xF8, 0xE3, 0x32, 0xAD,
            0x61, 0xBE, 0x0D, 0x9A, 0x3C, 0x3A, 0x1D, 0xFC, 0x2A, 0x92, 0x79, 0x1F, 0x7C, 0xA1, 0x84, 0xD1,
            0x55, 0x3E, 0xD8, 0xB0, 0xED, 0x0C, 0xF0, 0xEE, 0x50, 0x97, 0x78, 0x60, 0xFB, 0x0A, 0x80, 0x74,
            0xA6, 0xC0, 0xEA, 0x16, 0xA4, 0x07, 0xC5, 0x56, 0xCF, 0xD9, 0x7F, 0x66, 0x26, 0x45, 0x23, 0xA7,
            0x21, 0x70, 0x09, 0x77, 0x3A, 0x45, 0x4A, 0xE8, 0x53, 0xD8, 0x33, 0xFA, 0x80, 0x93, 0x78, 0xF0,
            0x1F, 0xCC, 0xCF, 0xF0, 0xF2, 0x39, 0xE5, 0x47, 0x33, 0x35, 0x92, 0x0B, 0x08, 0xA2, 0x6B, 0x92,
            0xC5, 0x8F, 0xDA, 0x7D, 0xF4, 0x85, 0xBD, 0xE4, 0xD0, 0xE1, 0xFD, 0x19, 0xFB, 0xFB, 0x7A, 0x56,
            0x01, 0xE7, 0xF1, 0x94, 0x32, 0xDD, 0x0E, 0x04, 0xF6, 0xDE, 0xCF, 0x11, 0xE5, 0x03, 0xAB, 0x45,
            0x57, 0xF8, 0x5B, 0xC2, 0xD8, 0xDA, 0x2A, 0x2A, 0xCB, 0x1A, 0x55, 0x1B, 0x6E, 0x7D, 0x0B, 0x0B,
            0x82, 0x38, 0x46, 0x0D, 0xBD, 0xC4, 0x3C, 0x2A, 0x14, 0xCE, 0x81, 0x38, 0xD1, 0x5E, 0x64, 0x75,
            0x7E, 0xDB, 0x31, 0x55, 0xD8, 0x6C, 0x98, 0x7E, 0x5D, 0x8E, 0x57, 0xA0, 0x95, 0xBE, 0x93, 0x9E,
            0x8E, 0x56, 0xA4, 0x80, 0xCF, 0x7C, 0x2E, 0x08, 0x19, 0xD7, 0x5C, 0x60, 0x7E, 0xA0, 0x58, 0x12,
            0xB1, 0xF5, 0x7A, 0xDD, 0xDE, 0x80, 0xCF, 0x54, 0xF2, 0x92, 0x60, 0x04, 0x68, 0x80, 0x9F, 0x00,
            0x2C, 0x26, 0x59, 0x65, 0x3D, 0x91, 0xE8, 0xC7, 0xF8, 0x41, 0xC3, 0x04, 0x98, 0xBE, 0x98, 0xF1,
            0xD7, 0x49, 0xEA, 0x56, 0x3D, 0xE1, 0xBA, 0xBD, 0xC5, 0x4C, 0xB7, 0x54, 0x08, 0x30, 0x17, 0xA0,
            0x57, 0xE5, 0xBB, 0xEB, 0x2C, 0xEC, 0x8F, 0xB1, 0xC0, 0xD3, 0x4E, 0x5F, 0xE1, 0x5C, 0xFB, 0xA9,
            0xB3, 0x3B, 0x4A, 0xE8, 0xE7, 0x83, 0x28, 0xDC, 0x78, 0x61, 0xA7, 0x30, 0x80, 0x94, 0x67, 0xC8,
            0x64, 0x43, 0x81, 0xB6, 0x2A, 0xF7, 0x1F, 0x7C, 0x28, 0xEF, 0x5D, 0xFA, 0x62, 0x3E, 0x42, 0x5B,
            0x9D, 0x05, 0x43, 0x77, 0x49, 0x94, 0x0B, 0x77, 0x80, 0xA7, 0x5F, 0x29, 0xE1, 0x6F, 0x5B, 0x40,
            0x72, 0xB3, 0xA2, 0x28, 0x46, 0x46, 0x09, 0xE7, 0xF3, 0xA8, 0x8D, 0x3B, 0xBC, 0x97, 0x4A, 0x7B,
            0xA2, 0xCF, 0xFA, 0x68, 0x59, 0x79, 0x7A, 0xFB, 0x5F, 0xB2, 0x6A, 0x8C, 0xD0, 0x74, 0x81, 0xA3,
            0x1C, 0x69, 0x25, 0xD9, 0x94, 0xD8, 0xB8, 0xB3, 0x97, 0x25, 0x3C, 0xA2, 0x09, 0x04, 0x4A, 0x35,
            0x85, 0xE5, 0x0C, 0xA4, 0xEB, 0xFD, 0x52, 0x0B, 0xD2, 0x7A, 0x01, 0x95, 0xA7, 0xA6, 0x18, 0x68,
            0x87, 0x1F, 0x21, 0x19, 0xA0, 0x0E, 0xA3, 0x93, 0xE7, 0xD7, 0x4E, 0xA9, 0xE4, 0xA5, 0x70, 0xBB,
            0x2F, 0xE6, 0xF5, 0x48, 0x07, 0x6D, 0xD1, 0x7B, 0x0F, 0xDA, 0xEF, 0x08, 0x25, 0x7C, 0x5E, 0xA5,
            0x16, 0x2D, 0x4B, 0x1E, 0xF5, 0xF8, 0x28, 0xCC, 0x8A, 0x8C, 0x74, 0xEF, 0xA0, 0x26, 0x47, 0xA4,
            0xEA, 0x1C, 0xA6, 0x60, 0x6D, 0xAE, 0x15, 0xAE, 0x7B, 0x12, 0x4D, 0x75, 0xE4, 0x5A, 0x42, 0x15,
            0x21, 0x8C, 0xDB, 0x81, 0x0B, 0xA2, 0x14, 0x6F, 0xB6, 0x0F, 0xB0, 0x0C, 0x21, 0x67, 0xE2, 0xA0,
            0x78, 0x31, 0x21, 0xE8, 0x8D, 0x45, 0x63, 0xE4, 0x59, 0x7B, 0x65, 0xD3, 0x64, 0xA2, 0x59, 0x9D,
            0xE8, 0x2A, 0xB2, 0x95, 0xB7, 0x36, 0xFC, 0xAB, 0x01, 0x71, 0xFB, 0xF2, 0xDA, 0x4D, 0x3B, 0x3B,
            0xB9, 0xE8, 0xE6, 0xD6, 0xB3, 0xB3, 0x80, 0x70, 0x04, 0x6B, 0x8D, 0xAF, 0x5D, 0xDA, 0xCB, 0xFC,
            0x77, 0x4C, 0x01, 0xD1, 0x6C, 0x21, 0x40, 0xBD, 0x20, 0x44, 0x69, 0x98, 0xA5, 0x95, 0xE0, 0x28
        };
    }
}
