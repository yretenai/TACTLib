// <TACT xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" HASH="2C0A99FAFEF5ED726BEDF3B3E3657B711D50728D" NAME="TACTLib.ProCMF_39935.dll" xmlns="https://chomp.gg/types/tactheader" />
using static TACTLib.Core.Product.Tank.CMFCryptHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [CMFMetadata(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_39935 : ICMFEncryptionProc {
        public byte[] Key(CMFHeader header, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[header.BuildVersion & 511];
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[kidx % 512];
                kidx += 3;
            }

            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length) {
            byte[] buffer = new byte[length];

            uint kidx = header.BuildVersion * (uint) length;
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[kidx % 512];
                switch (kidx % 3) {
                    case 0:
                        kidx += 103;
                        break;
                    case 1:
                        kidx = 4 * kidx % header.BuildVersion;
                        break;
                    case 2:
                        --kidx;
                        break;
                }

                buffer[i] ^= digest[(kidx + header.BuildVersion) % SHA1_DIGESTSIZE];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0xC0, 0x06, 0x97, 0xFF, 0x53, 0xCA, 0x73, 0xCA, 0x7C, 0x83, 0xFB, 0x72, 0x4D, 0x5E, 0xEA, 0x0B,
            0x11, 0x0A, 0x3A, 0x25, 0x24, 0x24, 0x0C, 0xFF, 0x02, 0x8D, 0xAF, 0x24, 0x41, 0x0B, 0xAB, 0x30,
            0xC4, 0xD2, 0xCA, 0x86, 0x49, 0xEB, 0xD9, 0x80, 0x87, 0xCC, 0x5F, 0xAD, 0x80, 0x3A, 0x36, 0xED,
            0x73, 0x29, 0x5F, 0x96, 0x03, 0x0A, 0xCC, 0xD6, 0x30, 0x87, 0xEE, 0x91, 0x26, 0x10, 0x2B, 0xC2,
            0xE3, 0x64, 0x92, 0x30, 0x0F, 0xD1, 0xFD, 0x31, 0x57, 0x64, 0x43, 0xC4, 0xEF, 0x5A, 0x94, 0x1E,
            0xC3, 0x83, 0x87, 0x73, 0x8C, 0x40, 0x6E, 0xC7, 0x00, 0x67, 0x78, 0xC6, 0x35, 0x9F, 0xA4, 0xF7,
            0xA5, 0xD6, 0xB9, 0x4F, 0x86, 0x1D, 0x76, 0xCF, 0xB5, 0x59, 0xE7, 0xCF, 0x04, 0xC7, 0x4B, 0x96,
            0x25, 0x17, 0x2B, 0xD2, 0xE5, 0xEC, 0x94, 0x5E, 0x3E, 0x3A, 0xA9, 0x07, 0x70, 0x5A, 0x5C, 0x31,
            0xD2, 0xEF, 0x0B, 0xFC, 0x48, 0x6A, 0x96, 0x59, 0xB0, 0xB3, 0x91, 0xCB, 0x03, 0xD3, 0x67, 0x31,
            0x37, 0x77, 0x9A, 0x75, 0xD4, 0x1D, 0x91, 0x52, 0xBC, 0xF2, 0xA1, 0xD8, 0x9A, 0x7B, 0x88, 0xE7,
            0x64, 0xA1, 0x77, 0x37, 0x35, 0x3C, 0x94, 0x53, 0x1B, 0x99, 0xC8, 0xD4, 0x49, 0x1D, 0x00, 0xF9,
            0x78, 0xDB, 0xEA, 0x62, 0x0F, 0x96, 0x61, 0xD6, 0xE4, 0x94, 0xA7, 0x2B, 0x9B, 0x8F, 0x8C, 0x42,
            0xE2, 0xA7, 0xED, 0xA2, 0x26, 0x0D, 0x1A, 0x30, 0xB3, 0x68, 0x1A, 0x7E, 0xCF, 0x04, 0xB1, 0xC6,
            0x93, 0xD3, 0x8C, 0x00, 0x25, 0x47, 0x92, 0x38, 0xD1, 0x05, 0x7B, 0x56, 0xC9, 0x7D, 0xEA, 0x5D,
            0x13, 0xF5, 0x11, 0xA9, 0x8C, 0x00, 0x61, 0xFD, 0xBE, 0x66, 0x0E, 0x60, 0x06, 0xD5, 0x7F, 0x76,
            0xEF, 0xA6, 0x99, 0xB3, 0x8D, 0x69, 0x4D, 0xD9, 0x50, 0xBC, 0x81, 0x35, 0x38, 0x65, 0x3D, 0x51,
            0xA6, 0x71, 0xBB, 0x91, 0x0B, 0xD7, 0xC4, 0xF6, 0xC5, 0xA8, 0x83, 0xAC, 0xD0, 0x7B, 0xE4, 0x72,
            0xC1, 0xE2, 0xF4, 0x79, 0x13, 0x67, 0x0C, 0xFA, 0x6E, 0xE9, 0x7D, 0xC4, 0x43, 0xD3, 0xAB, 0x85,
            0xCA, 0xBB, 0xC6, 0xDA, 0x18, 0x62, 0xD0, 0x5F, 0x82, 0x18, 0x74, 0xD6, 0xD5, 0xF3, 0xD6, 0x0D,
            0x9F, 0x0D, 0xF2, 0x89, 0x5B, 0x12, 0x9A, 0xFB, 0xB4, 0x05, 0x4E, 0xBA, 0x1C, 0xBE, 0x02, 0x1C,
            0x60, 0x5B, 0x8F, 0xF2, 0xD1, 0x5E, 0x3F, 0x6E, 0xAA, 0xD1, 0x28, 0x7A, 0x9C, 0xFF, 0xE1, 0x40,
            0x6D, 0xCF, 0x29, 0x04, 0x7E, 0x2C, 0xD5, 0x4C, 0x60, 0xBD, 0xEE, 0x4E, 0xE7, 0x03, 0x7F, 0x4B,
            0x03, 0x29, 0xA9, 0x0F, 0xEE, 0xE1, 0x69, 0x9D, 0x24, 0x28, 0x01, 0xFB, 0x27, 0x6E, 0x4E, 0x1D,
            0x2E, 0xCB, 0x2C, 0xD6, 0xF7, 0xF6, 0xA3, 0xD0, 0x0D, 0xE3, 0xCF, 0xF4, 0xA4, 0x78, 0xAA, 0x98,
            0x92, 0x9C, 0xE9, 0xE7, 0x72, 0x45, 0xFF, 0xC8, 0x91, 0xA8, 0x65, 0xCD, 0xBB, 0xDA, 0x8A, 0xAC,
            0x39, 0x24, 0x07, 0x51, 0xA9, 0xAD, 0x56, 0xB0, 0xBE, 0x00, 0x6D, 0x06, 0xF8, 0x12, 0xCD, 0x66,
            0xBF, 0x47, 0xF0, 0x48, 0xAE, 0xD9, 0x1A, 0xA2, 0x28, 0x87, 0x64, 0xF5, 0xAE, 0x1D, 0x45, 0x71,
            0x08, 0x9F, 0x22, 0x02, 0xB9, 0xE4, 0xA5, 0xB3, 0x53, 0x5B, 0xF7, 0x24, 0xEE, 0x8F, 0xD6, 0xC9,
            0x4F, 0x72, 0x8D, 0x98, 0xAC, 0x62, 0x14, 0xD9, 0xFA, 0xDC, 0xB1, 0xA8, 0x67, 0xBA, 0x0C, 0xEC,
            0x24, 0xAA, 0x01, 0x12, 0xD8, 0xD1, 0x51, 0x3C, 0x12, 0xB5, 0xAD, 0x89, 0xB6, 0x0B, 0xEE, 0xC6,
            0x46, 0x3F, 0xE1, 0xF6, 0xF9, 0x0E, 0xE9, 0x84, 0xD2, 0xB6, 0xBB, 0x3F, 0x45, 0xB5, 0xCF, 0x3C,
            0x38, 0x08, 0xA6, 0xFD, 0x24, 0x55, 0x02, 0xF4, 0xA5, 0xE1, 0x3E, 0x2E, 0x50, 0x01, 0x95, 0xDA
        };
    }
}
