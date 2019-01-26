// <TACT xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" HASH="D7CA5233BF9E74CDF4C189C599B27C64F89E4109" NAME="TACTLib.ProCMF_37755.dll" xmlns="https://chomp.gg/types/tactheader" />
using static TACTLib.Core.Product.Tank.CMFCryptHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [CMFMetadata(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_37755 : ICMFEncryptionProc {
        public byte[] Key(CMFHeader header, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[header.BuildVersion & 511];
            uint increment = header.BuildVersion * (uint)header.DataCount % 7;
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[kidx % 512];
                kidx += increment;
            }

            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[(Keytable[0] * digest[7]) & 511];
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[kidx % 512];
                kidx = header.BuildVersion - kidx;
                buffer[i] ^= digest[(kidx + i) % SHA1_DIGESTSIZE];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0xB1, 0x57, 0x67, 0x57, 0xE4, 0x29, 0x3D, 0x85, 0x7C, 0x8B, 0x71, 0x02, 0x05, 0x82, 0x5B, 0xD9,
            0xE5, 0xB5, 0x12, 0x73, 0x58, 0x2A, 0xD6, 0xAB, 0x7B, 0x81, 0x22, 0x4C, 0x97, 0x0B, 0x1C, 0x31,
            0xFA, 0xC4, 0xB6, 0xE7, 0x25, 0x3C, 0x3D, 0x7A, 0x59, 0xBC, 0x48, 0xF5, 0x5C, 0xA2, 0xD8, 0x9A,
            0xDB, 0x09, 0xE4, 0x8D, 0xFA, 0xA8, 0xC7, 0x9F, 0x96, 0x40, 0x9E, 0x93, 0x87, 0x5A, 0xA1, 0x23,
            0xE2, 0xC0, 0x06, 0x13, 0x94, 0xE8, 0x5C, 0x92, 0x54, 0x99, 0x68, 0xD8, 0x32, 0xBD, 0x07, 0xA2,
            0xD9, 0x4E, 0xCB, 0x0B, 0xE5, 0xF0, 0xBF, 0x79, 0x19, 0x33, 0x9B, 0x2E, 0xEA, 0x31, 0x5C, 0xA0,
            0xA0, 0x9E, 0x67, 0x28, 0xB0, 0x6E, 0x8F, 0x42, 0x95, 0x08, 0xCB, 0xD4, 0x57, 0x69, 0x0D, 0x88,
            0x2F, 0x24, 0x27, 0xA9, 0x61, 0x02, 0x00, 0x43, 0x82, 0x7F, 0x15, 0x67, 0x08, 0x06, 0x74, 0x68,
            0x75, 0x86, 0x45, 0xD9, 0x90, 0x08, 0x54, 0x81, 0x9E, 0x8F, 0x28, 0x5D, 0x90, 0x43, 0xD9, 0xD9,
            0x45, 0x5E, 0xC1, 0xCF, 0xA7, 0x17, 0x3B, 0x37, 0x8E, 0x7F, 0x9E, 0x8B, 0xB7, 0x6F, 0x83, 0x11,
            0x00, 0x45, 0xBF, 0x4E, 0xD5, 0xE7, 0x73, 0xF2, 0x00, 0xDA, 0xBE, 0x56, 0x52, 0x5E, 0x1C, 0x28,
            0x4F, 0x7D, 0x7C, 0x0F, 0xC5, 0x30, 0xAB, 0x80, 0x38, 0x54, 0x10, 0x00, 0xE2, 0x8C, 0x88, 0x91,
            0x12, 0x8B, 0x36, 0x05, 0x6E, 0xAC, 0x66, 0x0B, 0x9F, 0x36, 0x61, 0x49, 0xEC, 0x11, 0x8B, 0xE0,
            0x98, 0xA6, 0x0E, 0xB0, 0x11, 0xF0, 0x9A, 0x20, 0xB7, 0xA2, 0xFA, 0xED, 0xA4, 0xB1, 0xD3, 0x54,
            0xCF, 0xF4, 0x87, 0x75, 0x5A, 0x65, 0x14, 0xA8, 0x45, 0xC8, 0xA3, 0xC4, 0x8B, 0x72, 0xEE, 0xBB,
            0xA6, 0xF7, 0xBD, 0x9B, 0x8A, 0x65, 0x5A, 0x9A, 0xD9, 0x14, 0xAF, 0x0D, 0x88, 0xB0, 0xFE, 0x58,
            0x3D, 0x46, 0xA7, 0xD3, 0x2D, 0xF6, 0xD8, 0xE3, 0xAB, 0xC0, 0x8B, 0x04, 0x33, 0x70, 0x7D, 0x47,
            0x5A, 0x00, 0x43, 0xD4, 0xE1, 0x23, 0xDB, 0x8A, 0x42, 0xAB, 0x7D, 0x9D, 0x93, 0x9C, 0xC3, 0xAE,
            0xF1, 0x43, 0x94, 0x68, 0x9A, 0xA1, 0xC1, 0x31, 0x48, 0xA5, 0xD1, 0x37, 0x13, 0xEB, 0x9D, 0xBD,
            0xD1, 0x3C, 0xAD, 0x9F, 0xCA, 0x9E, 0x84, 0x21, 0xD9, 0x44, 0x08, 0x16, 0x91, 0xB5, 0x22, 0x79,
            0x82, 0x17, 0xA8, 0xC2, 0xC3, 0x2C, 0xEA, 0x08, 0x38, 0x17, 0x04, 0xE2, 0x0C, 0x4E, 0x94, 0xD2,
            0x10, 0x6F, 0x31, 0xFF, 0xB1, 0xFA, 0xC7, 0xEB, 0x76, 0xBB, 0x08, 0xCC, 0x0F, 0xFC, 0x7F, 0xFE,
            0x36, 0x37, 0x79, 0x04, 0x66, 0x73, 0xD0, 0x25, 0x64, 0x8A, 0xB3, 0x72, 0xA4, 0x19, 0x59, 0xDF,
            0x60, 0x4D, 0x22, 0x88, 0x02, 0x94, 0x03, 0x9E, 0xEC, 0xAE, 0x7E, 0x59, 0x9E, 0xA7, 0x7F, 0xFC,
            0xB4, 0xB2, 0xDA, 0xAC, 0x03, 0xE6, 0x5B, 0x67, 0x9B, 0x8B, 0x88, 0x5B, 0xAE, 0xF8, 0xBB, 0xC9,
            0x98, 0xF9, 0xF2, 0xE0, 0xF5, 0x76, 0x1A, 0x08, 0xD3, 0xBD, 0x91, 0x4B, 0xC6, 0x3E, 0x01, 0x6A,
            0xCF, 0x67, 0x1B, 0x8E, 0x91, 0xA9, 0xFD, 0x41, 0xA6, 0xFA, 0x4E, 0xC8, 0xE8, 0xE6, 0xC4, 0xE3,
            0xAA, 0x74, 0xCE, 0x23, 0xBA, 0x1F, 0xB4, 0xB5, 0x20, 0x35, 0x04, 0x8D, 0xA8, 0x1F, 0xD0, 0x86,
            0x70, 0xFF, 0xC5, 0x4A, 0xC1, 0x1E, 0x8E, 0x34, 0xE6, 0x3F, 0xEE, 0xF2, 0x60, 0x37, 0xB4, 0x2D,
            0xF2, 0x4F, 0x81, 0x82, 0xFD, 0x46, 0x9A, 0x6B, 0x65, 0xAE, 0xB0, 0xAB, 0x6C, 0x05, 0x47, 0x1D,
            0x2D, 0x51, 0x3A, 0x2A, 0x5D, 0xB6, 0x61, 0xFF, 0xDD, 0xFD, 0x8D, 0x3B, 0x82, 0xD5, 0x45, 0xB5,
            0x8D, 0x0C, 0xCE, 0xC2, 0xE3, 0x12, 0x20, 0xFF, 0x34, 0x28, 0x2D, 0x43, 0x44, 0x5D, 0x06, 0xB7
        };
    }
}
