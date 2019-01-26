// <TACT xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" HASH="7359AEF058CB7BB59171C1A71AADD6C259EBC0F8" NAME="TACTLib.ProCMF_45214.dll" xmlns="https://chomp.gg/types/tactheader" />
using static TACTLib.Core.Product.Tank.CMFCryptHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [CMFMetadata(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_45214 : ICMFEncryptionProc {
        public byte[] Key(CMFHeader header, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[length + 256];
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx += (uint)header.EntryCount;
            }

            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[SignedMod(2 * digest[13] - length, 512)];
            uint increment = header.BuildVersion * (uint)header.DataCount % 7;
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx += increment;
                buffer[i] ^= digest[SignedMod(kidx - 73, SHA1_DIGESTSIZE)];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0xF8, 0xB0, 0xF2, 0x21, 0x7D, 0xB9, 0x4A, 0x3F, 0x75, 0xE5, 0x11, 0x07, 0xA7, 0x94, 0xBF, 0x14, 
            0x7A, 0x8C, 0x07, 0x77, 0x6B, 0x40, 0x6E, 0x80, 0x8B, 0xAD, 0x28, 0xB2, 0x5B, 0x9A, 0x32, 0x9B, 
            0x97, 0x33, 0x37, 0x38, 0xAE, 0xDB, 0xAD, 0x68, 0xCB, 0xA0, 0xB9, 0x12, 0x82, 0x6D, 0x6A, 0x5E, 
            0xD5, 0xD1, 0xBA, 0xDF, 0x78, 0x80, 0x98, 0xCC, 0xC6, 0xEE, 0xCF, 0xCB, 0xBD, 0x7E, 0x0A, 0xE4, 
            0x63, 0x23, 0x09, 0x2E, 0x76, 0x33, 0x3A, 0x37, 0xDC, 0x6B, 0x86, 0x3A, 0x69, 0x87, 0x2B, 0x8D, 
            0x32, 0xBB, 0x89, 0xAC, 0x1F, 0xEC, 0x62, 0x4B, 0x83, 0xCD, 0xBA, 0x1F, 0x86, 0x1B, 0xAC, 0x25, 
            0x8B, 0x50, 0xD6, 0xDC, 0xE4, 0x77, 0xD2, 0x4F, 0xBA, 0x83, 0xDA, 0x1E, 0x7A, 0x6D, 0xE5, 0x67, 
            0xD2, 0x8F, 0xAE, 0x89, 0x26, 0x26, 0x00, 0x73, 0xA9, 0x57, 0x35, 0x47, 0xD7, 0x68, 0xF3, 0x00, 
            0x6B, 0xB0, 0x19, 0xDE, 0xB9, 0x2A, 0x2F, 0xF2, 0xA7, 0x52, 0x64, 0xC9, 0x65, 0x92, 0xEF, 0xB1, 
            0xDB, 0x43, 0xBE, 0x20, 0x9D, 0xC7, 0x68, 0x31, 0x06, 0x56, 0x5E, 0x24, 0x26, 0x64, 0x47, 0x03, 
            0x3D, 0xD4, 0xD1, 0x74, 0xA4, 0xF3, 0x30, 0x77, 0x89, 0xCB, 0xB4, 0x3E, 0x53, 0xD6, 0x39, 0x0A, 
            0xC2, 0xC2, 0xDD, 0xFE, 0x1A, 0x99, 0x3A, 0xAE, 0x87, 0x88, 0x7B, 0x3A, 0x8C, 0x91, 0xE8, 0x4F, 
            0xB6, 0x13, 0x39, 0xD8, 0xC9, 0x77, 0x4F, 0x62, 0x9B, 0xC7, 0xD8, 0x31, 0xF3, 0xDA, 0x9F, 0x03, 
            0x14, 0x14, 0xC2, 0xC0, 0x04, 0x45, 0x48, 0xEB, 0x86, 0xF8, 0xAB, 0x87, 0x04, 0xCB, 0x56, 0x90, 
            0xD1, 0x86, 0x7E, 0x12, 0xFE, 0x50, 0x08, 0x94, 0xD1, 0xD8, 0x3F, 0x31, 0xFA, 0xA2, 0xC8, 0x9A, 
            0x48, 0xCD, 0x99, 0xCA, 0xEC, 0x3B, 0x64, 0x98, 0x96, 0xC7, 0x9E, 0x66, 0xDA, 0x37, 0xE4, 0xDA, 
            0xC9, 0xA9, 0xF6, 0xC5, 0x86, 0xAB, 0xA7, 0x6E, 0x7D, 0x09, 0x95, 0x5D, 0xCE, 0x4C, 0x1D, 0x6E, 
            0x16, 0x44, 0x81, 0x41, 0x33, 0x1E, 0x0D, 0x8C, 0xDE, 0x8B, 0x04, 0xAE, 0x4E, 0xB9, 0x57, 0x42, 
            0x90, 0xF4, 0x92, 0x04, 0x85, 0x37, 0xF9, 0xF5, 0x9F, 0x5C, 0x54, 0xD8, 0xD1, 0x91, 0xEB, 0xD6, 
            0x29, 0x06, 0x44, 0x9C, 0x06, 0xC7, 0x80, 0xBF, 0x4F, 0x58, 0x95, 0xE9, 0xF8, 0x91, 0x6F, 0x8F, 
            0xA6, 0x46, 0xC8, 0x9B, 0xBE, 0xFE, 0x3F, 0x78, 0x5D, 0x71, 0x9F, 0xDB, 0x95, 0xFC, 0x65, 0x4C, 
            0x6C, 0x6F, 0x14, 0x49, 0x33, 0x79, 0x2C, 0x09, 0x5B, 0xBB, 0x45, 0x82, 0x70, 0x62, 0xEF, 0x9C, 
            0x34, 0xD6, 0xAE, 0x05, 0xAB, 0x62, 0x92, 0x6F, 0xCE, 0x16, 0x94, 0x87, 0xDA, 0x2B, 0xE9, 0x9F, 
            0xA2, 0xC8, 0x69, 0x60, 0x4C, 0x33, 0x52, 0x9F, 0xB6, 0xCF, 0xE7, 0x5F, 0x1F, 0xEB, 0x6F, 0x54, 
            0x26, 0xFA, 0xAF, 0xE4, 0xD6, 0x57, 0x39, 0x54, 0xE2, 0x02, 0x86, 0xEE, 0x75, 0x7A, 0xB8, 0xAA, 
            0x11, 0x45, 0xB7, 0xEB, 0x7E, 0x5C, 0xAC, 0x6A, 0x2C, 0xB8, 0xE3, 0x76, 0xE7, 0xB7, 0x09, 0x5B, 
            0xFE, 0x23, 0x44, 0x80, 0x78, 0xC2, 0xAB, 0x08, 0x3D, 0xFB, 0x18, 0x74, 0xD1, 0x3A, 0x8D, 0xBD, 
            0xD4, 0x0D, 0xE1, 0x9D, 0x51, 0x43, 0x28, 0x18, 0x4A, 0x8F, 0x75, 0x49, 0xC3, 0xA8, 0x43, 0xD9, 
            0xED, 0x46, 0x9B, 0x6F, 0xE7, 0x6F, 0x46, 0x42, 0xAA, 0xCE, 0xC7, 0xA1, 0x42, 0x98, 0xBA, 0x22, 
            0xEA, 0xC6, 0x08, 0xEC, 0x41, 0x2C, 0x4C, 0x07, 0x1C, 0x0A, 0xC5, 0x51, 0x75, 0x7C, 0xF1, 0x6B, 
            0xC9, 0x9E, 0xDD, 0xF8, 0x0F, 0x4F, 0x5C, 0xF2, 0x31, 0x10, 0xB9, 0x47, 0x86, 0x37, 0x5E, 0xDD, 
            0x6B, 0xE9, 0xB1, 0x11, 0xC4, 0x18, 0xE5, 0xC8, 0xC1, 0x2E, 0xA3, 0xB8, 0x79, 0x1E, 0x83, 0xA2
        };
    }
}
