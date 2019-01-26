// <TACT xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" HASH="9EBA4BDDFF8947645601752D82856022CEA7F83F" NAME="TACTLib.ProCMF_37104.dll" xmlns="https://chomp.gg/types/tactheader" />
using static TACTLib.Core.Product.Tank.CMFCryptHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [CMFMetadata(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_37104 : ICMFEncryptionProc {
        public byte[] Key(CMFHeader header, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[length + 256];
            uint increment = header.BuildVersion * (uint)header.DataCount % 7;
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[kidx % 512];
                kidx += increment;
            }

            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[(13 * digest[7]) & 511];
            for (int i = 0; i != length; ++i) {
                kidx += (uint)header.EntryCount + digest[header.EntryCount % SHA1_DIGESTSIZE];
                buffer[i] = digest[kidx % SHA1_DIGESTSIZE];
            }

            return buffer;
        }
        
        private static readonly byte[] Keytable = {
            0x0D, 0x95, 0x08, 0x0B, 0xF3, 0x80, 0xE1, 0x2E, 0x04, 0x0B, 0xF9, 0x1A, 0x5B, 0x5E, 0xF5, 0x60, 
            0xB3, 0xC6, 0x2F, 0x91, 0x8F, 0x3B, 0xED, 0x2B, 0x3D, 0xE5, 0xB2, 0x06, 0x76, 0x38, 0x7E, 0xAB, 
            0xDF, 0x70, 0x95, 0x3A, 0x6D, 0xE5, 0x13, 0x18, 0x3D, 0x54, 0x2B, 0x13, 0x2C, 0x4F, 0x62, 0x1B, 
            0x92, 0x5F, 0xDB, 0xC3, 0xF1, 0xA5, 0x21, 0xAC, 0x75, 0x6C, 0xE2, 0x92, 0x38, 0x3A, 0x5A, 0x8C, 
            0xFE, 0x40, 0xD1, 0xAB, 0x82, 0x4D, 0xF2, 0x00, 0x5D, 0x0C, 0xD1, 0xB8, 0x76, 0x53, 0x0E, 0xAF,
            0x90, 0xD5, 0x05, 0x66, 0x93, 0xF1, 0x0D, 0x5F, 0xFA, 0x93, 0x45, 0x27, 0x5F, 0xEF, 0x47, 0x66, 
            0x5F, 0x8D, 0xCA, 0x51, 0x38, 0x15, 0xC7, 0x79, 0x51, 0x80, 0x63, 0x2D, 0xDF, 0x68, 0x23, 0x1C, 
            0xEC, 0x3E, 0x37, 0xDE, 0x76, 0xB2, 0x5A, 0x8C, 0x12, 0x59, 0xFD, 0x13, 0x11, 0x20, 0x9D, 0xB9, 
            0x24, 0x67, 0xEF, 0x50, 0x12, 0x10, 0xCE, 0xE3, 0x17, 0x8A, 0xCB, 0x0D, 0xCF, 0xFA, 0x39, 0x79, 
            0xAC, 0x70, 0xE5, 0x04, 0xCA, 0xF9, 0x28, 0x30, 0x24, 0x78, 0x2F, 0x3F, 0x29, 0x96, 0x72, 0x8C, 
            0xDE, 0x1E, 0xDD, 0x10, 0x6E, 0x95, 0x9C, 0x39, 0x29, 0xF9, 0x44, 0x48, 0xFF, 0xF3, 0x0D, 0xD3, 
            0x8D, 0x20, 0x7D, 0x42, 0x2D, 0x6E, 0x31, 0x9F, 0xCA, 0xA6, 0xC2, 0x33, 0xEC, 0x31, 0xB6, 0x37, 
            0x4D, 0x1F, 0xA4, 0x3C, 0x1A, 0x90, 0xEE, 0xE5, 0x9C, 0xE9, 0x5B, 0xEF, 0x55, 0x2D, 0xE4, 0x9C, 
            0x9E, 0x38, 0x77, 0x57, 0x0D, 0x16, 0x20, 0x46, 0x57, 0xA6, 0x04, 0x4E, 0xE5, 0xB3, 0x09, 0x07,
            0x91, 0xD9, 0xAB, 0xB0, 0x8F, 0x81, 0x18, 0xAA, 0x9E, 0xBE, 0xE4, 0xBC, 0x68, 0xDD, 0xFD, 0x85, 
            0x6A, 0x1A, 0x31, 0x6C, 0x60, 0xEF, 0xE7, 0xBB, 0xE5, 0xEB, 0x57, 0x29, 0xF2, 0x38, 0x65, 0xF4, 
            0x0E, 0x9C, 0xBD, 0x55, 0x10, 0xD3, 0x86, 0x04, 0xDF, 0xE0, 0x22, 0x27, 0x09, 0x41, 0xBB, 0x3B, 
            0xF7, 0x46, 0xD9, 0x7A, 0xBE, 0x0D, 0xC3, 0x75, 0x77, 0xCA, 0x23, 0x90, 0xAA, 0xF2, 0x16, 0xC3, 
            0x2D, 0x75, 0xC9, 0x39, 0xC0, 0x06, 0x78, 0xDD, 0x91, 0xD7, 0x1A, 0xF0, 0x97, 0xE3, 0x9E, 0x12, 
            0xA5, 0xB8, 0xDE, 0xF6, 0x8E, 0x5A, 0x16, 0x01, 0xB0, 0xA9, 0x39, 0x05, 0xFB, 0x6C, 0xD5, 0x93, 
            0xBC, 0x86, 0x81, 0x3E, 0x15, 0x53, 0xD4, 0x88, 0xB6, 0x5A, 0xF2, 0x68, 0xD6, 0x80, 0x11, 0xC8, 
            0x71, 0xC5, 0xE5, 0xCA, 0x56, 0x83, 0xE1, 0x92, 0x86, 0x36, 0xFF, 0x40, 0x34, 0x58, 0xAD, 0xC7,
            0xBE, 0x6C, 0x20, 0x0A, 0x72, 0x64, 0xE5, 0xD7, 0xF6, 0xB7, 0x7F, 0x8F, 0xA8, 0xB4, 0xBC, 0x27, 
            0xC2, 0x6B, 0x25, 0xD4, 0xF6, 0x20, 0xBC, 0xA9, 0xB3, 0x44, 0x07, 0xFB, 0xFF, 0xA3, 0xDA, 0x75, 
            0x65, 0x05, 0x8E, 0x71, 0x10, 0xAD, 0xAD, 0x27, 0x87, 0xCE, 0xFE, 0xDC, 0xD8, 0xBD, 0x74, 0xBF, 
            0x43, 0x99, 0x15, 0x26, 0x8E, 0xAD, 0x50, 0x43, 0x9B, 0xB8, 0x2F, 0x66, 0x4B, 0x38, 0xC4, 0x44,
            0x71, 0xBD, 0x84, 0x8A, 0xC3, 0x22, 0x0D, 0x2E, 0xEC, 0x35, 0x5F, 0x61, 0xEF, 0x63, 0x7C, 0xBD, 
            0xED, 0xEF, 0x37, 0xA8, 0x31, 0xAC, 0xBC, 0xB0, 0x0C, 0xAC, 0x52, 0xA4, 0x6D, 0xE3, 0x84, 0x43, 
            0x3C, 0xF6, 0x8E, 0xC0, 0x57, 0x4E, 0xC9, 0x88, 0xAC, 0x71, 0x36, 0x7C, 0x8B, 0x81, 0x46, 0xE0, 
            0xC0, 0x49, 0xE5, 0x00, 0x6A, 0x86, 0xD3, 0x44, 0x10, 0x68, 0x69, 0x92, 0x48, 0xFB, 0x2A, 0x46, 
            0x96, 0x41, 0x89, 0xF0, 0xCE, 0x5D, 0x0A, 0x80, 0xA5, 0x34, 0x80, 0xDB, 0x82, 0xC1, 0x92, 0x8C,
            0x0C, 0x59, 0x15, 0x6C, 0x17, 0xF0, 0x58, 0x56, 0x08, 0x53, 0xE5, 0xCE, 0x2A, 0xB8, 0x3C, 0x28
        };
    }
}
