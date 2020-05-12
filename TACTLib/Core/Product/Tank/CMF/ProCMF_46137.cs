﻿using static TACTLib.Core.Product.Tank.ManifestCryptoHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [ManifestCrypto(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_46137 : ICMFEncryptionProc {
        public byte[] Key(CMFHeader header, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[SignedMod(length * Keytable[0], 512)];
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx += 3;
            }

            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length) {
            byte[] buffer = new byte[length];

            uint kidx = (uint)length * header.m_buildVersion;
            for (int i = 0; i != length; ++i) {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx = header.m_buildVersion - kidx;
                buffer[i] ^= digest[SignedMod(i + kidx, SHA1_DIGESTSIZE)];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0x39, 0x5D, 0xF5, 0x1F, 0x14, 0xB2, 0x36, 0x17, 0x42, 0x84, 0x04, 0xCB, 0xAE, 0xC6, 0xCE, 0xC5, 
            0x82, 0xD3, 0xAF, 0x97, 0x5D, 0xF2, 0x8E, 0x6E, 0xDA, 0x1C, 0x86, 0x66, 0xDE, 0x78, 0xA2, 0xFF, 
            0xD4, 0xBD, 0x4B, 0xCA, 0x39, 0x48, 0xD9, 0x4B, 0xCA, 0x1E, 0xDB, 0xF9, 0x87, 0xB3, 0xB1, 0x4F, 
            0x56, 0x6B, 0x46, 0xFE, 0xD4, 0xF6, 0x5C, 0xEC, 0x03, 0x4A, 0xE2, 0x1D, 0xB4, 0xFA, 0x63, 0x22, 
            0x4D, 0x3C, 0xB7, 0x2C, 0xCA, 0xF3, 0x79, 0xF9, 0x93, 0x92, 0xBA, 0x89, 0x0E, 0x0F, 0x98, 0x49, 
            0x7A, 0xC6, 0xE0, 0x96, 0x0A, 0xAC, 0x3B, 0xFD, 0x6E, 0x4E, 0xC2, 0x36, 0x1C, 0xA0, 0x4B, 0x18, 
            0x9C, 0x74, 0x46, 0x01, 0xCE, 0x75, 0x5F, 0x34, 0xB0, 0x26, 0x61, 0x47, 0xF9, 0xAC, 0xA0, 0xEA, 
            0x0D, 0x36, 0x8F, 0x34, 0xA0, 0x06, 0x51, 0x26, 0xA8, 0x74, 0x7E, 0x92, 0xAC, 0x32, 0x27, 0x8C, 
            0xE5, 0x41, 0xC8, 0x8F, 0xF2, 0x84, 0x13, 0x91, 0x36, 0x41, 0x3A, 0x2C, 0x24, 0x1E, 0xF0, 0x94, 
            0xED, 0xD4, 0xC0, 0xBC, 0x1E, 0x6D, 0x1E, 0x82, 0xB1, 0x57, 0x5C, 0xFA, 0x0B, 0x69, 0xDF, 0xCE, 
            0xA4, 0xC0, 0x9E, 0x73, 0x2C, 0xB9, 0xCA, 0xAD, 0x05, 0x3C, 0x9A, 0xFA, 0x23, 0xC1, 0xAB, 0xE2, 
            0xF2, 0xF3, 0xAE, 0x1C, 0xF6, 0x6E, 0xD3, 0x79, 0x35, 0x58, 0xA6, 0xF2, 0xC4, 0x1B, 0x57, 0x49, 
            0x2E, 0xBE, 0x97, 0x74, 0x0B, 0xB4, 0x66, 0x76, 0x4C, 0xAA, 0xD4, 0x69, 0x01, 0x28, 0x72, 0xA3, 
            0x40, 0xB8, 0x9A, 0x85, 0x4A, 0xAD, 0x6C, 0xEC, 0xBA, 0x81, 0x20, 0x7D, 0x2D, 0xB4, 0x49, 0xF4, 
            0xDE, 0xCA, 0x56, 0x19, 0xD6, 0xFF, 0x4E, 0x79, 0xF0, 0xDB, 0x2A, 0xFD, 0xB6, 0x11, 0xDC, 0x51, 
            0xB4, 0x55, 0x8C, 0xAD, 0xDC, 0xFD, 0xDA, 0x64, 0x64, 0xE2, 0x7D, 0x7E, 0xD2, 0x05, 0xE0, 0xC3, 
            0xC2, 0xD4, 0x34, 0x9D, 0xC7, 0xD4, 0x02, 0x5F, 0xED, 0x31, 0x14, 0x19, 0x3A, 0xF9, 0xB7, 0x3E, 
            0xE3, 0x6A, 0x40, 0x62, 0x95, 0x1A, 0x05, 0x2C, 0xF9, 0xDC, 0xBD, 0x8C, 0x1F, 0x78, 0xB1, 0x85, 
            0x07, 0x50, 0xF6, 0x93, 0xC6, 0x08, 0x97, 0x38, 0xFF, 0x19, 0x36, 0x24, 0x31, 0x55, 0x0B, 0x51, 
            0x2F, 0x3B, 0xD3, 0x06, 0xE0, 0xE2, 0xDB, 0x9B, 0x4A, 0xF8, 0x03, 0x6C, 0xBB, 0xCE, 0x4E, 0xDB, 
            0x28, 0x64, 0x6F, 0xED, 0x73, 0x02, 0x00, 0xA8, 0xF8, 0x25, 0x1E, 0xC6, 0x4F, 0x56, 0x49, 0xA2, 
            0x7D, 0x7C, 0x4A, 0x86, 0x47, 0x74, 0x1A, 0xFE, 0x10, 0xE8, 0xE4, 0x5E, 0x9E, 0x46, 0x6F, 0x1C, 
            0x12, 0xA9, 0xE8, 0xA0, 0x53, 0x60, 0xBC, 0xB8, 0xF8, 0xA0, 0xB5, 0x17, 0xAE, 0xE1, 0x4C, 0x68, 
            0xAE, 0xE0, 0x3E, 0x49, 0x80, 0x7F, 0xAF, 0xB9, 0xA1, 0xFB, 0x51, 0xBA, 0x70, 0xF0, 0x06, 0xA3, 
            0x72, 0xB8, 0xA7, 0xBE, 0xC2, 0x6D, 0xA3, 0x81, 0xA9, 0x64, 0xF0, 0x65, 0x82, 0xD3, 0x74, 0x6D, 
            0xA5, 0x03, 0x3A, 0x45, 0x48, 0xDE, 0x68, 0xD0, 0xD8, 0x80, 0x55, 0x1A, 0xEE, 0x9B, 0x3C, 0xED, 
            0x90, 0x5E, 0x99, 0x7F, 0x7E, 0xD3, 0x24, 0x56, 0x21, 0x49, 0x29, 0x0F, 0xCD, 0xC7, 0xDA, 0xCB, 
            0x1A, 0x0A, 0xFA, 0x69, 0x55, 0xF3, 0x20, 0x9A, 0x86, 0x18, 0x3B, 0xEE, 0xEB, 0x1A, 0x73, 0x4F, 
            0x7A, 0x3E, 0xC4, 0x2D, 0xCF, 0x04, 0xEF, 0x3E, 0x63, 0xB8, 0x8F, 0x29, 0x4B, 0x6B, 0x15, 0xBD, 
            0xFE, 0x10, 0x4C, 0x07, 0xB1, 0x16, 0x02, 0x92, 0x2B, 0x1F, 0xA5, 0xEE, 0x6B, 0xD3, 0xB9, 0x90, 
            0xDD, 0xB2, 0x48, 0x6F, 0xC7, 0x24, 0x45, 0x74, 0xEF, 0x7B, 0xB7, 0xD4, 0x58, 0x5B, 0x5E, 0x50, 
            0x4F, 0xAF, 0xA9, 0xCB, 0xAD, 0x7A, 0x7A, 0xDD, 0xD9, 0xB4, 0x14, 0xD7, 0xDB, 0xA8, 0xF5, 0x87
        };
    }
}