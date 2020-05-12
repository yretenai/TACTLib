﻿using static TACTLib.Core.Product.Tank.ManifestCryptoHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [ManifestCrypto(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_37664 : ICMFEncryptionProc {
        public byte[] Key(CMFHeader header, int length) {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[length + 256];
            uint increment = header.m_buildVersion * (uint)header.m_dataCount % 7;
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
                kidx += 3;
                buffer[i] ^= digest[(kidx - i) % SHA1_DIGESTSIZE];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0x92, 0x5B, 0xDD, 0x63, 0xAB, 0xD9, 0x1D, 0x84, 0x70, 0xAD, 0xF6, 0x07, 0xBF, 0xD8, 0x1A, 0x8C,
            0xAD, 0x14, 0x00, 0xD4, 0x9D, 0xE3, 0x03, 0xC6, 0x0A, 0xA6, 0xCE, 0xB4, 0xF6, 0xE6, 0x48, 0xCD,
            0x7E, 0x5C, 0x3B, 0x72, 0x9C, 0x4D, 0x76, 0xD6, 0x4E, 0x82, 0x3F, 0x52, 0xA2, 0x44, 0xC4, 0x82,
            0xAF, 0xDC, 0xFF, 0xCF, 0xC6, 0x06, 0x07, 0x51, 0xAD, 0x4B, 0x47, 0x9A, 0x8E, 0x9B, 0x6E, 0x28,
            0xCF, 0x43, 0x18, 0x00, 0xA7, 0xD9, 0xA7, 0xFB, 0x48, 0x10, 0x55, 0xF7, 0x7A, 0x9C, 0xA1, 0x8B,
            0x38, 0xCA, 0x26, 0xFD, 0x1C, 0x55, 0x79, 0x44, 0x21, 0x1B, 0xA4, 0x6A, 0x07, 0x03, 0x42, 0x9C,
            0x68, 0x31, 0x09, 0x4A, 0x79, 0xB6, 0x74, 0x19, 0xFE, 0x05, 0x9F, 0xAB, 0x0B, 0xFD, 0xB7, 0x11,
            0xA6, 0x74, 0x35, 0xD9, 0x5A, 0xE7, 0x0D, 0xE1, 0x0E, 0x4C, 0x67, 0x59, 0xA4, 0x52, 0xCC, 0x07,
            0x66, 0xED, 0x53, 0x6F, 0xD4, 0x21, 0x17, 0xBD, 0x31, 0x82, 0xDE, 0xC2, 0x48, 0x98, 0x2C, 0xF7,
            0xC2, 0x44, 0x41, 0xB0, 0x82, 0x08, 0xE2, 0xC6, 0xA9, 0x29, 0x7C, 0x7F, 0xFE, 0xF5, 0xC3, 0x20,
            0x46, 0x23, 0x84, 0x98, 0x0E, 0xB7, 0x44, 0x59, 0x05, 0x51, 0x11, 0x95, 0xA1, 0xBE, 0xB2, 0x15,
            0x49, 0x4F, 0x0C, 0xD8, 0x83, 0x92, 0x55, 0x7B, 0x76, 0x5B, 0x54, 0x14, 0xAB, 0x3F, 0xFF, 0xE2,
            0xEF, 0x9C, 0xB1, 0xD1, 0x8D, 0xDD, 0x8F, 0x69, 0x29, 0xE7, 0x25, 0x66, 0xD6, 0xBC, 0x43, 0x06,
            0xA8, 0x3E, 0x2C, 0xA6, 0x4E, 0x71, 0xE9, 0xDA, 0x90, 0xC8, 0xAD, 0x9A, 0x15, 0x18, 0x20, 0x65,
            0xF3, 0x79, 0xD0, 0x88, 0xFB, 0xA4, 0xE1, 0xC2, 0xB0, 0x34, 0x3E, 0x5F, 0xF6, 0xD0, 0xAD, 0x9C,
            0x52, 0x58, 0x00, 0xC8, 0x47, 0x08, 0xE9, 0x7A, 0xB6, 0x9F, 0xF5, 0x6C, 0xEF, 0x3B, 0x0D, 0x10,
            0x9B, 0x88, 0xFC, 0x6C, 0x51, 0x6C, 0xA0, 0xA2, 0x02, 0x6C, 0x5B, 0xCE, 0x23, 0xA1, 0x73, 0x90,
            0xDE, 0x9D, 0xD6, 0xF0, 0x1E, 0x40, 0xB0, 0x9F, 0x49, 0xBC, 0x24, 0x7F, 0x4F, 0x8D, 0x37, 0x68,
            0x77, 0x11, 0x97, 0x4C, 0x78, 0xE4, 0x3A, 0x9A, 0x01, 0x4A, 0xCC, 0xFE, 0xF6, 0x00, 0x11, 0xF4,
            0xBF, 0xAE, 0xC9, 0x16, 0x26, 0xCF, 0x91, 0xAD, 0xD3, 0x19, 0xB1, 0xA8, 0x5B, 0xE8, 0x6F, 0xB9,
            0x11, 0x34, 0x8A, 0x0B, 0xD2, 0x61, 0x39, 0xC0, 0xC6, 0x9B, 0x50, 0x8B, 0x99, 0xB3, 0xAB, 0x64,
            0x9F, 0x5C, 0x72, 0xF2, 0x4C, 0x25, 0xA4, 0x4D, 0x6F, 0xAF, 0xCF, 0x84, 0x4F, 0x63, 0x0B, 0xCB,
            0x97, 0xF8, 0x5F, 0x11, 0xE2, 0xE1, 0x92, 0x16, 0x6A, 0x1C, 0x4A, 0x4B, 0x1B, 0xC3, 0x67, 0x4E,
            0xE4, 0x62, 0xD1, 0x65, 0x50, 0xBD, 0x09, 0xA1, 0x77, 0x1B, 0xF9, 0x82, 0x03, 0x94, 0x14, 0x36,
            0x48, 0xE8, 0x01, 0x8E, 0xF9, 0x24, 0x2A, 0x77, 0x5F, 0x6F, 0x27, 0x88, 0x6F, 0x37, 0x34, 0x21,
            0x75, 0xBF, 0x60, 0xFC, 0x7C, 0xDF, 0x4A, 0xBE, 0x07, 0x1D, 0x13, 0xF4, 0xC3, 0xF7, 0x5A, 0xAB,
            0xDE, 0x41, 0x43, 0x2E, 0x53, 0xFE, 0xFA, 0x51, 0x6E, 0x28, 0x1E, 0xF7, 0x1F, 0x96, 0x90, 0xFC,
            0xAC, 0x07, 0x4F, 0xD9, 0xAE, 0xC0, 0x51, 0x9F, 0xAB, 0x79, 0x2B, 0x02, 0x52, 0x9F, 0xEE, 0x8A,
            0xEF, 0x38, 0xF7, 0xFD, 0x02, 0xBC, 0xCD, 0xA0, 0x90, 0x56, 0x06, 0x53, 0x34, 0x03, 0x4E, 0xCE,
            0x35, 0x1A, 0x68, 0xBA, 0xEF, 0x01, 0x45, 0x5B, 0x3E, 0x0D, 0xB1, 0x82, 0xE5, 0x71, 0x2C, 0xEB,
            0xD1, 0xF1, 0x60, 0x54, 0xA6, 0xC2, 0x2E, 0xE8, 0xCE, 0x45, 0x05, 0x04, 0xB2, 0x13, 0x88, 0xEA,
            0x6F, 0x0B, 0xEF, 0xCD, 0xE4, 0x70, 0x43, 0xFB, 0x6E, 0x22, 0x71, 0x60, 0xC7, 0x89, 0x0F, 0xCA
        };
    }
}