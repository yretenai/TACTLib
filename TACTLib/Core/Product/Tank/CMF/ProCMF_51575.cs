﻿using static TACTLib.Core.Product.Tank.ManifestCryptoHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [ManifestCrypto(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_51575 : ICMFEncryptionProc
    {
        public byte[] Key(CMFHeader header, int length)
        {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[header.m_buildVersion & 511];
            uint increment = kidx % 61;
            for (int i = 0; i != length; ++i)
            {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx += increment;
            }

            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length)
        {
            byte[] buffer = new byte[length];

            uint kidx = (uint)((digest[7] + (ushort)header.m_dataCount) & 511);
            uint increment = kidx % 13;
            for (int i = 0; i != length; ++i)
            {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx += increment;
                buffer[i] ^= digest[SignedMod(kidx + 0x16666D63, SHA1_DIGESTSIZE)];
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0x87, 0xDD, 0x69, 0x09, 0x8E, 0xD8, 0xB7, 0xBB, 0x11, 0x41, 0x75, 0x2C, 0x0C, 0xDA, 0x41, 0x6B, 
            0x6F, 0x26, 0x27, 0xC2, 0x48, 0xEB, 0x95, 0x69, 0x8E, 0x68, 0xA9, 0x9B, 0x2B, 0x14, 0xA8, 0x92, 
            0xD2, 0x75, 0x80, 0x37, 0xB0, 0xBA, 0x40, 0x49, 0xF1, 0x89, 0xAF, 0x35, 0x15, 0x85, 0x7E, 0x40, 
            0x8B, 0xDF, 0x25, 0x31, 0x14, 0x0E, 0x40, 0x2F, 0x8E, 0x03, 0x73, 0xBE, 0x83, 0x60, 0xEC, 0xE6, 
            0x51, 0xFB, 0xB6, 0x52, 0xF0, 0x59, 0xE5, 0x4B, 0x55, 0x41, 0x85, 0x5F, 0x48, 0xAE, 0x28, 0x34, 
            0xA7, 0xA2, 0x09, 0x77, 0xB1, 0x06, 0x18, 0xB6, 0x1D, 0x15, 0x23, 0x31, 0x6B, 0xA3, 0x24, 0x7F, 
            0x00, 0x1F, 0xF9, 0x42, 0x75, 0x56, 0xD2, 0x22, 0x70, 0x50, 0x1C, 0x69, 0x07, 0x0A, 0x1C, 0x95, 
            0x87, 0x6F, 0x4B, 0xAF, 0xD5, 0x25, 0xC9, 0x7E, 0xA7, 0x9E, 0x42, 0xCE, 0x8B, 0x7D, 0xFA, 0x01, 
            0x6B, 0xD4, 0x49, 0x4A, 0x4F, 0x8D, 0x11, 0xAC, 0x99, 0xCF, 0xF1, 0x3D, 0xD4, 0x13, 0x89, 0x57, 
            0xC9, 0x4B, 0x3E, 0x2E, 0x3B, 0x44, 0x4F, 0xBF, 0x36, 0xDA, 0xDC, 0x24, 0x8E, 0xBA, 0x12, 0x1D, 
            0xA1, 0xD6, 0x7E, 0xA8, 0x41, 0x00, 0xBD, 0xCD, 0x38, 0xAA, 0xCA, 0x71, 0x34, 0x72, 0xDB, 0x40, 
            0x5D, 0x58, 0x69, 0x70, 0x89, 0xB3, 0x16, 0x21, 0xCD, 0xF6, 0x1E, 0xAB, 0xC6, 0xAA, 0x21, 0xB6, 
            0x04, 0x69, 0xFC, 0xF2, 0x34, 0x2F, 0xF2, 0x74, 0x1E, 0xEC, 0x3D, 0x7E, 0x74, 0x6C, 0x82, 0xEA, 
            0xA7, 0x30, 0xF4, 0x7A, 0x50, 0xF4, 0x21, 0x33, 0x2E, 0x9F, 0xB0, 0x86, 0x38, 0x9F, 0x9C, 0x30, 
            0x46, 0xC5, 0xEA, 0x5B, 0xCA, 0xD4, 0x28, 0x9A, 0xBA, 0xF9, 0xF5, 0x46, 0x8F, 0x35, 0x85, 0xC2, 
            0x35, 0x0A, 0x63, 0xD5, 0xFB, 0xF5, 0x63, 0xDA, 0x25, 0x34, 0xAE, 0xE1, 0x01, 0xAF, 0xAF, 0xB4, 
            0x8F, 0x8A, 0x4C, 0xF3, 0x27, 0x34, 0x41, 0xD2, 0x28, 0xA1, 0xD8, 0x2F, 0x1E, 0xF2, 0xF7, 0xC4, 
            0xE8, 0x88, 0xD3, 0xED, 0x7A, 0xC6, 0xB0, 0x02, 0xB1, 0x30, 0x36, 0xA6, 0xB5, 0x1A, 0x31, 0x07, 
            0xE6, 0xB7, 0xB0, 0x87, 0xB7, 0xA9, 0xD0, 0x17, 0x2A, 0xD0, 0xB4, 0x78, 0xA6, 0x8A, 0x4B, 0x03, 
            0x8A, 0x2E, 0xEB, 0x46, 0x2F, 0xCB, 0x91, 0x90, 0x7F, 0xB3, 0x28, 0x14, 0x95, 0x0A, 0x31, 0x3E, 
            0x97, 0xD6, 0x9C, 0x42, 0xFC, 0xD0, 0xD8, 0x7E, 0x1E, 0xB8, 0x57, 0x70, 0x80, 0x14, 0x9C, 0xA0, 
            0xDC, 0x8F, 0xD4, 0xE0, 0x18, 0xEC, 0x8F, 0x55, 0xA6, 0xCA, 0xF8, 0xD1, 0x0F, 0xC4, 0x85, 0x42, 
            0xC2, 0x4B, 0x39, 0x49, 0x72, 0x36, 0xE6, 0xF1, 0x79, 0xF2, 0x8D, 0x45, 0xEE, 0xFE, 0x9F, 0x57, 
            0x9D, 0x1F, 0x39, 0xB5, 0x26, 0x26, 0x61, 0xA3, 0x1C, 0xA6, 0x66, 0x11, 0x5C, 0xCE, 0x47, 0xD0, 
            0xAE, 0x41, 0xF0, 0x23, 0x4E, 0x22, 0x59, 0x01, 0x58, 0x13, 0x6C, 0xD5, 0x77, 0x40, 0x2B, 0x8E, 
            0xB9, 0x97, 0xB2, 0x34, 0x95, 0xCD, 0xC3, 0x28, 0x7D, 0x12, 0x5C, 0x4D, 0xE6, 0x4E, 0x6F, 0x64, 
            0x31, 0x58, 0xDC, 0x63, 0x76, 0x2D, 0x90, 0xC6, 0x91, 0x0D, 0x81, 0xAA, 0x65, 0xE8, 0x2C, 0x07, 
            0x47, 0x49, 0x9E, 0x73, 0xC7, 0x73, 0xB4, 0x39, 0x19, 0xC4, 0x88, 0xAB, 0xC4, 0xAE, 0x0E, 0x48, 
            0x24, 0x94, 0x13, 0x2F, 0x8E, 0x76, 0xCF, 0x3D, 0xB9, 0xDF, 0x08, 0xBD, 0xFF, 0x98, 0xAC, 0xFF, 
            0xEA, 0xFF, 0xC9, 0x64, 0x9B, 0xF8, 0x94, 0x2E, 0x08, 0x36, 0xC1, 0xBB, 0x7B, 0x1B, 0xFE, 0xDA, 
            0x8C, 0xFD, 0x0E, 0x17, 0x57, 0xD7, 0x08, 0x1A, 0xE8, 0x86, 0xB8, 0x6F, 0xD8, 0x29, 0x74, 0xCB, 
            0x63, 0x95, 0xD7, 0x42, 0xE8, 0x64, 0x72, 0x7D, 0x49, 0x72, 0x08, 0xBB, 0x5F, 0xA8, 0x3B, 0xE7
        };
    }
}