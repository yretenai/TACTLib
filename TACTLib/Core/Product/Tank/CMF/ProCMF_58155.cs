﻿using static TACTLib.Core.Product.Tank.ManifestCryptoHandler;
using static TACTLib.Core.Product.Tank.ContentManifestFile;

namespace TACTLib.Core.Product.Tank.CMF {
    [ManifestCrypto(AutoDetectVersion = true, Product = TACTProduct.Overwatch)]
    public class ProCMF_58155 : ICMFEncryptionProc
    {
        public byte[] Key(CMFHeader header, int length)
        {
            byte[] buffer = new byte[length];

            uint kidx = Keytable[header.m_buildVersion & 511];
            uint increment = kidx % 61;
            for (uint i = 0; i != length; ++i)
            {
                buffer[i] =  Keytable[SignedMod(kidx, 512)];
                kidx += increment;
            }
            
            return buffer;
        }

        public byte[] IV(CMFHeader header, byte[] digest, int length)
        {
            byte[] buffer = new byte[length];

            uint kidx = (digest[7] + (uint) header.m_dataCount) & 511;
            uint increment = (uint)header.m_entryCount + digest[SignedMod(header.m_entryCount, SHA1_DIGESTSIZE)];
            uint digestIdx = header.m_buildVersion;
            for (int i = 0; i != length; ++i)
            {
                buffer[i] = Keytable[SignedMod(kidx, 512)];
                kidx += increment;
                buffer[i] ^= digest[SignedMod(digestIdx, SHA1_DIGESTSIZE)];
                ++digestIdx;
            }

            return buffer;
        }

        private static readonly byte[] Keytable = {
            0x9D, 0xC3, 0x5F, 0xC2, 0x45, 0xAB, 0x7C, 0x1F, 0x56, 0x1F, 0xF2, 0x0A, 0xFD, 0x37, 0x17, 0x3F, 
            0x59, 0x7D, 0xE8, 0x5F, 0x60, 0x7E, 0xF7, 0xA2, 0x04, 0xAA, 0x05, 0x2B, 0xA4, 0xAB, 0xB0, 0x75, 
            0xCC, 0xBA, 0xFF, 0xEB, 0x6F, 0x68, 0xFE, 0xC0, 0xBE, 0xC1, 0xE2, 0x1C, 0x1F, 0xA7, 0xAA, 0x18, 
            0x66, 0xCB, 0x85, 0x8D, 0xC7, 0x7E, 0xDF, 0xEF, 0x77, 0xFC, 0x01, 0x48, 0xA4, 0x82, 0x88, 0xE5, 
            0x1D, 0x54, 0xEF, 0xFF, 0x3B, 0x96, 0xC6, 0x3D, 0x3E, 0x7C, 0x26, 0x40, 0x46, 0x83, 0x58, 0x43, 
            0x3C, 0x4C, 0xFC, 0xA3, 0x60, 0x69, 0xA1, 0xD1, 0xE9, 0xB1, 0xC2, 0xA1, 0x3E, 0x21, 0x81, 0xF3, 
            0x37, 0x34, 0x75, 0xE9, 0x87, 0x86, 0x36, 0x8D, 0x38, 0x76, 0x7D, 0xE3, 0x7C, 0x13, 0x20, 0xC4, 
            0x7E, 0xD6, 0xEA, 0x3F, 0x99, 0xFC, 0xA3, 0x59, 0x5F, 0x84, 0x5E, 0x4E, 0x37, 0x79, 0xE3, 0x50, 
            0xB0, 0x8A, 0x43, 0xAB, 0xF2, 0x8B, 0x37, 0x05, 0x75, 0x0F, 0xD1, 0x90, 0xCE, 0x62, 0xF3, 0xDE, 
            0x51, 0x62, 0xB6, 0x94, 0xBF, 0x88, 0x93, 0x3E, 0x31, 0xD1, 0x3F, 0xDB, 0x4F, 0x97, 0x89, 0xE4, 
            0x1C, 0x67, 0x5B, 0x34, 0xD9, 0x67, 0xFF, 0x27, 0x3B, 0xB8, 0x9D, 0xA2, 0x90, 0xE5, 0x66, 0xAF, 
            0x45, 0x3D, 0x35, 0xEC, 0x9D, 0x90, 0x5E, 0x4E, 0x43, 0x7D, 0x34, 0x63, 0x5C, 0x41, 0x8B, 0x44, 
            0xD2, 0x31, 0x2A, 0x92, 0xD6, 0x9F, 0x67, 0x43, 0xDA, 0xB6, 0x4F, 0x9F, 0x96, 0x76, 0x46, 0x78, 
            0xAF, 0x7C, 0x79, 0xBE, 0x06, 0x34, 0x67, 0xE1, 0x60, 0x16, 0x17, 0x77, 0x19, 0x5B, 0xF9, 0x74, 
            0xAA, 0xA5, 0xCE, 0x48, 0x92, 0xD1, 0x87, 0x4B, 0xCB, 0xA7, 0x96, 0x7D, 0xAC, 0x65, 0xAE, 0xAD, 
            0x39, 0x26, 0x59, 0xA1, 0x84, 0x6A, 0x15, 0x3E, 0x34, 0x05, 0x12, 0xA8, 0x72, 0x95, 0x21, 0xA9, 
            0x9E, 0xB2, 0x73, 0x80, 0x07, 0xC0, 0x36, 0x08, 0x5E, 0x22, 0x46, 0xCC, 0x91, 0xA2, 0x0F, 0x9A, 
            0x41, 0x98, 0xBB, 0x48, 0x38, 0x58, 0xFF, 0x01, 0x18, 0x4C, 0xAC, 0xAC, 0x31, 0x6C, 0xBB, 0xE6, 
            0x9A, 0x4E, 0x72, 0x70, 0xF8, 0x24, 0xB0, 0xF0, 0x8D, 0x23, 0x43, 0xA8, 0xF7, 0xD5, 0x42, 0xB0, 
            0xE3, 0x26, 0xAA, 0xCE, 0x34, 0x98, 0x48, 0xFE, 0xFB, 0x72, 0x71, 0x36, 0xF2, 0x2B, 0xED, 0xBE, 
            0x6F, 0x9B, 0x70, 0xD6, 0x8B, 0xAF, 0xD8, 0x17, 0xCB, 0x20, 0x67, 0x9D, 0x2C, 0xC4, 0xBD, 0x84, 
            0xF7, 0x2D, 0x38, 0xCA, 0x1A, 0x3D, 0xA2, 0xFB, 0x20, 0x79, 0x8E, 0x9C, 0xC2, 0xD0, 0xAD, 0x46, 
            0x34, 0x9E, 0xCA, 0xE6, 0x1B, 0x63, 0x42, 0x3D, 0xD1, 0xF5, 0x81, 0x96, 0x49, 0xEF, 0xDE, 0x77, 
            0x52, 0x9B, 0x3B, 0x7C, 0xF9, 0xEF, 0x71, 0x06, 0x0D, 0xA9, 0x8F, 0x7E, 0x79, 0x09, 0x08, 0xDD, 
            0x5D, 0x26, 0xD5, 0x32, 0x9F, 0xEB, 0x61, 0x6F, 0x88, 0x73, 0x99, 0x78, 0x65, 0x44, 0xC8, 0xB6, 
            0x88, 0x7B, 0x31, 0x93, 0xF8, 0xC6, 0x68, 0x3E, 0xB5, 0x41, 0xA0, 0x5A, 0x1A, 0x2D, 0x76, 0x5A, 
            0xCA, 0x23, 0x40, 0xA3, 0x25, 0x67, 0xD0, 0x9A, 0x0E, 0xEA, 0xE3, 0x46, 0x85, 0x9F, 0x68, 0x14, 
            0x49, 0x20, 0x32, 0x69, 0x78, 0xAB, 0xAC, 0xDD, 0x5C, 0xD2, 0x83, 0xD9, 0x9C, 0xB7, 0x8D, 0xA8, 
            0x3F, 0xB8, 0xA3, 0x63, 0x9C, 0x12, 0x8B, 0x1B, 0x30, 0x63, 0x7A, 0xDF, 0x77, 0x4E, 0x27, 0xEC, 
            0xFE, 0x2D, 0xF9, 0x3F, 0xF4, 0x3F, 0xCA, 0x3F, 0x42, 0xCE, 0x50, 0xDD, 0xEE, 0xA1, 0xA0, 0xF6, 
            0x76, 0xDA, 0xA2, 0xFA, 0x38, 0x33, 0x4B, 0x18, 0x83, 0x5F, 0xCB, 0x3F, 0x73, 0xC4, 0x93, 0x1F, 
            0xBA, 0x5A, 0x94, 0x81, 0xE7, 0xB2, 0x69, 0x69, 0x8E, 0x75, 0xA4, 0x3D, 0x0C, 0x18, 0x42, 0x32
        };
    }
}