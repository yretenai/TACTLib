﻿using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TACTLib.Client;
using TACTLib.Container;
using TACTLib.Helpers;

namespace TACTLib.Core.Product.Tank {
    public class ContentManifestFile {
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct HashData {
            public ulong GUID;
            public uint Size;
            public CKey ContentKey;
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct CMFHeader {  // 1.22+
            public uint BuildVersion; // 0
            public uint Unk01; // 4
            public uint Unk02; // 8
            public uint Unk03; // 12
            public uint Unk04; // 16
            public int DataCount; // 20
            public uint Unk05; // 24
            public int EntryCount; // 28
            // 0x16666D63 '\x16fmc' -> Not Encrypted
            // 0x636D6616 'cmf\x16' -> Encrypted
            public uint Magic; // 32
        }

        public CMFHeader Header;
        
        public HashData[] HashList;
        public ApplicationPackageManifest.Entry[] Entries;
        public Dictionary<ulong, int> IndexMap;
        private Dictionary<ulong, HashData> _map;

        // ReSharper disable once InconsistentNaming
        public const int ENCRYPTED_MAGIC = 0x636D66; // todo: use the thingy again?
        
        public ContentManifestFile(ClientHandler client, Stream stream, string name) {
            using (BinaryReader reader = new BinaryReader(stream)) {
                Header = reader.Read<CMFHeader>();

                if(Header.BuildVersion >= 50483)
                {
                    Header.BuildVersion = Header.BuildVersion >> 8;
                }

                if (Header.Magic >> 8 == ENCRYPTED_MAGIC) {
                    using (BinaryReader decryptedReader = DecryptCMF(client, stream, name)) {
                        ParseEntries(decryptedReader);
                    }
                } else {
                    ParseEntries(reader);
                }
            }
        }

        protected BinaryReader DecryptCMF(ClientHandler client, Stream stream, string name) {
            CMFCryptHandler.GenerateKeyIV(name, Header, client.Product, out byte[] key, out byte[] iv); 
            
            using (RijndaelManaged rijndael = new RijndaelManaged {Key = key, IV = iv, Mode = CipherMode.CBC}) {
                CryptoStream cryptoStream = new CryptoStream(stream, rijndael.CreateDecryptor(),
                    CryptoStreamMode.Read);
                return new BinaryReader(cryptoStream);
            }
        }

        private void ParseEntries(BinaryReader reader) {
            Entries = reader.ReadArray<ApplicationPackageManifest.Entry>(Header.EntryCount);
            HashList = reader.ReadArray<HashData>(Header.DataCount);
            
            IndexMap = new Dictionary<ulong, int>(Header.DataCount);
            _map = new Dictionary<ulong, HashData>(Header.DataCount); 
            for (int i = 0; i < Header.DataCount; i++) {
                var hashData = HashList[i];
                IndexMap[hashData.GUID] = i;

                _map[hashData.GUID] = hashData;
            }
        }

        public bool TryGet(ulong guid, out HashData hashData) {
            // if (_indexMap.TryGetValue(guid, out int index)) {
            //     hashData = _hashList[index];
            //     return true;
            // }
            // hashData = default;
            // return false;
            return _map.TryGetValue(guid, out hashData);
        }

        public bool Exists(ulong guid) {
            return IndexMap.ContainsKey(guid);
        }

        public HashData GetHashData(ulong guid) {
            if (IndexMap.TryGetValue(guid, out int index)) {
                return HashList[index];
            }
            throw new FileNotFoundException(); // todo
        }

        public Stream OpenFile(ClientHandler client, ulong guid) {
            var data = GetHashData(guid);
            try {
                return client.OpenCKey(data.ContentKey);
            } catch (InvalidDataException) {
                Logger.Debug("debug", $"{guid:X8}");
                Logger.Debug("debug", "------");
                return null;
            }
        }
    }
}