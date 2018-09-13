﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using TACTLib.Client;
using TACTLib.Helpers;
using static TACTLib.Utils;

namespace TACTLib.Container {
    public class ContainerHandler {
        // ReSharper disable once InconsistentNaming
        /// <summary>Number of index files</summary>
        public const int CASC_INDEX_COUNT = 0x10;

        /// <summary>
        /// Container directory. Where the data, config, indices etc subdirectories are located.
        /// </summary>
        public readonly string ContainerDirectory;

        /// <summary>Data directory name</summary>
        public const string DataDirectory = "data";
        
        /// <summary>Config directory name</summary>
        public const string ConfigDirectory = "config";
        
        /// <summary>Indices directory name</summary>
        public const string CDNIndicesDirectory = "indices";
        
        /// <summary>Patch directory name</summary>
        public const string PatchDirectory = "patch";

        /// <summary>Local index map</summary>
        public readonly Dictionary<EKey, IndexEntry> IndexEntries;

        private readonly ClientHandler _client;

        public ContainerHandler(ClientHandler client) {
            _client = client;
            if (client.BasePath == null) throw new Exception("no 'BasePath' specified");
            ContainerDirectory = Path.Combine(client.BasePath, GetContainerDirectory(client.Product));

            IndexEntries = new Dictionary<EKey, IndexEntry>(CASCKeyComparer.Instance);
            LoadIndexFiles();
        }

        private void LoadIndexFiles() {
            for (int i = 0; i < CASC_INDEX_COUNT; i++) {
                List<string> files = Directory.EnumerateFiles(Path.Combine(ContainerDirectory, DataDirectory), $"{i:X2}*.idx" + _client.CreateArgs.ExtraFileEnding).ToList();

                string selectedFile = null;
                int selectedVersion = 0;
                foreach (string file in files) {
                    string fileName = Path.GetFileNameWithoutExtension(file);
                    if (fileName == null) continue;
                    string sub = fileName.Substring(2);
                    int version = int.Parse(sub, NumberStyles.HexNumber);

                    if (version > selectedVersion) {
                        selectedFile = file;
                        selectedVersion = version;
                    }
                }
                
                LoadIndexFile(selectedFile, i);
            }
        }

        /// <summary>
        /// Load an index file
        /// </summary>
        /// <param name="file">File path</param>
        /// <param name="bucketIndex">Index</param>
        /// <exception cref="InvalidDataException">Index file is invalid</exception>
        private unsafe void LoadIndexFile(string file, int bucketIndex) {
            using (Stream stream = File.OpenRead(file))
            using (BinaryReader reader = new BinaryReader(stream)) {
                var header = reader.Read<IndexHeaderV2>();

                if (header.IndexVersion != 0x07 ||
                    header.BucketIndex != bucketIndex ||
                    header.ExtraBytes != 0x00 ||
                    header.SpanSizeBytes != 0x04 ||
                    header.SpanOffsBytes != 0x05 ||
                    header.EKeyBytes != EKey.CASC_EKEY_SIZE) {
                    throw new InvalidDataException("invalid index header");
                }

                var eKey1Block = reader.Read<BlockSizeAndHash>();
                int entryCount = eKey1Block.BlockSize / sizeof(EKeyEntry);

                EKeyEntry[] entries = reader.ReadArray<EKeyEntry>(entryCount);
                for (int i = 0; i < entryCount; i++) {
                    EKeyEntry entry = entries[i];
                    if (IndexEntries.ContainsKey(entry.EKey)) continue;
                    
                    IndexEntries[entry.EKey] = new IndexEntry(entry);
                }
            }
        }

        /// <summary>
        /// Open an encoded file from Encoding Key
        /// </summary>
        /// <param name="key">The Encoding Key</param>
        /// <returns>Loaded file</returns>
        internal Stream OpenEKey(EKey key) {
            if (!IndexEntries.TryGetValue(key, out IndexEntry indexEntry)) {
                Debugger.Log(0, "ContainerHandler", $"Missing local index {key.ToHexString()}");
                return null;
            }
            return OpenIndexEntry(indexEntry);
        }

        /// <summary>
        /// Open an index entry and get data
        /// </summary>
        /// <param name="indexEntry">Source index entry</param>
        /// <returns>Encoded stream</returns>
        private Stream OpenIndexEntry(IndexEntry indexEntry) {
            using (Stream dataStream = OpenDataFile(indexEntry.Index))
            using (BinaryReader reader = new BinaryReader(dataStream, Encoding.ASCII, false)) {  // ASCII = important. one byte per char
                dataStream.Position = indexEntry.Offset;

                //CKey cKey = reader.Read<CKey>();
                dataStream.Position += 16;
                
                int size = reader.ReadInt32();

                if (size < 0) {
                    Logger.Debug("debug", $"file failing due to neg size ({size})");
                    Logger.Error("debug", $"{indexEntry.Index} {indexEntry.Offset}");
                    throw new InvalidDataException("data size < 0");
                }
                
                // 2+8 byte block of something?
                dataStream.Position += 10;
                
                byte[] data = reader.ReadBytes(size - 30);

                return new MemoryStream(data);
            }
        }

        /// <summary>Open a data file</summary>
        /// <param name="index">Data file index ("data.{index}")</param>
        /// <returns>Data stream</returns>
        private Stream OpenDataFile(int index) {
            return File.OpenRead(Path.Combine(ContainerDirectory, DataDirectory, $"data.{index:D3}") + _client.CreateArgs.ExtraFileEnding);
        }
        
        /// <summary>
        /// Get container directory from product type
        /// </summary>
        /// <param name="product">Target product</param>
        /// <returns>Container directory</returns>
        /// <exception cref="NotImplementedException">Product is unsupported</exception>
        public static string GetContainerDirectory(TACTProduct product) {
            if (product == TACTProduct.HeroesOfTheStorm)
                return "HeroesData";

            if (product == TACTProduct.StarCraft2)
                return "SC2Data";

            if (product == TACTProduct.Hearthstone)
                return "Hearthstone_Data";

            if (product == TACTProduct.Warcraft3 || product == TACTProduct.WorldOfWarcraft || product == TACTProduct.Diablo3 || 
                product == TACTProduct.BlackOps4)
                return "Data";

            if (product == TACTProduct.Overwatch)
                return "data\\casc";
            
            throw new NotImplementedException("unsupported product");
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct IndexHeaderV2 {
            public BlockSizeAndHash BlockHeader;
            public ushort IndexVersion;
            public byte BucketIndex;
            public byte ExtraBytes;
            public byte SpanSizeBytes;             // Size of field with file size
            public byte SpanOffsBytes;             // Size of field with file offset
            public byte EKeyBytes;                 // Size of the file key (bytes)
            public byte ArchiveFileHeaderBytes;    // Number of bits for the file offset (rest is archive index)
            public ulong ArchiveTotalSizeMaximum;  // The maximum size of a casc installation; 0x4000000000, or 256GiB.
            public fixed byte Padding[8];          // Always here
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct BlockSizeAndHash {
            /// <summary>
            /// Block size, in bytes
            /// </summary>
            public int BlockSize;
            
            /// <summary>
            /// hashlittle2 on the following BlockSize bytes of the file with an initial value of 0 for pb and pc.
            /// </summary>
            public int BlockHash;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct EKeyEntry {
            /// <summary>Encoding Key</summary>
            public EKey EKey;                   // The first 9 bytes of the encoded key
            
            /// <summary>Index of data file and offset within (big endian)</summary>
            public fixed byte FileOffsetBE[5];
            
            /// <summary>Size of the encoded file</summary>
            public int EncodedSize;
        }
        
        public struct IndexEntry {
            /// <summary>Data file index</summary>
            public int Index;
            
            /// <summary>Offset to data, in bytes</summary>
            public int Offset;

            public unsafe IndexEntry(EKeyEntry entry) {
                int indexHigh = entry.FileOffsetBE[0];
                int indexLow = Int32FromPtrBE(entry.FileOffsetBE+1);

                Index = indexHigh << 2 | (byte) ((indexLow & 0xC0000000) >> 30);
                Offset = indexLow & 0x3FFFFFFF;
            }
        }
    }
}