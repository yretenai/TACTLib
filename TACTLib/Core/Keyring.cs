﻿using System.Collections.Generic;
using System.Globalization;
using TACTLib.Helpers;

namespace TACTLib.Core {
    public class Keyring : Config.Config {
        public readonly Dictionary<ulong, byte[]> Keys;

        public Keyring(string containerPath, string key) : base(containerPath, key) {
            Keys = new Dictionary<ulong, byte[]>();
            foreach (KeyValuePair<string,List<string>> pair in Values) {
                string reverseKey = pair.Key.Substring(pair.Key.Length - 16);
                string keyIDString = "";
                for (int i = 0; i < 8; ++i) {
                    keyIDString = reverseKey.Substring(i * 2, 2) + keyIDString;
                }
                
                ulong keyID = ulong.Parse(keyIDString, NumberStyles.HexNumber);
                Keys[keyID] = Utils.StringToByteArray(pair.Value[0]);
            }
        }
        
        public byte[] GetKey(ulong keyID) {
            Keys.TryGetValue(keyID, out byte[] key);
            return key;
        }

    }
}