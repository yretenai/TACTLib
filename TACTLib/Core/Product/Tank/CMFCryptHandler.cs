using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;
using Microsoft.CodeDom.Providers.DotNetCompilerPlatform;

namespace TACTLib.Core.Product.Tank {
    public static class CMFCryptHandler {
        #region Helpers
        // ReSharper disable once InconsistentNaming
        public const uint SHA1_DIGESTSIZE = 20;
        
        internal static uint Constrain(long value) {
            return (uint)(value % uint.MaxValue);
        }
        
        public static long SignedMod(long a, long b) {
            return a % b < 0 ? a % b + b : a % b;
        }
        #endregion
        
        private static readonly Dictionary<TACTProduct, Dictionary<uint, ICMFEncryptionProc>> Providers = new Dictionary<TACTProduct, Dictionary<uint, ICMFEncryptionProc>>();
        private static bool _baseProvidersFound;
        
        private static void FindProviders() {
            Assembly asm = typeof(ICMFEncryptionProc).Assembly;
            AddProviders(asm);
        }
        
        public static void GenerateKeyIV(string name, ContentManifestFile.CMFHeader header, TACTProduct product, out byte[] key, out byte[] iv) {
            if (!_baseProvidersFound) {
                FindProviders();
                _baseProvidersFound = true;
            }

            byte[] digest = CreateDigest(name);

            ICMFEncryptionProc provider;
            if (TestVersion(product, header.BuildVersion)) {
                Logger.Info("CMF", $"Using CMF procedure {header.BuildVersion}");
                provider = Providers[product][header.BuildVersion];
            } else {
                Logger.Warn("CMF", $"No CMF procedure for build {header.BuildVersion}, trying closest version");
                try {
                    KeyValuePair<uint, ICMFEncryptionProc> pair = Providers[product].Where(it => it.Key < header.BuildVersion).OrderByDescending(it => it.Key).First();
                    Logger.Info("CMF", $"Using CMF procedure {pair.Key}");
                    provider = pair.Value;
                } catch {
                    throw new CryptographicException("Missing CMF generators");
                }
            }

            key = provider.Key(header, 32);
            iv = provider.IV(header, digest, 16);

            name = Path.GetFileNameWithoutExtension(name);
            Logger.Debug("CMF", $"{name} key:{string.Join(" ", key.Select(x => x.ToString("X2")))}");
            Logger.Debug("CMF", $"{name} iv:{string.Join(" ", iv.Select(x => x.ToString("X2")))}");
        }

        private static bool TestVersion(TACTProduct product, uint headerBuildVersion) {
            if (Providers[product].ContainsKey(headerBuildVersion)) return true;
            var testUrl = $"https://raw.githubusercontent.com/overtools/TACTLib/master/TACTLib/Core/Product/Tank/CMF/ProCMF_{headerBuildVersion}.cs";
            using (var http = new HttpClient()) {
                var response = http.GetAsync(testUrl)
                                   .GetAwaiter()
                                   .GetResult();
                if (response.IsSuccessStatusCode) {
                    Compile(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                }
            }

            return Providers[product].ContainsKey(headerBuildVersion);
        }


        private static HashSet<byte[]> ParsedExpressions = new HashSet<byte[]>();

        [Serializable]
        [XmlType(AnonymousType = false, TypeName = "TACT", Namespace = "https://chomp.gg/types/tactheader")]
        [XmlRoot(Namespace = "https://chomp.gg/types/tactheader", IsNullable = false)]
        public class CompiledTACTHeader {
            [XmlAttribute]
            public string HASH { get; set; }
            [XmlAttribute]
            public string NAME { get; set; }
        }

        public static void Compile(string cs) {
            Assembly assembly = null;
            byte[] test = Array.Empty<byte>();
            string name = "";
            if (cs.StartsWith("// <TACT ")) {
                var lines      = cs.Split('\n');
                var serializer = new XmlSerializer(typeof(CompiledTACTHeader));
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(lines.First()
                                                                             .Substring(2)
                                                                             .Trim()))) {
                    if (serializer.Deserialize(ms) is CompiledTACTHeader header) {
                        test = new byte[header.HASH.Length / 2];
                        for (int i = 0; i < header.HASH.Length; i += 2)
                            test[i / 2] = Convert.ToByte(header.HASH.Substring(i, 2), 16);

                        name = header.NAME;
                    }
                }


                cs = string.Join("\n", lines.Skip(1));
            } else {
                Logger.Info("CMF", "Downloaded CMF procedure has no metadata! Please update TACTLib");
                return;
            }
            
            if (test.Length != SHA1_DIGESTSIZE) {
                Logger.Info("CMF", "Downloaded CMF procedure is insane! Please update TACTLib");
                return;
            }

            if (!File.Exists(name)) {
                cs = cs.Trim();
                
                var hash = CreateDigest(cs);
                if (!hash.SequenceEqual(test)) {
                    Logger.Info("CMF", "Downloaded CMF procedure is corrupted! Please update TACTLib");
                    return;
                }

                if (ParsedExpressions.Add(hash)) {
                    Logger.Error("CMF", "Compiling new CMF procedure.");
                    var provider   = new CSharpCodeProvider();
                    var parameters = new CompilerParameters();
                    parameters.ReferencedAssemblies.Add("mscorlib.dll");
                    parameters.ReferencedAssemblies.Add("System.dll");
                    parameters.ReferencedAssemblies.Add(Assembly.GetExecutingAssembly().Location);
                    parameters.GenerateInMemory        = false;
                    parameters.OutputAssembly          = name;
                    parameters.GenerateExecutable      = false;
                    var temp = Path.Combine(Path.GetTempPath(), "TACTLibBuild");
                    if (!Directory.Exists(temp)) Directory.CreateDirectory(temp);
                    parameters.TempFiles               = new TempFileCollection(temp, false);
                    parameters.WarningLevel            = 3;
                    parameters.IncludeDebugInformation = true;
                    parameters.CompilerOptions         = "/unsafe /optimize /platform:x64 /langversion:latest";
                    var results = provider.CompileAssemblyFromSource(parameters, cs);
                    if (results.Errors.HasErrors) {
                        Logger.Error("CMF", "Catastrophic failure.");
                        foreach (CompilerError error in results.Errors) {
                            Logger.Error("CSC", $"{error.ErrorNumber}: {error.ErrorText}");
                        }

                        return;
                    }

                    assembly = results.CompiledAssembly;
                }
            } else {
                assembly = Assembly.LoadFile(name);
            }

            AddProviders(assembly);
        }

        public static byte[] CreateDigest(string value) {
            byte[] digest;
            using (SHA1 shaM = new SHA1Managed()) {
                byte[] stringBytes = Encoding.ASCII.GetBytes(value);
                digest = shaM.ComputeHash(stringBytes);
            }
            return digest;
        }

        public static void AddProviders(Assembly asm) {
            Type t = typeof(ICMFEncryptionProc);
            List<Type> types = asm.GetTypes().Where(tt => tt != t && t.IsAssignableFrom(tt)).ToList();
            foreach (Type tt in types) {
                if (tt.IsInterface) {
                    continue;
                }
                CMFMetadataAttribute metadata = tt.GetCustomAttribute<CMFMetadataAttribute>();
                if (metadata == null) {
                    continue;
                }

                if (!Providers.ContainsKey(metadata.Product)) {
                    Providers[metadata.Product] = new Dictionary<uint, ICMFEncryptionProc>();
                }
                var providerRef = Providers[metadata.Product];
                ICMFEncryptionProc provider = (ICMFEncryptionProc)Activator.CreateInstance(tt);
                if (metadata.AutoDetectVersion) {
                    try {
                        var buildVersion = uint.Parse(tt.Name.Split('_')[1]);
                        if (!providerRef.ContainsKey(buildVersion)) {
                            providerRef[buildVersion] = provider;
                        }
                    } catch {
                        //
                    }
                }

                if (metadata.BuildVersions != null) {
                    foreach (uint buildVersion in metadata.BuildVersions) {
                        if (!providerRef.ContainsKey(buildVersion)) {
                            Providers[metadata.Product][buildVersion] = provider;
                        }
                    }
                }
            }
        }
        
        [AttributeUsage(AttributeTargets.Class, Inherited = false)]
        public class CMFMetadataAttribute : Attribute {
            public bool AutoDetectVersion { get; set; } = true;
            public TACTProduct Product { get; set; } = TACTProduct.Overwatch;
            public uint[] BuildVersions { get; set; } = new uint[0];
            public int ManifestVersion { get; set; } = 1;
        }
    }
}
