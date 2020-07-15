using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace NetMQSecurityFactory
{
    public static class EncryptionFactory
    {
        private static Container<ICurveEncrypt> CurveEncrypt;

        static EncryptionFactory()
        {
            LoadPlugins();
        }

        public static void LoadPlugins()
        {
            CurveEncrypt = LoadPluginsOfType<ICurveEncrypt>();
        }

        private static Container<T> LoadPluginsOfType<T>() where T : class
        {
            var type = typeof(T);
            var path = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
            var assemblies = Directory.GetFiles(path, "*.dll");
            var encryptorTypes = new List<Type>();

            foreach (var assemblyName in assemblies)
            {
                try
                {
                    var assembly = Assembly.LoadFrom(assemblyName);
                    if (assembly != null)
                    {
                        encryptorTypes.AddRange(assembly.GetTypes().Where(p => type.IsAssignableFrom(p) && p.IsAbstract == false));
                    }
                }
                catch (Exception)
                {
                }
            }

            var fallback = encryptorTypes.First(x => EncryptionFallback(x));
            var priority = encryptorTypes.FirstOrDefault(x => EncryptionPriority(x));
            return new Container<T>(priority, fallback);
        }

        private class Container<T> where T : class
        {
            private Type priority;
            private Type fallback;

            public Container(Type priority, Type fallback)
            {
                this.priority = priority;
                this.fallback = fallback;
            }

            public T CreateInstance()
            {
                try
                {
                    if (priority != null)
                    {
                        return Activator.CreateInstance(priority) as T;
                    }
                }
                catch (Exception e)
                {
                    priority = null;
                }
                return Activator.CreateInstance(fallback) as T;
            }
        }

        private static bool EncryptionPriority(Type t)
        {
            var priorityAttributes = (EncryptionPriorityAttribute[])t.GetCustomAttributes(typeof(EncryptionPriorityAttribute), false);
            return (priorityAttributes.Length > 0);
        }

        private static bool EncryptionFallback(Type t)
        {
            var priorityAttributes = (EncryptionFallbackAttribute[])t.GetCustomAttributes(typeof(EncryptionFallbackAttribute), false);
            return (priorityAttributes.Length > 0);
        }

        static public ICurveEncrypt GetCurveEncryptor(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> publicKey)
        {
            ICurveEncrypt encryptor = null; 
            if (CurveEncrypt != null)
            {
                encryptor = CurveEncrypt.CreateInstance();
                encryptor?.SetKey(secretKey, publicKey);
            }
            return encryptor;
        }
    }
}
