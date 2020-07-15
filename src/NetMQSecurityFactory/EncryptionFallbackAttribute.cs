using System;

namespace NetMQSecurityFactory
{
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false)]
    public class EncryptionFallbackAttribute : System.Attribute
    {
    }
}