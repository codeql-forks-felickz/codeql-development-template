using System;
using System.Collections.Generic;
using System.Reflection;

namespace UnsafeReflectionTests
{
    public interface IPlugin { }

    public class Tests
    {
        private static readonly HashSet<string> AllowedTypes = new HashSet<string>
        {
            "UnsafeReflectionTests.SafePlugin"
        };

        private static readonly Dictionary<string, Type> TypeMap = new Dictionary<string, Type>
        {
            ["safe"] = typeof(Tests)
        };

        public void BadTypeGetType()
        {
            string name = Console.ReadLine(); // $ Source
            Type t = Type.GetType(name, true); // $ Alert
            Activator.CreateInstance(t);
        }

        public void BadActivatorByName()
        {
            string asm = Console.ReadLine(); // $ Source
            string typeName = Console.ReadLine(); // $ Source
            Activator.CreateInstance(asm, typeName); // $ Alert
        }

        public void BadAssemblyGetType()
        {
            string typeName = Environment.GetEnvironmentVariable("PLUGIN_TYPE"); // $ Source
            Type t = typeof(Tests).Assembly.GetType(typeName); // $ Alert
            Activator.CreateInstance(t);
        }

        public void BadAssemblyCreateInstance()
        {
            string typeName = Console.ReadLine(); // $ Source
            Assembly.GetExecutingAssembly().CreateInstance("Prefix." + typeName); // $ Alert
        }

        public void BadAppDomainCreateInstance()
        {
            string typeName = Console.ReadLine(); // $ Source
            AppDomain.CurrentDomain.CreateInstanceAndUnwrap("SomeAssembly", typeName); // $ Alert
        }

        public void GoodConstantTypeName()
        {
            Type t = Type.GetType("UnsafeReflectionTests.SafePlugin");
            Activator.CreateInstance(t);
        }

        public void GoodAllowListContains()
        {
            string name = Console.ReadLine();
            if (AllowedTypes.Contains(name))
            {
                Type t = Type.GetType(name);
                Activator.CreateInstance(t);
            }
        }

        public void BadStringContains()
        {
            string input = Console.ReadLine();
            string name = Console.ReadLine(); // $ Source
            if (input.Contains(name))
            {
                Type t = Type.GetType(name); // $ Alert
                Activator.CreateInstance(t);
            }
        }

        public void GoodDictionaryContainsKey()
        {
            string name = Console.ReadLine();
            if (TypeMap.ContainsKey(name))
            {
                Type t = Type.GetType(name);
                Activator.CreateInstance(t);
            }
        }

        public void GoodAllowListEquality()
        {
            string name = Console.ReadLine();
            if (name == "UnsafeReflectionTests.SafePlugin")
            {
                Type t = Type.GetType(name);
                Activator.CreateInstance(t);
            }
        }

        public void GoodLookupTable()
        {
            string key = Console.ReadLine();
            if (TypeMap.TryGetValue(key, out Type t))
            {
                Activator.CreateInstance(t);
            }
        }
    }
}
