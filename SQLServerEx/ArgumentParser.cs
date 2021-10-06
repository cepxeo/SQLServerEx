using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLServerEx
{
    public class ArgumentParser
    {
        public static readonly char[] ArgumentPrefixes;

        static ArgumentParser()
        {
            ArgumentParser.ArgumentPrefixes = BuildArgumentPrefixes();
        }

        public ArgumentList Parse(string[] args)
        {
            List<Argument> results = new List<Argument>();
            foreach (string arg in args)
            {
                if (ValueIsArgPrefix(arg))
                    results.Add(new Argument(arg.TrimStart(ArgumentParser.ArgumentPrefixes)));
                else
                    results.Last().Values.Add(arg);
            }
            return new ArgumentList(results);
        }

        private static bool ValueIsArgPrefix(string value)
        {
            if (string.IsNullOrEmpty(value))
                return false;

            return ArgumentParser.ArgumentPrefixes.Any(c => value[0] == c);
        }

        private static char[] BuildArgumentPrefixes()
        {
            return new char[] { '-', '/' };
        }
    }

    public class ArgumentList : List<Argument>
    {
        public ArgumentList()
        {
        }

        public ArgumentList(IEnumerable<Argument> collection) : base(collection)
        {
        }

        public List<Argument> Find(params string[] prefixes)
        {
            return this.Where(x => prefixes.Contains(x.Prefix, StringComparer.CurrentCultureIgnoreCase)).ToList();
        }

        public string GetValue(params string[] prefixes)
        {
            return Find(prefixes).FirstOrDefault()?.Values.FirstOrDefault();
        }
    }

    public class Argument
    {
        public Argument(string prefix)
            : this(prefix, null)
        {
        }

        public Argument(string prefix, IEnumerable<string> values)
        {
            this.Values = new List<string>();
            this.Prefix = prefix;
            if (values != null)
                this.Values.AddRange(values);
        }

        public string Prefix { get; private set; }
        public List<string> Values { get; private set; }
    }
}