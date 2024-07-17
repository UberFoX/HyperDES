using System;

namespace HyperDES.LUtils
{
    public static class UArrayUtils
    {
        #region FixedTimeEquals
        public static Boolean FixedTimeEquals(Byte[] a, Byte[] b)
        {
            if (null == a || null == b)
                return false;
            var len = a.Length;
            if (len != b.Length)
                return false;
            var d = 0;
            for (var i = 0; i < len; ++i)
                d |= a[i] ^ b[i];
            return 0 == d;
        }
        #endregion
        #region Reverse
        public static void Reverse<T>(T[] input, T[] output)
        {
            var last = input.Length - 1;
            for (var i = 0; i <= last; ++i)
                output[i] = input[last - i];
        }
        #endregion
    }
}
