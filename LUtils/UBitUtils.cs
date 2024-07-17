using System;

namespace HyperDES.LUtils
{
    public static class UBitUtils
    {
        #region LoDWord
        public static UInt32 LoDWord(UInt64 x)
        {
            return (UInt32)(x & 0xFFFFFFFF);
        }
        #endregion
        #region HiDWord
        public static UInt32 HiDWord(UInt64 x)
        {
            return (UInt32)(x >> 32);
        }
        #endregion
        #region MakeQWord
        public static UInt64 MakeQWord(UInt32 loWord, UInt32 hiWord)
        {
            return (((UInt64)hiWord & 0xffffffff) << 32) | ((UInt64)loWord & 0xffffffff);
        }
        #endregion
    }
}
