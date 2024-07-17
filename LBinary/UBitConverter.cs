using System;

namespace HyperDES.LBinary
{
    public static class UBitConverter
    {
        #region BeToUInt32
        public static UInt32 BeToUInt32(Byte[] bs, Int32 off)
        {
            return (UInt32)bs[off] << 24
                   | (UInt32)bs[off + 1] << 16
                   | (UInt32)bs[off + 2] << 8
                   | bs[off + 3];
        }
        #endregion
        #region BeToUInt64
        public static UInt64 BeToUInt64(Byte[] bs, Int32 off)
        {
            var hi = BeToUInt32(bs, off);
            var lo = BeToUInt32(bs, off + 4);
            return ((UInt64)hi << 32) | lo;
        }
        #endregion
        #region UInt32ToBe
        public static void UInt32ToBe(UInt32 n, Byte[] bs, Int32 off)
        {
            bs[off] = (Byte)(n >> 24);
            bs[off + 1] = (Byte)(n >> 16);
            bs[off + 2] = (Byte)(n >> 8);
            bs[off + 3] = (Byte)n;
        }
        #endregion
        #region UInt64ToBe
        public static void UInt64ToBe(UInt64 n, Byte[] bs, Int32 off)
        {
            UInt32ToBe((UInt32)(n >> 32), bs, off);
            UInt32ToBe((UInt32)n, bs, off + 4);
        }
        #endregion
    }
}
