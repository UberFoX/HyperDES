using System;

namespace HyperDES.LUtils
{
    public static class UCheckUtils
    {
        #region DataLength
        public static void DataLength(Boolean condition, String message)
        {
            if (condition)
                ThrowDataLengthException(message);
        }
        public static void DataLength(Byte[] buf, Int32 off, Int32 len, String message)
        {
            if (off > (buf.Length - len))
                ThrowDataLengthException(message);
        }
        #endregion
        #region OutputLength
        public static void OutputLength(Byte[] buf, Int32 off, Int32 len, String message)
        {
            if (off > (buf.Length - len))
                ThrowOutputLengthException(message);
        }
        public static void OutputLength(Boolean condition, String message)
        {
            if (condition)
                ThrowOutputLengthException(message);
        }
        #endregion
        #region ThrowDataLengthException
        private static void ThrowDataLengthException(String message)
        {
            throw new Exception(message);
        }
        #endregion
        #region ThrowOutputLengthException
        private static void ThrowOutputLengthException(String message)
        {
            throw new Exception(message);
        }
        #endregion
    }
}
