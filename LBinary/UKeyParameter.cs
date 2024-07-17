using System;
using HyperDES.LInterfaces;
using HyperDES.LUtils;

namespace HyperDES.LBinary
{
    public class UKeyParameter
        : IUCipherParameters
    {
        #region Variables
        private readonly Byte[] _mKey;
        #endregion
        #region Properties
        public Int32 KeyLength => _mKey.Length;
        #endregion
        #region Constructors
        public UKeyParameter(Byte[] key)
        {
            if (key == null)
                key = Array.Empty<Byte>();
            _mKey = (Byte[])key.Clone();
        }
        public UKeyParameter(Byte[] key, Int32 keyOff, Int32 keyLen)
        {
            if (key == null)
                key = Array.Empty<Byte>();
            if (keyOff < 0 || keyOff > key.Length)
                keyOff = 0;
            if (keyLen < 0 || keyLen > (key.Length - keyOff))
                keyLen = 0;
            _mKey = new Byte[keyLen];
            Array.Copy(key, keyOff, _mKey, 0, keyLen);
        }
        private UKeyParameter(Int32 length)
        {
            if (length < 1)
                length = 0;
            _mKey = new Byte[length];
        }
        #endregion
        #region CopyTo
        public void CopyTo(Byte[] buf, Int32 off, Int32 len)
        {
            if (_mKey.Length != len)
                throw new ArgumentOutOfRangeException(nameof(len));
            Array.Copy(_mKey, 0, buf, off, len);
        }
        #endregion
        #region GetKey
        public Byte[] GetKey()
        {
            return (Byte[])_mKey.Clone();
        }
        #endregion
        #region FixedTimeEquals
        internal Boolean FixedTimeEquals(Byte[] data)
        {
            return UArrayUtils.FixedTimeEquals(_mKey, data);
        }
        #endregion
        #region Reverse
        public UKeyParameter Reverse()
        {
            var reversed = new UKeyParameter(_mKey.Length);
            UArrayUtils.Reverse(_mKey, reversed._mKey);
            return reversed;
        }
        #endregion
    }
}
