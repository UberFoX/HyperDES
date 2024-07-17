using System;

namespace HyperDES.LInterfaces
{
    public interface IUBlockCipher
    {
        void Init(Boolean forEncryption, IUCipherParameters parameters);
        Int32 GetBlockSize();
        Int32 ProcessBlock(Byte[] inBuf, Int32 inOff, Byte[] outBuf, Int32 outOff);
    }
}
