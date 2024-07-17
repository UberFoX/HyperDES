using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using HyperDES.LBinary;
using HyperDES.LCiphers;
using HyperDES.LInterfaces;

namespace HyperDES.LUtils
{
    public static class UCryptoUtils
    {
        #region GenerateHyperDesKey
        public static Byte[] GenerateHyperDesKey(String password, String salt = "salt12345678", Int32 iterations = 32768)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(salt), iterations))
                return deriveBytes.GetBytes(96);
        }
        #endregion
        #region Encrypt
        public static Byte[] Encrypt(Byte[] data, IUBlockCipher engine)
        {
            var blockSize = engine.GetBlockSize();
            var encryptedDataLength = (data.Length + blockSize - 1) / blockSize * blockSize;
            var encryptedData = new Byte[encryptedDataLength];
            Array.Copy(data, encryptedData, data.Length);
            var numBlocks = encryptedData.Length / blockSize;
            Parallel.For(0, numBlocks, blockIndex =>
            {
                var i = blockIndex * blockSize;
                engine.ProcessBlock(encryptedData, i, encryptedData, i);
            });
            return encryptedData;
        }
        #endregion
        #region Decrypt
        public static Byte[] Decrypt(Byte[] data, IUBlockCipher engine)
        {
            var blockSize = engine.GetBlockSize();
            var encryptedDataLength = (data.Length + blockSize - 1) / blockSize * blockSize;
            var encryptedData = new Byte[encryptedDataLength];
            Array.Copy(data, encryptedData, data.Length);
            var numBlocks = encryptedData.Length / blockSize;
            Parallel.For(0, numBlocks, blockIndex =>
            {
                var i = blockIndex * blockSize;
                engine.ProcessBlock(encryptedData, i, encryptedData, i);
            });
            return encryptedData;
        }
        #endregion
        #region EncryptHyperDes
        public static Byte[] EncryptHyperDes(Byte[] data, Byte[] key)
        {
            var parameters = new UKeyParameter(key); // uses full space!
            var engine = new UHyperDesEngine();
            engine.Init(true, parameters);
            return Encrypt(data, engine);
        }
        #endregion
        #region DecryptHyperDes
        public static Byte[] DecryptHyperDes(Byte[] encryptedData, Byte[] key)
        {
            var parameters = new UKeyParameter(key); // uses full space!
            var engine = new UHyperDesEngine();
            engine.Init(false, parameters);
            return Decrypt(encryptedData, engine);
        }
        #endregion
    }
}
