using System;
using System.Collections.Generic;
using HyperDES.LBinary;
using HyperDES.LInterfaces;
using HyperDES.LUtils;

namespace HyperDES.LCiphers
{
    public class UHyperDesEngine
        : IUBlockCipher
    {
        #region Constants
        private const Int32 BlockSize = 32;
        private const Int32 KeyCount = 12;
        #endregion
        #region Variables
        private List<Int32[]> _workingKeys;
        private Boolean _encrypting;
        #endregion
        #region Static Variables
        private static readonly Int16[] ByteBit =
        {
            128, 64, 32, 16, 8, 4, 2, 1
        };
        private static readonly Int32[] BigByte =
        {
            0x800000,   0x400000,   0x200000,   0x100000,
            0x80000,    0x40000,    0x20000,    0x10000,
            0x8000,     0x4000,     0x2000,     0x1000,
            0x800,      0x400,      0x200,      0x100,
            0x80,       0x40,       0x20,       0x10,
            0x8,        0x4,        0x2,        0x1
        };
        /*
        * Use the key schedule specified in the Standard (ANSI X3.92-1981).
        */
        private static readonly Byte[] Pc1 =
        {
            56, 48, 40, 32, 24, 16,  8,   0, 57, 49, 41, 33, 25, 17,
            9,   1, 58, 50, 42, 34, 26,  18, 10,  2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14,   6, 61, 53, 45, 37, 29, 21,
            13,  5, 60, 52, 44, 36, 28,  20, 12,  4, 27, 19, 11,  3
        };
        private static readonly Byte[] TotRot =
        {
            1,   2,  4,  6,  8, 10, 12, 14,
            15, 17, 19, 21, 23, 25, 27, 28
        };
        private static readonly Byte[] Pc2 =
        {
            13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
            22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
            40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
        };
        private static readonly UInt32[] Sp1 =
        {
            0x01010400, 0x00000000, 0x00010000, 0x01010404,
            0x01010004, 0x00010404, 0x00000004, 0x00010000,
            0x00000400, 0x01010400, 0x01010404, 0x00000400,
            0x01000404, 0x01010004, 0x01000000, 0x00000004,
            0x00000404, 0x01000400, 0x01000400, 0x00010400,
            0x00010400, 0x01010000, 0x01010000, 0x01000404,
            0x00010004, 0x01000004, 0x01000004, 0x00010004,
            0x00000000, 0x00000404, 0x00010404, 0x01000000,
            0x00010000, 0x01010404, 0x00000004, 0x01010000,
            0x01010400, 0x01000000, 0x01000000, 0x00000400,
            0x01010004, 0x00010000, 0x00010400, 0x01000004,
            0x00000400, 0x00000004, 0x01000404, 0x00010404,
            0x01010404, 0x00010004, 0x01010000, 0x01000404,
            0x01000004, 0x00000404, 0x00010404, 0x01010400,
            0x00000404, 0x01000400, 0x01000400, 0x00000000,
            0x00010004, 0x00010400, 0x00000000, 0x01010004
        };
        private static readonly UInt32[] Sp2 =
        {
            0x80108020, 0x80008000, 0x00008000, 0x00108020,
            0x00100000, 0x00000020, 0x80100020, 0x80008020,
            0x80000020, 0x80108020, 0x80108000, 0x80000000,
            0x80008000, 0x00100000, 0x00000020, 0x80100020,
            0x00108000, 0x00100020, 0x80008020, 0x00000000,
            0x80000000, 0x00008000, 0x00108020, 0x80100000,
            0x00100020, 0x80000020, 0x00000000, 0x00108000,
            0x00008020, 0x80108000, 0x80100000, 0x00008020,
            0x00000000, 0x00108020, 0x80100020, 0x00100000,
            0x80008020, 0x80100000, 0x80108000, 0x00008000,
            0x80100000, 0x80008000, 0x00000020, 0x80108020,
            0x00108020, 0x00000020, 0x00008000, 0x80000000,
            0x00008020, 0x80108000, 0x00100000, 0x80000020,
            0x00100020, 0x80008020, 0x80000020, 0x00100020,
            0x00108000, 0x00000000, 0x80008000, 0x00008020,
            0x80000000, 0x80100020, 0x80108020, 0x00108000
        };
        private static readonly UInt32[] Sp3 =
        {
            0x00000208, 0x08020200, 0x00000000, 0x08020008,
            0x08000200, 0x00000000, 0x00020208, 0x08000200,
            0x00020008, 0x08000008, 0x08000008, 0x00020000,
            0x08020208, 0x00020008, 0x08020000, 0x00000208,
            0x08000000, 0x00000008, 0x08020200, 0x00000200,
            0x00020200, 0x08020000, 0x08020008, 0x00020208,
            0x08000208, 0x00020200, 0x00020000, 0x08000208,
            0x00000008, 0x08020208, 0x00000200, 0x08000000,
            0x08020200, 0x08000000, 0x00020008, 0x00000208,
            0x00020000, 0x08020200, 0x08000200, 0x00000000,
            0x00000200, 0x00020008, 0x08020208, 0x08000200,
            0x08000008, 0x00000200, 0x00000000, 0x08020008,
            0x08000208, 0x00020000, 0x08000000, 0x08020208,
            0x00000008, 0x00020208, 0x00020200, 0x08000008,
            0x08020000, 0x08000208, 0x00000208, 0x08020000,
            0x00020208, 0x00000008, 0x08020008, 0x00020200
        };
        private static readonly UInt32[] Sp4 =
        {
            0x00802001, 0x00002081, 0x00002081, 0x00000080,
            0x00802080, 0x00800081, 0x00800001, 0x00002001,
            0x00000000, 0x00802000, 0x00802000, 0x00802081,
            0x00000081, 0x00000000, 0x00800080, 0x00800001,
            0x00000001, 0x00002000, 0x00800000, 0x00802001,
            0x00000080, 0x00800000, 0x00002001, 0x00002080,
            0x00800081, 0x00000001, 0x00002080, 0x00800080,
            0x00002000, 0x00802080, 0x00802081, 0x00000081,
            0x00800080, 0x00800001, 0x00802000, 0x00802081,
            0x00000081, 0x00000000, 0x00000000, 0x00802000,
            0x00002080, 0x00800080, 0x00800081, 0x00000001,
            0x00802001, 0x00002081, 0x00002081, 0x00000080,
            0x00802081, 0x00000081, 0x00000001, 0x00002000,
            0x00800001, 0x00002001, 0x00802080, 0x00800081,
            0x00002001, 0x00002080, 0x00800000, 0x00802001,
            0x00000080, 0x00800000, 0x00002000, 0x00802080
        };
        private static readonly UInt32[] Sp5 =
        {
            0x00000100, 0x02080100, 0x02080000, 0x42000100,
            0x00080000, 0x00000100, 0x40000000, 0x02080000,
            0x40080100, 0x00080000, 0x02000100, 0x40080100,
            0x42000100, 0x42080000, 0x00080100, 0x40000000,
            0x02000000, 0x40080000, 0x40080000, 0x00000000,
            0x40000100, 0x42080100, 0x42080100, 0x02000100,
            0x42080000, 0x40000100, 0x00000000, 0x42000000,
            0x02080100, 0x02000000, 0x42000000, 0x00080100,
            0x00080000, 0x42000100, 0x00000100, 0x02000000,
            0x40000000, 0x02080000, 0x42000100, 0x40080100,
            0x02000100, 0x40000000, 0x42080000, 0x02080100,
            0x40080100, 0x00000100, 0x02000000, 0x42080000,
            0x42080100, 0x00080100, 0x42000000, 0x42080100,
            0x02080000, 0x00000000, 0x40080000, 0x42000000,
            0x00080100, 0x02000100, 0x40000100, 0x00080000,
            0x00000000, 0x40080000, 0x02080100, 0x40000100
        };
        private static readonly UInt32[] Sp6 =
        {
            0x20000010, 0x20400000, 0x00004000, 0x20404010,
            0x20400000, 0x00000010, 0x20404010, 0x00400000,
            0x20004000, 0x00404010, 0x00400000, 0x20000010,
            0x00400010, 0x20004000, 0x20000000, 0x00004010,
            0x00000000, 0x00400010, 0x20004010, 0x00004000,
            0x00404000, 0x20004010, 0x00000010, 0x20400010,
            0x20400010, 0x00000000, 0x00404010, 0x20404000,
            0x00004010, 0x00404000, 0x20404000, 0x20000000,
            0x20004000, 0x00000010, 0x20400010, 0x00404000,
            0x20404010, 0x00400000, 0x00004010, 0x20000010,
            0x00400000, 0x20004000, 0x20000000, 0x00004010,
            0x20000010, 0x20404010, 0x00404000, 0x20400000,
            0x00404010, 0x20404000, 0x00000000, 0x20400010,
            0x00000010, 0x00004000, 0x20400000, 0x00404010,
            0x00004000, 0x00400010, 0x20004010, 0x00000000,
            0x20404000, 0x20000000, 0x00400010, 0x20004010
        };
        private static readonly UInt32[] Sp7 =
        {
            0x00200000, 0x04200002, 0x04000802, 0x00000000,
            0x00000800, 0x04000802, 0x00200802, 0x04200800,
            0x04200802, 0x00200000, 0x00000000, 0x04000002,
            0x00000002, 0x04000000, 0x04200002, 0x00000802,
            0x04000800, 0x00200802, 0x00200002, 0x04000800,
            0x04000002, 0x04200000, 0x04200800, 0x00200002,
            0x04200000, 0x00000800, 0x00000802, 0x04200802,
            0x00200800, 0x00000002, 0x04000000, 0x00200800,
            0x04000000, 0x00200800, 0x00200000, 0x04000802,
            0x04000802, 0x04200002, 0x04200002, 0x00000002,
            0x00200002, 0x04000000, 0x04000800, 0x00200000,
            0x04200800, 0x00000802, 0x00200802, 0x04200800,
            0x00000802, 0x04000002, 0x04200802, 0x04200000,
            0x00200800, 0x00000000, 0x00000002, 0x04200802,
            0x00000000, 0x00200802, 0x04200000, 0x00000800,
            0x04000002, 0x04000800, 0x00000800, 0x00200002
        };
        private static readonly UInt32[] Sp8 =
        {
            0x10001040, 0x00001000, 0x00040000, 0x10041040,
            0x10000000, 0x10001040, 0x00000040, 0x10000000,
            0x00040040, 0x10040000, 0x10041040, 0x00041000,
            0x10041000, 0x00041040, 0x00001000, 0x00000040,
            0x10040000, 0x10000040, 0x10001000, 0x00001040,
            0x00041000, 0x00040040, 0x10040040, 0x10041000,
            0x00001040, 0x00000000, 0x00000000, 0x10040040,
            0x10000040, 0x10001000, 0x00041040, 0x00040000,
            0x00041040, 0x00040000, 0x10041000, 0x00001000,
            0x00000040, 0x10040040, 0x00001000, 0x00041040,
            0x10001000, 0x00000040, 0x10000040, 0x10040000,
            0x10040040, 0x10000000, 0x00040000, 0x10001040,
            0x00000000, 0x10041040, 0x00040040, 0x10000040,
            0x10040000, 0x10001000, 0x10001040, 0x00000000,
            0x10041040, 0x00041000, 0x00041000, 0x00001040,
            0x00001040, 0x00040040, 0x10000000, 0x10041000
        };
        #endregion
        #region Constructor
        public UHyperDesEngine()
        {
        }
        #endregion
        #region Init
        public virtual void Init(Boolean encrypting, IUCipherParameters parameters)
        {
            if (!(parameters is UKeyParameter keyParameter))
                throw new ArgumentException("invalid parameter passed to HyperDES init - " + UPlatformUtils.GetTypeName(parameters));
            var keyData = keyParameter.GetKey();
            if (keyData.Length < KeyCount * 8)
                throw new ArgumentException($"key size must be at least {KeyCount * 8} byte(s).");
            var keyMaster = UBinaryUtils.CopySlice(keyData, 0, KeyCount * 8);
            _encrypting = encrypting;
            _workingKeys = new List<Int32[]>();
            _workingKeys.AddRange(GenerateWorkingKeys(encrypting, keyMaster, KeyCount));
        }
        #endregion
        #region GetBlockSize
        public virtual Int32 GetBlockSize()
        {
            return BlockSize;
        }
        #endregion
        #region ProcessBlock
        public virtual Int32 ProcessBlock(Byte[] input, Int32 inOff, Byte[] output, Int32 outOff)
        {
            if (_workingKeys == null || _workingKeys.Count <= 0)
                throw new InvalidOperationException("HyperDES engine not initialised");
            UCheckUtils.DataLength(input, inOff, BlockSize, "input buffer too short");
            UCheckUtils.OutputLength(output, outOff, BlockSize, "output buffer too short");
            #region Unpack Block
            // unpack block
            var high1 = UBitConverter.BeToUInt64(input, inOff);
            var low1 = UBitConverter.BeToUInt64(input, inOff + 8);
            var high2 = UBitConverter.BeToUInt64(input, inOff + 16);
            var low2 = UBitConverter.BeToUInt64(input, inOff + 24);
            #endregion
            #region Unpack Sub-Blocks
            // unpack sub-block1
            var highHi1 = UBitUtils.HiDWord(high1);
            var highLo1 = UBitUtils.LoDWord(high1);
            var lowHi1 = UBitUtils.HiDWord(low1);
            var lowLo1 = UBitUtils.LoDWord(low1);
            // unpack sub-block2
            var highHi2 = UBitUtils.HiDWord(high2);
            var highLo2 = UBitUtils.LoDWord(high2);
            var lowHi2 = UBitUtils.HiDWord(low2);
            var lowLo2 = UBitUtils.LoDWord(low2);
            #endregion
            if (_encrypting)
            {
                // shuffle sub-block1
                HyperDesFunc(0, ref highHi1, ref highLo1, ref lowHi1, ref lowLo1, ref highHi1, ref lowHi1, ref lowHi1, ref highHi1);
                // shuffle sub-block2
                HyperDesFunc(4, ref highHi1, ref highLo2, ref lowHi2, ref lowLo2, ref highHi2, ref lowHi2, ref lowHi2, ref highHi2);
                // shuffle sub-block 1 with sub-block 2
                HyperDesFunc(8, ref highHi1, ref highLo1, ref lowHi1, ref lowLo1, ref highHi2, ref lowHi2, ref lowHi2, ref highHi2);
            }
            else
            {
                // shuffle sub-block 1 with sub-block 2
                HyperDesFunc(8, ref highHi1, ref highLo1, ref lowHi1, ref lowLo1, ref highHi2, ref lowHi2, ref lowHi2, ref highHi2);
                // shuffle sub-block2
                HyperDesFunc(4, ref highHi1, ref highLo2, ref lowHi2, ref lowLo2, ref highHi2, ref lowHi2, ref lowHi2, ref highHi2);
                // shuffle sub-block1
                HyperDesFunc(0, ref highHi1, ref highLo1, ref lowHi1, ref lowLo1, ref highHi1, ref lowHi1, ref lowHi1, ref highHi1);
            }
            #region Pack Sub-Blocks
            // pack sub-block1
            high1 = UBitUtils.MakeQWord(highLo1, highHi1);
            low1 = UBitUtils.MakeQWord(lowLo1, lowHi1);
            // pack sub-block2
            high2 = UBitUtils.MakeQWord(highLo2, highHi2);
            low2 = UBitUtils.MakeQWord(lowLo2, lowHi2);
            #endregion
            #region Pack Block
            // pack pack block
            UBitConverter.UInt64ToBe(high1, output, outOff);
            UBitConverter.UInt64ToBe(low1, output, outOff + 8);
            UBitConverter.UInt64ToBe(high2, output, outOff + 16);
            UBitConverter.UInt64ToBe(low2, output, outOff + 24);
            #endregion
            return BlockSize;
        }
        #endregion
        #region HyperDesFunc
        public void HyperDesFunc(Int32 keyIdx, ref UInt32 a1, ref UInt32 a2, ref UInt32 b1, ref UInt32 b2, ref UInt32 c1, ref UInt32 c2, ref UInt32 d1, ref UInt32 d2)
        {
            if (_encrypting)
            {
                DesFunc(_workingKeys[keyIdx], ref a1, ref a2);
                DesFunc(_workingKeys[keyIdx + 1], ref b1, ref b2);
                DesFunc(_workingKeys[keyIdx + 2], ref c1, ref c2);
                DesFunc(_workingKeys[keyIdx + 3], ref d1, ref d2);
            }
            else
            {
                DesFunc(_workingKeys[keyIdx + 3], ref d1, ref d2);
                DesFunc(_workingKeys[keyIdx + 2], ref c1, ref c2);
                DesFunc(_workingKeys[keyIdx + 1], ref b1, ref b2);
                DesFunc(_workingKeys[keyIdx], ref a1, ref a2);
            }
        }
        #endregion
        #region DesFunc
        public static void DesFunc(Int32[] wKey, ref UInt32 hi32, ref UInt32 lo32)
        {
            var left = hi32;
            var right = lo32;
            var work = ((left >> 4) ^ right) & 0x0f0f0f0f;
            right ^= work;
            left ^= (work << 4);
            work = ((left >> 16) ^ right) & 0x0000ffff;
            right ^= work;
            left ^= (work << 16);
            work = ((right >> 2) ^ left) & 0x33333333;
            left ^= work;
            right ^= (work << 2);
            work = ((right >> 8) ^ left) & 0x00ff00ff;
            left ^= work;
            right ^= (work << 8);
            right = (right << 1) | (right >> 31);
            work = (left ^ right) & 0xaaaaaaaa;
            left ^= work;
            right ^= work;
            left = (left << 1) | (left >> 31);
            for (var round = 0; round < 8; round++)
            {
                work = (right << 28) | (right >> 4);
                work ^= (UInt32)wKey[round * 4 + 0];
                var fVal = Sp7[work & 0x3f];
                fVal |= Sp5[(work >> 8) & 0x3f];
                fVal |= Sp3[(work >> 16) & 0x3f];
                fVal |= Sp1[(work >> 24) & 0x3f];
                work = right ^ (UInt32)wKey[round * 4 + 1];
                fVal |= Sp8[work & 0x3f];
                fVal |= Sp6[(work >> 8) & 0x3f];
                fVal |= Sp4[(work >> 16) & 0x3f];
                fVal |= Sp2[(work >> 24) & 0x3f];
                left ^= fVal;
                work = (left << 28) | (left >> 4);
                work ^= (UInt32)wKey[round * 4 + 2];
                fVal = Sp7[work & 0x3f];
                fVal |= Sp5[(work >> 8) & 0x3f];
                fVal |= Sp3[(work >> 16) & 0x3f];
                fVal |= Sp1[(work >> 24) & 0x3f];
                work = left ^ (UInt32)wKey[round * 4 + 3];
                fVal |= Sp8[work & 0x3f];
                fVal |= Sp6[(work >> 8) & 0x3f];
                fVal |= Sp4[(work >> 16) & 0x3f];
                fVal |= Sp2[(work >> 24) & 0x3f];
                right ^= fVal;
            }
            right = (right << 31) | (right >> 1);
            work = (left ^ right) & 0xaaaaaaaa;
            left ^= work;
            right ^= work;
            left = (left << 31) | (left >> 1);
            work = ((left >> 8) ^ right) & 0x00ff00ff;
            right ^= work;
            left ^= (work << 8);
            work = ((left >> 2) ^ right) & 0x33333333;
            right ^= work;
            left ^= (work << 2);
            work = ((right >> 16) ^ left) & 0x0000ffff;
            left ^= work;
            right ^= (work << 16);
            work = ((right >> 4) ^ left) & 0x0f0f0f0f;
            left ^= work;
            right ^= (work << 4);
            hi32 = right;
            lo32 = left;
        }
        #endregion
        #region GenerateWorkingKeys
        public Int32[][] GenerateWorkingKeys(Boolean encrypting, Byte[] keyMaster, Int32 keyCount)
        {
            var ret = new Int32[keyCount][];
            for (var i = 0; i < keyCount; i++)
                ret[i] = GenerateWorkingKey(encrypting, UBinaryUtils.CopySlice(keyMaster, i * 8, 8));
            return ret;
        }
        #endregion
        #region GenerateWorkingKey
        public static Int32[] GenerateWorkingKey(Boolean encrypting, Byte[] key)
        {
            var newKey = new Int32[32];
            var pc1M = new Boolean[56];
            var pcr = new Boolean[56];
            for (var j = 0; j < 56; j++)
            {
                Int32 l = Pc1[j];
                pc1M[j] = ((key[(UInt32)l >> 3] & ByteBit[l & 07]) != 0);
            }
            for (var i = 0; i < 16; i++)
            {
                Int32 l, m;
                if (encrypting)
                    m = i << 1;
                else
                    m = (15 - i) << 1;
                var n = m + 1;
                newKey[m] = newKey[n] = 0;
                for (var j = 0; j < 28; j++)
                {
                    l = j + TotRot[i];
                    if (l < 28)
                        pcr[j] = pc1M[l];
                    else
                        pcr[j] = pc1M[l - 28];
                }
                for (var j = 28; j < 56; j++)
                {
                    l = j + TotRot[i];
                    if (l < 56)
                        pcr[j] = pc1M[l];
                    else
                        pcr[j] = pc1M[l - 28];
                }
                for (var j = 0; j < 24; j++)
                {
                    if (pcr[Pc2[j]])
                        newKey[m] |= BigByte[j];
                    if (pcr[Pc2[j + 24]])
                        newKey[n] |= BigByte[j];
                }
            }
            // store the processed key
            for (var i = 0; i != 32; i += 2)
            {
                var i1 = newKey[i];
                var i2 = newKey[i + 1];
                newKey[i] = (Int32)((UInt32)((i1 & 0x00fc0000) << 6) |
                                    (UInt32)((i1 & 0x00000fc0) << 10) |
                                    ((UInt32)(i2 & 0x00fc0000) >> 10) |
                                    ((UInt32)(i2 & 0x00000fc0) >> 6));
                newKey[i + 1] = (Int32)((UInt32)((i1 & 0x0003f000) << 12) |
                                        (UInt32)((i1 & 0x0000003f) << 16) |
                                        ((UInt32)(i2 & 0x0003f000) >> 4) |
                                        (UInt32)(i2 & 0x0000003f));
            }
            return newKey;
        }
        #endregion
    }
}
