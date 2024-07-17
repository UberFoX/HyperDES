using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace HyperDES.LUtils
{
    public static class UBinaryUtils
    {
        #region CopySlice
        public static T[] CopySlice<T>(T[] source, Int32 index, Int32 length, Boolean padToLength = false)
        {
            var n = length;
            T[] slice = null;
            if (source.Length < index + length)
            {
                n = source.Length - index;
                if (padToLength)
                    slice = new T[length];
            }
            if (slice == null)
                slice = new T[n];
            Array.Copy(source, index, slice, 0, n);
            return slice;
        }
        #endregion
        #region Expand
        public static String Expand(Byte[] binary, Boolean usePrefix = true)
        {
            return Expand(binary, 0, Int32.MaxValue, usePrefix);
        }
        public static String Expand(Byte[] binary, Int32 start, Boolean usePrefix = true)
        {
            return Expand(binary, start, Int32.MaxValue, usePrefix);
        }
        public static String Expand(Byte[] bin, Int32 start, Int32 length, Boolean usePrefix = true) // todo show as Int32s etc, show all 00s
        {
            var lines = new List<String> { "" };
            var count = 0;
            var line = 0;
            length = Math.Min(length, Int32.MaxValue);
            if (start > 0)
            {
                if (length == Int32.MaxValue)
                    length = bin.Length - start;
                else
                    length += start;
            }
            else if (start == 0 && length == Int32.MaxValue)
                length = bin.Length;
            if (length <= 0 || length > bin.Length)
                return "";
            // Add the bytes
            for (var index = start; index < length; index++)
            {
                var var = bin[index];
                if (count == 16)
                {
                    count = 0;
                    lines.Add("");
                    line++;
                }
                lines[line] += $"{var:X2} ";
                count++;
            }
            // Fill in blank spaces
            if (count > 0 && count != 16)
            {
                while (count != 16)
                {
                    lines[line] += "-- ";
                    count++;
                }
            }
            // Add visible chars
            count = 0;
            line = 0;
            for (var index = start; index < length; index++)
            {
                var var = bin[index];
                if (count == 16)
                {
                    count = 0;
                    line++;
                }
                var ch = (Char)var;
                lines[line] += Char.IsDigit(ch) || Char.IsLetter(ch) || (ch >= 0x21 && ch <= 0x7e) || Char.IsSymbol(ch) || Char.IsPunctuation(ch) || ch == ' ' ? ch : '.';
                count++;
            }
            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            var ignoreFrom = lines.Count + 1;
            for (var i = lines.Count - 1; i > 0; i--)
            {
                var lineT = lines[i];
                if (lineT.Contains("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))
                    ignoreFrom = i;
                else
                    break;
            }
            // Build the final array
            var finalArray = lines.TakeWhile((t, i) => i != ignoreFrom).ToArray();
            // Add numbers to each line
            if (usePrefix)
            {
                var padCount = finalArray.Length.ToString(CultureInfo.InvariantCulture).Length;
                if (padCount < 2)
                    padCount = 2;
                for (var index = 0; index < finalArray.Length; index++)
                {
                    var tmp = finalArray[index];
                    var pad = index.ToString(CultureInfo.InvariantCulture).PadLeft(padCount, '0');
                    finalArray[index] = pad + " | " + tmp;
                }
            }
            // Return finished array
            return String.Join("\n", finalArray);
        }
        #endregion
    }
}
