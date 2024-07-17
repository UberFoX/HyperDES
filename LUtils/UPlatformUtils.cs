using System;

namespace HyperDES.LUtils
{
    public static class UPlatformUtils
    {
        #region GetTypeName
        public static String GetTypeName(Object obj)
        {
            return GetTypeName(obj.GetType());
        }
        public static String GetTypeName(Type t)
        {
            return t.FullName;
        }
        #endregion
    }
}
