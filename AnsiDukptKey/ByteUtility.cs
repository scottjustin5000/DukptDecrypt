using System;
using System.Linq;

namespace AnsiDukptKey
{
    public sealed class ByteUtility
    {
        static readonly ByteUtility _instance = new ByteUtility();

        private ByteUtility() { }

        public static ByteUtility Instance
        {
            get
            {
                return _instance;
            }
        }

        public void ClearBitsUpTo(byte[] bytes, int highestBitZeroBased)
        {
            int checkedBit = 0;
            for (int byteIndex = bytes.Count() - 1; byteIndex >= 0; byteIndex--)
            {
                int currentBit = 0;
                while (currentBit < 8)
                {
                    bytes[byteIndex] &= (byte)~(1 << (((currentBit + 1) % 8) - 1));  // The +1/-1 is for the mod to work properly
                    currentBit++;
                    checkedBit++; if (checkedBit >= highestBitZeroBased) return;
                }
            }
        }

        // Helper to Xor the c0c0c0c0 value into and array
        public byte[] GetXordKey(byte[] originalKey)
        {
            byte c0 = 0xc0;
            byte[] result = { (byte)(originalKey[0] ^ c0), (byte)(originalKey[1] ^ c0), (byte)(originalKey[2] ^ c0), (byte)(originalKey[3] ^ c0), (byte)(originalKey[4] ^ 0x00), (byte)(originalKey[5] ^ 0x00), (byte)(originalKey[6] ^ 0x00), (byte)(originalKey[7] ^ 0x00) };
            return result;
        }


        // Xor's 2 byte arrays.  Assumes they're of the same size
        public byte[] XorByteArrays(byte[] data, byte[] xorData)
        {
            byte[] result = new byte[data.Count()];


            for (int byteIndex = 0; byteIndex < data.Count(); byteIndex++)
            {
                result[byteIndex] = (byte)(((byte)data[byteIndex]) ^ ((byte)xorData[byteIndex]));
            }


            return result;
        }

        // Or's 2 byte arrays.  Assumes they're of the same size
        public byte[] OrByteArrays(byte[] data, byte[] xorData)
        {
            byte[] result = new byte[data.Count()];

            for (int byteIndex = 0; byteIndex < data.Count(); byteIndex++)
            {
                result[byteIndex] = (byte)(((byte)data[byteIndex]) | ((byte)xorData[byteIndex]));
            }

            return result;
        }

        // Or's 2 byte arrays.  Assumes they're of the same size
        public byte[] AndByteArrays(byte[] data, byte[] andData)
        {
            byte[] result = new byte[data.Count()];

            for (int byteIndex = 0; byteIndex < data.Count(); byteIndex++)
            {
                result[byteIndex] = (byte)(((byte)data[byteIndex]) & ((byte)andData[byteIndex]));
            }

            return result;
        }

        // Helper to make copies of arrays.  
        //  Since many are modified in place, I needed this 
        // to be able to create clean copies
        public byte[] NewArrayFromBytes(byte[] data, int numberOfBytes)
        {
            byte[] result = new byte[data.Count()];
            for (int byteIndex = 0; byteIndex < data.Count(); byteIndex++)
            {
                result[byteIndex] = data[byteIndex];
            }

            return result;
        }

        // Combines 2 arrays regardless of their sizes.
        public byte[] CombineArrays(byte[] left, byte[] right)
        {
            byte[] result = new byte[left.Count() + right.Count()];

            for (int byteIndex = 0; byteIndex < left.Count(); byteIndex++)
            {
                result[byteIndex] = left[byteIndex];
            }

            for (int byteIndex = 0; byteIndex < right.Count(); byteIndex++)
            {
                result[byteIndex + left.Count()] = right[byteIndex];
            }

            return result;
        }
        // Helper to debug binary data
        public void DebugBinaryBytes(byte[] bytes)
        {
            for (int byteIndex = 0; byteIndex < bytes.Count(); byteIndex++)
            {
                System.Diagnostics.Debug.Write(Convert.ToString(bytes[byteIndex], 2).PadLeft(8, '0') + "-");
            }
            System.Diagnostics.Debug.WriteLine(".");
        }

        // Helper to show Hex of the bytes passed
        public void DebugBytes(byte[] bytes)
        {
            string output = "";
            for (int index = 0; index < bytes.Count(); index++)
            {
                output += "0x" + Convert.ToString(bytes[index], 16) + ", ";
            }
            System.Diagnostics.Debug.WriteLine(output);
        }
        // Helper to debug keys, etc in binary
        public void DebugBinaryBytesWithMessage(string msg, byte[] bytes)
        {
            System.Diagnostics.Debug.Write(msg);
            DebugBinaryBytes(bytes);
        }

        public byte[] StringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];

            for (int index = 0; index < length; index += 2) bytes[index / 2] = Convert.ToByte(hex.Substring(index, 2), 16);

            return bytes;
        }


    }

}
