using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AnsiDukptKey
{
    public class AnsiProvider
    {
        private byte[][] futureKeys = new byte[21][];
        private byte[] cryptoRegister1 = null;
        private byte[] cryptoRegister2 = null;

        private byte[] ipekLeft = null;
        private byte[] ipekRight = null;

        private byte[] bdkLeft = null;
        private byte[] bdkRight = null;

        private byte[] ksn = null;

        private int shiftCounter = 20;

        private ByteUtility _utility = ByteUtility.Instance;

        public string Decrypt(string bdk, string deviceksn, string data)
        {
            if (!string.IsNullOrEmpty(data))
            {
                byte[] ksnArray = _utility.StringToByteArray(deviceksn);
                byte[] leftBdk = _utility.StringToByteArray(bdk.Substring(0, 16));
                byte[] rightBdk = _utility.StringToByteArray(bdk.Substring(16));
                byte[] dataBytes = _utility.StringToByteArray(data);

                return Decrypt(ksnArray, leftBdk, rightBdk, dataBytes, dataBytes.Length);
            }
            return string.Empty;
        }

        public string Decrypt(byte[] deviceksn, byte[] inputBdkLeft, byte[] inputBdkRight, byte[] data, int dataLength)
        {
            ksn = deviceksn;
            bdkLeft = inputBdkLeft;
            bdkRight = inputBdkRight;
            string decodedData = string.Empty;

            if (GetIPEKs(ksn, bdkLeft, bdkRight, out ipekLeft, out ipekRight))
            {
                // The left and right keys are now set to essentially what was used as the IPEK on the device.
                System.Diagnostics.Debug.Write("Ipek (L): ");
                _utility.DebugBytes(ipekLeft);

                System.Diagnostics.Debug.Write("Ipek (R): ");
                _utility.DebugBytes(ipekRight);

                GetCryptoKeys();

                byte[] cryptoRegister1ForPin = _utility.XorByteArrays(cryptoRegister1,
                                                                      new byte[]
                                                                          {
                                                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                                              0xff
                                                                          });
                byte[] cryptoRegister2ForPin = _utility.XorByteArrays(cryptoRegister2,
                                                                      new byte[]
                                                                          {
                                                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                                              0xff
                                                                          });


                byte[] leftBytes = data;
                    // Gets a copy of the data to decrypt - This side is done with TDEA ECB / "None" padding for the first 8 bytes
                byte[] rightBytes = data;
                    // Gets a copy of the data to decrypt - This side is done with TDEA CBC / Zero's padded for all bytes after 8

                leftBytes = EncryptDecrypt(cryptoRegister1ForPin, cryptoRegister2ForPin, leftBytes, leftBytes.Count(),
                                           false, false);
                rightBytes = EncryptDecrypt(cryptoRegister1ForPin, cryptoRegister2ForPin, rightBytes, rightBytes.Count(),
                                            false, true);

                decodedData = Encoding.UTF8.GetString(leftBytes).Substring(0, 8) +
                              Encoding.Default.GetString(rightBytes).Substring(8);
                System.Diagnostics.Debug.WriteLine("Decrypt: " + decodedData);

            }

            return decodedData;
        }

        // Get's the IPEK's based on the bdk and ksn
        private bool GetIPEKs(byte[] deviceksn, byte[] bdkLeft, byte[] bdkRight, out byte[] ipekLeft,
                              out byte[] ipekRight)
        {
            byte[] ksn =
                {
                    deviceksn[0], deviceksn[1], deviceksn[2], deviceksn[3], deviceksn[4], deviceksn[5],
                    deviceksn[6], deviceksn[7], deviceksn[8], deviceksn[9]
                };

            //Set the 21 least-significant bits of this 10-byte register to zero.  This means we're clearing the counter value out
            ksn[8] = ksn[9] = 0;
            for (int bit = 0; bit < 5; bit++) ksn[7] &= unchecked((byte) (~(1 << bit)));

            // 3) Take the eight most-significant bytes of this 10-byte register, and encrypt/decrypt/encrypt these eight bytes using...
            byte[] eightMostSignificantBytes = {ksn[0], ksn[1], ksn[2], ksn[3], ksn[4], ksn[5], ksn[6], ksn[7]};

            // 3) - Cont - the double-length derivation key

            // 4) Use the ciphertext produced by Step 3 as the left half of the Initial Key. 
            byte[] leftKey = EncryptDecrypt(bdkLeft, bdkRight, eightMostSignificantBytes, 8, true, false);

            // 5) Take the 8 most-significant bytes from the 10-byte register of Step 2 and encrypt/decrypt/encrypt these 8 bytes using as the key the double-length derivation key XORed with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000.
            byte[] bdkLeft8Xord = _utility.GetXordKey(bdkLeft);
            byte[] bdkRight8Xord = _utility.GetXordKey(bdkRight);

            byte[] rightKey = EncryptDecrypt(bdkLeft8Xord, bdkRight8Xord, eightMostSignificantBytes, 8, true, false);

            ipekLeft = leftKey;
            ipekRight = rightKey;

            System.Diagnostics.Debug.Write("Left Key: ");
            _utility.DebugBytes(ipekLeft);

            System.Diagnostics.Debug.Write("Right Key: ");
            _utility.DebugBytes(ipekRight);
            return true;
        }

        private void ClearBits(byte[] data, int zeroBasedUpToBit)
        {

            int byteIndex = 0;
            while (true)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    data[byteIndex] &= (byte) ~(1 << (bit));
                }
                byteIndex++;
            }
        }

        private void ClearBitAt(byte[] data, int zeroBasedUpToBit)
        {
            int reverseByteIndex = (data.Count() - 1) - (int) (zeroBasedUpToBit/8);
            int bitToFlip = zeroBasedUpToBit%8;

            data[reverseByteIndex] &= (byte) ~(1 << (bitToFlip));
        }

        private void GetCryptoKeys()
        {
            byte[] R8A = null, R8B = null;

            // 1
            byte[] CURKEY = _utility.CombineArrays(ipekLeft, ipekRight);

            // 2
            byte[] R8 = GetRightBits(ksn, 64);

            //3
            ClearBitsUpTo(R8, 20);

            //4 - Default to 8 bytes, but only 21 bits used, so we clear the left set of bits
            byte[] R3 = GetRightBits(ksn, 64);
            for (int bit = 63; bit > 20; bit--) ClearBitAt(R3, bit);
            _utility.DebugBinaryBytesWithMessage("R3: ", R3);

            //5
            byte[] SR = new byte[8];
            SetBit(SR, 20);
            _utility.DebugBinaryBytesWithMessage("SR: ", SR);

            // TAG1
            //1 Is SR AND'ed with R3 != 0, go into loop, otherwise need to shift SR
            while (BitConverter.ToInt64(SR, 0) != 0)
            {
                // 1
                if (BitConverter.ToInt64(_utility.AndByteArrays(SR, R3), 0) != 0)
                {
                    // 2
                    R8 = _utility.OrByteArrays(R8, SR);
                    _utility.DebugBinaryBytesWithMessage("R8 After Or: ", R8);

                    // 3
                    R8A = _utility.XorByteArrays(GetRightBits(CURKEY, 64), R8);

                    // 4
                    R8A = DesEncryptDecrypt(GetLeftBits(CURKEY, 64), R8A, true);

                    // 5
                    R8A = _utility.XorByteArrays(R8A, GetRightBits(CURKEY, 64));

                    // 6
                    CURKEY = _utility.XorByteArrays(CURKEY,
                                                    new byte[]
                                                        {
                                                            0xc0, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xc0,
                                                            0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00
                                                        });

                    // 7
                    R8B = _utility.XorByteArrays(GetRightBits(CURKEY, 64), R8);

                    // 8
                    R8B = DesEncryptDecrypt(GetLeftBits(CURKEY, 64), R8B, true);

                    // 9
                    R8B = _utility.XorByteArrays(R8B, GetRightBits(CURKEY, 64));

                    // 10 & 11
                    for (int byteIndex = 0; byteIndex < 8; byteIndex++)
                    {
                        CURKEY[byteIndex] = R8B[byteIndex];
                        CURKEY[byteIndex + 8] = R8A[byteIndex];
                    }
                    cryptoRegister1 = R8B;
                    cryptoRegister2 = R8A;

                    futureKeys[shiftCounter] = _utility.CombineArrays(cryptoRegister1, cryptoRegister2);
                }

                // Shift here
                SR = new byte[8];
                shiftCounter--;
                if (shiftCounter > -1) SetBit(SR, shiftCounter);
                _utility.DebugBinaryBytesWithMessage("SR after Shift: ", SR);
            }
        }

        // Triple DES (aka TDEA) - This function wraps enc/dec, as well as flipping from ECB to CBC and padding modes
        // This runs slightly different than the ANSI spec for use by the decryption portion.
        private byte[] EncryptDecrypt(byte[] leftKey, byte[] rightKey, byte[] data, int byteCount, bool encrypt,
                                      bool useCBC)
        {
            byte[] fullKey = null;
            fullKey = new byte[]
                {
                    leftKey[0], leftKey[1], leftKey[2], leftKey[3], leftKey[4], leftKey[5], leftKey[6], leftKey[7],
                    rightKey[0], rightKey[1], rightKey[2], rightKey[3], rightKey[4], rightKey[5], rightKey[6],
                    rightKey[7]
                };

            MemoryStream output = new MemoryStream();
            byte[] result = null;

            TripleDES des = TripleDES.Create();
            des.Key = fullKey;
            des.Mode = !useCBC ? CipherMode.ECB : CipherMode.CBC;
            des.Padding = !useCBC ? PaddingMode.None : PaddingMode.Zeros;

            CryptoStream encryptionStream = null;
            if (encrypt)
            {
                encryptionStream = new CryptoStream(output, des.CreateEncryptor(), CryptoStreamMode.Write);
            }
            else
            {
                encryptionStream = new CryptoStream(output, des.CreateDecryptor(), CryptoStreamMode.Write);
            }

            encryptionStream.Write(data, 0, byteCount);
            encryptionStream.FlushFinalBlock();

            result = output.ToArray();

            output.Close();
            encryptionStream.Close();

            return result;
        }

        // DES Encrypt/Decrypt - Single DES, setup like the ANSI standard for DUKPT
        private byte[] DesEncryptDecrypt(byte[] key, byte[] data, bool encrypt)
        {
            MemoryStream output = new MemoryStream();
            byte[] result = null;

            DES des = DES.Create();
            des.Key = key;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.Zeros;

            CryptoStream encryptionStream = null;
            if (encrypt)
            {
                encryptionStream = new CryptoStream(output, des.CreateEncryptor(), CryptoStreamMode.Write);
            }
            else
            {
                encryptionStream = new CryptoStream(output, des.CreateDecryptor(), CryptoStreamMode.Write);
            }

            encryptionStream.Write(data, 0, data.Count());
            encryptionStream.FlushFinalBlock();

            result = output.ToArray();

            output.Close();
            encryptionStream.Close();

            return result;
        }

        // Helper to set a bit 'On'
        private void SetBit(byte[] bytes, int whichBit)
        {
            int byteToWorkWith = bytes.Count() - ((int) (whichBit/8)) - 1;
            int bitToFlip = whichBit%8;

            bytes[byteToWorkWith] |= (byte) (1 << (bitToFlip));

        }

        // Helper to clear a bit
        private void ClearBit(byte[] bytes, int whichBit)
        {
            int byteToWorkWith = (int) (whichBit/8);
            int bitToFlip = whichBit%8;

            bytes[byteToWorkWith] &= (byte) ~(1 << (bitToFlip));

        }

        private byte[] GetRightBits(byte[] data, int bits)
        {
            int totalBytes = bits/8;
            byte[] result = new byte[totalBytes];
            for (int index = 0; index < totalBytes; index++)
            {
                result[index] = data[(data.Count() - totalBytes) + index];
            }

            return result;
        }

        private byte[] GetLeftBits(byte[] data, int bits)
        {
            int totalBytes = bits/8;
            byte[] result = new byte[totalBytes];
            for (int index = 0; index < totalBytes; index++)
            {
                result[index] = data[index];
            }

            return result;
        }

        private void ClearBitsUpTo(byte[] bytes, int highestBitZeroBased)
        {
            int checkedBit = 0;
            for (int byteIndex = bytes.Count() - 1; byteIndex >= 0; byteIndex--)
            {
                int currentBit = 0;
                while (currentBit < 8)
                {
                    bytes[byteIndex] &= (byte) ~(1 << (((currentBit + 1)%8) - 1));
                        // The +1/-1 crap is for the mod to work properly
                    currentBit++;
                    checkedBit++;
                    if (checkedBit >= highestBitZeroBased) return;
                }
            }
        }
    }
}
