using System;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace clsHideData
{
    public class DataHidden
    {
        private Random random = new Random();

        private string GenerateRandomCode()
        {
            Random r = new Random();
            string s = "";
            for (int j = 0; j < 5; j++)
            {
                int i = r.Next(3);
                int ch;
                switch (i)
                {
                    case 1:
                        ch = r.Next(0, 9);
                        s = s + ch.ToString();
                        break;
                    case 2:
                        ch = r.Next(65, 90);
                        s = s + Convert.ToChar(ch).ToString();
                        break;
                    case 3:
                        ch = r.Next(97, 122);
                        s = s + Convert.ToChar(ch).ToString();
                        break;
                    default:
                        ch = r.Next(97, 122);
                        s = s + Convert.ToChar(ch).ToString();
                        break;
                }
                r.NextDouble();
                r.Next(100, 1999);
            }
            return s;
        }
        

        //byte[] IV = Encoding.UTF8.GetBytes(textBox.Text);
        //byte[] KEY = Encoding.UTF8.GetBytes(textBox1.Text);


        public static byte[] ByteDonustur(string deger)
        {

            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            return ByteConverter.GetBytes(deger);

        }

        public static byte[] Byte8(string deger)
        {
            char[] arrayChar = deger.ToCharArray();
            byte[] arrayByte = new byte[arrayChar.Length];
            for (int i = 0; i < arrayByte.Length; i++)
            {
                arrayByte[i] = Convert.ToByte(arrayChar[i]);
            }
            return arrayByte;
        }

        public string MD5(string strData)
        {
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash");
            }
            else
            {
                MD5CryptoServiceProvider sifre = new MD5CryptoServiceProvider();
                byte[] arySifre = ByteDonustur(strData);
                byte[] aryHash = sifre.ComputeHash(arySifre);
                return BitConverter.ToString(aryHash);
            }
        }
        public string SHA1(string strData)
        {
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                SHA1CryptoServiceProvider sifre = new SHA1CryptoServiceProvider();
                byte[] arySifre = ByteDonustur(strData);
                byte[] aryHash = sifre.ComputeHash(arySifre);
                return BitConverter.ToString(aryHash);
            }
        }
        public string SHA256(string strData)
        {
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("Şifrelenecek Veri Yok");
            }
            else
            {
                SHA256Managed sifre = new SHA256Managed();
                byte[] arySifre = ByteDonustur(strData);
                byte[] aryHash = sifre.ComputeHash(arySifre);
                return BitConverter.ToString(aryHash);
            }
        }

        public string SHA384(string strData)
        {
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                SHA384Managed sifre = new SHA384Managed();
                byte[] arySifre = ByteDonustur(strData);
                byte[] aryHash = sifre.ComputeHash(arySifre);
                return BitConverter.ToString(aryHash);
            }
        }
        public string SHA512(string strData)
        {
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                SHA512Managed sifre = new SHA512Managed();
                byte[] arySifre = ByteDonustur(strData);
                byte[] aryHash = sifre.ComputeHash(arySifre);
                return BitConverter.ToString(aryHash);
            }
        }
        public string DES_Hide(string strData)
        {
            string sonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash");
            }
            else
            {
                byte[] aryKey = Byte8("12345678"); // enter 8 bit data
                byte[] aryIV = Byte8("12345678"); // enter 8 bit data
                DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, cryptoProvider.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
                StreamWriter writer = new StreamWriter(cs);
                writer.Write(strData);
                writer.Flush();
                cs.FlushFinalBlock();
                writer.Flush();
                sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                writer.Dispose();
                cs.Dispose();
                ms.Dispose();
            }
            return sonuc;
        }

        public string DES_Reverse(string strData)
        {
            string strSonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                byte[] aryKey = Byte8("12345678");
                byte[] aryIV = Byte8("12345678");
                DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
                MemoryStream ms = new MemoryStream(Convert.FromBase64String(strData));
                CryptoStream cs = new CryptoStream(ms, cryptoProvider.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
                StreamReader reader = new StreamReader(cs);
                strSonuc = reader.ReadToEnd();
                reader.Dispose();
                cs.Dispose();
                ms.Dispose();
            }
            return strSonuc;
        }

        public string DES3_Hide(string strData)
        {
            string sonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                byte[] aryKey = Byte8("123456781234567812345678");
                byte[] aryIV = Byte8("12345678");
                TripleDESCryptoServiceProvider dec = new TripleDESCryptoServiceProvider();
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, dec.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
                StreamWriter writer = new StreamWriter(cs);
                writer.Write(strData);
                writer.Flush();
                cs.FlushFinalBlock();
                writer.Flush();
                sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                writer.Dispose();
                cs.Dispose();
                ms.Dispose();
            }
            return sonuc;
        }

        public string DES3_Reverse(string strData)
        {
            string strSonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                byte[] aryKey = Byte8("123456781234567812345678");
                byte[] aryIV = Byte8("12345678");
                TripleDESCryptoServiceProvider cryptoProvider = new TripleDESCryptoServiceProvider();
                MemoryStream ms = new MemoryStream(Convert.FromBase64String(strData));
                CryptoStream cs = new CryptoStream(ms, cryptoProvider.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
                StreamReader reader = new StreamReader(cs);
                strSonuc = reader.ReadToEnd();
                reader.Dispose();
                cs.Dispose();
                ms.Dispose();
            }
            return strSonuc;
        }

        public string RC2_Hide(string strData)
        {
            string sonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                byte[] aryKey = Byte8("12345678");
                byte[] aryIV = Byte8("12345678");
                RC2CryptoServiceProvider dec = new RC2CryptoServiceProvider();
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, dec.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
                StreamWriter writer = new StreamWriter(cs);
                writer.Write(strData);
                writer.Flush();
                cs.FlushFinalBlock();
                writer.Flush();
                sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                writer.Dispose();
                cs.Dispose();
                ms.Dispose();
            }
            return sonuc;
        }

        public string RC2_Reverse(string strData)
        {
            string strSonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("Şifresi çözülecek veri yok.");
            }
            else
            {
                byte[] aryKey = Byte8("12345678");
                byte[] aryIV = Byte8("12345678");
                RC2CryptoServiceProvider cp = new RC2CryptoServiceProvider();
                MemoryStream ms = new MemoryStream(Convert.FromBase64String(strData));
                CryptoStream cs = new CryptoStream(ms, cp.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
                StreamReader reader = new StreamReader(cs);
                strSonuc = reader.ReadToEnd();
                reader.Dispose();
                cs.Dispose();
                ms.Dispose();
            }
            return strSonuc;
        }

        public string RIJNDAEL_Hide(string strData)
        {
            string sonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                byte[] aryKey = Byte8("12345678");
                byte[] aryIV = Byte8("1234567812345678");
                RijndaelManaged dec = new RijndaelManaged();
                dec.Mode = CipherMode.CBC;
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, dec.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
                StreamWriter writer = new StreamWriter(cs);
                writer.Write(strData);
                writer.Flush();
                cs.FlushFinalBlock();
                writer.Flush();
                sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                writer.Dispose();
                cs.Dispose();
                ms.Dispose();
            }
            return sonuc;
        }
        public string RIJNDAEL_Reverse(string strData)
        {
            string strSonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("Şifrezi çözülecek veri yok.");
            }
            else
            {
                byte[] aryKey = Byte8("12345678");
                byte[] aryIV = Byte8("1234567812345678");
                RijndaelManaged cp = new RijndaelManaged();
                MemoryStream ms = new MemoryStream(Convert.FromBase64String(strData));
                CryptoStream cs = new CryptoStream(ms, cp.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
                StreamReader reader = new StreamReader(cs);
                strSonuc = reader.ReadToEnd();
                reader.Dispose();
                cs.Dispose();
                ms.Dispose();
            }
            return strSonuc;
        }

        public string RSA_Hide(string strData, out RSAParameters prm)
        {
            string strSonuc = "";
            if (strData == "")
            {
                throw new ArgumentNullException("No data to hash.");
            }
            else
            {
                byte[] aryDizi = ByteDonustur(strData);
                RSACryptoServiceProvider dec = new RSACryptoServiceProvider();
                prm = dec.ExportParameters(true);
                byte[] aryDonus = dec.Encrypt(aryDizi, false);
                strSonuc = Convert.ToBase64String(aryDonus);
            }
            return strSonuc;
        }

        public string RSA_Reverse(string strData, RSAParameters prm)
        {
            string strSonuc = "";
            if (strData == "" || strData == null)
            {
                throw new ArgumentNullException("Çözülecek kayıt yok");
            }
            else
            {
                RSACryptoServiceProvider dec = new RSACryptoServiceProvider();
                byte[] aryDizi = Convert.FromBase64String(strData);
                UnicodeEncoding UE = new UnicodeEncoding();
                dec.ImportParameters(prm);
                byte[] aryDonus = dec.Decrypt(aryDizi, false);
                strSonuc = UE.GetString(aryDonus);
            }
            return strSonuc;

        }

        public string RandomString(int length)
        {
            const string chars = "ABvnm**kCD EFsfrtG++HIJ KLrtM NtyyuOPQR STU--VtutWX YZ34ju0123 4yuy56 789+ - =?# qwe .@";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public string PassHash(string data, string salt, int intChoosenAlgorithm)
        {
            if (data == "") return "";
            var str = salt + data;
            if (intChoosenAlgorithm == 9)
            {
                return SHA256(str);                
            } else
            {
                var pass1 = DES_Hide(str);
                if (intChoosenAlgorithm == 0) return pass1;
                if (intChoosenAlgorithm == 1) return RIJNDAEL_Hide(str);
                var pass2 = RIJNDAEL_Hide(pass1);
                if (intChoosenAlgorithm == 2) return RC2_Hide(str);
                return RC2_Hide(pass2);  
            }

        }
        public string PassHash_Reverse(string inputwithhash, string salt, int intChoosenAlgorithm)
        {
            if (inputwithhash == "") return "";
            var pass7 = "";
            if (intChoosenAlgorithm == 2) 
                pass7 = RC2_Reverse(inputwithhash);
            else if (intChoosenAlgorithm == 1)
                pass7 = RIJNDAEL_Reverse(inputwithhash);
            else if (intChoosenAlgorithm == 0)
                pass7 = DES_Reverse(inputwithhash);
            else
            {
                var pass5 = RC2_Reverse(inputwithhash);
                var pass6 = RIJNDAEL_Reverse(pass5);
                pass7 = DES_Reverse(pass6);
            }
            return (pass7.Length > salt.Length) ? pass7.Substring(salt.Length, pass7.Length - salt.Length) : "";
        }

        public string getMac()
        {
            var macAddr =
                (
                    from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where nic.OperationalStatus == OperationalStatus.Up
                    select nic.GetPhysicalAddress().ToString()
                ).FirstOrDefault();
                        return macAddr;
        }

    }

    public class Car
    {
        string color = "red";

        //static void Main(string[] args)
        //{
        //    Car myObj = new Car();
        //    Console.WriteLine(myObj.color);
        //}
    }

}
