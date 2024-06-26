﻿using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Windows.Forms;
using Windows.Devices.Geolocation;
using Windows.UI.Popups;
using System.IO;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TextBox;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;


namespace cer2pfx
{
    internal class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                OpenFileDialog dialog = new OpenFileDialog();
                dialog.Filter = "Certificate Files|*.crt;*.cer;*.pfx|All Files|*.*";
                if (DialogResult.OK == dialog.ShowDialog())
                {
                    string crtpath = dialog.FileName;
                    if (crtpath.EndsWith("pfx"))
                    {
                        string certPass = "";
                        while (string.IsNullOrWhiteSpace(certPass))
                        {
                            certPass = Microsoft.VisualBasic.Interaction.InputBox("پسورد را وارد کنید?", "پسورد", "");
                        }

                        // Create a collection object and populate it using the PFX file
                        using (X509Certificate2 cert = new X509Certificate2(crtpath, certPass, X509KeyStorageFlags.Exportable))
                        {
                            SaveFileDialog saveFileDialog = new SaveFileDialog();
                            saveFileDialog.Filter = "PEM Files|*.cer";


                            if (DialogResult.OK == saveFileDialog.ShowDialog())
                            {
                                string savepath = saveFileDialog.FileName;
                                File.WriteAllText(savepath, cert.ExportCertificatePem());
                            }

                            if (cert.HasPrivateKey && cert.PrivateKey != null)
                            {

                                saveFileDialog = new SaveFileDialog();
                                saveFileDialog.Filter = "Public Key File|*.pub";


                                if (DialogResult.OK == saveFileDialog.ShowDialog())
                                {
                                    string savepath = saveFileDialog.FileName;
                                    File.WriteAllText(savepath, cert.PrivateKey.ExportSubjectPublicKeyInfoPem());
                                }






                                saveFileDialog = new SaveFileDialog();
                                saveFileDialog.Filter = "Privet Key File|*.key";


                                if (DialogResult.OK == saveFileDialog.ShowDialog())
                                {
                                    string savepath = saveFileDialog.FileName;

                                    File.WriteAllText(savepath, cert.PrivateKey.ExportPkcs8PrivateKeyPem());
                                }
                            }



                        }
                    }
                    else
                    {

                        using (X509Certificate2 cert = new X509Certificate2(crtpath))
                        {
                            using (RSA key = RSA.Create())
                            {
                                dialog = new OpenFileDialog();
                                dialog.Filter = "PrivetKey Files|*.key;*.txt|All Files|*.*";
                                if (DialogResult.OK == dialog.ShowDialog())
                                {
                                    string keypath = dialog.FileName;

                                    string privateKeyContent = File.ReadAllText(keypath);
                                    byte[] privateKeyBytes;
                                    bool isPkcsprivateKey = privateKeyContent.Contains("BEGIN PRIVATE KEY");
                                    if (isPkcsprivateKey)
                                    {
                                        var privateKey = privateKeyContent.Replace("-----BEGIN PRIVATE KEY-----", string.Empty).Replace("-----END PRIVATE KEY-----", string.Empty);
                                        privateKey = privateKey.Replace(Environment.NewLine, string.Empty);
                                        privateKeyBytes = Convert.FromBase64String(privateKey);
                                    }
                                    else
                                    {
                                        var privateKey = privateKeyContent.Replace("-----BEGIN RSA PRIVATE KEY-----", string.Empty).Replace("-----END RSA PRIVATE KEY-----", string.Empty);
                                        privateKey = privateKey.Replace(Environment.NewLine, string.Empty);
                                        privateKeyBytes = Convert.FromBase64String(privateKey);
                                    }
                                    key.ImportPkcs8PrivateKey(privateKeyBytes, out _);

                                    using (X509Certificate2 certWithKey = cert.CopyWithPrivateKey(key))
                                    {
                                        string pass = "";
                                        while (string.IsNullOrWhiteSpace(pass))
                                        {
                                            pass = Microsoft.VisualBasic.Interaction.InputBox("پسورد را وارد کنید?", "پسورد", "");
                                        }
                                        byte[] pkcs12 = certWithKey.Export(X509ContentType.Pfx, pass);

                                        SaveFileDialog saveFileDialog = new SaveFileDialog();
                                        saveFileDialog.Filter = "pkcs12 Files|*.pfx";
                                        if (DialogResult.OK == saveFileDialog.ShowDialog())
                                        {
                                            string savepath = saveFileDialog.FileName;
                                            File.WriteAllBytes(savepath, pkcs12);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show("ورودی فابل اشتباه انتخاب شده است." + ex.Message, "خطا", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
