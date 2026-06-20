using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using WHCryptoManager.Crypto;

namespace WHCryptoManager.ViewModel
{
    public class IndicatorItem : INotifyPropertyChanged
    {
        private string _fileName = "";
        public string FileName { get => _fileName; set { _fileName = value; OnPropertyChanged(); } }

        private string _filePath = "";
        public string FilePath { get => _filePath; set { _filePath = value; OnPropertyChanged(); } }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class CustomerRecord
    {
        public string Time { get; set; } = "";
        public string UserName { get; set; } = "";
        public string Contact { get; set; } = "";
        public string SoftwareName { get; set; } = "";
        public string SoftwareVersion { get; set; } = "";
        public int ExpireDays { get; set; } = 0;
        public string ExpirePreview { get; set; } = "";
        public string MachineCode { get; set; } = "";
        public string LicenseKey { get; set; } = "";
        public string OutputPath { get; set; } = "";
        public System.Collections.Generic.List<string> IndicatorFiles { get; set; } =
            new System.Collections.Generic.List<string>();
    }

    public class ManagerConfig
    {
        public string Contact { get; set; } = "微信: your_contact";
        public string SoftwareName { get; set; } = "文华指标客户端";
        public string SoftwareVersion { get; set; } = "1.0";
        public int ExpireDays { get; set; } = 30;
        public string MasterKeyHex { get; set; } = "";
        public string OutputPath { get; set; } = "";
    }

    public class MainViewModel : INotifyPropertyChanged
    {
        private string _userName = "";
        public string UserName { get => _userName; set { _userName = value; OnPropertyChanged(); } }

        private string _contact = "微信: your_contact";
        public string Contact { get => _contact; set { _contact = value; OnPropertyChanged(); } }

        private string _note = "";
        public string Note { get => _note; set { _note = value; OnPropertyChanged(); } }

        private string _softwareName = "文华指标客户端";
        public string SoftwareName
        {
            get => _softwareName;
            set
            {
                if (_softwareName == value) return;
                string old = _softwareName;
                _softwareName = value;
                OnPropertyChanged();
                SwitchProject(old, value);
            }
        }

        private string _softwareVersion = "1.0";
        public string SoftwareVersion { get => _softwareVersion; set { _softwareVersion = value; OnPropertyChanged(); } }

        private int _expireDays = 30;
        public int ExpireDays
        {
            get => _expireDays;
            set { _expireDays = value; OnPropertyChanged(); OnPropertyChanged(nameof(ExpirePreview)); }
        }

        public string ExpirePreview =>
            ExpireDays <= 0 ? "永久授权" : DateTime.UtcNow.AddDays(ExpireDays).ToString("yyyy-MM-dd") + " UTC";

        private string _masterKeyHex = "";
        public string MasterKeyHex { get => _masterKeyHex; set { _masterKeyHex = value; OnPropertyChanged(); } }

        private string _machineCode = "";
        public string MachineCode { get => _machineCode; set { _machineCode = value; OnPropertyChanged(); } }

        private string _licenseKey = "";
        public string LicenseKey { get => _licenseKey; set { _licenseKey = value; OnPropertyChanged(); } }

        public ObservableCollection<IndicatorItem> ExtraIndicators { get; } = new ObservableCollection<IndicatorItem>();

        private IndicatorItem _selectedIndicator;
        public IndicatorItem SelectedIndicator { get => _selectedIndicator; set { _selectedIndicator = value; OnPropertyChanged(); } }

        private string _outputPath = "";
        public string OutputPath { get => _outputPath; set { _outputPath = value; OnPropertyChanged(); } }

        private string _logText = "";
        public string LogText { get => _logText; set { _logText = value; OnPropertyChanged(); } }

        private bool _isGenerating;
        public bool IsGenerating { get => _isGenerating; set { _isGenerating = value; OnPropertyChanged(); } }

        public ObservableCollection<CustomerRecord> CustomerHistory { get; } = new ObservableCollection<CustomerRecord>();

        public MainViewModel()
        {
            _softwareName = LoadLastProject() ?? _softwareName;
            LoadConfig();
            LoadIndicators();
            LoadCustomerHistory();
        }

        public void Log(string msg) => LogText += $"[{DateTime.Now:HH:mm:ss}] {msg}\n";

        private static string AppDir() => Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? "";
        private static string SafeName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "default";
            return string.Join("_", name.Split(Path.GetInvalidFileNameChars()));
        }

        private static string ConfigPath(string softwareName) => Path.Combine(AppDir(), $"{SafeName(softwareName)}_config.json");
        private static string IndicatorsPath(string softwareName) => Path.Combine(AppDir(), $"{SafeName(softwareName)}_indicators.json");
        private static string CustomerHistoryPath(string softwareName) => Path.Combine(AppDir(), $"{SafeName(softwareName)}_customers.json");
        private static string LastProjectPath() => Path.Combine(AppDir(), "last_project.json");

        private static string LoadLastProject()
        {
            string path = LastProjectPath();
            if (!File.Exists(path)) return null;
            try { return File.ReadAllText(path, Encoding.UTF8); }
            catch { return null; }
        }

        private static void SaveLastProject(string softwareName)
        {
            try { File.WriteAllText(LastProjectPath(), softwareName ?? "", Encoding.UTF8); }
            catch { }
        }

        private void SwitchProject(string oldName, string newName)
        {
            if (!string.IsNullOrWhiteSpace(oldName))
            {
                SaveConfig(oldName);
                SaveIndicators(oldName);
                SaveCustomerHistory(oldName);
            }
            SaveLastProject(newName);
            LoadConfig(newName);
            LoadIndicators(newName);
            LoadCustomerHistory(newName);
        }

        private void LoadCustomerHistory(string softwareName = null)
        {
            string path = CustomerHistoryPath(softwareName ?? SoftwareName);
            if (!File.Exists(path)) { CustomerHistory.Clear(); return; }
            try
            {
                string json = File.ReadAllText(path, Encoding.UTF8);
                var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                var list = serializer.Deserialize<List<CustomerRecord>>(json);
                CustomerHistory.Clear();
                if (list != null)
                {
                    foreach (var r in list)
                        CustomerHistory.Add(r);
                }
            }
            catch (Exception ex)
            {
                Log("加载客户记录失败: " + ex.Message);
            }
        }

        private void SaveCustomerHistory(string softwareName = null)
        {
            string path = CustomerHistoryPath(softwareName ?? SoftwareName);
            try
            {
                var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                string json = serializer.Serialize(new List<CustomerRecord>(CustomerHistory));
                File.WriteAllText(path, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Log("保存客户记录失败: " + ex.Message);
            }
        }

        private void LoadConfig(string softwareName = null)
        {
            string path = ConfigPath(softwareName ?? SoftwareName);
            if (!File.Exists(path)) return;
            try
            {
                string json = File.ReadAllText(path, Encoding.UTF8);
                var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                var cfg = serializer.Deserialize<ManagerConfig>(json);
                if (cfg != null)
                {
                    Contact = cfg.Contact ?? "微信: your_contact";
                    SoftwareVersion = cfg.SoftwareVersion ?? "1.0";
                    ExpireDays = cfg.ExpireDays;
                    MasterKeyHex = cfg.MasterKeyHex ?? "";
                    OutputPath = cfg.OutputPath ?? "";
                }
            }
            catch (Exception ex)
            {
                Log("加载配置失败: " + ex.Message);
            }
        }

        private void SaveConfig(string softwareName = null)
        {
            string path = ConfigPath(softwareName ?? SoftwareName);
            try
            {
                var cfg = new ManagerConfig
                {
                    Contact = Contact ?? "微信: your_contact",
                    SoftwareVersion = SoftwareVersion ?? "1.0",
                    ExpireDays = ExpireDays,
                    MasterKeyHex = MasterKeyHex ?? "",
                    OutputPath = OutputPath ?? ""
                };
                var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                File.WriteAllText(path, serializer.Serialize(cfg), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Log("保存配置失败: " + ex.Message);
            }
        }

        private void LoadIndicators(string softwareName = null)
        {
            string path = IndicatorsPath(softwareName ?? SoftwareName);
            if (!File.Exists(path)) { ExtraIndicators.Clear(); return; }
            try
            {
                string json = File.ReadAllText(path, Encoding.UTF8);
                var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                var list = serializer.Deserialize<List<IndicatorItem>>(json);
                ExtraIndicators.Clear();
                if (list != null)
                {
                    foreach (var item in list)
                        ExtraIndicators.Add(item);
                }
            }
            catch (Exception ex)
            {
                Log("加载指标文件列表失败: " + ex.Message);
            }
        }

        private static bool IsPasswordProtectedXtrd(string filePath)
        {
            try
            {
                byte[] data = File.ReadAllBytes(filePath);
                if (data.Length < 16) return false;
                string text = Encoding.Default.GetString(data);
                if (!text.Contains("<HEAD>")) return false;
                int s = text.IndexOf("<CODE>");
                int e = text.IndexOf("</CODE>");
                if (s < 0 || e < 0 || e <= s) return false;
                string body = text.Substring(s + 6, e - s - 6);
                int n = 0;
                foreach (char c in body)
                {
                    if (c == '\r' || c == '\n') continue;
                    if (!Uri.IsHexDigit(c)) return false;
                    ++n;
                }
                return n >= 32;
            }
            catch { return false; }
        }

        private static string SuffixFileNameWithSoftware(string fileName, string softwareName)
        {
            if (string.IsNullOrWhiteSpace(softwareName)) return fileName;
            string suffix = new string(softwareName.Where(c => !Path.GetInvalidFileNameChars().Contains(c)).ToArray());
            if (string.IsNullOrEmpty(suffix)) return fileName;
            string ext = Path.GetExtension(fileName);
            string baseName = Path.GetFileNameWithoutExtension(fileName);
            return $"{baseName}_{suffix}{ext}";
        }

        private void SaveIndicators(string softwareName = null)
        {
            string path = IndicatorsPath(softwareName ?? SoftwareName);
            try
            {
                var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                File.WriteAllText(path, serializer.Serialize(new List<IndicatorItem>(ExtraIndicators)), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Log("保存指标文件列表失败: " + ex.Message);
            }
        }

        public void GenerateMasterKey()
        {
            var key = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(key);
            MasterKeyHex = BitConverter.ToString(key).Replace("-", "").ToLower();
            Log("已生成主密钥");
        }

        public void GenerateLicense()
        {
            if (string.IsNullOrWhiteSpace(MachineCode))
            { MessageBox.Show("请输入客户机器码"); return; }
            string code = MachineCode.Trim().ToUpperInvariant();
            if (code.Length != 26 || !System.Text.RegularExpressions.Regex.IsMatch(code, "^[A-Z2-7]+$"))
            { MessageBox.Show("机器码格式不正确，应为 26 位大写字母与数字（2-7）组合"); return; }
            if (string.IsNullOrWhiteSpace(MasterKeyHex) || MasterKeyHex.Length != 64)
                GenerateMasterKey();
            try
            {
                long expireUnix = ExpireDays > 0
                    ? (long)(DateTime.UtcNow.AddDays(ExpireDays) - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
                    : 0;
                var key = Enumerable.Range(0, 64).Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(MasterKeyHex.Substring(x, 2), 16)).ToArray();
                LicenseKey = WhLicense.GenerateLicenseKey(key, MachineCode.Trim().ToUpperInvariant(), expireUnix);
                Log($"已生成注册码（到期：{(ExpireDays <= 0 ? "永久" : DateTime.UtcNow.AddDays(ExpireDays).ToString("yyyy-MM-dd"))}）");
            }
            catch (Exception ex)
            {
                Log("生成注册码失败: " + ex.Message);
                MessageBox.Show(ex.Message, "错误");
            }
        }

        public void AddIndicators()
        {
            var dlg = new OpenFileDialog
            {
                Title = "选择已设密码的文华指标文件",
                Filter = "文华指标 (*.XTRD)|*.XTRD|所有文件 (*.*)|*.*",
                Multiselect = true,
            };
            if (dlg.ShowDialog() != true) return;
            var skipped = new List<string>();
            foreach (var path in dlg.FileNames)
            {
                var name = Path.GetFileName(path);
                if (!IsPasswordProtectedXtrd(path))
                {
                    skipped.Add(name);
                    continue;
                }
                var renamed = SuffixFileNameWithSoftware(name, SoftwareName);
                ExtraIndicators.Add(new IndicatorItem
                {
                    FileName = renamed,
                    FilePath = path,
                });
                Log($"已添加加密指标: {name} -> {renamed}");
            }
            if (skipped.Count > 0)
            {
                MessageBox.Show($"以下文件未设置查看密码，已跳过加入：\n{string.Join("\n", skipped)}",
                                "需要设密码", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            SaveIndicators();
        }

        public void RemoveIndicator(IndicatorItem item)
        {
            if (item != null)
            {
                ExtraIndicators.Remove(item);
                Log("已删除加密指标");
                SaveIndicators();
            }
        }

        public void SaveAll()
        {
            SaveConfig();
            SaveIndicators();
            SaveCustomerHistory();
            SaveLastProject(SoftwareName);
        }

        static string ProjectRoot()
        {
            var dir = AppDomain.CurrentDomain.BaseDirectory;
            for (int i = 0; i < 6; i++)
            {
                if (File.Exists(Path.Combine(dir, "tools", "build_client.py")))
                    return dir;
                dir = Path.GetDirectoryName(dir);
            }
            return Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
        }

        public void GenerateClient()
        {
            if (string.IsNullOrWhiteSpace(SoftwareName))
            { MessageBox.Show("请输入软件名称"); return; }
            if (string.IsNullOrWhiteSpace(UserName))
            { MessageBox.Show("请输入用户名"); return; }
            if (string.IsNullOrWhiteSpace(Contact))
            { MessageBox.Show("请输入联系方式"); return; }
            if (ExtraIndicators.Count == 0)
            { MessageBox.Show("请至少添加一个加密指标文件"); return; }

            try
            {
                IsGenerating = true;
                Log("开始生成客户端...");

                if (string.IsNullOrWhiteSpace(MasterKeyHex) || MasterKeyHex.Length != 64)
                    GenerateMasterKey();

                long expireUnix = ExpireDays > 0
                    ? (long)(DateTime.UtcNow.AddDays(ExpireDays) - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
                    : 0;

                string root = ProjectRoot();
                var srcArgs = new StringBuilder();
                foreach (var item in ExtraIndicators)
                {
                    if (string.IsNullOrWhiteSpace(item.FilePath) || !File.Exists(item.FilePath)) continue;
                    srcArgs.Append($"--xtrd \"{item.FilePath}\" ");
                }

                string safeUser = new string(UserName.Where(c => !Path.GetInvalidFileNameChars().Contains(c)).ToArray());
                if (string.IsNullOrEmpty(safeUser)) safeUser = "client";
                string safeSoftware = new string(SoftwareName.Where(c => !Path.GetInvalidFileNameChars().Contains(c)).ToArray());
                if (string.IsNullOrEmpty(safeSoftware)) safeSoftware = "WH8Crypto";
                string appName = $"{SoftwareName} v{SoftwareVersion}";
                if (string.IsNullOrEmpty(OutputPath))
                {
                    string clientDir = Path.Combine(AppDir(), "客户端");
                    Directory.CreateDirectory(clientDir);
                    OutputPath = Path.Combine(clientDir, $"wh8_{safeSoftware}_{safeUser}_v{SoftwareVersion}.exe");
                }

                string script = Path.Combine(root, "tools", "build_client.py");
                if (!File.Exists(script))
                    throw new FileNotFoundException("找不到 build_client.py", script);

                string licenseArgs = "";
                if (!string.IsNullOrWhiteSpace(MachineCode))
                    licenseArgs += $" --machine-code {MachineCode.Trim().ToUpperInvariant()}";
                if (!string.IsNullOrWhiteSpace(LicenseKey))
                    licenseArgs += $" --license-key {LicenseKey.Trim()}";

                var psi = new ProcessStartInfo
                {
                    FileName = "python",
                    Arguments = $"\"{script}\" {srcArgs}--user \"{UserName}\" " +
                                $"--contact \"{Contact}\" --indicator-version \"{SoftwareVersion}\" " +
                                $"--expire {expireUnix} --master {MasterKeyHex} " +
                                $"--software-name \"{SoftwareName}\" --app-name \"{appName}\"{licenseArgs} -o \"{OutputPath}\"",


                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = root,
                };
                using (var p = Process.Start(psi))
                {
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    Log(stdout);
                    if (!string.IsNullOrWhiteSpace(stderr)) Log(stderr);
                    if (p.ExitCode != 0)
                        throw new Exception("build_client.py 失败，请确认已安装 MSVC + Windows SDK + Python cryptography");
                }

                var record = new CustomerRecord
                {
                    Time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                    UserName = UserName.Trim(),
                    Contact = Contact.Trim(),
                    SoftwareName = SoftwareName.Trim(),
                    SoftwareVersion = SoftwareVersion.Trim(),
                    ExpireDays = ExpireDays,
                    ExpirePreview = ExpirePreview,
                    MachineCode = MachineCode.Trim().ToUpperInvariant(),
                    LicenseKey = LicenseKey.Trim(),
                    OutputPath = OutputPath,
                    IndicatorFiles = ExtraIndicators.Select(x => x.FileName).ToList(),
                };
                CustomerHistory.Insert(0, record);
                SaveCustomerHistory();
                SaveConfig();
                SaveIndicators();

                MessageBox.Show($"客户端已生成:\n{OutputPath}", "成功");
            }
            catch (Exception ex)
            {
                Log("失败: " + ex.Message);
                MessageBox.Show(ex.Message, "错误");
            }
            finally
            {
                IsGenerating = false;
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
