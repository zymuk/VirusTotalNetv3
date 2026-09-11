using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Serialization;
using VirusTotalNet.v3;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;
using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.ReportGenerator;

internal class Program
{
    private static VirusTotal _virusTotal = null!;
    private static List<string> _filesQueue = new();
    private static Dictionary<string, string> _dicFileCheckingResult = new();
    private static string _pathReport = string.Empty;
    private static bool _hasShowTabDetecting;
    private static List<string> _pathFiles = new();
    private static string _pathLogging = string.Empty;
    private static readonly ScanVirusTotalProtocol Protocol = new();
    private static int _numberDetected;
    private static int _numberUndetected;

    private static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Helper();
            return;
        }

        var argsDict = new Dictionary<string, string>
        {
            { "-apiKey", Environment.GetEnvironmentVariable("VT_API_KEY") ?? string.Empty },
            { "-path", string.Empty },
            { "-report", string.Empty },
            { "-logPathUpload", string.Empty }
        };

        _hasShowTabDetecting = InitializeArguments(args, argsDict);

        _pathReport = argsDict["-report"];
        _pathLogging = argsDict["-logPathUpload"];

        var text = argsDict["-path"];
        if (File.Exists(text))
        {
            _pathFiles.Add(text);
        }
        else if (Directory.Exists(text))
        {
            _pathFiles = Directory.GetFiles(text).ToList();
        }
        else
        {
            Console.WriteLine("File " + text + " does not exist.");
            return;
        }

        InitProtocol();

        try
        {
            var apiKey = argsDict["-apiKey"];
            _virusTotal = new VirusTotal(apiKey);
            CheckFilesUpdated(_pathFiles);
            UploadFileToVirusTotal();
            GetResultCheckingUploaded();
            if (!string.IsNullOrEmpty(_pathReport))
                Process.Start(_pathReport);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception: (" + ex.GetHashCode() + ") " + ex.Message);
        }
    }

    private static bool InitializeArguments(string[] args, Dictionary<string, string> arguments)
    {
        bool showTabAnalyzing = false;
        foreach (var text in args)
        {
            if ("-showTabAnalyzing".Equals(text, StringComparison.OrdinalIgnoreCase))
            {
                showTabAnalyzing = true;
                continue;
            }

            if ("-help".Equals(text, StringComparison.OrdinalIgnoreCase))
            {
                Helper();
                continue;
            }

            var pair = text.Split('=');
            if (pair.Length == 2)
                arguments[pair[0]] = pair[1];
        }

        return showTabAnalyzing;
    }

    private static void Helper()
    {
        var exe = Path.GetFileName(Process.GetCurrentProcess().MainModule?.FileName ?? "CheckingFileVirus");
        Console.WriteLine("Usage: {0} [-option] [args...]", exe);
        Console.WriteLine("Eg: {0} {1} {2}=\"{3}\" {4}=\"{5}\"", exe, "-showTabAnalyzing", "-path", @"D:\MyApp", "-report", @"D:\Report.xml");
        Console.WriteLine("where options include:");
        Console.WriteLine("\t{0,-20}\topen analytics tab in default browser", "-showTabAnalyzing");
        Console.WriteLine("\t{0,-20}\tprint this help message", "-help");
        Console.WriteLine("\t{0,-20}\tset api key (get from VirusTotal)", "-apiKey=<api key>");
        Console.WriteLine("\t{0,-20}\tset api key via env var VT_API_KEY", " ");
        Console.WriteLine("\t{0,-20}\tfolder or file for analysis", "-path=<path file/dir>");
        Console.WriteLine("\t{0,-20}\tset a report file", "-report=<pathreport>");
        Console.WriteLine("\t{0,-20}\tset a logging file", "-logPathUpload=<pathlogfile>");
        Console.WriteLine();
    }

    private static async void CheckFilesUpdated(List<string> pathFiles)
    {
        for (int i = 0; i < pathFiles.Count; i++)
        {
            var path = pathFiles[i];
            var fileName = Path.GetFileName(path);
            Console.WriteLine("Get result file " + fileName);
            var bytes = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
            var sha256 = Hash(bytes, HashAlgorithmName.SHA256);
            var md5 = Hash(bytes, HashAlgorithmName.MD5);
            var sha1 = Hash(bytes, HashAlgorithmName.SHA1);

            try
            {
                var report = await _virusTotal.FileClient.GetFileAsync(sha256).ConfigureAwait(false);

                if (report.Attributes?.LastAnalysisResults is { Count: > 0 } results)
                {
                    PrintScan(results);
                    AddResultToProtocol(path, report, bytes.Length, md5, sha1, sha256);
                }
                else
                {
                    _filesQueue.Add(path);
                    Console.WriteLine("Added queue for uploading VirusTotal analytics.");
                    Console.WriteLine();
                }
            }
            catch (NotFoundException)
            {
                _filesQueue.Add(path);
                Console.WriteLine("Added queue for uploading VirusTotal analytics.");
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: (" + ex.GetHashCode() + ") " + ex.InnerException);
                WaitingOrInputAnyKeyToContinue();
            }
        }
    }

    private static async void UploadFileToVirusTotal()
    {
        for (int i = 0; i < _filesQueue.Count; i++)
        {
            var path = _filesQueue[i];
            var info = new FileInfo(path);
            Console.WriteLine("Uploading file " + info.Name);

            try
            {
                var now = DateTime.Now;
                var bytes = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
                using var stream = new MemoryStream(bytes, false);
                var analysis = info.Length <= FileClient.MaxScanSize
                    ? await _virusTotal.FileClient.ScanFileAsync(stream, fileName: info.Name).ConfigureAwait(false)
                    : await _virusTotal.FileClient.ScanLargeFileAsync(stream, fileName: info.Name).ConfigureAwait(false);

                Console.WriteLine("Scan response code: Queued");
                Console.WriteLine("Scan result ID: " + analysis.Id);
                Console.WriteLine("Duration: {0}", (DateTime.Now - now).ToString("mm\\:ss"));

                WriteLog(analysis);
                _dicFileCheckingResult.Add(path, analysis.Id);
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: (" + ex.GetHashCode() + ") " + ex.InnerException);
                WaitingOrInputAnyKeyToContinue();
            }
        }
    }

    private static async void GetResultCheckingUploaded()
    {
        var completed = new List<string>();

        foreach (var pair in _dicFileCheckingResult)
        {
            try
            {
                Console.WriteLine("Get result file " + Path.GetFileName(pair.Key));
                await _virusTotal.AnalysisClient.WaitForCompletionAsync(pair.Value).ConfigureAwait(false);

                var bytes = await File.ReadAllBytesAsync(pair.Key).ConfigureAwait(false);
                var sha256 = Hash(bytes, HashAlgorithmName.SHA256);
                var md5 = Hash(bytes, HashAlgorithmName.MD5);
                var sha1 = Hash(bytes, HashAlgorithmName.SHA1);
                var report = await _virusTotal.FileClient.GetFileAsync(sha256).ConfigureAwait(false);

                if (report.Attributes?.LastAnalysisResults is { Count: > 0 } results)
                {
                    PrintScan(results);
                    _filesQueue.Remove(pair.Key);
                    completed.Add(pair.Key);
                    AddResultToProtocol(pair.Key, report, bytes.Length, md5, sha1, sha256);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: (" + ex.GetHashCode() + ") " + ex.InnerException);
                WaitingOrInputAnyKeyToContinue();
            }
        }

        foreach (var path in completed)
            _dicFileCheckingResult.Remove(path);

        if (_filesQueue.Count > 0)
            UploadFileToVirusTotal();
    }

    private static void AddResultToProtocol(string pathFileName, FileObject report, long fileSize, string md5, string sha1, string sha256)
    {
        var info = new FileInfo(pathFileName);
        var attrs = report.Attributes!;
        var results = attrs.LastAnalysisResults!;

        int detected = 0;
        int total = results.Count;
        var now = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Unspecified);
        long unix = new DateTimeOffset(now).ToUnixTimeSeconds();

        var scanFile = new ScanFile
        {
            fileDateTime = File.GetLastWriteTime(pathFileName),
            fileName = info.Name,
            fileSize = fileSize,
            md5 = string.IsNullOrEmpty(attrs.Md5) ? md5 : attrs.Md5,
            pathFile = info.FullName,
            permalink = $"https://www.virustotal.com/gui/file/{sha256}/detection/f-{sha256}-{unix}",
            resource = sha256,
            scanDate = now,
            scanId = $"{sha256}-{unix}",
            sha1 = string.IsNullOrEmpty(attrs.Sha1) ? sha1 : attrs.Sha1,
            sha256 = string.IsNullOrEmpty(attrs.Sha256) ? sha256 : attrs.Sha256,
            total = total,
            verboseMsg = "Scan finished, information embedded"
        };

        foreach (var engine in results)
        {
            var cat = engine.Value.Category;
            var isDetected = cat is "malicious" or "suspicious";
            if (isDetected) detected++;

            scanFile.scanSteps.Add(new ScanStepsScanStep
            {
                result = isDetected ? ResultEnum.Detected : ResultEnum.Undetected,
                resultDescription = isDetected && !string.IsNullOrEmpty(engine.Value.Result) ? engine.Value.Result : "Undetected",
                toolAntivirus = engine.Key,
                updateDate = DateTime.TryParse(engine.Value.EngineUpdate, out var dt)
                    ? DateTime.SpecifyKind(dt.Date, DateTimeKind.Unspecified)
                    : DateTime.MinValue,
                vesion = engine.Value.EngineVersion ?? string.Empty
            });
        }

        scanFile.positives = detected;
        _numberDetected += detected;
        _numberUndetected += (total - detected);

        Protocol.scanFile.Add(scanFile);
        SaveProtocol();
    }

    private static void PrintScan(Dictionary<string, LastAnalysisResult> results)
    {
        foreach (var engine in results)
        {
            var isDetected = engine.Value.Category is "malicious" or "suspicious";
            Console.WriteLine("{0,-25} Detected: {1}", engine.Key, isDetected);
        }

        Console.WriteLine();
    }

    private static void InitProtocol()
    {
        Protocol.header = new ScanVirusTotalProtocolHeader();
        Protocol.header.fileList = string.Join("; ", _pathFiles);
        Protocol.header.shortName = GetShortName(_pathFiles);
        Protocol.header.startDateTime = DateTime.Now;
    }

    private static string GetShortName(List<string> paths)
    {
        var joined = string.Join("; ", paths);
        using var md5 = System.Security.Cryptography.MD5.Create();
        var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(joined));
        return Convert.ToHexString(hash.AsSpan(0, 4));
    }

    private static void SaveProtocol()
    {
        if (string.IsNullOrEmpty(_pathReport)) return;

        Protocol.header.scanCaseDetected = _numberDetected + " Detected";
        Protocol.header.scanCaseUndetected = _numberUndetected + " Undetected";
        var total = _numberDetected + _numberUndetected;
        Protocol.header.summaryScanCase = $"Total {total} ({Protocol.scanFile.Count} of {_pathFiles.Count} files)";
        Protocol.header.fileScannedList = string.Join("; ", Protocol.scanFile.Select(f => f.fileName));
        Protocol.header.executionTime = (DateTime.Now - Protocol.header.startDateTime).Duration().ToString("hh\\:mm\\:ss");

        var dir = Path.GetDirectoryName(_pathReport);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var xmlSerializer = new XmlSerializer(typeof(ScanVirusTotalProtocol));
        var settings = new XmlWriterSettings { Indent = true };
        using (var writer = XmlWriter.Create(_pathReport, settings))
        {
            xmlSerializer.Serialize(writer, Protocol);
        }

        var duration = Protocol.header.executionTime;
        var styleSheet = ProtocolUtil.GetTotalInformationTestProtocol(duration);
        ProtocolUtil.AddStyleSheetForProtocol(_pathReport, styleSheet);
    }

    private static void WaitingOrInputAnyKeyToContinue()
    {
        Console.WriteLine("Please enter any character or wait 60 seconds to continue...");
        var start = DateTime.Now;
        while (DateTime.Now.Subtract(start).TotalMinutes < 1.0)
        {
            Thread.Sleep(1000);
            Console.Write(".");
        }

        Console.WriteLine();
    }

    private static void WriteLog(object? obj)
    {
        if (obj == null || _pathLogging.Length == 0) return;

        var lines = new List<string>();
        if (File.Exists(_pathLogging))
        {
            lines.AddRange(File.ReadAllLines(_pathLogging));
            lines.Add(string.Empty);
        }

        if (obj is AnalysisObject analysis)
        {
            lines.Add("ID: " + analysis.Id);
        }

        File.WriteAllLines(_pathLogging, lines.ToArray());
    }

    private static string Hash(byte[] data, HashAlgorithmName name)
    {
        using var algo = IncrementalHash.CreateHash(name);
        algo.AppendData(data);
        return Convert.ToHexString(algo.GetHashAndReset()).ToLowerInvariant();
    }
}