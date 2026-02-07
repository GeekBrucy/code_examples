using System.Text;
using file_upload_sftp.Dtos;
using file_upload_sftp.Settings;
using Microsoft.Extensions.Options;
using Renci.SshNet;

namespace file_upload_sftp.Services
{
    public interface ISftpService
    {
        Task UploadJsonAsync(SftpUploadRequest request, CancellationToken ct = default);
    }
    public sealed class SftpService : ISftpService
    {
        private readonly SftpOptions _opt;
        private readonly ILogger<SftpService> _log;

        public SftpService(IOptions<SftpOptions> opt, ILogger<SftpService> log)
        {
            _opt = opt.Value;
            _log = log;
        }

        public async Task UploadJsonAsync(SftpUploadRequest req, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(req.RemoteDirectory))
                throw new ArgumentException("RemoteDirectory is required.");
            if (string.IsNullOrWhiteSpace(req.FileName))
                throw new ArgumentException("FileName is required.");

            // SSH.NET is sync-only; wrap in Task.Run to avoid blocking request threads.
            await Task.Run(() =>
            {
                var finalPath = CombineRemote(req.RemoteDirectory, req.FileName);
                var tempPath = finalPath + ".part";

                using var client = new SftpClient(_opt.Host, _opt.Port, _opt.Username, _opt.Password);
                client.Connect();

                try
                {
                    EnsureRemoteDirectoryExists(client, req.RemoteDirectory);

                    var bytes = Encoding.UTF8.GetBytes(req.JsonContent);
                    using var ms = new MemoryStream(bytes);

                    client.UploadFile(ms, tempPath, canOverride: true);

                    if (client.Exists(finalPath))
                        client.DeleteFile(finalPath);

                    client.RenameFile(tempPath, finalPath);
                }
                finally
                {
                    if (client.IsConnected) client.Disconnect();
                }
            }, ct);
        }

        private static void EnsureRemoteDirectoryExists(Renci.SshNet.SftpClient client, string remoteDir)
        {
            var parts = remoteDir.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var path = "/";
            foreach (var part in parts)
            {
                path = path == "/" ? "/" + part : path + "/" + part;
                if (!client.Exists(path))
                    client.CreateDirectory(path);
            }
        }

        private static string CombineRemote(string dir, string fileName)
        {
            dir = dir.TrimEnd('/');
            fileName = fileName.TrimStart('/');
            return $"{dir}/{fileName}";
        }
    }

}