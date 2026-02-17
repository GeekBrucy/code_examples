using file_upload_zip.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace file_upload_zip.Tests.Services;

public sealed class SystemIoCompressionZipServiceTests : ZipServiceTestBase
{
    protected override IZipService CreateService() =>
        new SystemIoCompressionZipService(
            new Mock<ILogger<SystemIoCompressionZipService>>().Object);
}
