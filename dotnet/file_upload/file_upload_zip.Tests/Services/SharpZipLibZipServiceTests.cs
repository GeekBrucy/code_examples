using file_upload_zip.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace file_upload_zip.Tests.Services;

public sealed class SharpZipLibZipServiceTests : ZipServiceTestBase
{
    protected override IZipService CreateService() =>
        new SharpZipLibZipService(
            new Mock<ILogger<SharpZipLibZipService>>().Object);
}
