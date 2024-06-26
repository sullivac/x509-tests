using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace X509Tests;

public interface ICertificateService
{
    Task<X509Certificate2> LoadFromPath(string certificatePath);

    X509Certificate2 CombineWithPrivateKey(X509Certificate2 certificate, RSA privateKey);

    RSA GetPrivateKey(string privateKey);
}

public interface ISecretsManager
{
    Task<string?> GetSecretValue(string secretId, string key);
}

public record CertificateOptions
{
    public string CertificatePath { get; init; } = string.Empty;

    public string SecretId { get; init; } = string.Empty;

    public string SecretKey { get; init; } = string.Empty;
}

public class CertificateLoader(
    ISecretsManager _secretsManager,
    ICertificateService _certificateService,
    IOptions<CertificateOptions> _certificateOptions)
{
    public async Task<X509Certificate2> LoadCertificate()
    {
        var privateKeyValue =
            await _secretsManager.GetSecretValue(
                _certificateOptions.Value.SecretId,
                _certificateOptions.Value.SecretKey);

        if (string.IsNullOrWhiteSpace(privateKeyValue))
        {
            throw new InvalidOperationException("Private key not found");
        }

        var privateKey = _certificateService.GetPrivateKey(privateKeyValue);

        var certificate =
            await _certificateService.LoadFromPath(
                _certificateOptions.Value.CertificatePath);

        return _certificateService.CombineWithPrivateKey(certificate, privateKey);
    }
}

public class UnitTest1
{
    [Fact]
    public async Task Test1()
    {
        var originalCertificate = Mock.Of<X509Certificate2>();
        var combinedCertificate = Mock.Of<X509Certificate2>();
        var secretsManager = Mock.Of<ISecretsManager>();
        var certificateService = Mock.Of<ICertificateService>();

        var certificateOptions =
            Options.Create(
                new CertificateOptions
                {
                    CertificatePath = "certificatePath",
                    SecretId = "secretId",
                    SecretKey = "secretKey"
                });

        var privateKey = RSA.Create();

        Mock.Get(secretsManager)
            .Setup(mock => mock.GetSecretValue("secretId", "secretKey"))
            .ReturnsAsync("privateKeyValue");

        Mock.Get(certificateService)
            .Setup(mock => mock.GetPrivateKey("privateKeyValue"))
            .Returns(privateKey);

        Mock.Get(certificateService)
            .Setup(mock => mock.LoadFromPath("certificatePath"))
            .ReturnsAsync(originalCertificate);

        Mock.Get(certificateService)
            .Setup(mock => mock.CombineWithPrivateKey(originalCertificate, privateKey))
            .Returns(combinedCertificate);

        var sut = new CertificateLoader(
            secretsManager,
            certificateService,
            certificateOptions);

        var result = await sut.LoadCertificate();

        result.Should().BeSameAs(combinedCertificate);
    }
}