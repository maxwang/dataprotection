# Data Protection

Fix Asp.net Core warning "No XML encryptor configured. Key may be persisted to storage in unencrypted form ..."

## Prerequisites

1. .NET Core SDK 3.1

## Method 1: Protect Key with certificate

### generate certificate

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout company.key -out company.crt -subj "//CN=your.company.com" -days 7300
openssl pkcs12 -export -out company.pfx -inkey company.key -in company.crt -certfile company.crt -passout pass:yourstrongpassword
```

### add pfx to project as "Embedded resource

### update startup file as below code

```csharp
public void ConfigureServices(IServiceCollection services)
{
    //..
    services.AddDataProtection()
        .PersistKeysToFileSystem(new System.IO.DirectoryInfo(@"./"))
        .ProtectKeysWithCertificate(GetCertificate());
}
 
private X509Certificate2 GetCertificate()
{
    var assembly = typeof(Startup).GetTypeInfo().Assembly;
    using (var stream = assembly.GetManifestResourceStream(
        assembly.GetManifestResourceNames().First(r => r.EndsWith("company.pfx"))))
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));
 
        var bytes = new byte[stream.Length];
        stream.Read(bytes, 0, bytes.Length);
        return new X509Certificate2(bytes, "yorustrongpassword");
    }
}
```

## Reference

(https://www.programmersought.com/article/51301938966/)
(https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?view=aspnetcore-3.1)
