package org.commonjava.util.http.ssl.threadlocal;

public class SSLKeyCert
{

    private String keyPem;

    private String keyPassword;

    private String certPem;

    public SSLKeyCert( final String keyPem, final String keyPassword, final String certPem )
    {
        this.keyPem = keyPem;
        this.keyPassword = keyPassword;
        this.certPem = certPem;
    }

    public SSLKeyCert( final String certPem )
    {
        this.certPem = certPem;
    }

    public SSLKeyCert( final String keyPem, final String keyPassword )
    {
        this.keyPem = keyPem;
        this.keyPassword = keyPassword;
    }

    public String getKeyPem()
    {
        return keyPem;
    }

    public String getKeyPassword()
    {
        return keyPassword;
    }

    public String getCertPem()
    {
        return certPem;
    }

}
