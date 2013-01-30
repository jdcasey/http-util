package org.commonjava.util.http.ssl.conf;

import java.security.KeyStore;

import javax.net.ssl.X509TrustManager;

public class TrustConfig
{

    private final KeyStore keystore;

    private final X509TrustManager trustManager;

    public TrustConfig( final KeyStore keystore, final X509TrustManager trustManager )
    {
        this.keystore = keystore;
        this.trustManager = trustManager;
    }

    public KeyStore getKeystore()
    {
        return keystore;
    }

    public X509TrustManager getTrustManager()
    {
        return trustManager;
    }

}
