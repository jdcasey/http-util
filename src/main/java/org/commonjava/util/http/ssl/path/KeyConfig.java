package org.commonjava.util.http.ssl.path;

import java.security.KeyStore;

import javax.net.ssl.X509KeyManager;

public class KeyConfig
{

    private final KeyStore keystore;

    private final X509KeyManager keyManager;

    public KeyConfig( final KeyStore keystore, final X509KeyManager keyManager )
    {
        this.keystore = keystore;
        this.keyManager = keyManager;
    }

    public KeyStore getKeystore()
    {
        return keystore;
    }

    public X509KeyManager getKeyManager()
    {
        return keyManager;
    }

}
