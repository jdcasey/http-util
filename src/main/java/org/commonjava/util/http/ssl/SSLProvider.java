package org.commonjava.util.http.ssl;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.commonjava.util.http.HTTPException;

public interface SSLProvider
{

    SSLSocketFactory build()
        throws HTTPException;

    KeyManager getKeyManager()
        throws HTTPException;

    TrustManager getTrustManager()
        throws HTTPException;

}
