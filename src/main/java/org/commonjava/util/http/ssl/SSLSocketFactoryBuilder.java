package org.commonjava.util.http.ssl;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.conf.KeyConfig;
import org.commonjava.util.http.ssl.conf.TrustConfig;

public interface SSLSocketFactoryBuilder
{

    SSLSocketFactory build( KeyConfig kc, TrustConfig tc, X509HostnameVerifier verifier )
        throws HTTPException;

}
