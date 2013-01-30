package org.commonjava.util.http.ssl;

import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.conf.KeyConfig;
import org.commonjava.util.http.ssl.conf.TrustConfig;

public interface SSLResourceLoader
{

    KeyConfig getKeyConfig()
        throws HTTPException;

    TrustConfig getTrustConfig()
        throws HTTPException;
}
