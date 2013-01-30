package org.commonjava.util.http.ssl.impl;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.SSLSocketFactoryBuilder;
import org.commonjava.util.http.ssl.conf.KeyConfig;
import org.commonjava.util.http.ssl.conf.TrustConfig;
import org.commonjava.util.logging.Logger;

public class SimpleSSLSocketFactoryBuilder
    implements SSLSocketFactoryBuilder
{

    private final Logger logger = new Logger( getClass() );

    @Override
    public SSLSocketFactory build( final KeyConfig kc, final TrustConfig tc, final X509HostnameVerifier verifier )
        throws HTTPException
    {
        try
        {
            return new SSLSocketFactory( SSLSocketFactory.TLS, kc.getKeystore(), null, tc.getKeystore(), null, null,
                                         verifier );
        }
        catch ( final KeyManagementException e )
        {
            logger.error( "Failed to setup SSL socket factory: %s", e, e.getMessage() );
            throw new HTTPException( "Failed to setup SSL socket factory: %s", e, e.getMessage() );
        }
        catch ( final UnrecoverableKeyException e )
        {
            logger.error( "Failed to setup SSL socket factory: %s", e, e.getMessage() );
            throw new HTTPException( "Failed to setup SSL socket factory: %s", e, e.getMessage() );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            logger.error( "Failed to setup SSL socket factory: %s", e, e.getMessage() );
            throw new HTTPException( "Failed to setup SSL socket factory: %s", e, e.getMessage() );
        }
        catch ( final KeyStoreException e )
        {
            logger.error( "Failed to setup SSL socket factory: %s", e, e.getMessage() );
            throw new HTTPException( "Failed to setup SSL socket factory: %s", e, e.getMessage() );
        }
    }
}
