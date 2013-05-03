package org.commonjava.util.http.ssl.path;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.enterprise.inject.Alternative;
import javax.inject.Inject;
import javax.inject.Named;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.SSLProvider;
import org.commonjava.util.logging.Logger;

@Alternative
@Named( "path" )
public class PathSSLProvider
    implements SSLProvider
{

    private final Logger logger = new Logger( getClass() );

    @Inject
    private PathSSLResourceLoader loader;

    @Inject
    private X509HostnameVerifier verifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;

    public PathSSLProvider()
    {
    }

    public PathSSLProvider( final PathSSLResourceLoader loader, final X509HostnameVerifier verifier )
    {
        this.loader = loader;
        this.verifier = verifier;
    }

    @Override
    public SSLSocketFactory build()
        throws HTTPException
    {
        final KeyConfig kc = loader.getKeyConfig();
        final TrustConfig tc = loader.getTrustConfig();

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

    @Override
    public KeyManager getKeyManager()
        throws HTTPException
    {
        return loader.getKeyConfig()
                     .getKeyManager();
    }

    @Override
    public TrustManager getTrustManager()
        throws HTTPException
    {
        return loader.getTrustConfig()
                     .getTrustManager();
    }

}
