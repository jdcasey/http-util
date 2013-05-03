package org.commonjava.util.http.ssl.threadlocal;

import static org.commonjava.util.http.ssl.SSLUtils.getDefaultKeyManager;
import static org.commonjava.util.http.ssl.SSLUtils.getDefaultTrustManager;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.SSLProvider;

public class ThreadLocalSSLProvider
    implements SSLProvider
{

    @Inject
    private ThreadLocalCredentialsProvider credProvider;

    @Inject
    private X509HostnameVerifier verifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;

    public ThreadLocalSSLProvider()
    {
    }

    public ThreadLocalSSLProvider( final ThreadLocalCredentialsProvider credProvider, final X509HostnameVerifier verifier )
    {
        this.credProvider = credProvider;
        this.verifier = verifier;
    }

    @Override
    public SSLSocketFactory build()
        throws HTTPException
    {
        if ( credProvider == null )
        {
            throw new IllegalStateException(
                                             "No "
                                                 + ThreadLocalCredentialsProvider.class.getName()
                                                 + " was configured! This object coordinates binding and looking up credentials for a http client thread, "
                                                 + "so must be initialized and passed in." );
        }

        try
        {
            return new ThreadLocalSSLSocketFactory( credProvider, verifier );
        }
        catch ( final KeyManagementException e )
        {
            throw new HTTPException( "Cannot initialize socket factory: %s", e, e.getMessage() );
        }
        catch ( final UnrecoverableKeyException e )
        {
            throw new HTTPException( "Cannot initialize socket factory: %s", e, e.getMessage() );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Cannot initialize socket factory: %s", e, e.getMessage() );
        }
        catch ( final KeyStoreException e )
        {
            throw new HTTPException( "Cannot initialize socket factory: %s", e, e.getMessage() );
        }
    }

    @Override
    public KeyManager getKeyManager()
        throws HTTPException
    {
        return new TLKeyManager( credProvider, getDefaultKeyManager() );
    }

    @Override
    public TrustManager getTrustManager()
        throws HTTPException
    {
        return new TLTrustManager( credProvider, getDefaultTrustManager() );
    }

}
