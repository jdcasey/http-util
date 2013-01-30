package org.commonjava.util.http.ssl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.conf.KeyConfig;
import org.commonjava.util.http.ssl.conf.TrustConfig;

@ApplicationScoped
public class SSLManager
{

    @Inject
    private SSLResourceLoader loader;

    @Inject
    private X509HostnameVerifier verifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;

    @Inject
    private SSLSocketFactoryBuilder builder;

    public SSLManager()
    {
    }

    public SSLManager( final SSLResourceLoader loader, final SSLSocketFactoryBuilder builder )
    {
        this.loader = loader;
        this.builder = builder;
    }

    public SSLManager( final SSLResourceLoader loader, final SSLSocketFactoryBuilder builder,
                       final X509HostnameVerifier verifier )
    {
        this.loader = loader;
        this.builder = builder;
        this.verifier = verifier;
    }

    public SSLSocketFactory setupSSL()
        throws HTTPException
    {
        final KeyConfig kc = loader.getKeyConfig();
        final TrustConfig tc = loader.getTrustConfig();

        setSSLContext( kc, tc );
        return builder.build( kc, tc, verifier );
    }

    public void setSSLContext( final String basedir )
        throws HTTPException
    {
        final KeyConfig kc = loader.getKeyConfig();
        final TrustConfig tc = loader.getTrustConfig();

        setSSLContext( kc, tc );
    }

    private void setSSLContext( final KeyConfig kc, final TrustConfig tc )
        throws HTTPException
    {
        SSLContext ctx;
        try
        {
            ctx = SSLContext.getInstance( "SSL" );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Failed to retrieve SSLContext: %s", e, e.getMessage() );
        }

        try
        {
            ctx.init( new KeyManager[] { kc.getKeyManager() }, new TrustManager[] { tc.getTrustManager() }, null );
        }
        catch ( final KeyManagementException e )
        {
            throw new HTTPException( "Failed to initialize SSLContext with new PEM-based TrustStore: %s", e,
                                     e.getMessage() );
        }

        SSLContext.setDefault( ctx );
    }

    public SSLSocketFactory newSSLSocketFactory()
        throws HTTPException
    {
        final KeyConfig kc = loader.getKeyConfig();
        final TrustConfig tc = loader.getTrustConfig();

        return builder.build( kc, tc, verifier );
    }
}
