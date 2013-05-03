package org.commonjava.util.http.ssl.threadlocal;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.inject.Inject;

import org.apache.http.auth.AuthScope;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.params.HttpParams;
import org.commonjava.util.http.client.HTTPClient;
import org.commonjava.util.logging.Logger;

public class ThreadLocalSSLSocketFactory
    extends SSLSocketFactory
{

    private final Logger logger = new Logger( getClass() );

    @Inject
    private ThreadLocalCredentialsProvider credProvider;

    @Inject
    private X509HostnameVerifier verifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;

    public ThreadLocalSSLSocketFactory( final X509HostnameVerifier verifier )
        throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException
    {
        super( (TrustStrategy) null, verifier );
        this.verifier = verifier;
    }

    public ThreadLocalSSLSocketFactory( final ThreadLocalCredentialsProvider credProvider, final X509HostnameVerifier verifier )
        throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException
    {
        super( (TrustStrategy) null, verifier );
        this.credProvider = credProvider;
    }

    @Override
    public Socket createSocket( final HttpParams params )
        throws IOException
    {
        final AuthScope scope = (AuthScope) params.getParameter( HTTPClient.AUTH_SCOPE_PARAM );

        if ( scope != null )
        {
            final SSLSocketFactory fac = getSSLFactory( scope );
            if ( fac != null )
            {
                return fac.createSocket( params );
            }
            else
            {
                return super.createSocket( params );
            }
        }

        return super.createSocket( params );
    }

    private synchronized SSLSocketFactory getSSLFactory( final AuthScope scope )
        throws IOException
    {
        SSLSocketFactory factory = null; // TODO: cache these??
        if ( factory == null )
        {
            final KeyStore ks = credProvider.getKeyStore();
            final KeyStore ts = credProvider.getTrustStore();
            final String kp = credProvider.getKeyPassword( scope );

            if ( ks != null )
            {
                if ( kp == null || kp.length() < 1 )
                {
                    logger.error( "Invalid configuration. %s cannot have an empty key password!", scope );

                    throw new IOException( scope + " is misconfigured!" );
                }
            }

            if ( ks != null || ts != null )
            {
                try
                {
                    factory = new SSLSocketFactory( SSLSocketFactory.TLS, ks, kp, ts, null, null, verifier );
                }
                catch ( final KeyManagementException e )
                {
                    logger.error( "Invalid configuration. Cannot initialize SSL socket factory for: %s. Error: %s", e,
                                  scope, e.getMessage() );
                    throw new IOException( "Failed to initialize SSL connection for: " + scope );
                }
                catch ( final UnrecoverableKeyException e )
                {
                    logger.error( "Invalid configuration. Cannot initialize SSL socket factory for: %s. Error: %s", e,
                                  scope, e.getMessage() );
                    throw new IOException( "Failed to initialize SSL connection for: " + scope );
                }
                catch ( final NoSuchAlgorithmException e )
                {
                    logger.error( "Invalid configuration. Cannot initialize SSL socket factory for: %s. Error: %s", e,
                                  scope, e.getMessage() );
                    throw new IOException( "Failed to initialize SSL connection for: " + scope );
                }
                catch ( final KeyStoreException e )
                {
                    logger.error( "Invalid configuration. Cannot initialize SSL socket factory for: %s. Error: %s", e,
                                  scope, e.getMessage() );
                    throw new IOException( "Failed to initialize SSL connection for: " + scope );
                }
            }
        }

        return factory;
    }

    @Override
    @Deprecated
    public Socket createLayeredSocket( final Socket socket, final String host, final int port, final boolean autoClose )
        throws IOException, UnknownHostException
    {
        final AuthScope scope = new AuthScope( host, port );

        final SSLSocketFactory fac = getSSLFactory( scope );
        if ( fac != null )
        {
            return fac.createLayeredSocket( socket, host, port, autoClose );
        }
        else
        {
            return super.createLayeredSocket( socket, host, port, autoClose );
        }
    }

    @Override
    public Socket createLayeredSocket( final Socket socket, final String host, final int port, final HttpParams params )
        throws IOException, UnknownHostException
    {
        AuthScope scope = (AuthScope) params.getParameter( HTTPClient.AUTH_SCOPE_PARAM );
        if ( scope == null )
        {
            scope = new AuthScope( host, port );
        }

        final SSLSocketFactory fac = getSSLFactory( scope );
        if ( fac != null )
        {
            return fac.createLayeredSocket( socket, host, port, params );
        }
        else
        {
            return super.createLayeredSocket( socket, host, port, params );
        }
    }

}
