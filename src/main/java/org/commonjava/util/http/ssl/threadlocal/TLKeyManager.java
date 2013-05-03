package org.commonjava.util.http.ssl.threadlocal;

import static org.commonjava.util.http.ssl.SSLUtils.getAlias;
import static org.commonjava.util.http.ssl.SSLUtils.toAuthScope;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.X509KeyManager;

import org.apache.http.auth.AuthScope;
import org.commonjava.util.logging.Logger;

public class TLKeyManager
    implements X509KeyManager
{

    private final Logger logger = new Logger( getClass() );

    private final ThreadLocalCredentialsProvider credProvider;

    private final X509KeyManager defaultManager;

    public TLKeyManager( final ThreadLocalCredentialsProvider credProvider, final X509KeyManager defaultManager )
    {
        this.credProvider = credProvider;
        this.defaultManager = defaultManager;
    }

    @Override
    public String chooseClientAlias( final String[] keyTypes, final Principal[] issuers, final Socket socket )
    {
        final InetSocketAddress sa = (InetSocketAddress) socket.getRemoteSocketAddress();
        final String alias = getAlias( sa, true );

        final KeyStore ks = credProvider.getKeyStore();
        try
        {
            if ( ks.containsAlias( alias ) )
            {
                return alias;
            }
        }
        catch ( final KeyStoreException e )
        {
            logger.error( "Failed to check for alias in keystore: %s. Reason: %s", e, alias, e.getMessage() );
        }

        return defaultManager.chooseClientAlias( keyTypes, issuers, socket );
    }

    @Override
    public String chooseServerAlias( final String keyType, final Principal[] issuers, final Socket socket )
    {
        final InetSocketAddress sa = (InetSocketAddress) socket.getRemoteSocketAddress();
        final String alias = getAlias( sa, true );

        final KeyStore ts = credProvider.getTrustStore();
        try
        {
            if ( ts.containsAlias( alias ) )
            {
                return alias;
            }
        }
        catch ( final KeyStoreException e )
        {
            logger.error( "Failed to check for alias in truststore: %s. Reason: %s", e, alias, e.getMessage() );
        }

        return defaultManager.chooseServerAlias( keyType, issuers, socket );
    }

    @Override
    public X509Certificate[] getCertificateChain( final String alias )
    {
        final AuthScope scope = toAuthScope( alias );
        if ( scope != null )
        {
            final KeyStore ks = credProvider.getKeyStore();
            if ( ks != null )
            {
                Certificate[] chain = null;
                try
                {
                    chain = ks.getCertificateChain( alias );
                }
                catch ( final KeyStoreException e )
                {
                    logger.error( "Failed to retrieve X.509 certificate chain for: %s. Reason: %s", e, alias,
                                  e.getMessage() );
                }

                if ( chain != null )
                {
                    final X509Certificate[] result = new X509Certificate[chain.length];
                    for ( int i = 0; i < chain.length; i++ )
                    {
                        result[i] = (X509Certificate) chain[i];
                    }

                    return result;
                }
            }
        }

        return defaultManager.getCertificateChain( alias );
    }

    @Override
    public String[] getClientAliases( final String keyType, final Principal[] issuers )
    {
        final Set<String> aliases = new HashSet<String>();

        final KeyStore ks = credProvider.getKeyStore();
        try
        {
            // TODO: filter by issuers?
            aliases.addAll( Collections.list( ks.aliases() ) );
        }
        catch ( final KeyStoreException e )
        {
            logger.error( "Cannot get list of aliases from thread-local keystore: %s", e, e.getMessage() );
        }

        aliases.addAll( Arrays.asList( defaultManager.getClientAliases( keyType, issuers ) ) );

        return aliases.isEmpty() ? null : aliases.toArray( new String[] {} );
    }

    @Override
    public PrivateKey getPrivateKey( final String alias )
    {
        final KeyStore ks = credProvider.getKeyStore();
        final String pass = credProvider.getKeyPassword( toAuthScope( alias ) );
        try
        {
            return (PrivateKey) ks.getKey( alias, pass.toCharArray() );
        }
        catch ( final UnrecoverableKeyException e )
        {
            logger.error( "Failed to retrieve private key: %s from thread-local keystore: %s", e, alias, e.getMessage() );
        }
        catch ( final KeyStoreException e )
        {
            logger.error( "Failed to retrieve private key: %s from thread-local keystore: %s", e, alias, e.getMessage() );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            logger.error( "Failed to retrieve private key: %s from thread-local keystore: %s", e, alias, e.getMessage() );
        }

        return defaultManager.getPrivateKey( alias );
    }

    @Override
    public String[] getServerAliases( final String keyType, final Principal[] issuers )
    {
        final Set<String> aliases = new HashSet<String>();

        final KeyStore ts = credProvider.getTrustStore();
        try
        {
            // TODO: filter by issuers?
            aliases.addAll( Collections.list( ts.aliases() ) );
        }
        catch ( final KeyStoreException e )
        {
            logger.error( "Cannot get list of aliases from thread-local truststore: %s", e, e.getMessage() );
        }

        aliases.addAll( Arrays.asList( defaultManager.getServerAliases( keyType, issuers ) ) );

        return aliases.isEmpty() ? null : aliases.toArray( new String[] {} );
    }
}
